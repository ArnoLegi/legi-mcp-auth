"""Middleware ASGI exigeant un jeton Bearer valide sur les routes MCP.

Middleware ASGI **pur**, et non `BaseHTTPMiddleware` : ce dernier fait passer la réponse
par une file d'attente interne, ce qui casse les transports à flux long — le SSE de
`/sse` et les réponses en flux de `/mcp` seraient tamponnés, et la session MCP
tomberait sur un délai d'inactivité.
"""
from __future__ import annotations

import hmac
import json
import logging
from typing import Any, Awaitable, Callable, Iterable

from .config import ParametresAuth
from .validation import JetonRefuse, ValidateurEntra, utilisateur_depuis_revendications

log = logging.getLogger("legi_mcp_auth.middleware")

#: Journal dédié à l'audit d'accès : « qui a appelé quel outil ». À router vers une
#: destination durable en production (fichier, collecteur), c'est la trace d'accès.
audit = logging.getLogger("legi_mcp_auth.audit")

#: Chemins exacts jamais protégés.
CHEMINS_EXEMPTES: tuple[str, ...] = ("/health",)

#: Préfixes jamais protégés — la découverte OAuth doit précéder l'authentification.
PREFIXES_EXEMPTES: tuple[str, ...] = ("/.well-known/",)

#: Corps de requête au-delà duquel on renonce à identifier l'outil appelé (le corps
#: n'est alors PAS tamponné). Un message JSON-RPC MCP pèse quelques kilo-octets.
TAILLE_MAX_AUDIT = 256 * 1024

MESSAGE_401_ENTRA = (
    "Jeton d'accès absent ou invalide. Ce serveur MCP exige un jeton Bearer émis par "
    "Microsoft Entra ID. Voir le document de métadonnées indiqué par l'en-tête "
    "WWW-Authenticate pour l'autorité et la portée à demander."
)

MESSAGE_401_JETONS = (
    "Jeton absent ou invalide. Ce serveur MCP exige un jeton d'administration présenté "
    "en Authorization: Bearer. Il n'y a pas de flux OAuth à suivre : le jeton est "
    "délivré par l'administrateur du serveur."
)


class EntraAuthMiddleware:
    """Exige un `Authorization: Bearer` valide sur tout ce qui n'est pas exempté."""

    def __init__(
        self,
        app: Any,
        parametres: ParametresAuth,
        *,
        validateur: ValidateurEntra | None = None,
        chemins_exemptes: Iterable[str] = CHEMINS_EXEMPTES,
        prefixes_exemptes: Iterable[str] = PREFIXES_EXEMPTES,
    ) -> None:
        self.app = app
        self.parametres = parametres
        # En mode « jetons », aucun validateur : pas d'autorité, donc pas de JWKS à
        # télécharger ni de client HTTP à ouvrir. Le construire quand même serait
        # inutile, et il pointerait vers une URL de tenant vide.
        if validateur is None and parametres.entra_actif:
            validateur = ValidateurEntra(parametres)
        self.validateur = validateur
        self.chemins_exemptes = tuple(chemins_exemptes)
        self.prefixes_exemptes = tuple(prefixes_exemptes)

    # ------------------------------------------------------------------ ASGI

    async def __call__(self, scope: dict, receive: Callable, send: Callable) -> None:
        # `lifespan` et `websocket` ne portent pas d'en-tête Authorization utilisable :
        # laissés au serveur, qui n'expose aucun WebSocket ici.
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        chemin = scope.get("path", "")
        if self._exempte(chemin):
            await self.app(scope, receive, send)
            return

        jeton = _jeton_bearer(scope)
        if not jeton:
            log.info("401 %s %s : en-tête Authorization absent ou mal formé",
                     scope.get("method"), chemin)
            await self._refuser(send)
            return

        if self._est_jeton_admin(jeton):
            utilisateur: dict[str, Any] = {"admin": True}
        elif self.validateur is not None:
            try:
                revendications = await self.validateur.valider(jeton)
            except JetonRefuse as exc:
                # Le motif reste dans le journal ; la réponse, elle, ne dit rien.
                log.warning("401 %s %s : %s", scope.get("method"), chemin, exc.motif)
                await self._refuser(send)
                return
            utilisateur = utilisateur_depuis_revendications(revendications)
        else:
            # Mode « jetons » : rien d'autre à essayer, la liste est la seule référence.
            log.warning(
                "401 %s %s : jeton inconnu (mode jetons)", scope.get("method"), chemin
            )
            await self._refuser(send)
            return

        scope.setdefault("state", {})["utilisateur"] = utilisateur

        receive = await self._auditer(scope, receive, utilisateur)
        await self.app(scope, receive, send)

    # -------------------------------------------------------------- décisions

    def _exempte(self, chemin: str) -> bool:
        return chemin in self.chemins_exemptes or chemin.startswith(self.prefixes_exemptes)

    def _est_jeton_admin(self, jeton: str) -> bool:
        """Compare le jeton présenté aux jetons administrateurs, en temps constant.

        Aucune sortie anticipée : la boucle parcourt toute la liste quoi qu'il arrive,
        pour ne pas révéler par le temps de réponse combien de jetons ont été comparés.
        """
        presente = jeton.encode("utf-8")
        valide = False
        for attendu in self.parametres.jetons_admin:
            valide |= hmac.compare_digest(presente, attendu.encode("utf-8"))
        return valide

    # ----------------------------------------------------------------- audit

    async def _auditer(
        self, scope: dict, receive: Callable, utilisateur: dict[str, Any]
    ) -> Callable[[], Awaitable[dict]]:
        """Journalise « utilisateur=… outil=… » et rend un `receive` rejouable.

        Le nom de l'outil n'existe que dans le corps JSON-RPC. On tamponne donc le corps
        pour le lire, puis on le rejoue à l'application : elle doit le recevoir intact.
        """
        if scope.get("method") != "POST" or not _corps_tamponnable(scope):
            return receive

        corps, receive_rejouable = await _tamponner(receive, TAILLE_MAX_AUDIT)
        for outil in _outils_appeles(corps):
            audit.info("utilisateur=%s outil=%s", _libelle(utilisateur), outil)
        return receive_rejouable

    # -------------------------------------------------------------- réponses

    async def _refuser(self, send: Callable) -> None:
        """401 conforme au brouillon MCP « Authorization » et à la RFC 6750.

        En mode « entra », le 401 porte de quoi découvrir le flux OAuth :
        `resource_metadata` et `scope`. En mode « jetons », il ne les porte PAS — il
        n'existe aucune autorité, aucune métadonnée à servir et aucune portée à
        demander. Annoncer une adresse de découverte qui répondrait 404 enverrait les
        clients dans un flux impossible.
        """
        p = self.parametres
        if p.entra_actif:
            entete = (
                f'Bearer resource_metadata="{p.url_metadonnees}", '
                f'scope="{p.scope_complet}", '
                f'error="invalid_token"'
            )
            charge = {
                "error": "invalid_token",
                "error_description": MESSAGE_401_ENTRA,
                "resource_metadata": p.url_metadonnees,
                "scope": p.scope_complet,
            }
        else:
            entete = 'Bearer error="invalid_token"'
            charge = {
                "error": "invalid_token",
                "error_description": MESSAGE_401_JETONS,
            }
        corps = json.dumps(charge, ensure_ascii=False, indent=2).encode("utf-8")
        await send(
            {
                "type": "http.response.start",
                "status": 401,
                "headers": [
                    (b"content-type", b"application/json; charset=utf-8"),
                    (b"content-length", str(len(corps)).encode("ascii")),
                    (b"www-authenticate", entete.encode("utf-8")),
                    (b"cache-control", b"no-store"),
                ],
            }
        )
        await send({"type": "http.response.body", "body": corps})


# --------------------------------------------------------------------- outils


def _jeton_bearer(scope: dict) -> str:
    """Extrait le jeton de `Authorization: Bearer <jeton>`, ou renvoie une chaîne vide."""
    for nom, valeur in scope.get("headers", []):
        if nom.lower() != b"authorization":
            continue
        try:
            brut = valeur.decode("latin-1").strip()
        except UnicodeDecodeError:  # pragma: no cover — latin-1 ne lève pas
            return ""
        schema, _, jeton = brut.partition(" ")
        if schema.lower() != "bearer":
            return ""
        return jeton.strip()
    return ""


def _corps_tamponnable(scope: dict) -> bool:
    """Vrai si le corps est du JSON de taille annoncée et raisonnable."""
    longueur: int | None = None
    type_contenu = b""
    for nom, valeur in scope.get("headers", []):
        cle = nom.lower()
        if cle == b"content-length":
            try:
                longueur = int(valeur)
            except ValueError:
                return False
        elif cle == b"content-type":
            type_contenu = valeur.lower()
    if longueur is None or longueur > TAILLE_MAX_AUDIT:
        # Longueur inconnue (transfert par morceaux) : on ne tamponne pas, au risque de
        # retenir un flux. L'audit saute cet appel, le service passe.
        return False
    return b"json" in type_contenu


async def _tamponner(receive: Callable, limite: int) -> tuple[bytes, Callable]:
    """Lit le corps entier et renvoie (corps, receive rejouant les messages lus)."""
    messages: list[dict] = []
    morceaux: list[bytes] = []
    taille = 0
    depasse = False
    while True:
        message = await receive()
        messages.append(message)
        if message["type"] != "http.request":
            break  # http.disconnect : rien de plus à lire
        if not depasse:
            corps = message.get("body", b"")
            taille += len(corps)
            if taille > limite:
                depasse = True
                morceaux.clear()
            else:
                morceaux.append(corps)
        if not message.get("more_body", False):
            break

    file = iter(messages)

    async def rejouer() -> dict:
        for message in file:
            return message
        return await receive()

    return (b"" if depasse else b"".join(morceaux)), rejouer


def _outils_appeles(corps: bytes) -> list[str]:
    """Noms des outils appelés dans un corps JSON-RPC (message seul ou lot)."""
    if not corps:
        return []
    try:
        charge = json.loads(corps)
    except (ValueError, UnicodeDecodeError):
        return []
    messages = charge if isinstance(charge, list) else [charge]
    noms = []
    for message in messages:
        if not isinstance(message, dict) or message.get("method") != "tools/call":
            continue
        parametres = message.get("params")
        nom = parametres.get("name") if isinstance(parametres, dict) else None
        noms.append(str(nom) if nom else "?")
    return noms


def _libelle(utilisateur: dict[str, Any]) -> str:
    """Libellé d'audit : jamais le jeton, seulement une identité lisible."""
    if utilisateur.get("admin"):
        return "admin"
    return utilisateur.get("preferred_username") or utilisateur.get("oid") or "inconnu"
