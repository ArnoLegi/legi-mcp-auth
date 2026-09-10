"""Lecture et validation de la configuration d'authentification.

Tout est piloté par variables d'environnement. Le principe directeur : SANS
configuration, le paquet est NEUTRE (mode « off », comportement du serveur inchangé) ;
AVEC une configuration incomplète, il REFUSE de démarrer plutôt que de laisser croire
qu'une protection est en place. Une authentification à moitié configurée qui laisse
passer tout le monde est le pire des trois cas.
"""
from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field

log = logging.getLogger("legi_mcp_auth.config")

MODE_OFF = "off"
MODE_JETONS = "jetons"
MODE_ENTRA = "entra"
MODES = (MODE_OFF, MODE_JETONS, MODE_ENTRA)

#: Autorité Microsoft Entra ID (nuage public). Les nuages souverains (Chine, US Gov)
#: utilisent d'autres hôtes ; ils ne sont pas gérés ici, faute d'usage au cabinet.
AUTORITE = "https://login.microsoftonline.com"

#: Chemin des métadonnées de ressource protégée, fixé par la RFC 9728.
CHEMIN_METADONNEES = "/.well-known/oauth-protected-resource"

SCOPE_DEFAUT = "mcp.access"

#: Tolérance d'horloge, en secondes, sur `exp` et `nbf`.
TOLERANCE_HORLOGE = 60

#: Durée de vie du cache JWKS, en secondes (24 h). Un `kid` inconnu déclenche de toute
#: façon un rafraîchissement immédiat : ce TTL n'est qu'un filet de sécurité.
JWKS_TTL = 86_400.0

#: Longueur en dessous de laquelle un jeton administrateur est jugé trop faible.
LONGUEUR_MINI_JETON_ADMIN = 32


class ConfigurationAuthInvalide(RuntimeError):
    """Configuration d'authentification inutilisable — le serveur ne doit pas démarrer."""


@dataclass(frozen=True)
class ParametresAuth:
    """Configuration effective de l'authentification."""

    mode: str = MODE_OFF
    tenant_id: str = ""
    client_id: str = ""
    #: Audience attendue dans le jeton. Défaut : le client ID.
    audience: str = ""
    scope_requis: str = SCOPE_DEFAUT
    #: Identifiants (GUID) des groupes Entra autorisés. Vide = aucun filtrage par groupe.
    groupes_autorises: tuple[str, ...] = ()
    #: URL publique du serveur, sans barre oblique finale. Sert au champ `resource` des
    #: métadonnées et à l'en-tête WWW-Authenticate.
    url_publique: str = ""
    #: Jetons statiques acceptés tels quels en Authorization: Bearer.
    jetons_admin: tuple[str, ...] = field(default=(), repr=False)
    tolerance_horloge: int = TOLERANCE_HORLOGE
    jwks_ttl: float = JWKS_TTL

    # ------------------------------------------------------------------ état

    @property
    def actif(self) -> bool:
        """Vrai si une authentification est exigée — donc si le middleware s'installe."""
        return self.mode in (MODE_JETONS, MODE_ENTRA)

    @property
    def entra_actif(self) -> bool:
        """Vrai si les jetons Microsoft Entra ID sont validés.

        Distinct de `actif` : en mode « jetons », le middleware s'installe et refuse
        tout ce qui n'est pas un jeton d'administration, sans qu'aucune autorité
        OAuth n'existe — donc sans JWKS, sans métadonnées et sans `resource_metadata`
        dans le 401.
        """
        return self.mode == MODE_ENTRA

    # ------------------------------------------------------- valeurs dérivées

    @property
    def issuer(self) -> str:
        """Émetteur attendu (`iss`) des jetons v2.0."""
        return f"{AUTORITE}/{self.tenant_id}/v2.0"

    @property
    def url_jwks(self) -> str:
        """Point d'accès des clés publiques de signature du tenant."""
        return f"{AUTORITE}/{self.tenant_id}/discovery/v2.0/keys"

    @property
    def audience_uri(self) -> str:
        """Audience sous forme d'URI d'ID d'application (`api://<guid>`).

        Entra ID nomme les portées d'une API `api://<client-id>/<portée>`, jamais
        `<client-id>/<portée>`. Un client ID nu est donc préfixé ici : c'est cette forme
        qui part dans WWW-Authenticate et dans `scopes_supported`, sinon le client
        demanderait une portée que l'autorité ne connaît pas.
        """
        audience = self.audience or self.client_id
        return audience if "://" in audience else f"api://{audience}"

    @property
    def scope_complet(self) -> str:
        """Portée complète telle qu'un client doit la demander à Entra ID."""
        return f"{self.audience_uri}/{self.scope_requis}"

    @property
    def audiences_acceptees(self) -> tuple[str, ...]:
        """Valeurs de `aud` acceptées dans un jeton.

        Entra ID émet `aud` = le client ID nu ou l'URI d'ID d'application selon le
        manifeste de l'application (`requestedAccessTokenVersion`, forme de la portée
        demandée). Les deux désignent la même application : les deux sont acceptées,
        pour qu'un changement de manifeste ne coupe pas le service.
        """
        candidats: list[str] = []
        for brut in (self.audience, self.client_id):
            if not brut:
                continue
            candidats.append(brut)
            if "://" not in brut:
                candidats.append(f"api://{brut}")
        # dédoublonnage en conservant l'ordre
        return tuple(dict.fromkeys(candidats))

    @property
    def url_metadonnees(self) -> str:
        """URL des métadonnées de ressource protégée (RFC 9728)."""
        return f"{self.url_publique}{CHEMIN_METADONNEES}"


def _texte(nom: str, defaut: str = "") -> str:
    """Lit une variable d'environnement, espaces et guillemets parasites retirés.

    Erreur fréquente sur Railway : coller la valeur entre guillemets
    (ENTRA_CLIENT_ID="xxx"), qui sont alors stockés littéralement — et le diagnostic
    d'un jeton refusé pour cette raison coûte une heure.
    """
    valeur = os.environ.get(nom, "").strip()
    if len(valeur) >= 2 and valeur[0] == valeur[-1] and valeur[0] in "\"'":
        valeur = valeur[1:-1].strip()
    return valeur or defaut


def _liste(nom: str) -> tuple[str, ...]:
    """Lit une liste séparée par des virgules (ou des espaces, ou des retours ligne)."""
    brut = _texte(nom)
    if not brut:
        return ()
    elements = [e.strip() for e in brut.replace("\n", ",").replace(" ", ",").split(",")]
    return tuple(dict.fromkeys(e for e in elements if e))


def parametres_depuis_env() -> ParametresAuth:
    """Construit les paramètres depuis l'environnement, ou lève si c'est incohérent."""
    mode = _texte("MCP_AUTH_MODE", MODE_OFF).lower()
    if mode not in MODES:
        # Ne PAS retomber sur « off » : une faute de frappe désactiverait
        # l'authentification en silence, sur un serveur qu'on croit protégé.
        raise ConfigurationAuthInvalide(
            f"MCP_AUTH_MODE={mode!r} inconnu. Valeurs admises : {', '.join(MODES)}."
        )

    jetons_admin = _liste("MCP_ADMIN_TOKENS")

    parametres = ParametresAuth(
        mode=mode,
        tenant_id=_texte("ENTRA_TENANT_ID"),
        client_id=_texte("ENTRA_CLIENT_ID"),
        audience=_texte("ENTRA_AUDIENCE"),
        scope_requis=_texte("ENTRA_SCOPE_REQUIS", SCOPE_DEFAUT),
        groupes_autorises=_liste("ENTRA_GROUPES_AUTORISES"),
        url_publique=_texte("MCP_PUBLIC_URL").rstrip("/"),
        jetons_admin=jetons_admin,
    )

    if parametres.actif:
        verifier(parametres)
    elif jetons_admin:
        log.warning(
            "MCP_ADMIN_TOKENS est renseigné mais MCP_AUTH_MODE=off : ces jetons ne "
            "servent à rien, le serveur reste ouvert à tous."
        )
    return parametres


def verifier(parametres: ParametresAuth) -> None:
    """Vérifie qu'un jeu de paramètres actif est exploitable, ou lève."""
    if parametres.mode == MODE_JETONS:
        _verifier_jetons(parametres)
    elif parametres.mode == MODE_ENTRA:
        _verifier_entra(parametres)


def _verifier_jetons(parametres: ParametresAuth) -> None:
    """Mode « jetons » : la liste de jetons EST toute la sécurité du serveur.

    Aucune tolérance ici, contrairement au mode « entra » où les jetons ne sont qu'un
    filet de secours à côté de l'autorité : une liste vide ouvrirait le serveur à
    personne (tout serait refusé, panne totale), et un jeton court l'ouvrirait à qui
    prend le temps d'essayer. Les deux cas empêchent le démarrage.
    """
    if not parametres.jetons_admin:
        raise ConfigurationAuthInvalide(
            "MCP_AUTH_MODE=jetons exige MCP_ADMIN_TOKENS : sans jeton, aucun appel ne "
            "pourrait aboutir. Générez-en un avec "
            "python -c \"import secrets; print(secrets.token_urlsafe(32))\"."
        )
    courts = [len(j) for j in parametres.jetons_admin if len(j) < LONGUEUR_MINI_JETON_ADMIN]
    if courts:
        raise ConfigurationAuthInvalide(
            f"MCP_ADMIN_TOKENS contient {len(courts)} jeton(s) de moins de "
            f"{LONGUEUR_MINI_JETON_ADMIN} caractères (le plus court : {min(courts)}). "
            "En mode jetons, c'est la seule barrière : elle doit résister à une attaque "
            "en ligne. Utilisez secrets.token_urlsafe(32)."
        )


def _verifier_entra(parametres: ParametresAuth) -> None:
    """Mode « entra » : l'autorité et l'URL publique sont indispensables."""
    for jeton in parametres.jetons_admin:
        if len(jeton) < LONGUEUR_MINI_JETON_ADMIN:
            # Simple avertissement ici : l'autorité Entra reste la voie normale, ces
            # jetons ne sont qu'un accès de service. En mode « jetons », c'est une erreur.
            log.warning(
                "MCP_ADMIN_TOKENS contient un jeton de %d caractères : trop court pour "
                "résister à une attaque en ligne. Utilisez au moins %d caractères "
                "aléatoires (python -c \"import secrets; print(secrets.token_urlsafe(32))\").",
                len(jeton),
                LONGUEUR_MINI_JETON_ADMIN,
            )
    manquants = [
        nom
        for nom, valeur in (
            ("ENTRA_TENANT_ID", parametres.tenant_id),
            ("ENTRA_CLIENT_ID", parametres.client_id),
            ("MCP_PUBLIC_URL", parametres.url_publique),
        )
        if not valeur
    ]
    if manquants:
        raise ConfigurationAuthInvalide(
            "MCP_AUTH_MODE=entra exige " + ", ".join(manquants) + ". Le serveur ne "
            "démarre pas : mieux vaut une panne visible qu'un serveur ouvert."
        )
    if not parametres.scope_requis:
        raise ConfigurationAuthInvalide("ENTRA_SCOPE_REQUIS ne peut pas être vide.")
    if not parametres.url_publique.startswith(("https://", "http://localhost", "http://127.0.0.1")):
        raise ConfigurationAuthInvalide(
            f"MCP_PUBLIC_URL={parametres.url_publique!r} : une URL publique en HTTPS est "
            "exigée (un jeton Bearer sur HTTP en clair est un jeton compromis)."
        )
    if parametres.url_publique.startswith("http://"):
        log.warning(
            "MCP_PUBLIC_URL est en HTTP local (%s) : à réserver aux essais.",
            parametres.url_publique,
        )
