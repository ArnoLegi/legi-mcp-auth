"""Cache des clés publiques de signature du tenant (JWKS).

Microsoft fait tourner ses clés de signature régulièrement, sans préavis. On ne peut
donc ni figer les clés dans la configuration, ni les recharger à chaque appel (un aller-
retour réseau par requête, et une dépendance dure à login.microsoftonline.com).

Le compromis retenu : cache de 24 h, plus un rafraîchissement immédiat lorsqu'un jeton
présente un `kid` absent du cache — c'est exactement la signature d'une rotation de clé.
Ce rafraîchissement forcé est bridé après un échec (cf. `DELAI_APRES_ECHEC`) : sinon,
n'importe qui pourrait nous faire marteler l'autorité avec des `kid` inventés.
"""
from __future__ import annotations

import asyncio
import json
import logging
import time
from typing import Any

import httpx
import jwt

log = logging.getLogger("legi_mcp_auth.jwks")

#: Délai minimal entre deux rafraîchissements forcés APRÈS un échec (secondes).
DELAI_APRES_ECHEC = 300.0

DELAI_RESEAU = 10.0

ALGORITHME = "RS256"


class JWKSIndisponible(RuntimeError):
    """Les clés publiques du tenant n'ont pas pu être obtenues."""


class CleInconnue(LookupError):
    """Aucune clé publique ne correspond au `kid` du jeton, rafraîchissement compris."""


class CacheJWKS:
    """Fournit la clé publique correspondant à un `kid`, avec cache et rotation."""

    def __init__(
        self,
        url: str,
        *,
        ttl: float,
        client: httpx.AsyncClient | None = None,
    ) -> None:
        self.url = url
        self.ttl = ttl
        self._client = client
        self._client_propre = client is None
        self._cles: dict[str, Any] = {}
        self._charge_a: float = 0.0
        # `None` = aucun échec à ce jour. Surtout PAS 0.0 : `time.monotonic()` part
        # de zéro au démarrage de la machine, et un sentinelle à 0.0 briderait la
        # première rotation de clé survenant dans les cinq minutes suivant un
        # redémarrage — exactement le moment où elle est la plus probable.
        self._dernier_echec: float | None = None
        self._verrou = asyncio.Lock()

    # ------------------------------------------------------------------ API

    async def cle(self, kid: str) -> Any:
        """Clé publique pour ce `kid`.

        Charge le JWKS s'il est absent ou périmé ; si le `kid` reste introuvable, force
        UN rafraîchissement (rotation de clé côté Microsoft) avant d'abandonner.
        """
        if not kid:
            raise CleInconnue("jeton sans `kid` : impossible de choisir une clé publique")

        async with self._verrou:
            if self._perime():
                await self._charger()
            cle = self._cles.get(kid)
            if cle is not None:
                return cle

            # `kid` inconnu : très probablement une rotation de clé.
            if (
                self._dernier_echec is not None
                and time.monotonic() - self._dernier_echec < DELAI_APRES_ECHEC
            ):
                raise CleInconnue(
                    f"kid={kid} inconnu et rafraîchissement bridé "
                    f"(un échec il y a moins de {DELAI_APRES_ECHEC:.0f} s)"
                )
            log.info("kid=%s absent du cache JWKS : rafraîchissement forcé.", kid)
            await self._charger()
            cle = self._cles.get(kid)
            if cle is None:
                self._dernier_echec = time.monotonic()
                raise CleInconnue(f"kid={kid} absent du JWKS après rafraîchissement")
            # Rotation réussie : le bridage repart de zéro.
            self._dernier_echec = None
            return cle

    async def aclose(self) -> None:
        if self._client is not None and self._client_propre:
            await self._client.aclose()
            self._client = None

    # -------------------------------------------------------------- interne

    def _perime(self) -> bool:
        return not self._cles or (time.monotonic() - self._charge_a) > self.ttl

    async def _charger(self) -> None:
        donnees = await self._telecharger()
        cles: dict[str, Any] = {}
        for jwk in donnees.get("keys", []):
            kid = jwk.get("kid")
            # On n'accepte QUE des clés RSA destinées à la signature : une clé
            # symétrique ou de chiffrement n'a rien à faire dans ce cache.
            if not kid or jwk.get("kty") != "RSA":
                continue
            if jwk.get("use", "sig") != "sig":
                continue
            if jwk.get("alg", ALGORITHME) != ALGORITHME:
                continue
            try:
                cles[kid] = jwt.algorithms.RSAAlgorithm.from_jwk(json.dumps(jwk))
            except Exception as exc:  # noqa: BLE001 — une clé illisible n'invalide pas les autres
                log.warning("Clé JWKS kid=%s illisible, ignorée : %s", kid, exc)
        if not cles:
            raise JWKSIndisponible(f"aucune clé RSA de signature exploitable dans {self.url}")
        self._cles = cles
        self._charge_a = time.monotonic()
        log.debug("JWKS chargé : %d clé(s) depuis %s", len(cles), self.url)

    async def _telecharger(self) -> dict[str, Any]:
        client = self._client
        if client is None:
            client = self._client = httpx.AsyncClient(timeout=DELAI_RESEAU)
        try:
            reponse = await client.get(self.url, timeout=DELAI_RESEAU)
            reponse.raise_for_status()
            return reponse.json()
        except (httpx.HTTPError, ValueError) as exc:
            raise JWKSIndisponible(f"JWKS injoignable ({self.url}) : {exc}") from exc
