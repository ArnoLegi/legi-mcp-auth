"""Autorité Entra ID factice : paire RSA locale, JWKS servi par un mock httpx.

Aucun test ne touche au réseau. Les jetons sont de VRAIS JWT signés RS256 par une clé
générée à la volée : la validation exercée est donc la validation réelle, y compris la
vérification cryptographique de la signature. Les valeurs du tenant du cabinet ne sont
pas nécessaires, et ne doivent d'ailleurs jamais figurer ici.
"""
from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from typing import Any

import httpx
import jwt
import pytest
import respx
from cryptography.hazmat.primitives.asymmetric import rsa
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route

from legi_mcp_auth import EntraAuthMiddleware, ParametresAuth, ValidateurEntra
from legi_mcp_auth.config import MODE_ENTRA
from legi_mcp_auth.jwks import CacheJWKS
from legi_mcp_auth.metadonnees import routes as routes_metadonnees

TENANT = "11111111-1111-1111-1111-111111111111"
CLIENT_ID = "22222222-2222-2222-2222-222222222222"
URL_PUBLIQUE = "https://mcp-eurlex-production.up.railway.app"
GROUPE_AUTORISE = "33333333-3333-3333-3333-333333333333"
GROUPE_INTERDIT = "44444444-4444-4444-4444-444444444444"
JETON_ADMIN = "jeton-administrateur-de-test-uniquement-0123456789"


def _paire_rsa() -> rsa.RSAPrivateKey:
    # 2048 bits : la taille réelle des clés Entra. Générée une fois par session, la
    # génération coûte quelques centaines de millisecondes.
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


@dataclass
class Autorite:
    """Autorité de signature factice, capable d'émettre des jetons et un JWKS."""

    tenant: str = TENANT
    client_id: str = CLIENT_ID
    cles: dict[str, rsa.RSAPrivateKey] = field(default_factory=dict)
    #: `kid` publiés dans le JWKS. Retirer un `kid` d'ici simule une rotation de clé.
    publies: list[str] = field(default_factory=list)

    def ajouter_cle(self, kid: str, *, publier: bool = True) -> None:
        self.cles[kid] = _paire_rsa()
        if publier and kid not in self.publies:
            self.publies.append(kid)

    @property
    def url_jwks(self) -> str:
        return f"https://login.microsoftonline.com/{self.tenant}/discovery/v2.0/keys"

    def jwks(self) -> dict[str, Any]:
        """Document JWKS tel que le sert Microsoft, restreint aux `kid` publiés."""
        cles = []
        for kid in self.publies:
            publique = self.cles[kid].public_key()
            jwk = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(publique))
            jwk.update({"kid": kid, "use": "sig", "alg": "RS256"})
            cles.append(jwk)
        return {"keys": cles}

    def jeton(
        self,
        *,
        kid: str = "cle-1",
        algorithme: str = "RS256",
        tenant: str | None = None,
        audience: str | None = None,
        scope: str | None = "mcp.access",
        groupes: list[str] | None = None,
        expire_dans: int = 3600,
        emis_il_y_a: int = 60,
        oid: str = "55555555-5555-5555-5555-555555555555",
        upn: str = "avocat@cabinet.example",
        nom: str = "Maître Test",
        revendications_sup: dict[str, Any] | None = None,
        omettre: tuple[str, ...] = (),
    ) -> str:
        """Émet un jeton d'accès. Chaque paramètre permet de fabriquer un cas de refus."""
        maintenant = int(time.time())
        charge: dict[str, Any] = {
            "iss": f"https://login.microsoftonline.com/{tenant or self.tenant}/v2.0",
            "aud": audience if audience is not None else self.client_id,
            "tid": tenant or self.tenant,
            "iat": maintenant - emis_il_y_a,
            "nbf": maintenant - emis_il_y_a,
            "exp": maintenant + expire_dans,
            "sub": "sujet-stable",
            "oid": oid,
            "preferred_username": upn,
            "name": nom,
            "azp": self.client_id,
            "ver": "2.0",
        }
        if scope is not None:
            charge["scp"] = scope
        if groupes is not None:
            charge["groups"] = groupes
        if revendications_sup:
            charge.update(revendications_sup)
        for cle in omettre:
            charge.pop(cle, None)

        if algorithme == "none":
            # `jwt.encode` refuse d'émettre un jeton non signé : on le fabrique à la main,
            # car c'est précisément l'attaque que le validateur doit rejeter.
            import base64

            def b64(donnees: bytes) -> str:
                return base64.urlsafe_b64encode(donnees).rstrip(b"=").decode("ascii")

            entete = b64(json.dumps({"alg": "none", "typ": "JWT", "kid": kid}).encode())
            corps = b64(json.dumps(charge).encode())
            return f"{entete}.{corps}."

        return jwt.encode(
            charge,
            self.cles[kid],
            algorithm=algorithme,
            headers={"kid": kid},
        )


@pytest.fixture(scope="session")
def autorite() -> Autorite:
    a = Autorite()
    a.ajouter_cle("cle-1")
    # « cle-2 » existe mais n'est PAS publiée : elle sert au test de rotation.
    a.ajouter_cle("cle-2", publier=False)
    return a


@pytest.fixture
def parametres() -> ParametresAuth:
    return ParametresAuth(
        mode=MODE_ENTRA,
        tenant_id=TENANT,
        client_id=CLIENT_ID,
        audience=CLIENT_ID,
        scope_requis="mcp.access",
        url_publique=URL_PUBLIQUE,
        jetons_admin=(JETON_ADMIN,),
    )


@pytest.fixture
def jwks(autorite: Autorite):
    """Intercepte le seul appel réseau du paquet : le téléchargement du JWKS.

    `assert_all_mocked=False` laisse passer tout le reste — notamment les requêtes que
    les tests adressent à l'application ASGI elle-même.
    """
    with respx.mock(assert_all_called=False, assert_all_mocked=False) as mock:
        route = mock.get(autorite.url_jwks).mock(
            side_effect=lambda _requete: httpx.Response(200, json=autorite.jwks())
        )
        yield route


@pytest.fixture
def validateur(parametres: ParametresAuth, jwks) -> ValidateurEntra:
    """Validateur neuf (cache JWKS vide) pour chaque test."""
    return ValidateurEntra(
        parametres,
        cache_jwks=CacheJWKS(parametres.url_jwks, ttl=parametres.jwks_ttl),
    )


# --------------------------------------------------------------- application


async def _health(_requete: Request) -> JSONResponse:
    return JSONResponse({"status": "ok", "service": "mcp-test"})


async def _mcp(requete: Request) -> JSONResponse:
    """Simule un endpoint MCP : renvoie l'identité vue et le corps reçu.

    Le corps est relu volontairement : il prouve que le tamponnage d'audit rejoue bien
    la requête intacte à l'application.
    """
    corps = await requete.body()
    return JSONResponse(
        {
            "utilisateur": getattr(requete.state, "utilisateur", None),
            "corps_recu": corps.decode("utf-8"),
        }
    )


def construire_app(
    parametres: ParametresAuth,
    validateur: ValidateurEntra | None = None,
    *,
    protegee: bool = True,
) -> Starlette:
    """Application Starlette minimale calquée sur `main.py` des serveurs MCP."""
    routes = [
        Route("/", _health, methods=["GET"]),
        Route("/health", _health, methods=["GET"]),
        Route("/mcp", _mcp, methods=["GET", "POST"]),
    ]
    if protegee:
        routes[0:0] = routes_metadonnees(parametres)
    app = Starlette(routes=routes)
    if protegee:
        app.add_middleware(EntraAuthMiddleware, parametres=parametres, validateur=validateur)
    return app


@pytest.fixture
def app(parametres: ParametresAuth, validateur: ValidateurEntra) -> Starlette:
    return construire_app(parametres, validateur)


@pytest.fixture
def client(app: Starlette):
    """Client HTTP asynchrone parlant directement à l'application ASGI."""
    transport = httpx.ASGITransport(app=app)
    return httpx.AsyncClient(transport=transport, base_url="http://serveur-de-test")
