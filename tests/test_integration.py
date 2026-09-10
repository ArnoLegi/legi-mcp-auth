"""`proteger()` : mode off strictement neutre, mode entra effectif.

Le mode off est le test le plus important du paquet : il garantit qu'installer
`legi-mcp-auth` sur les quatre serveurs MCP du cabinet ne change RIEN tant que les
valeurs Entra ne sont pas disponibles.
"""
from __future__ import annotations

import dataclasses

import httpx
import pytest
from starlette.applications import Starlette
from starlette.responses import JSONResponse
from starlette.routing import Route

from legi_mcp_auth import ParametresAuth, proteger
from legi_mcp_auth.config import MODE_ENTRA, MODE_OFF

from .conftest import JETON_ADMIN, Autorite

APPEL_OUTIL = {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "statut_acte"}}


def app_nue() -> Starlette:
    async def health(_r):
        return JSONResponse({"status": "ok"})

    async def mcp(requete):
        return JSONResponse({"utilisateur": getattr(requete.state, "utilisateur", None)})

    return Starlette(
        routes=[
            Route("/health", health, methods=["GET"]),
            Route("/mcp", mcp, methods=["GET", "POST"]),
        ]
    )


def client_de(app: Starlette) -> httpx.AsyncClient:
    return httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://serveur-de-test"
    )


# ------------------------------------------------------------------- mode off


@pytest.fixture
def parametres_off() -> ParametresAuth:
    return ParametresAuth(mode=MODE_OFF)


async def test_mode_off_laisse_tout_passer(parametres_off):
    app = proteger(app_nue(), None, parametres=parametres_off)
    async with client_de(app) as client:
        assert (await client.get("/health")).status_code == 200
        reponse = await client.post("/mcp", json=APPEL_OUTIL)
        assert reponse.status_code == 200
        assert reponse.json()["utilisateur"] is None


async def test_mode_off_n_ajoute_ni_route_ni_middleware(parametres_off):
    app = app_nue()
    avant = list(app.router.routes)
    proteger(app, None, parametres=parametres_off)
    assert app.router.routes == avant
    assert app.user_middleware == []


async def test_mode_off_pas_de_metadonnees(parametres_off):
    """Publier des métadonnées sans protection serait mensonger."""
    app = proteger(app_nue(), None, parametres=parametres_off)
    async with client_de(app) as client:
        assert (await client.get("/.well-known/oauth-protected-resource")).status_code == 404


async def test_mode_off_avertit_au_demarrage(parametres_off, caplog):
    with caplog.at_level("WARNING", logger="legi_mcp_auth"):
        proteger(app_nue(), None, parametres=parametres_off)
    assert "AUTHENTIFICATION DÉSACTIVÉE" in caplog.text


async def test_proteger_renvoie_l_application(parametres_off):
    app = app_nue()
    assert proteger(app, None, parametres=parametres_off) is app


# ----------------------------------------------------------------- mode entra


async def test_branchement_en_une_ligne(parametres, validateur, autorite: Autorite):
    app = proteger(app_nue(), None, parametres=parametres, validateur=validateur)
    async with client_de(app) as client:
        # /health reste ouvert : la sonde de Railway ne doit pas se voir refuser l'accès.
        assert (await client.get("/health")).status_code == 200
        # Les métadonnées apparaissent.
        assert (await client.get("/.well-known/oauth-protected-resource")).status_code == 200
        # /mcp est fermé.
        assert (await client.post("/mcp", json=APPEL_OUTIL)).status_code == 401
        # ... et s'ouvre avec un jeton valide.
        reponse = await client.post(
            "/mcp", json=APPEL_OUTIL, headers={"Authorization": f"Bearer {autorite.jeton()}"}
        )
        assert reponse.status_code == 200
        assert reponse.json()["utilisateur"]["preferred_username"] == "avocat@cabinet.example"


async def test_settings_du_serveur_hote_tolere(parametres, validateur, autorite: Autorite):
    """`proteger(app, settings)` accepte l'objet de configuration du serveur hôte.

    Chaque serveur MCP passe son propre `settings` (eurlex_mcp, inpi_mcp, …) : la ligne
    d'intégration doit être identique partout, sans que le paquet connaisse ces types.
    """

    @dataclasses.dataclass(frozen=True)
    class SettingsHote:
        port: int = 8080

    app = proteger(app_nue(), SettingsHote(), parametres=parametres, validateur=validateur)
    async with client_de(app) as client:
        assert (await client.post("/mcp", json=APPEL_OUTIL)).status_code == 401


async def test_parametres_auth_passes_en_settings(autorite: Autorite, jwks):
    """Un `ParametresAuth` passé en deuxième argument est utilisé tel quel."""
    p = ParametresAuth(
        mode=MODE_ENTRA,
        tenant_id=autorite.tenant,
        client_id=autorite.client_id,
        url_publique="https://exemple.test",
        jetons_admin=(JETON_ADMIN,),
    )
    app = proteger(app_nue(), p)
    async with client_de(app) as client:
        assert (await client.post("/mcp", json=APPEL_OUTIL)).status_code == 401
        reponse = await client.post(
            "/mcp", json=APPEL_OUTIL, headers={"Authorization": f"Bearer {JETON_ADMIN}"}
        )
        assert reponse.status_code == 200


async def test_metadonnees_prioritaires_sur_les_routes_du_serveur(parametres, validateur):
    """Une route générique du serveur ne doit pas pouvoir masquer la découverte OAuth."""

    async def attrape_tout(_r):
        return JSONResponse({"attrape": True})

    app = Starlette(routes=[Route("/{chemin:path}", attrape_tout, methods=["GET"])])
    proteger(app, None, parametres=parametres, validateur=validateur)
    async with client_de(app) as client:
        reponse = await client.get("/.well-known/oauth-protected-resource")
        assert reponse.status_code == 200
        assert "resource" in reponse.json()
