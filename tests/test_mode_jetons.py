"""Mode « jetons » : les jetons d'administration seuls, sans autorité OAuth.

C'est le mode d'un serveur à usage restreint (un utilisateur, une sonde, Claude Code)
ou d'une préproduction. Il n'a aucune configuration Entra, ne publie aucune métadonnée,
et son 401 ne renvoie vers aucune adresse de découverte — il n'y a rien à découvrir.
"""
from __future__ import annotations

import dataclasses

import httpx
import pytest
from starlette.applications import Starlette
from starlette.responses import JSONResponse
from starlette.routing import Route

from legi_mcp_auth import ConfigurationAuthInvalide, ParametresAuth, parametres_depuis_env, proteger
from legi_mcp_auth.config import LONGUEUR_MINI_JETON_ADMIN, MODE_JETONS

JETON = "jeton-d-administration-de-test-0123456789abcd"  # 45 caractères
AUTRE_JETON = "second-jeton-d-administration-de-test-0123456"

APPEL_OUTIL = {
    "jsonrpc": "2.0",
    "id": 1,
    "method": "tools/call",
    "params": {"name": "fiche_article", "arguments": {}},
}

VARIABLES = (
    "MCP_AUTH_MODE",
    "MCP_ADMIN_TOKENS",
    "ENTRA_TENANT_ID",
    "ENTRA_CLIENT_ID",
    "MCP_PUBLIC_URL",
)


@pytest.fixture
def parametres_jetons() -> ParametresAuth:
    # Ni tenant, ni client ID, ni URL publique : le mode jetons n'en a pas besoin.
    return ParametresAuth(mode=MODE_JETONS, jetons_admin=(JETON, AUTRE_JETON))


@pytest.fixture
def app(parametres_jetons: ParametresAuth) -> Starlette:
    async def health(_r):
        return JSONResponse({"status": "ok"})

    async def mcp(requete):
        return JSONResponse({"utilisateur": getattr(requete.state, "utilisateur", None)})

    application = Starlette(
        routes=[
            Route("/", health, methods=["GET"]),
            Route("/health", health, methods=["GET"]),
            Route("/mcp", mcp, methods=["GET", "POST"]),
        ]
    )
    return proteger(application, None, parametres=parametres_jetons)


@pytest.fixture
def client(app: Starlette):
    return httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://serveur-de-test"
    )


def entete(jeton: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {jeton}"}


# ----------------------------------------------------------------- acceptation


async def test_jeton_accepte(client):
    reponse = await client.post("/mcp", json=APPEL_OUTIL, headers=entete(JETON))
    assert reponse.status_code == 200
    assert reponse.json()["utilisateur"] == {"admin": True}


async def test_second_jeton_accepte(client):
    """La liste en accepte plusieurs : c'est ce qui permet une rotation sans coupure."""
    reponse = await client.post("/mcp", json=APPEL_OUTIL, headers=entete(AUTRE_JETON))
    assert reponse.status_code == 200


async def test_audit_utilisateur_admin(client, caplog):
    with caplog.at_level("INFO", logger="legi_mcp_auth.audit"):
        await client.post("/mcp", json=APPEL_OUTIL, headers=entete(JETON))
    assert "utilisateur=admin outil=fiche_article" in caplog.text


async def test_aucun_jeton_dans_les_journaux(client, caplog):
    with caplog.at_level("DEBUG"):
        await client.post("/mcp", json=APPEL_OUTIL, headers=entete(JETON))
        await client.post("/mcp", json=APPEL_OUTIL, headers=entete("mauvais-jeton"))
    assert JETON not in caplog.text
    assert "mauvais-jeton" not in caplog.text


# ---------------------------------------------------------------------- refus


@pytest.mark.parametrize(
    "en_tetes",
    [
        {},
        {"Authorization": "Bearer"},
        {"Authorization": f"Bearer {JETON}x"},
        {"Authorization": f"Bearer {JETON[:-1]}"},
        {"Authorization": f"Basic {JETON}"},
        {"Authorization": JETON},
    ],
    ids=["absent", "vide", "allonge", "tronque", "basic", "sans-schema"],
)
async def test_refus(client, en_tetes):
    reponse = await client.post("/mcp", json=APPEL_OUTIL, headers=en_tetes)
    assert reponse.status_code == 401


async def test_401_sans_metadonnees_oauth(client):
    """Le 401 ne doit annoncer NI resource_metadata NI scope : il n'y a pas d'autorité.

    Annoncer une adresse de découverte qui répondrait 404 enverrait un client MCP dans
    un flux OAuth impossible à mener.
    """
    reponse = await client.post("/mcp", json=APPEL_OUTIL)
    assert reponse.status_code == 401
    assert reponse.headers["www-authenticate"] == 'Bearer error="invalid_token"'
    assert "resource_metadata" not in reponse.headers["www-authenticate"]
    assert "scope" not in reponse.headers["www-authenticate"]

    corps = reponse.json()
    assert corps["error"] == "invalid_token"
    assert corps["error_description"]
    assert "resource_metadata" not in corps
    assert "scope" not in corps
    assert "microsoftonline" not in reponse.text.lower()


async def test_pas_de_route_de_metadonnees(client):
    """Aucune métadonnée n'est publiée en mode jetons."""
    for chemin in (
        "/.well-known/oauth-protected-resource",
        "/.well-known/oauth-protected-resource/mcp",
    ):
        assert (await client.get(chemin)).status_code == 404


# ------------------------------------------------------------------ exemptions


async def test_health_exempte(client):
    reponse = await client.get("/health")
    assert reponse.status_code == 200
    assert reponse.json()["status"] == "ok"


async def test_well_known_exempte(client):
    """Exempté du contrôle : le 404 vient du routage, pas d'un 401."""
    reponse = await client.get("/.well-known/quelque-chose")
    assert reponse.status_code == 404
    assert "www-authenticate" not in reponse.headers


async def test_racine_protegee(client):
    assert (await client.get("/")).status_code == 401


# --------------------------------------------------------- refus de démarrage


@pytest.fixture(autouse=False)
def environnement_propre(monkeypatch):
    for nom in VARIABLES:
        monkeypatch.delenv(nom, raising=False)


def test_liste_vide_refuse_le_demarrage(monkeypatch, environnement_propre):
    """Sans jeton, aucun appel ne pourrait aboutir : mieux vaut ne pas démarrer."""
    monkeypatch.setenv("MCP_AUTH_MODE", "jetons")
    with pytest.raises(ConfigurationAuthInvalide, match="MCP_ADMIN_TOKENS"):
        parametres_depuis_env()


def test_variable_absente_refuse_le_demarrage(monkeypatch, environnement_propre):
    monkeypatch.setenv("MCP_AUTH_MODE", "jetons")
    monkeypatch.setenv("MCP_ADMIN_TOKENS", "   ")
    with pytest.raises(ConfigurationAuthInvalide, match="MCP_ADMIN_TOKENS"):
        parametres_depuis_env()


@pytest.mark.parametrize("longueur", [1, 8, LONGUEUR_MINI_JETON_ADMIN - 1])
def test_jeton_trop_court_refuse_le_demarrage(monkeypatch, environnement_propre, longueur):
    """En mode jetons, la liste EST la sécurité : un jeton court est une erreur, pas un avis."""
    monkeypatch.setenv("MCP_AUTH_MODE", "jetons")
    monkeypatch.setenv("MCP_ADMIN_TOKENS", "a" * longueur)
    with pytest.raises(ConfigurationAuthInvalide, match="caractères"):
        parametres_depuis_env()


def test_un_seul_jeton_court_suffit_a_refuser(monkeypatch, environnement_propre):
    monkeypatch.setenv("MCP_AUTH_MODE", "jetons")
    monkeypatch.setenv("MCP_ADMIN_TOKENS", f"{JETON},court")
    with pytest.raises(ConfigurationAuthInvalide):
        parametres_depuis_env()


def test_jeton_a_la_longueur_minimale_accepte(monkeypatch, environnement_propre):
    monkeypatch.setenv("MCP_AUTH_MODE", "jetons")
    monkeypatch.setenv("MCP_ADMIN_TOKENS", "a" * LONGUEUR_MINI_JETON_ADMIN)
    parametres = parametres_depuis_env()
    assert parametres.mode == MODE_JETONS
    assert parametres.actif is True
    assert parametres.entra_actif is False


def test_aucune_variable_entra_exigee(monkeypatch, environnement_propre):
    """Le mode jetons ne demande ni tenant, ni client ID, ni URL publique."""
    monkeypatch.setenv("MCP_AUTH_MODE", "jetons")
    monkeypatch.setenv("MCP_ADMIN_TOKENS", JETON)
    parametres = parametres_depuis_env()
    assert parametres.tenant_id == ""
    assert parametres.client_id == ""
    assert parametres.url_publique == ""


def test_jeton_court_en_mode_entra_avertit_seulement(monkeypatch, environnement_propre, caplog):
    """En mode entra, les jetons ne sont qu'un accès de service : avertissement, pas erreur."""
    monkeypatch.setenv("MCP_AUTH_MODE", "entra")
    monkeypatch.setenv("ENTRA_TENANT_ID", "11111111-1111-1111-1111-111111111111")
    monkeypatch.setenv("ENTRA_CLIENT_ID", "22222222-2222-2222-2222-222222222222")
    monkeypatch.setenv("MCP_PUBLIC_URL", "https://exemple.test")
    monkeypatch.setenv("MCP_ADMIN_TOKENS", "court")
    with caplog.at_level("WARNING"):
        parametres = parametres_depuis_env()
    assert parametres.entra_actif is True
    assert "trop court" in caplog.text


def test_mode_inconnu_toujours_refuse(monkeypatch, environnement_propre):
    monkeypatch.setenv("MCP_AUTH_MODE", "jeton")  # au singulier : faute de frappe
    with pytest.raises(ConfigurationAuthInvalide, match="MCP_AUTH_MODE"):
        parametres_depuis_env()


# ------------------------------------------------------------------ intégration


async def test_middleware_installe_sans_client_jwks(parametres_jetons):
    """Aucun validateur, donc aucun client HTTP vers login.microsoftonline.com."""
    from legi_mcp_auth import EntraAuthMiddleware

    middleware = EntraAuthMiddleware(lambda *a: None, parametres_jetons)
    assert middleware.validateur is None


async def test_mode_jetons_journalise_son_activation(parametres_jetons, caplog):
    async def health(_r):
        return JSONResponse({})

    with caplog.at_level("INFO", logger="legi_mcp_auth"):
        proteger(
            Starlette(routes=[Route("/health", health)]), None, parametres=parametres_jetons
        )
    assert "JETONS ACTIVE" in caplog.text
    assert "2 jeton(s)" in caplog.text


async def test_parametres_jetons_sans_url_publique_valides():
    """`verifier` ne réclame pas d'URL publique hors mode entra."""
    from legi_mcp_auth.config import verifier

    verifier(dataclasses.replace(ParametresAuth(mode=MODE_JETONS, jetons_admin=(JETON,))))
