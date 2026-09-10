"""Configuration : défauts, refus de démarrer, valeurs dérivées."""
from __future__ import annotations

import pytest

from legi_mcp_auth import ConfigurationAuthInvalide, ParametresAuth, parametres_depuis_env
from legi_mcp_auth.config import MODE_ENTRA, MODE_OFF

from .conftest import CLIENT_ID, TENANT, URL_PUBLIQUE

VARIABLES = (
    "MCP_AUTH_MODE",
    "ENTRA_TENANT_ID",
    "ENTRA_CLIENT_ID",
    "ENTRA_AUDIENCE",
    "ENTRA_SCOPE_REQUIS",
    "ENTRA_GROUPES_AUTORISES",
    "MCP_PUBLIC_URL",
    "MCP_ADMIN_TOKENS",
)


@pytest.fixture(autouse=True)
def environnement_propre(monkeypatch):
    for nom in VARIABLES:
        monkeypatch.delenv(nom, raising=False)


def test_defaut_est_off():
    """Sans aucune variable, le paquet est neutre."""
    parametres = parametres_depuis_env()
    assert parametres.mode == MODE_OFF
    assert parametres.actif is False


def test_mode_inconnu_refuse(monkeypatch):
    """Une faute de frappe ne doit PAS désactiver l'authentification en silence."""
    monkeypatch.setenv("MCP_AUTH_MODE", "entraa")
    with pytest.raises(ConfigurationAuthInvalide, match="MCP_AUTH_MODE"):
        parametres_depuis_env()


@pytest.mark.parametrize("manquante", ["ENTRA_TENANT_ID", "ENTRA_CLIENT_ID", "MCP_PUBLIC_URL"])
def test_mode_entra_incomplet_refuse(monkeypatch, manquante):
    monkeypatch.setenv("MCP_AUTH_MODE", "entra")
    monkeypatch.setenv("ENTRA_TENANT_ID", TENANT)
    monkeypatch.setenv("ENTRA_CLIENT_ID", CLIENT_ID)
    monkeypatch.setenv("MCP_PUBLIC_URL", URL_PUBLIQUE)
    monkeypatch.delenv(manquante)
    with pytest.raises(ConfigurationAuthInvalide, match=manquante):
        parametres_depuis_env()


def test_url_publique_en_clair_refusee(monkeypatch):
    monkeypatch.setenv("MCP_AUTH_MODE", "entra")
    monkeypatch.setenv("ENTRA_TENANT_ID", TENANT)
    monkeypatch.setenv("ENTRA_CLIENT_ID", CLIENT_ID)
    monkeypatch.setenv("MCP_PUBLIC_URL", "http://mcp.example.com")
    with pytest.raises(ConfigurationAuthInvalide, match="HTTPS"):
        parametres_depuis_env()


def test_lecture_complete(monkeypatch):
    monkeypatch.setenv("MCP_AUTH_MODE", "Entra")  # la casse est indifférente
    monkeypatch.setenv("ENTRA_TENANT_ID", TENANT)
    monkeypatch.setenv("ENTRA_CLIENT_ID", CLIENT_ID)
    monkeypatch.setenv("ENTRA_AUDIENCE", f'"api://{CLIENT_ID}"')  # guillemets parasites
    monkeypatch.setenv("ENTRA_GROUPES_AUTORISES", "g1, g2 ,,g1")
    monkeypatch.setenv("MCP_PUBLIC_URL", URL_PUBLIQUE + "/")  # barre oblique finale
    monkeypatch.setenv("MCP_ADMIN_TOKENS", "a" * 40 + "," + "b" * 40)

    p = parametres_depuis_env()
    assert p.mode == MODE_ENTRA
    assert p.audience == f"api://{CLIENT_ID}"
    assert p.groupes_autorises == ("g1", "g2")
    assert p.url_publique == URL_PUBLIQUE
    assert p.jetons_admin == ("a" * 40, "b" * 40)
    assert p.scope_requis == "mcp.access"


def test_valeurs_derivees():
    p = ParametresAuth(
        mode=MODE_ENTRA,
        tenant_id=TENANT,
        client_id=CLIENT_ID,
        url_publique=URL_PUBLIQUE,
    )
    assert p.issuer == f"https://login.microsoftonline.com/{TENANT}/v2.0"
    assert p.url_jwks == f"https://login.microsoftonline.com/{TENANT}/discovery/v2.0/keys"
    # Un client ID nu est préfixé `api://` pour former une portée qu'Entra reconnaît.
    assert p.audience_uri == f"api://{CLIENT_ID}"
    assert p.scope_complet == f"api://{CLIENT_ID}/mcp.access"
    assert p.url_metadonnees == f"{URL_PUBLIQUE}/.well-known/oauth-protected-resource"
    # Les deux formes d'audience émises par Entra sont acceptées.
    assert set(p.audiences_acceptees) == {CLIENT_ID, f"api://{CLIENT_ID}"}


def test_jetons_admin_inutiles_en_mode_off(monkeypatch, caplog):
    """En mode off, des jetons configurés ne protègent rien : il faut le dire.

    (La longueur des jetons, elle, est contrôlée là où elle compte : erreur bloquante
    en mode « jetons », avertissement en mode « entra ». Cf. test_mode_jetons.py.)
    """
    monkeypatch.setenv("MCP_ADMIN_TOKENS", "a" * 40)
    with caplog.at_level("WARNING"):
        parametres = parametres_depuis_env()
    assert parametres.actif is False
    assert "ne servent à rien" in caplog.text
