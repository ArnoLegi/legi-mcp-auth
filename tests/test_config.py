"""Configuration : défauts, refus de démarrer, valeurs dérivées."""
from __future__ import annotations

import pytest

from legi_mcp_auth import ConfigurationAuthInvalide, ParametresAuth, parametres_depuis_env
from legi_mcp_auth.config import MODE_ENTRA, MODE_OFF, PORTEES_OIDC

from .conftest import CLIENT_ID, RESSOURCE, TENANT, URL_PUBLIQUE

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
    # L'unique ressource du serveur, CALCULÉE depuis la racine : jamais saisie.
    assert p.resource_canonique == RESSOURCE == f"{URL_PUBLIQUE}/mcp"
    # La portée se bâtit sur la ressource. Entra v2.0 exige que la portée demandée et le
    # `resource` (RFC 8707) désignent la même application ; `api://<client-id>/<portée>`
    # avec un `resource` https échoue en AADSTS9010010 avant tout écran de connexion.
    assert p.scope_complet == f"{URL_PUBLIQUE}/mcp/mcp.access"
    assert p.scope_complet.startswith(p.resource_canonique + "/")
    assert not p.scope_complet.startswith("api://")
    # `api://<client-id>` ne sert plus qu'aux audiences acceptées.
    assert p.audience_uri == f"api://{CLIENT_ID}"
    # RFC 9728 : le suffixe well-known s'insère AVANT le chemin de la ressource.
    assert p.url_metadonnees == f"{URL_PUBLIQUE}/.well-known/oauth-protected-resource/mcp"


def test_portees_publiees():
    """La portée de la ressource EN PREMIER, `offline_access` ensuite.

    `offline_access` n'est pas une portée de notre API : c'est la demande d'un jeton de
    rafraîchissement, qu'Entra ne délivre que si le mot figure dans le `scope` de la
    requête d'autorisation. Claude.ai ne demande que ce que le serveur publie : non
    publiée, elle n'est jamais demandée, et la connexion expire au bout d'une heure.
    """
    p = ParametresAuth(
        mode=MODE_ENTRA,
        tenant_id=TENANT,
        client_id=CLIENT_ID,
        url_publique=URL_PUBLIQUE,
    )
    assert p.scopes_publies == (f"{RESSOURCE}/mcp.access", "offline_access")
    # L'ordre est porteur de sens : l'accès vient de la portée de la ressource.
    assert p.scopes_publies[0] == p.scope_complet
    assert "offline_access" in p.scopes_publies
    # RFC 6750 : `scope` est une liste séparée par des espaces.
    assert p.scope_entete == f"{RESSOURCE}/mcp.access offline_access"
    assert p.scope_entete.split(" ") == list(p.scopes_publies)


def test_portees_oidc_limitees_au_rafraichissement():
    """Seule `offline_access` est ajoutée : `openid`, `profile` et `email` ne servent à rien ici.

    Ce serveur ne valide qu'un jeton d'ACCÈS ; le jeton d'identité ne l'intéresse pas.
    Les publier allongerait l'écran de consentement sans rien apporter.
    """
    assert PORTEES_OIDC == ("offline_access",)


def test_portee_publiee_nexige_rien_de_plus_du_jeton():
    """Publier `offline_access` ne change PAS ce qui est exigé d'un jeton d'accès.

    `scope_requis` — la seule valeur que la validation cherche dans `scp` — reste la
    portée nue. Entra ne fait jamais figurer `offline_access` dans le `scp` d'un jeton
    d'accès : l'exiger refuserait tous les jetons.
    """
    p = ParametresAuth(
        mode=MODE_ENTRA,
        tenant_id=TENANT,
        client_id=CLIENT_ID,
        url_publique=URL_PUBLIQUE,
    )
    assert p.scope_requis == "mcp.access"
    assert "offline_access" not in p.scope_requis
    assert p.scope_complet == f"{RESSOURCE}/mcp.access"


def test_audiences_acceptees():
    """Les deux formes émises par Entra, plus la ressource canonique par tolérance."""
    p = ParametresAuth(
        mode=MODE_ENTRA,
        tenant_id=TENANT,
        client_id=CLIENT_ID,
        url_publique=URL_PUBLIQUE,
    )
    # Un jeton v2 porte le client ID en `aud` : c'est l'attente, et elle ne bouge pas.
    assert p.audiences_acceptees[0] == CLIENT_ID
    assert p.audiences_acceptees[1] == f"api://{CLIENT_ID}"
    # La ressource s'ajoute APRÈS, sans rien retirer.
    assert p.audiences_acceptees[2] == RESSOURCE
    assert set(p.audiences_acceptees) == {CLIENT_ID, f"api://{CLIENT_ID}", RESSOURCE}


@pytest.mark.parametrize("suffixe", ["/mcp", "/sse"])
def test_url_publique_avec_le_chemin_du_transport_refusee(monkeypatch, suffixe):
    """Coller l'URL du connecteur produirait la ressource `…/mcp/mcp`, refusée par Entra.

    Le symptôme serait un AADSTS9010010 illisible côté Claude.ai ; mieux vaut ne pas
    démarrer et le dire.
    """
    monkeypatch.setenv("MCP_AUTH_MODE", "entra")
    monkeypatch.setenv("ENTRA_TENANT_ID", TENANT)
    monkeypatch.setenv("ENTRA_CLIENT_ID", CLIENT_ID)
    monkeypatch.setenv("MCP_PUBLIC_URL", URL_PUBLIQUE + suffixe)
    with pytest.raises(ConfigurationAuthInvalide) as refus:
        parametres_depuis_env()
    message = str(refus.value)
    assert "MCP_PUBLIC_URL" in message
    assert "RACINE" in message
    assert f"{URL_PUBLIQUE}{suffixe}/mcp" in message
    assert "AADSTS9010010" in message


def test_url_publique_racine_acceptee(monkeypatch):
    """La contrepartie du garde-fou : la racine, elle, passe — barre finale comprise."""
    monkeypatch.setenv("MCP_AUTH_MODE", "entra")
    monkeypatch.setenv("ENTRA_TENANT_ID", TENANT)
    monkeypatch.setenv("ENTRA_CLIENT_ID", CLIENT_ID)
    monkeypatch.setenv("MCP_PUBLIC_URL", URL_PUBLIQUE + "/")
    p = parametres_depuis_env()
    assert p.url_publique == URL_PUBLIQUE
    assert p.resource_canonique == RESSOURCE


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
