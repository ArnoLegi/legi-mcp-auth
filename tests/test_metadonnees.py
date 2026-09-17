"""Métadonnées de ressource protégée (RFC 9728) : forme exacte du document.

Une seule ressource, donc un seul document : `<MCP_PUBLIC_URL>/mcp`. Il est servi sous
`/.well-known/oauth-protected-resource/mcp` — la RFC insère le suffixe well-known AVANT
le chemin de la ressource — et, à l'identique, sous la racine `well-known` pour les
clients qui la sondent.
"""
from __future__ import annotations

import pytest

from .conftest import (
    RESSOURCE,
    SCOPE_COMPLET,
    SCOPE_ENTETE,
    SCOPES_PUBLIES,
    TENANT,
    URL_PUBLIQUE,
)

CHEMIN_CANONIQUE = "/.well-known/oauth-protected-resource/mcp"
CHEMIN_RACINE = "/.well-known/oauth-protected-resource"


@pytest.mark.parametrize("chemin", [CHEMIN_CANONIQUE, CHEMIN_RACINE])
async def test_document(client, chemin):
    reponse = await client.get(chemin)
    assert reponse.status_code == 200
    document = reponse.json()
    # La ressource annoncée est l'URL du TRANSPORT, jamais la racine du service : c'est
    # elle que le client envoie à Entra dans `resource` (RFC 8707).
    assert document["resource"] == RESSOURCE == f"{URL_PUBLIQUE}/mcp"
    assert document["authorization_servers"] == [
        f"https://login.microsoftonline.com/{TENANT}/v2.0"
    ]
    # La portée se bâtit sur la ressource, pas sur `api://<client-id>` ; et
    # `offline_access` la suit, sans quoi Entra ne délivre pas de jeton de
    # rafraîchissement.
    assert document["scopes_supported"] == list(SCOPES_PUBLIES)
    assert document["scopes_supported"] == [f"{RESSOURCE}/mcp.test", "offline_access"]
    assert document["bearer_methods_supported"] == ["header"]


async def test_racine_et_chemin_servent_le_meme_document(client):
    """La racine n'est gardée que pour les clients qui la sondent : même corps, pas de 3xx.

    Annoncer deux ressources différentes selon le chemin sondé ferait demander à Entra
    une portée bâtie sur la mauvaise, et le refus serait un AADSTS9010010 illisible.
    """
    racine = await client.get(CHEMIN_RACINE)
    canonique = await client.get(CHEMIN_CANONIQUE)
    assert racine.status_code == canonique.status_code == 200
    assert racine.json() == canonique.json()


async def test_aucune_ressource_sse(client):
    """`/sse` n'est plus une ressource : son document est retiré, sans redirection."""
    reponse = await client.get("/.well-known/oauth-protected-resource/sse")
    assert reponse.status_code == 404


@pytest.mark.parametrize("chemin", [CHEMIN_CANONIQUE, CHEMIN_RACINE])
async def test_aucune_redirection(client, chemin):
    reponse = await client.get(chemin)
    assert reponse.status_code == 200, "ni 301, ni 302, ni 307 : le document répond ici"


async def test_portees_publiees_identiques_a_celles_du_401(client):
    """ÉGALITÉ STRICTE entre `scopes_supported` et le `scope` de WWW-Authenticate.

    Claude.ai lit l'en-tête EN PRIORITÉ, et ne retombe sur le document que s'il n'y
    trouve pas son compte. Les deux valeurs ne valent donc que faites ensemble : si
    elles divergent d'un seul caractère, la portée demandée à Entra dépend du chemin que
    le client a suivi, et l'un des deux chemins échoue.

    Le `scope` de l'en-tête est une LISTE séparée par des espaces (RFC 6750) : découpé,
    il doit rendre `scopes_supported` à l'identique, ordre compris.
    """
    document = (await client.get(CHEMIN_CANONIQUE)).json()

    refus = await client.post("/mcp", json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
    assert refus.status_code == 401
    entete = refus.headers["www-authenticate"]
    scope_entete = entete.split('scope="', 1)[1].split('"', 1)[0]

    assert scope_entete == SCOPE_ENTETE
    assert scope_entete.split(" ") == document["scopes_supported"]
    # ... et le corps du 401 annonce lui aussi la même valeur.
    assert refus.json()["scope"] == scope_entete


async def test_portee_de_la_ressource_en_premier(client):
    """`scopes_supported[0]` est la portée de la RESSOURCE, jamais `offline_access`.

    C'est elle qui ouvre l'accès : `offline_access` ne fait qu'obtenir un jeton de
    rafraîchissement. Un client qui ne retiendrait qu'une portée doit retenir celle-là,
    et l'ordre est le seul moyen de le lui dire.
    """
    document = (await client.get(CHEMIN_CANONIQUE)).json()
    assert document["scopes_supported"][0] == SCOPE_COMPLET
    assert document["scopes_supported"][0].startswith(RESSOURCE + "/")


async def test_offline_access_publie(client):
    """Sans `offline_access` dans ce que le serveur publie, aucun jeton de rafraîchissement.

    Claude.ai demande à Entra ce que le serveur publie, et Entra n'émet de jeton de
    rafraîchissement que si `offline_access` figure dans le paramètre `scope` de la
    requête d'autorisation. Non publiée, elle n'est pas demandée : le jeton d'accès dure
    une heure, puis « la connexion a expiré ».
    """
    document = (await client.get(CHEMIN_CANONIQUE)).json()
    assert "offline_access" in document["scopes_supported"]

    refus = await client.post("/mcp", json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
    assert "offline_access" in refus.headers["www-authenticate"]
    assert "offline_access" in refus.json()["scope"].split(" ")


async def test_metadonnees_sans_jeton(client):
    """La découverte précède l'authentification : aucun jeton n'est exigé ici."""
    reponse = await client.get(CHEMIN_CANONIQUE)
    assert "www-authenticate" not in reponse.headers


@pytest.mark.parametrize("chemin", [CHEMIN_CANONIQUE, CHEMIN_RACINE])
async def test_metadonnees_en_cache(client, chemin):
    reponse = await client.get(chemin)
    assert reponse.headers["cache-control"] == "public, max-age=3600"
