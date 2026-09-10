"""Métadonnées de ressource protégée (RFC 9728) : forme exacte du document."""
from __future__ import annotations

import pytest

from .conftest import CLIENT_ID, TENANT, URL_PUBLIQUE


@pytest.mark.parametrize(
    ("chemin", "ressource"),
    [
        ("/.well-known/oauth-protected-resource", URL_PUBLIQUE),
        ("/.well-known/oauth-protected-resource/mcp", f"{URL_PUBLIQUE}/mcp"),
        ("/.well-known/oauth-protected-resource/sse", f"{URL_PUBLIQUE}/sse"),
    ],
)
async def test_document(client, chemin, ressource):
    reponse = await client.get(chemin)
    assert reponse.status_code == 200
    document = reponse.json()
    assert document["resource"] == ressource
    assert document["authorization_servers"] == [
        f"https://login.microsoftonline.com/{TENANT}/v2.0"
    ]
    assert document["scopes_supported"] == [f"api://{CLIENT_ID}/mcp.access"]
    assert document["bearer_methods_supported"] == ["header"]


async def test_metadonnees_sans_jeton(client):
    """La découverte précède l'authentification : aucun jeton n'est exigé ici."""
    reponse = await client.get("/.well-known/oauth-protected-resource")
    assert "www-authenticate" not in reponse.headers


async def test_metadonnees_en_cache(client):
    reponse = await client.get("/.well-known/oauth-protected-resource")
    assert reponse.headers["cache-control"] == "public, max-age=3600"
