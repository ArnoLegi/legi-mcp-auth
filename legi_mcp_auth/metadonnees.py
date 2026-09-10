"""Métadonnées de ressource protégée (RFC 9728).

C'est le document qui rend l'authentification DÉCOUVRABLE : le client MCP reçoit un 401
portant `resource_metadata=...`, lit ce document, y trouve l'autorité Entra ID et la
portée à demander, puis lance le flux OAuth tout seul. Sans lui, chaque utilisateur
devrait être configuré à la main.

Deux chemins sont servis, parce que les clients diffèrent sur la ressource qu'ils
considèrent : la racine du serveur, ou l'URL du transport (`/mcp`). La RFC construit
l'URL des métadonnées en insérant `/.well-known/oauth-protected-resource` AVANT le
chemin de la ressource — d'où `/.well-known/oauth-protected-resource/mcp` pour la
ressource `<serveur>/mcp`.
"""
from __future__ import annotations

from typing import Any

from starlette.responses import JSONResponse
from starlette.routing import Route

from .config import CHEMIN_METADONNEES, ParametresAuth


def document(parametres: ParametresAuth, chemin_ressource: str = "") -> dict[str, Any]:
    """Document de métadonnées pour la ressource `<url publique><chemin_ressource>`."""
    return {
        "resource": f"{parametres.url_publique}{chemin_ressource}",
        "authorization_servers": [parametres.issuer],
        "scopes_supported": [parametres.scope_complet],
        "bearer_methods_supported": ["header"],
        "resource_documentation": f"{parametres.url_publique}/health",
    }


def routes(parametres: ParametresAuth) -> list[Route]:
    """Routes Starlette servant les métadonnées, en lecture seule et sans jeton."""

    def _reponse(chemin_ressource: str):
        async def handler(_request):
            return JSONResponse(
                document(parametres, chemin_ressource),
                headers={
                    # Document public et stable : un cache d'une heure évite de le
                    # reconstruire à chaque tentative de connexion d'un client.
                    "Cache-Control": "public, max-age=3600",
                },
            )

        return handler

    return [
        Route(CHEMIN_METADONNEES, _reponse(""), methods=["GET"]),
        Route(f"{CHEMIN_METADONNEES}/mcp", _reponse("/mcp"), methods=["GET"]),
        Route(f"{CHEMIN_METADONNEES}/sse", _reponse("/sse"), methods=["GET"]),
    ]
