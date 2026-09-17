"""Métadonnées de ressource protégée (RFC 9728).

C'est le document qui rend l'authentification DÉCOUVRABLE : le client MCP reçoit un 401
portant `resource_metadata=...`, lit ce document, y trouve l'autorité Entra ID et la
portée à demander, puis lance le flux OAuth tout seul. Sans lui, chaque utilisateur
devrait être configuré à la main.

Il n'y a qu'UNE ressource — `<MCP_PUBLIC_URL>/mcp`, l'URL du transport, celle que le
client envoie à Entra dans le paramètre `resource` (RFC 8707) — donc qu'UN document. La
RFC 9728 construit l'URL de ce document en insérant `/.well-known/oauth-protected-resource`
AVANT le chemin de la ressource : il vit donc sous
`/.well-known/oauth-protected-resource/mcp`.

La route racine `/.well-known/oauth-protected-resource` est conservée, mais elle sert
EXACTEMENT le même document canonique (`resource` = `…/mcp`), sans redirection : c'est
uniquement pour les clients qui sondent la racine avant d'essayer le chemin correct.
Les servir tous les deux évite un 404 sans jamais annoncer deux ressources différentes.
"""
from __future__ import annotations

from typing import Any

from starlette.responses import JSONResponse
from starlette.routing import Route

from .config import CHEMIN_METADONNEES, CHEMIN_RESSOURCE, ParametresAuth


def document(parametres: ParametresAuth) -> dict[str, Any]:
    """Document de métadonnées de l'unique ressource, `parametres.resource_canonique`."""
    return {
        "resource": parametres.resource_canonique,
        "authorization_servers": [parametres.issuer],
        # Les portées que le client doit demander : celle de la RESSOURCE en premier
        # (`<resource>/<portée>`), puis `offline_access`, sans laquelle Entra ne délivre
        # aucun jeton de rafraîchissement et la session expire au bout d'une heure.
        # La même liste, au caractère près, que le paramètre `scope` du 401.
        "scopes_supported": list(parametres.scopes_publies),
        "bearer_methods_supported": ["header"],
        "resource_documentation": f"{parametres.url_publique}/health",
    }


def routes(parametres: ParametresAuth) -> list[Route]:
    """Routes Starlette servant les métadonnées, en lecture seule et sans jeton."""

    async def handler(_request):
        return JSONResponse(
            document(parametres),
            headers={
                # Document public et stable : un cache d'une heure évite de le
                # reconstruire à chaque tentative de connexion d'un client.
                "Cache-Control": "public, max-age=3600",
            },
        )

    return [
        # Aucune redirection 3xx : les deux chemins RÉPONDENT, avec le même corps.
        Route(f"{CHEMIN_METADONNEES}{CHEMIN_RESSOURCE}", handler, methods=["GET"]),
        Route(CHEMIN_METADONNEES, handler, methods=["GET"]),
    ]
