"""Branchement en une ligne dans une application Starlette.

    from legi_mcp_auth import proteger
    app = proteger(app, settings)

Sans configuration (MCP_AUTH_MODE absent ou « off »), l'appel n'ajoute NI middleware NI
route : l'application repart telle quelle, avec un avertissement au démarrage.
"""
from __future__ import annotations

import logging
from typing import Any

from starlette.applications import Starlette

from .config import MODE_ENTRA, MODE_JETONS, ParametresAuth, parametres_depuis_env
from .metadonnees import routes as routes_metadonnees
from .middleware import EntraAuthMiddleware
from .validation import ValidateurEntra

log = logging.getLogger("legi_mcp_auth")


def proteger(
    app: Starlette,
    settings: Any = None,
    *,
    parametres: ParametresAuth | None = None,
    validateur: ValidateurEntra | None = None,
) -> Starlette:
    """Ajoute l'authentification Entra ID à `app` et renvoie `app`.

    Paramètres
    ----------
    app
        L'application Starlette du serveur MCP, routes déjà montées.
    settings
        Toléré et ignoré, sauf s'il s'agit d'un `ParametresAuth`. Chaque serveur passe
        son propre objet de configuration (`eurlex_mcp.config.settings`, etc.) : la
        signature reste `proteger(app, settings)` partout, et la configuration de
        l'authentification vient de l'environnement.
    parametres
        Paramètres explicites, pour les tests. Court-circuite l'environnement.

    Renvoie l'application, pour permettre `app = proteger(app, settings)`.
    """
    if parametres is None:
        parametres = settings if isinstance(settings, ParametresAuth) else parametres_depuis_env()

    if not parametres.actif:
        log.warning(
            "AUTHENTIFICATION DÉSACTIVÉE (MCP_AUTH_MODE=%s) : les endpoints MCP sont "
            "publics. Posez MCP_AUTH_MODE=%s (jetons d'administration seuls) ou "
            "MCP_AUTH_MODE=%s (jetons Microsoft Entra ID, avec ENTRA_TENANT_ID, "
            "ENTRA_CLIENT_ID et MCP_PUBLIC_URL) pour exiger un jeton.",
            parametres.mode,
            MODE_JETONS,
            MODE_ENTRA,
        )
        return app

    if parametres.entra_actif:
        # Les métadonnées passent DEVANT les routes existantes : le serveur ne doit pas
        # pouvoir masquer la découverte OAuth avec une route générique. En mode
        # « jetons », il n'y a aucune autorité : pas de métadonnées à servir, et le 401
        # ne renvoie vers aucune adresse de découverte.
        app.router.routes[0:0] = routes_metadonnees(parametres)

    app.add_middleware(EntraAuthMiddleware, parametres=parametres, validateur=validateur)

    if parametres.entra_actif:
        log.info(
            "Authentification Entra ID ACTIVE — tenant=%s audience=%s portée=%s "
            "groupes=%s jetons_admin=%d ressource=%s",
            parametres.tenant_id,
            parametres.audience_uri,
            parametres.scope_complet,
            ", ".join(parametres.groupes_autorises) or "tous",
            len(parametres.jetons_admin),
            parametres.url_publique,
        )
    else:
        log.info(
            "Authentification par JETONS ACTIVE — %d jeton(s) d'administration acceptés, "
            "aucune autorité OAuth. Tout appel hors /health et /.well-known exige un "
            "jeton en Authorization: Bearer.",
            len(parametres.jetons_admin),
        )
    return app
