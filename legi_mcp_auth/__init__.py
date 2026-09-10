"""Authentification OAuth 2.0 (Microsoft Entra ID) pour les serveurs MCP du cabinet.

Un serveur MCP exposé sur Internet sans authentification est une base de données du
cabinet ouverte à qui connaît l'URL. Ce paquet ferme les endpoints `/mcp` et `/sse`
derrière un jeton d'accès Entra ID, et publie les métadonnées qui permettent au client
(Claude.ai, Claude Code) de découvrir seul l'autorité et la portée à demander.

Branchement, dans le `main.py` du serveur :

    from legi_mcp_auth import proteger
    app = proteger(app, settings)

Sans variables d'environnement, l'appel est neutre : rien n'est ajouté, le serveur reste
tel qu'avant, un avertissement est journalisé. La protection s'active en posant
MCP_AUTH_MODE=entra (voir le README).
"""
from __future__ import annotations

from .config import (
    CHEMIN_METADONNEES,
    MODE_ENTRA,
    MODE_OFF,
    ConfigurationAuthInvalide,
    ParametresAuth,
    parametres_depuis_env,
)
from .integration import proteger
from .jwks import CacheJWKS, CleInconnue, JWKSIndisponible
from .metadonnees import document as document_metadonnees
from .middleware import EntraAuthMiddleware
from .validation import JetonRefuse, ValidateurEntra

__version__ = "0.1.1"

__all__ = [
    "CHEMIN_METADONNEES",
    "CacheJWKS",
    "CleInconnue",
    "ConfigurationAuthInvalide",
    "EntraAuthMiddleware",
    "JWKSIndisponible",
    "JetonRefuse",
    "MODE_ENTRA",
    "MODE_OFF",
    "ParametresAuth",
    "ValidateurEntra",
    "__version__",
    "document_metadonnees",
    "parametres_depuis_env",
    "proteger",
]
