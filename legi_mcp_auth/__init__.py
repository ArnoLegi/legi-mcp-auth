"""Authentification OAuth 2.0 (Microsoft Entra ID) pour les serveurs MCP du cabinet.

Un serveur MCP exposé sur Internet sans authentification est une base de données du
cabinet ouverte à qui connaît l'URL. Ce paquet ferme le serveur derrière un jeton
d'accès Entra ID, et publie les métadonnées qui permettent au client (Claude.ai, Claude
Code) de découvrir seul l'autorité et la portée à demander.

La ressource protégée, au sens de la RFC 8707, est unique : `<MCP_PUBLIC_URL>/mcp`. La
portée publiée se bâtit sur elle — `<resource>/<portée>` — et non sur
`api://<client-id>`, faute de quoi Entra refuse la demande d'autorisation par
AADSTS9010010. `offline_access` est publiée à côté : sans elle dans la demande
d'autorisation, Entra ne délivre aucun jeton de rafraîchissement et la connexion expire
au bout d'une heure.

Branchement, dans le `main.py` du serveur :

    from legi_mcp_auth import proteger
    app = proteger(app, settings)

Trois modes, pilotés par MCP_AUTH_MODE :

  off      défaut. L'appel est neutre : rien n'est ajouté, le serveur reste tel
           qu'avant, un avertissement est journalisé.
  jetons   seuls les jetons de MCP_ADMIN_TOKENS sont acceptés. Aucune configuration
           Entra n'est nécessaire, aucune métadonnée n'est publiée.
  entra    jetons délivrés par l'annuaire Entra ID du cabinet, avec découverte OAuth.

Voir le README pour le choix du mode et la procédure de bascule.
"""
from __future__ import annotations

from .config import (
    CHEMIN_METADONNEES,
    CHEMIN_RESSOURCE,
    MODE_ENTRA,
    MODE_JETONS,
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

__version__ = "0.3.1"

__all__ = [
    "CHEMIN_METADONNEES",
    "CHEMIN_RESSOURCE",
    "CacheJWKS",
    "CleInconnue",
    "ConfigurationAuthInvalide",
    "EntraAuthMiddleware",
    "JWKSIndisponible",
    "JetonRefuse",
    "MODE_ENTRA",
    "MODE_JETONS",
    "MODE_OFF",
    "ParametresAuth",
    "ValidateurEntra",
    "__version__",
    "document_metadonnees",
    "parametres_depuis_env",
    "proteger",
]
