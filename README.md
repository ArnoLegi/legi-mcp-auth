# legi-mcp-auth

Authentification OAuth 2.0 (jetons Microsoft Entra ID) pour les serveurs MCP du cabinet
— `mcp-inpi`, `mcp-joafe`, `mcp-eurlex`, `mcp-distribution` — construits sur Starlette et
FastMCP.

Un serveur MCP déployé sur Internet sans authentification est une porte ouverte : qui
connaît l'URL appelle les outils. Ce paquet ferme `/mcp` et `/sse` derrière un jeton
d'accès délivré par l'annuaire Entra ID du cabinet, publie les métadonnées qui permettent
au client (Claude.ai, Claude Code) de découvrir seul le flux OAuth, et journalise qui
appelle quel outil.

**Il ne fait rien tant qu'il n'est pas configuré.** Sans `MCP_AUTH_MODE=entra`, le
branchement est neutre : aucun middleware, aucune route ajoutée, le serveur se comporte
exactement comme avant, avec un avertissement au démarrage. C'est voulu : le paquet peut
être installé sur les quatre serveurs bien avant que le tenant Entra ne soit prêt.

---

## Installation

```bash
pip install git+https://github.com/ArnoLegi/legi-mcp-auth@v0.1.0
```

Dans un `requirements.txt` :

```
legi-mcp-auth @ git+https://github.com/ArnoLegi/legi-mcp-auth@v0.1.0
```

Le tag est **épinglé volontairement**. Ne jamais écrire `@main` : le code
d'authentification des quatre serveurs changerait à chaque déploiement, sans revue.

Deux dépendances seulement : `PyJWT[crypto]` et `httpx`. Starlette n'en fait pas partie —
il est apporté par le serveur hôte, et une seconde version installée à côté serait une
source de pannes difficiles.

Python ≥ 3.11.

---

## Intégration, en une ligne

Dans le `main.py` du serveur, après la construction de l'application :

```python
from legi_mcp_auth import proteger

app = build_app()
app = proteger(app, settings)   # <- la ligne
```

`settings` est l'objet de configuration du serveur hôte (`eurlex_mcp.config.settings`,
etc.). Il est **toléré et ignoré** : la configuration de l'authentification vient
uniquement de l'environnement. La signature reste ainsi identique sur les quatre
serveurs.

Ce que la ligne ajoute, quand `MCP_AUTH_MODE=entra` :

| | |
|---|---|
| Middleware | `EntraAuthMiddleware`, ASGI pur (ne casse ni le SSE ni le flux `/mcp`) |
| Routes | `/.well-known/oauth-protected-resource`, `…/mcp`, `…/sse` |
| Exemptions | `/health` et tout `/.well-known/*` |
| Protégé | tout le reste, `/` compris |

### Lire l'identité de l'appelant

```python
utilisateur = request.state.utilisateur
# {"oid": "...", "preferred_username": "avocat@cabinet.fr", "name": "..."}
# ou {"admin": True} pour un jeton administrateur
```

---

## Variables d'environnement

| Variable | Défaut | Rôle |
|---|---|---|
| `MCP_AUTH_MODE` | `off` | `off` (neutre) ou `entra` (protection active). Une valeur inconnue **fait échouer le démarrage** : une faute de frappe ne doit pas désactiver l'authentification en silence. |
| `ENTRA_TENANT_ID` | — | GUID de l'annuaire. **Obligatoire** en mode `entra`. |
| `ENTRA_CLIENT_ID` | — | GUID de l'inscription d'application exposant l'API MCP. **Obligatoire.** |
| `ENTRA_AUDIENCE` | `ENTRA_CLIENT_ID` | Audience attendue. `api://<client-id>` est **aussi accepté** dans tous les cas : Entra émet l'une ou l'autre forme selon le manifeste. |
| `ENTRA_SCOPE_REQUIS` | `mcp.access` | Portée déléguée exigée dans `scp`. |
| `ENTRA_GROUPES_AUTORISES` | — | GUID de groupes séparés par des virgules. Vide = tout utilisateur du tenant porteur de la portée. |
| `MCP_PUBLIC_URL` | — | URL publique du serveur, sans barre finale, en HTTPS. **Obligatoire** : c'est le `resource` des métadonnées. Ex. `https://mcp-eurlex-production.up.railway.app`. |
| `MCP_ADMIN_TOKENS` | — | Jetons statiques acceptés tels quels en `Authorization: Bearer`, séparés par des virgules. Comparaison en temps constant. |

Toutes les valeurs sont nettoyées des espaces et des guillemets parasites : coller
`ENTRA_CLIENT_ID="xxx"` dans Railway est l'erreur la plus fréquente, et la plus longue à
diagnostiquer.

### Exemple, une fois le tenant disponible

```
MCP_AUTH_MODE=entra
ENTRA_TENANT_ID=aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee
ENTRA_CLIENT_ID=11111111-2222-3333-4444-555555555555
ENTRA_SCOPE_REQUIS=mcp.access
MCP_PUBLIC_URL=https://mcp-eurlex-production.up.railway.app
MCP_ADMIN_TOKENS=<sortie de: python -c "import secrets; print(secrets.token_urlsafe(32))">
```

### Jetons administrateurs

À réserver à trois usages : **Claude Code** en développement, la **sonde** de
déploiement, et les **tests**. Ce sont des mots de passe permanents : ils ne connaissent
ni expiration, ni révocation par Entra, ni identité — l'audit les journalise
`utilisateur=admin`, sans dire lequel ni qui.

- au moins 32 caractères aléatoires (`secrets.token_urlsafe(32)`) ; en dessous, le
  paquet avertit au démarrage ;
- un jeton distinct par serveur et par usage, jamais partagé ;
- à faire tourner tous les six mois, et immédiatement après tout départ ;
- **jamais** dans le dépôt, dans un fichier `.env` versionné, ni dans un ticket.

---

## Ce qui est vérifié dans un jeton

1. `alg` = **RS256** — `none` et tout autre algorithme sont refusés avant toute autre
   opération (les deux attaques classiques : jeton non signé, et substitution HS256 en
   utilisant la clé publique comme secret partagé) ;
2. la **signature**, avec la clé publique du tenant désignée par `kid`, obtenue sur
   `https://login.microsoftonline.com/<tenant>/discovery/v2.0/keys` (cache 24 h,
   rafraîchi immédiatement si le `kid` est inconnu — c'est la signature d'une rotation
   de clé chez Microsoft ; bridé 5 minutes après un échec, pour qu'un `kid` inventé ne
   nous fasse pas marteler l'autorité) ;
3. `iss` = `https://login.microsoftonline.com/<tenant>/v2.0` ;
4. `aud` ∈ { client ID, `api://<client-id>` } ;
5. `exp` et `nbf`, avec **60 secondes** de tolérance d'horloge ;
6. `tid` = tenant attendu — sans ce contrôle, un jeton d'un **autre** annuaire Entra
   portant la bonne audience passerait ;
7. `scp` contient la portée requise ;
8. `groups` recoupe `ENTRA_GROUPES_AUTORISES`, si la variable est définie.

Si un utilisateur appartient à plus de ~200 groupes, Entra remplace `groups` par une
référence à Microsoft Graph : le jeton est alors refusé, avec un message explicite dans
le journal. Configurer l'application pour n'émettre que les **groupes assignés**.

---

## La réponse 401

Aucun détail sur la cause du refus n'apparaît dans la réponse : un attaquant apprendrait
à chaque essai ce qu'il doit corriger. Le motif exact est dans le journal
(`legi_mcp_auth.middleware`, niveau WARNING).

```http
HTTP/1.1 401 Unauthorized
content-type: application/json; charset=utf-8
cache-control: no-store
www-authenticate: Bearer resource_metadata="https://mcp-eurlex-production.up.railway.app/.well-known/oauth-protected-resource", scope="api://11111111-2222-3333-4444-555555555555/mcp.access", error="invalid_token"
```

```json
{
  "error": "invalid_token",
  "error_description": "Jeton d'accès absent ou invalide. Ce serveur MCP exige un jeton Bearer émis par Microsoft Entra ID. Voir le document de métadonnées indiqué par l'en-tête WWW-Authenticate pour l'autorité et la portée à demander.",
  "resource_metadata": "https://mcp-eurlex-production.up.railway.app/.well-known/oauth-protected-resource",
  "scope": "api://11111111-2222-3333-4444-555555555555/mcp.access"
}
```

C'est cet en-tête qui déclenche tout : le client MCP y lit l'adresse des métadonnées, s'y
rend, y trouve l'autorité et la portée, puis mène le flux OAuth sans configuration
manuelle.

> **Note sur `scope`.** La spécification interne dit `<audience>/<scope>`. Entra ID nomme
> les portées d'une API `api://<client-id>/<portée>`, jamais `<client-id>/<portée>` : un
> client ID nu est donc préfixé `api://` pour former cette valeur. Sans cela, le client
> demanderait à Entra une portée que l'annuaire ne connaît pas et le consentement
> échouerait.

---

## Métadonnées de ressource protégée (RFC 9728)

Servies sans jeton sur `/.well-known/oauth-protected-resource`, sur `…/mcp` et sur
`…/sse` — les clients diffèrent sur la ressource qu'ils considèrent (la racine du
serveur, ou l'URL du transport). La RFC construit l'URL des métadonnées en insérant
`/.well-known/oauth-protected-resource` **avant** le chemin de la ressource : d'où
`…/oauth-protected-resource/mcp` pour la ressource `<serveur>/mcp`.

```json
{
  "resource": "https://mcp-eurlex-production.up.railway.app/mcp",
  "authorization_servers": [
    "https://login.microsoftonline.com/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee/v2.0"
  ],
  "scopes_supported": [
    "api://11111111-2222-3333-4444-555555555555/mcp.access"
  ],
  "bearer_methods_supported": ["header"],
  "resource_documentation": "https://mcp-eurlex-production.up.railway.app/health"
}
```

---

## Audit d'accès

À chaque appel d'outil, une ligne sur le journal `legi_mcp_auth.audit` :

```
utilisateur=avocat@cabinet.fr outil=rechercher_legislation
utilisateur=admin outil=texte_acte
```

Jamais le jeton, jamais les arguments de l'appel (ils contiennent les recherches du
cabinet). En production, router ce journal vers une destination durable : c'est la trace
qui permettra de dire qui a consulté quoi.

---

## Procédure de bascule

L'ordre compte : activer l'authentification avant d'avoir un jeton en main coupe l'accès
au serveur pour tout le monde, soi-même compris.

1. **Côté Entra ID** — inscrire l'application, exposer une API `api://<client-id>` avec
   la portée déléguée `mcp.access`, autoriser les applications clientes (Claude), et
   assigner les utilisateurs ou le groupe.
2. **Vérifier le mode off** — le paquet est déjà installé et branché, `MCP_AUTH_MODE`
   absent. `/health` et `/mcp` répondent comme avant. C'est l'état actuel.
3. **Générer un jeton administrateur** et le poser dans `MCP_ADMIN_TOKENS`, **avant**
   d'activer le mode `entra`. C'est le filet de sécurité : la sonde et Claude Code
   continueront de fonctionner même si la configuration Entra est fautive.
4. **Poser les variables Entra** et `MCP_PUBLIC_URL`, puis `MCP_AUTH_MODE=entra`.
   Redéployer.
5. **Vérifier**, dans cet ordre :
   - `GET /health` → 200 (sinon Railway déclarera le déploiement en échec) ;
   - `GET /.well-known/oauth-protected-resource` → le document ci-dessus ;
   - `POST /mcp` sans jeton → 401 avec l'en-tête `WWW-Authenticate` ;
   - `POST /mcp` avec le jeton administrateur → 200 ;
   - reconnexion du connecteur dans Claude.ai → flux OAuth, consentement, outils
     disponibles.
6. **Retour arrière** : `MCP_AUTH_MODE=off` et redéploiement. Une variable, un
   redéploiement, aucune modification de code.

Ne basculer les quatre serveurs qu'après validation complète sur EUR-Lex.

---

## Rotation du secret, et son expiration

### Ce qui expire, et ce qui n'expire pas

Le serveur MCP est une **ressource**, pas un client : il ne détient aucun secret Entra.
Il ne fait que vérifier des signatures avec des clés **publiques**. Conséquence directe :

> **Le secret client d'Entra ID n'a aucun effet sur ce serveur. S'il expire, la
> validation des jetons continue de fonctionner.**

Ce qui casse quand un secret expire, c'est le **client** qui s'en sert pour obtenir un
jeton — Claude.ai lors du flux OAuth, un script d'intégration. Le symptôme est alors
`invalid_client` ou `AADSTS7000222` **côté client**, jamais un 401 de notre part. Erreur
de diagnostic classique : chercher la panne dans le serveur MCP, où il n'y a rien à
trouver.

| Élément | Durée | Effet à l'expiration |
|---|---|---|
| Secret client Entra | 6 à 24 mois, au choix | Les clients n'obtiennent plus de jeton. Le serveur, lui, va bien. |
| Jeton d'accès | ~1 h | Le client le renouvelle seul avec son jeton de rafraîchissement. |
| Clés de signature Microsoft | rotation régulière, sans préavis | **Aucun** : le `kid` inconnu déclenche un rechargement automatique du JWKS. |
| Jeton administrateur | jamais | Aucun. C'est bien le problème : à faire tourner à la main. |

### Rotation d'un secret client Entra

À faire **avant** l'expiration ; Entra permet deux secrets valides simultanément.

1. Portail Entra → l'inscription d'application → *Certificats & secrets* → nouveau
   secret, durée 12 mois, noter la date de fin.
2. Poser le nouveau secret **là où il est utilisé** (le client), pas sur le serveur MCP.
3. Vérifier une connexion complète depuis Claude.ai.
4. Supprimer l'ancien secret dans le portail.
5. Poser un rappel de calendrier deux mois avant la prochaine échéance.

### Rotation d'un jeton administrateur

1. Générer : `python -c "import secrets; print(secrets.token_urlsafe(32))"`.
2. Ajouter le **nouveau** à `MCP_ADMIN_TOKENS` **à côté** de l'ancien (la variable est
   une liste) et redéployer.
3. Mettre à jour la sonde et la configuration de Claude Code.
4. Retirer l'ancien de `MCP_ADMIN_TOKENS`, redéployer.

Cet ordre évite toute coupure. En cas de fuite avérée, sauter les étapes : retirer le
jeton immédiatement et redéployer.

---

## Diagnostic

| Symptôme | Cause probable |
|---|---|
| Tout passe sans jeton | `MCP_AUTH_MODE` absent ou `off`. Le journal le dit au démarrage. |
| Le serveur refuse de démarrer | Mode `entra` sans `ENTRA_TENANT_ID`, `ENTRA_CLIENT_ID` ou `MCP_PUBLIC_URL`. Volontaire : une panne visible vaut mieux qu'un serveur ouvert. |
| 401 systématique avec un jeton frais | Lire le journal `legi_mcp_auth.middleware` : il donne le motif exact (audience, `tid`, portée, groupe…). |
| `portée 'mcp.access' absente` | Le client demande `.default` ou une autre portée ; ou la portée n'est pas exposée dans l'inscription d'application. |
| `audience invalide` | Le client a demandé un jeton pour Graph et non pour notre API. Vérifier la portée demandée : `api://<client-id>/mcp.access`. |
| `JWKS indisponible` | `login.microsoftonline.com` injoignable depuis Railway. Le serveur refuse alors tout (choix délibéré : *fail closed*). |
| `invalid_client` côté Claude.ai | Secret client Entra expiré. Rien à corriger sur le serveur MCP. |

---

## Développement

```bash
python -m venv .venv
.venv/Scripts/activate      # Windows
pip install -e ".[dev]"
pytest -q
```

Les tests ne touchent **jamais** au réseau : une paire RSA est générée à la volée, le
JWKS est servi par un mock `respx`, et les jetons sont de vrais JWT signés RS256 — la
validation exercée est donc la validation réelle, signature comprise. Aucune valeur du
tenant du cabinet ne figure dans le dépôt.

La CI ajoute `pip-audit` (vulnérabilités des dépendances) et Dependabot hebdomadaire :
c'est le dépôt dont la sécurité compte le plus, il garde les clés des quatre serveurs.

## Licence

MIT.
