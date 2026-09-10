# legi-mcp-auth

Authentification OAuth 2.0 (jetons Microsoft Entra ID) pour les serveurs MCP du cabinet
— `mcp-inpi`, `mcp-joafe`, `mcp-eurlex`, `mcp-distribution` — construits sur Starlette et
FastMCP.

Un serveur MCP déployé sur Internet sans authentification est une porte ouverte : qui
connaît l'URL appelle les outils. Ce paquet ferme `/mcp` et `/sse` derrière un jeton
d'accès délivré par l'annuaire Entra ID du cabinet, publie les métadonnées qui permettent
au client (Claude.ai, Claude Code) de découvrir seul le flux OAuth, et journalise qui
appelle quel outil.

**Il ne fait rien tant qu'il n'est pas configuré.** Sans `MCP_AUTH_MODE`, le
branchement est neutre : aucun middleware, aucune route ajoutée, le serveur se comporte
exactement comme avant, avec un avertissement au démarrage. C'est voulu : le paquet peut
être installé sur les quatre serveurs bien avant que le tenant Entra ne soit prêt.

---

## Installation

```bash
pip install git+https://github.com/ArnoLegi/legi-mcp-auth@v0.2.0
```

Dans un `requirements.txt` :

```
legi-mcp-auth @ git+https://github.com/ArnoLegi/legi-mcp-auth@v0.2.0
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

## Les trois modes

`MCP_AUTH_MODE` décide de tout. Un mode n'est pas un réglage de confort : c'est le choix
de qui peut appeler le serveur.

| Mode | Qui est accepté | Configuration exigée | Métadonnées OAuth |
|---|---|---|---|
| `off` *(défaut)* | tout le monde | aucune | aucune |
| `jetons` | les porteurs d'un jeton de `MCP_ADMIN_TOKENS` | `MCP_ADMIN_TOKENS` seule | aucune |
| `entra` | les utilisateurs du tenant, plus les jetons d'administration | tenant, client ID, URL publique | publiées |

### `off` — le développement, et rien d'autre

Le serveur est ouvert. C'est l'état d'un poste de travail, d'un serveur qui n'expose
aucune donnée du cabinet, ou d'un dépôt où le paquet vient d'être branché et attend sa
configuration. Un avertissement le rappelle à chaque démarrage, en majuscules, pour
qu'un serveur oublié dans cet état finisse par se faire remarquer.

Jamais en production sur un serveur qui sert du contenu du cabinet.

### `jetons` — un serveur à usage restreint, ou une préproduction

Seuls les jetons de `MCP_ADMIN_TOKENS` passent, comparés en temps constant. Rien
d'autre : ni tenant, ni inscription d'application, ni flux OAuth, ni métadonnées. Le 401
ne porte **pas** de `resource_metadata` — il n'y a aucune autorité vers laquelle
renvoyer un client, et annoncer une adresse de découverte qui répondrait 404 enverrait
les clients MCP dans un flux impossible à mener.

Deux usages :

- **un serveur à usage restreint** : un seul utilisateur, ou un serveur appelé par la
  sonde et par Claude Code plutôt que par le cabinet. Le jeton se colle dans la
  configuration du connecteur, et c'est tout ;
- **une préproduction**, le temps que l'inscription Entra existe et fonctionne.

Ce que ce mode ne donne pas, et qu'il faut avoir en tête : aucune identité (l'audit
journalise `utilisateur=admin`, sans dire qui), aucune expiration, aucune révocation
centralisée. Un jeton est un mot de passe permanent. C'est suffisant pour un accès de
service, insuffisant pour tracer qui a consulté quoi.

Le paquet **refuse de démarrer** si `MCP_ADMIN_TOKENS` est vide ou si l'un des jetons
fait moins de 32 caractères : dans ce mode, cette liste est la seule barrière, il n'y a
pas d'autorité derrière pour rattraper une faiblesse.

### `entra` — la production

Les jetons sont délivrés par l'annuaire Entra ID du cabinet et validés contre le JWKS du
tenant. C'est le seul mode qui donne une identité par appel (`oid`,
`preferred_username`), une expiration, une révocation par l'annuaire, un filtrage par
groupe, et un audit d'accès qui nomme les personnes. Les métadonnées de ressource
protégée sont publiées, et Claude.ai mène le flux OAuth tout seul.

Les jetons de `MCP_ADMIN_TOKENS` restent acceptés à côté — pour la sonde et Claude Code,
qui n'ont pas d'identité Entra. Un jeton court n'y est qu'un avertissement, l'annuaire
restant la voie normale.

---

## Variables d'environnement

| Variable | Défaut | Rôle |
|---|---|---|
| `MCP_AUTH_MODE` | `off` | `off` (neutre), `jetons` ou `entra`. Une valeur inconnue **fait échouer le démarrage** : une faute de frappe ne doit pas désactiver l'authentification en silence. |
| `ENTRA_TENANT_ID` | — | GUID de l'annuaire. **Obligatoire** en mode `entra`, inutile en mode `jetons`. |
| `ENTRA_CLIENT_ID` | — | GUID de l'inscription d'application exposant l'API MCP. **Obligatoire** en mode `entra`. |
| `ENTRA_AUDIENCE` | `ENTRA_CLIENT_ID` | Audience attendue. `api://<client-id>` est **aussi accepté** dans tous les cas : Entra émet l'une ou l'autre forme selon le manifeste. |
| `ENTRA_SCOPE_REQUIS` | `mcp.access` | Portée déléguée exigée dans `scp`. |
| `ENTRA_GROUPES_AUTORISES` | — | GUID de groupes séparés par des virgules. Vide = tout utilisateur du tenant porteur de la portée. |
| `MCP_PUBLIC_URL` | — | URL publique du serveur, sans barre finale, en HTTPS. **Obligatoire** en mode `entra` : c'est le `resource` des métadonnées. Ex. `https://mcp-eurlex-production.up.railway.app`. |
| `MCP_ADMIN_TOKENS` | — | Jetons statiques acceptés tels quels en `Authorization: Bearer`, séparés par des virgules. Comparaison en temps constant. **Obligatoire** en mode `jetons`, où 32 caractères minimum sont exigés. |

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
- à faire tourner tous les six mois, et immédiatement après tout départ — la
  rotation se fait sur Railway (`MCP_ADMIN_TOKENS` accepte plusieurs valeurs, donc
  sans coupure) et partout où le jeton est utilisé : sonde, configuration de
  Claude Code ;
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

Voici la forme du mode `entra`. En mode `jetons`, l'en-tête se réduit à
`Bearer error="invalid_token"` et le corps aux deux champs `error` et
`error_description` : sans autorité, il n'y a ni `resource_metadata` ni `scope` à
annoncer.

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

Quatre temps, dans cet ordre. Le principe : **rien n'est activé en production avant
qu'un appel d'outil ait réussi de bout en bout sur un service de préproduction.**
Activer l'authentification avant d'avoir vu le flux fonctionner coupe l'accès à tout le
monde, soi-même compris.

### 1. Vérifier l'inscription d'application Entra ID

Quatre points, et ce sont les quatre qui font échouer une bascule quand ils manquent.

| À vérifier | Où | Valeur |
|---|---|---|
| **URI de redirection** | *Authentification* → plateforme *Web* | `https://claude.ai/api/mcp/auth_callback` — celui qu'affiche Claude.ai à la création du connecteur. Le recopier depuis l'écran, ne pas le deviner. |
| **Portée exposée** | *Exposer une API* | ID d'application `api://<client-id>`, portée déléguée nommée exactement `mcp.access`, consentement *administrateurs et utilisateurs*. |
| **`offline_access`** | *Autorisations d'API* → Microsoft Graph, déléguée | Sans elle, pas de jeton de rafraîchissement : le connecteur redemande une authentification toutes les heures. C'est l'oubli le plus courant, et il ne se voit qu'au bout d'une heure. |
| **`accessTokenAcceptedVersion`** | *Manifeste* | `2`. À `null` (défaut), Entra émet des jetons v1.0 : `iss` vaut `https://sts.windows.net/<tenant>/`, que ce paquet refuse — il attend l'émetteur v2.0. Symptôme : 401 systématique, journal « émetteur invalide ». |

Ajouter aussi `openid` et `profile` (déléguées), et assigner les utilisateurs ou le
groupe si l'application exige une assignation.

### 2. Éprouver sur un service de préproduction

Ne pas éprouver sur un service que le cabinet utilise.

1. Dans le projet Railway, créer un **second service** déployé depuis le **même dépôt**
   que `mcp-eurlex`, même branche. Il aura sa propre URL
   (`https://<service>-<projet>.up.railway.app`) et ses propres variables.
2. Y poser `MCP_AUTH_MODE=entra`, `ENTRA_TENANT_ID`, `ENTRA_CLIENT_ID`,
   `MCP_PUBLIC_URL` = l'URL **de ce service de préproduction**, et
   `MCP_ADMIN_TOKENS` — le filet de sécurité : il permet de tester le serveur même si
   la configuration Entra est fautive.
3. Vérifier à la main, dans cet ordre :
   - `GET /health` → 200 (sinon Railway déclare le déploiement en échec et redémarre) ;
   - `GET /.well-known/oauth-protected-resource` → le document attendu, avec la bonne
     `resource` et la bonne portée ;
   - `POST /mcp` sans jeton → 401 portant `WWW-Authenticate` ;
   - `POST /mcp` avec le jeton administrateur → 200.
4. Créer dans Claude.ai un **connecteur de test** pointant sur ce service, avec le
   Client ID et le secret client de l'inscription. Se connecter : l'écran Microsoft
   doit apparaître, le consentement être demandé une fois.
5. **Appeler un outil** depuis une conversation, et obtenir une réponse. C'est le seul
   critère de succès : tant qu'un outil n'a pas répondu après l'écran Microsoft, la
   bascule n'est pas prête. Vérifier au passage la ligne d'audit
   `utilisateur=<upn> outil=<nom>` dans les journaux Railway.

Un échec ici se corrige sur la préproduction, sans que personne ne s'en aperçoive.

### 3. Basculer la production, un service à la fois

Dans l'ordre : `mcp-eurlex`, puis `mcp-inpi`, `mcp-joafe`, `mcp-distribution`. Pour
chacun, et **seulement une fois le précédent validé** :

1. Poser les variables sur le service Railway — `MCP_PUBLIC_URL` étant l'URL **de ce
   service-là**, jamais celle d'un autre, et `MCP_ADMIN_TOKENS` un jeton propre à ce
   serveur. Redéployer.
2. Vérifier le 401 et les métadonnées comme en préproduction.
3. **Éditer le connecteur Claude.ai correspondant** : y renseigner le Client ID et le
   secret client. Un connecteur qui n'a pas été édité continuera d'appeler sans jeton
   et recevra des 401 — l'authentification ne se propage pas toute seule aux
   connecteurs existants.
4. Reconnecter, consentir, appeler un outil.

`mcp-distribution` demande une décision préalable : il porte déjà sa propre
authentification par jeton (`mcp_auth`, `MCPDIST_ADMIN_TOKEN`). Les deux couches ne
peuvent pas être actives ensemble — elles liraient le même en-tête `Authorization` et se
refuseraient mutuellement les jetons. Retirer l'une des deux avant de basculer.

### 4. Retour arrière

`MCP_AUTH_MODE=off` sur le service concerné, redéploiement. Une variable, un
redéploiement, aucune modification de code, aucun retour en arrière sur les dépôts. Les
autres variables peuvent rester en place : elles ne sont plus lues.

Le connecteur Claude.ai, lui, reste configuré avec son Client ID — sans effet, le
serveur n'exigeant plus rien.

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
| Secret client Entra | 6 à 24 mois, au choix | Les clients n'obtiennent plus de jeton : **chaque connecteur Claude.ai** tombe. Le serveur, lui, va bien. |
| Jeton d'accès | ~1 h | Le client le renouvelle seul avec son jeton de rafraîchissement. |
| Clés de signature Microsoft | rotation régulière, sans préavis | **Aucun** : le `kid` inconnu déclenche un rechargement automatique du JWKS. |
| Jeton administrateur | jamais | Aucun. C'est bien le problème : à faire tourner à la main. |

### Rotation d'un secret client Entra

À faire **avant** l'expiration ; Entra permet deux secrets valides simultanément, et
c'est ce recouvrement qui évite toute coupure.

Le point à retenir : **la rotation touche deux endroits, et le second s'oublie.**

| Où | Quoi | Pourquoi |
|---|---|---|
| **Railway** | Rien, pour le secret client. Éventuellement `MCP_ADMIN_TOKENS`, qui suit son propre calendrier. | Le serveur MCP est une *ressource* : il ne détient aucun secret Entra, il ne vérifie que des signatures avec des clés publiques. |
| **Chaque connecteur Claude.ai** | Le nouveau secret client, **connecteur par connecteur** | C'est le *client* qui présente le secret à Entra pour obtenir un jeton. Quatre serveurs = jusqu'à quatre connecteurs à éditer, plus les connecteurs de test. Un connecteur oublié cesse de fonctionner à l'expiration de l'ancien secret, et lui seul. |

Marche à suivre :

1. Portail Entra → l'inscription d'application → *Certificats & secrets* → nouveau
   secret, durée 12 mois, noter la date de fin **et la valeur** (elle n'est affichée
   qu'une fois).
2. **Éditer chaque connecteur Claude.ai** qui pointe vers un serveur MCP du cabinet et
   y remplacer le secret client. Faire la liste avant de commencer : un connecteur
   oublié tombera silencieusement, à l'expiration de l'ancien secret, c'est-à-dire des
   semaines plus tard et sans lien apparent avec ce geste.
3. Reconnecter et **appeler un outil** sur chaque connecteur édité. Un connecteur qui
   détient encore un jeton valide semble fonctionner sans avoir été mis à jour : le
   test n'est probant qu'après une reconnexion.
4. Supprimer l'ancien secret dans le portail — seulement une fois l'étape 3 faite
   partout.
5. Poser un rappel de calendrier **deux mois** avant la prochaine échéance.

Si l'ancien secret expire avant d'avoir été remplacé : le symptôme est
`invalid_client` / `AADSTS7000222` **côté Claude.ai**, jamais un 401 de notre part. Rien
à corriger sur Railway ni dans le code — un nouveau secret et l'étape 2 suffisent.

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

## Versions

| Version | Contenu |
|---|---|
| `v0.2.0` | Nouveau mode `MCP_AUTH_MODE=jetons` : les jetons d'administration seuls, sans configuration Entra ni métadonnées OAuth, pour un serveur à usage restreint ou une préproduction. Refuse de démarrer si la liste est vide ou si un jeton fait moins de 32 caractères. Aucun changement de comportement pour les modes `off` et `entra`. |
| `v0.1.1` | Correctif : une rotation de clé survenant dans les cinq minutes suivant le démarrage de la machine était bridée à tort (`time.monotonic()` part de zéro, et le sentinelle d'échec valait `0.0` — donc « échec à l'instant »). Sans effet en mode `off`. |
| `v0.1.0` | Version initiale. **Ne pas utiliser** : contient le défaut ci-dessus. |

## Licence

MIT.
