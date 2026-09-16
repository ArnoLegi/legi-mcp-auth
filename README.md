# legi-mcp-auth

Authentification OAuth 2.0 (jetons Microsoft Entra ID) pour les serveurs MCP du cabinet
— `mcp-inpi`, `mcp-joafe`, `mcp-eurlex`, `mcp-distribution` — construits sur Starlette et
FastMCP.

Un serveur MCP déployé sur Internet sans authentification est une porte ouverte : qui
connaît l'URL appelle les outils. Ce paquet ferme le serveur derrière un jeton d'accès
délivré par l'annuaire Entra ID du cabinet, publie les métadonnées qui permettent au
client (Claude.ai, Claude Code) de découvrir seul le flux OAuth, et journalise qui
appelle quel outil.

La ressource protégée, au sens de la RFC 8707, est **unique** : `<MCP_PUBLIC_URL>/mcp`,
l'URL du transport. La portée publiée se bâtit sur elle, `<resource>/<portée>` — et non
sur `api://<client-id>`. Voir *[La forme de la portée](#la-forme-de-la-portée)*.

**Il ne fait rien tant qu'il n'est pas configuré.** Sans `MCP_AUTH_MODE`, le
branchement est neutre : aucun middleware, aucune route ajoutée, le serveur se comporte
exactement comme avant, avec un avertissement au démarrage. C'est voulu : le paquet peut
être installé sur les quatre serveurs bien avant que le tenant Entra ne soit prêt.

---

## Installation

```bash
pip install git+https://github.com/ArnoLegi/legi-mcp-auth@v0.3.0
```

Dans un `requirements.txt` :

```
legi-mcp-auth @ git+https://github.com/ArnoLegi/legi-mcp-auth@v0.3.0
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
| Routes | `/.well-known/oauth-protected-resource/mcp`, et la racine `/.well-known/oauth-protected-resource` qui sert **le même** document |
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
| `ENTRA_AUDIENCE` | `ENTRA_CLIENT_ID` | **À ne pas poser.** Un jeton v2.0 porte toujours le client ID en `aud` ; le défaut est donc juste. La variable ne reste que pour le jour où un manifeste émettrait une autre forme — `api://<client-id>` et la ressource canonique sont de toute façon acceptées aussi. |
| `ENTRA_SCOPE_REQUIS` | `mcp.access` | **À poser** : le nom exact de la portée déléguée exposée pour CE serveur, une portée par serveur. Le serveur ne vérifie que ce nom nu dans `scp` ; c'est en revanche lui qui, joint à la ressource, forme la portée publiée `<resource>/<portée>`. |
| `ENTRA_GROUPES_AUTORISES` | — | GUID de groupes séparés par des virgules. **À ne pas poser tant que `groupMembershipClaims` vaut `null`** dans le manifeste : sans cette revendication, aucun jeton ne porte `groups` et *tout* serait refusé. Vide = tout utilisateur du tenant porteur de la portée. |
| `MCP_PUBLIC_URL` | — | **La RACINE du service**, en HTTPS, sans barre finale et **sans `/mcp`** : le paquet ajoute lui-même le chemin du transport. Ex. `https://mcp.example.com` — et non `https://mcp.example.com/mcp`, qui produirait la ressource `https://mcp.example.com/mcp/mcp` et un refus `AADSTS9010010` d'Entra. Le paquet **refuse de démarrer** si la valeur se termine par `/mcp` ou `/sse`. **Obligatoire** en mode `entra`. |
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
MCP_PUBLIC_URL=https://mcp.example.com
MCP_ADMIN_TOKENS=<sortie de: python -c "import secrets; print(secrets.token_urlsafe(32))">
```

Ni `ENTRA_AUDIENCE` ni `ENTRA_GROUPES_AUTORISES` : les poser sans nécessité n'ajoute
aucune sécurité et fabrique deux motifs de 401 supplémentaires. Avec cette
configuration, le serveur annonce :

```
ressource : https://mcp.example.com/mcp
portée    : https://mcp.example.com/mcp/mcp.access
métadonnées : https://mcp.example.com/.well-known/oauth-protected-resource/mcp
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
4. `aud` ∈ { client ID, `api://<client-id>`, la ressource canonique } — un jeton v2.0
   porte le client ID, les deux autres formes ne sont qu'une tolérance ;
5. `exp` et `nbf`, avec **60 secondes** de tolérance d'horloge ;
6. `tid` = tenant attendu — sans ce contrôle, un jeton d'un **autre** annuaire Entra
   portant la bonne audience passerait ;
7. `scp` contient la portée requise ;
8. `groups` recoupe `ENTRA_GROUPES_AUTORISES`, si la variable est définie.

Si un utilisateur appartient à plus de ~200 groupes, Entra remplace `groups` par une
référence à Microsoft Graph : le jeton est alors refusé, avec un message explicite dans
le journal. Configurer l'application pour n'émettre que les **groupes assignés**.

Au **premier jeton accepté** de chaque processus, une ligne de contrôle est journalisée
sur `legi_mcp_auth.validation`, niveau INFO :

```
Premier jeton validé — contrôle de configuration : aud=11111111-2222-3333-4444-555555555555 scp=mcp.access ver=2.0
```

Elle porte `aud`, `scp` et `ver`, et rien d'autre — jamais le jeton, jamais `oid`, `upn`
ni `name` : elle décrit une **configuration**, pas une personne. Elle sert à constater en
préproduction, sans décoder un jeton à la main, que `aud` vaut bien le client ID (donc
que `ENTRA_AUDIENCE` n'a pas à être posée), que `ver` vaut `2.0` et que `scp` porte la
portée du serveur. Une seule ligne par processus : ces trois valeurs sont les mêmes pour
tous les jetons d'une même inscription.

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
www-authenticate: Bearer resource_metadata="https://mcp.example.com/.well-known/oauth-protected-resource/mcp", scope="https://mcp.example.com/mcp/mcp.access", error="invalid_token"
```

```json
{
  "error": "invalid_token",
  "error_description": "Jeton d'accès absent ou invalide. Ce serveur MCP exige un jeton Bearer émis par Microsoft Entra ID. Voir le document de métadonnées indiqué par l'en-tête WWW-Authenticate pour l'autorité et la portée à demander.",
  "resource_metadata": "https://mcp.example.com/.well-known/oauth-protected-resource/mcp",
  "scope": "https://mcp.example.com/mcp/mcp.access"
}
```

C'est cet en-tête qui déclenche tout : le client MCP y lit l'adresse des métadonnées, s'y
rend, y trouve l'autorité et la portée, puis mène le flux OAuth sans configuration
manuelle. Claude.ai lit **l'en-tête en priorité** : le `scope` qu'il porte et le
`scopes_supported[0]` du document sont, au caractère près, la même valeur — un test le
vérifie, car les deux ne valent que faites ensemble.

### La forme de la portée

> La portée annoncée est `<resource>/<portée>`, où `<resource>` est
> `<MCP_PUBLIC_URL>/mcp` — **pas** `api://<client-id>/<portée>`.

Un client MCP envoie à Entra un paramètre `resource` (RFC 8707) égal à l'URL canonique du
serveur, soit `<MCP_PUBLIC_URL>/mcp`, en minuscules et sans barre finale. Or Entra v2.0
exige que la portée demandée et ce `resource` désignent **la même application** : une
portée `api://<client-id>/<portée>` accompagnée d'un `resource` en `https` est refusée
par **`AADSTS9010010`**, avant même l'écran de connexion — il n'y a donc rien à voir dans
les journaux du serveur MCP, qui n'est jamais appelé.

Conséquence côté inscription d'application : la portée doit être exposée **sous la forme
`<resource>/<portée>`**, donc il faut **ajouter aux URI d'ID d'application** l'URL
`https` du serveur, `https://mcp.example.com/mcp`. Une inscription en porte plusieurs :
un par serveur MCP qu'elle sert, **plus `api://<client-id>`, l'URI par défaut, qui
reste en place**. Rien à retirer. Le document de métadonnées et le 401 annoncent alors
la portée telle qu'elle est demandable *pour cette ressource*.

`api://<client-id>` ne sert simplement plus à bâtir la portée : il **reste accepté en
`aud`**, à côté du client ID nu et de la ressource canonique.

Source : documentation Anthropic, « Troubleshooting connectors », section « Microsoft
Entra ID rejects the resource value ».

---

## Métadonnées de ressource protégée (RFC 9728)

Il n'y a **qu'une ressource**, donc **qu'un document**. Il est servi sans jeton sur
`/.well-known/oauth-protected-resource/mcp` : la RFC construit l'URL des métadonnées en
insérant `/.well-known/oauth-protected-resource` **avant** le chemin de la ressource,
d'où ce chemin pour la ressource `<serveur>/mcp`.

```json
{
  "resource": "https://mcp.example.com/mcp",
  "authorization_servers": [
    "https://login.microsoftonline.com/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee/v2.0"
  ],
  "scopes_supported": [
    "https://mcp.example.com/mcp/mcp.access"
  ],
  "bearer_methods_supported": ["header"],
  "resource_documentation": "https://mcp.example.com/health"
}
```

La racine `/.well-known/oauth-protected-resource` est conservée, mais elle sert
**exactement le même document** — `resource` y vaut `…/mcp`, pas la racine du service.
Elle n'est là que pour les clients qui sondent la racine avant d'essayer le chemin
correct : les servir tous les deux évite un 404, sans jamais annoncer deux ressources
différentes. **Aucune redirection 3xx nulle part** : les deux chemins répondent 200.

`…/oauth-protected-resource/sse` a été **retiré** en 0.3.0 : `/sse` n'était pas une
ressource distincte, et le document qu'il servait annonçait une `resource` que personne
ne demandait.

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

Cinq points, et ce sont les cinq qui font échouer une bascule quand ils manquent.

| À vérifier | Où | Valeur |
|---|---|---|
| **URI de redirection** | *Authentification* → plateforme *Web* | `https://claude.ai/api/mcp/auth_callback` — celui qu'affiche Claude.ai à la création du connecteur. Le recopier depuis l'écran, ne pas le deviner. |
| **URI d'ID d'application** | *Exposer une API* | **Ajouter** l'URL `https` de la ressource, `https://mcp.example.com/mcp`, à la liste des URI d'ID d'application. C'est ce qui permet à la portée demandée et au paramètre `resource` envoyé par le client de désigner la même application. Une inscription en porte plusieurs : `api://<client-id>`, l'URI par défaut, **reste en place** — il ne sert plus qu'à l'audience — et chaque serveur MCP servi par l'inscription ajoute la sienne, puisque chacun a sa propre URL. |
| **Portée exposée** | *Exposer une API* | Portée déléguée nommée exactement comme `ENTRA_SCOPE_REQUIS` (`mcp.access`), consentement *administrateurs et utilisateurs*. Publiée sous l'URI ci-dessus, elle se demande `https://mcp.example.com/mcp/mcp.access` — c'est cette chaîne-là que le serveur annonce dans son 401 et dans ses métadonnées. |
| **`offline_access`** | *Autorisations d'API* → Microsoft Graph, déléguée | Sans elle, pas de jeton de rafraîchissement : le connecteur redemande une authentification toutes les heures. C'est l'oubli le plus courant, et il ne se voit qu'au bout d'une heure. |
| **`accessTokenAcceptedVersion`** | *Manifeste* | `2`. À `null` (défaut), Entra émet des jetons v1.0 : `iss` vaut `https://sts.windows.net/<tenant>/`, que ce paquet refuse — il attend l'émetteur v2.0. Symptôme : 401 systématique, journal « émetteur invalide ». |

Ajouter aussi `openid` et `profile` (déléguées), et assigner les utilisateurs ou le
groupe si l'application exige une assignation.

Deux réglages à **laisser tels quels** : `groupMembershipClaims` reste à `null` tant que
`ENTRA_GROUPES_AUTORISES` n'est pas posée (les deux vont ensemble, ou aucun des deux),
et rien ne demande de poser `ENTRA_AUDIENCE` — un jeton v2.0 porte le client ID en `aud`,
et la ligne de contrôle du premier jeton validé permet de le constater.

### 2. Éprouver sur un service de préproduction

Ne pas éprouver sur un service que le cabinet utilise.

1. Dans le projet Railway, créer un **second service** déployé depuis le **même dépôt**
   que `mcp-eurlex`, même branche. Il aura sa propre URL
   (`https://<service>-<projet>.up.railway.app`) et ses propres variables.
2. Y poser `MCP_AUTH_MODE=entra`, `ENTRA_TENANT_ID`, `ENTRA_CLIENT_ID`,
   `ENTRA_SCOPE_REQUIS`, `MCP_PUBLIC_URL` = la **racine** de ce service de
   préproduction — sans `/mcp`, le paquet l'ajoute — et `MCP_ADMIN_TOKENS`, le filet de
   sécurité : il permet de tester le serveur même si la configuration Entra est fautive.
   Ni `ENTRA_AUDIENCE`, ni `ENTRA_GROUPES_AUTORISES`.
3. Vérifier à la main, dans cet ordre :
   - `GET /health` → 200 (sinon Railway déclare le déploiement en échec et redémarre) ;
   - `GET /.well-known/oauth-protected-resource/mcp` → le document attendu, avec
     `resource` = `<racine>/mcp` (une seule fois `/mcp`, jamais `/mcp/mcp`) et
     `scopes_supported[0]` = `<racine>/mcp/<portée>` ;
   - `GET /.well-known/oauth-protected-resource` → **le même document**, au caractère
     près, et un 200 direct (aucune redirection) ;
   - `POST /mcp` sans jeton → 401 portant `WWW-Authenticate`, dont le `scope` est
     **identique** à `scopes_supported[0]` ci-dessus. C'est cette valeur-là que
     Claude.ai utilisera : si les deux diffèrent, s'arrêter ici ;
   - `POST /mcp` avec le jeton administrateur → 200.
4. Créer dans Claude.ai un **connecteur de test** pointant sur ce service, avec le
   Client ID et le secret client de l'inscription. Se connecter : l'écran Microsoft
   doit apparaître, le consentement être demandé une fois.
5. **Appeler un outil** depuis une conversation, et obtenir une réponse. C'est le seul
   critère de succès : tant qu'un outil n'a pas répondu après l'écran Microsoft, la
   bascule n'est pas prête. Vérifier au passage, dans les journaux Railway, la ligne
   d'audit `utilisateur=<upn> outil=<nom>` **et** la ligne de contrôle du premier jeton
   validé : `aud` doit valoir le client ID, `ver` valoir `2.0`, et `scp` porter la
   portée du serveur. C'est le moyen le plus court de confirmer que `ENTRA_AUDIENCE`
   n'a pas à être posée.

Si l'écran Microsoft ne s'affiche jamais et que Claude.ai affiche `AADSTS9010010`, le
serveur MCP n'est pas en cause — il n'a même pas été appelé. C'est que la portée
demandée et le paramètre `resource` ne désignent pas la même application : vérifier
les URI d'ID d'application de l'inscription (étape 1) et `MCP_PUBLIC_URL`, qui ne doit
pas se terminer par `/mcp`.

Un échec ici se corrige sur la préproduction, sans que personne ne s'en aperçoive.

### 3. Basculer la production, un service à la fois

Dans l'ordre : `mcp-eurlex`, puis `mcp-inpi`, `mcp-joafe`, `mcp-distribution`. Pour
chacun, et **seulement une fois le précédent validé** :

1. Poser les variables sur le service Railway — `MCP_PUBLIC_URL` étant la **racine** de
   ce service-là, jamais celle d'un autre et jamais l'URL du connecteur (qui, elle,
   finit par `/mcp`), et `MCP_ADMIN_TOKENS` un jeton propre à ce serveur. Redéployer.
   Le serveur refuse de démarrer si `MCP_PUBLIC_URL` se termine par `/mcp` ou `/sse` :
   c'est volontaire, la ressource `…/mcp/mcp` qui en résulterait serait refusée par
   Entra.
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
| Le serveur refuse de démarrer | Mode `entra` sans `ENTRA_TENANT_ID`, `ENTRA_CLIENT_ID` ou `MCP_PUBLIC_URL` ; ou `MCP_PUBLIC_URL` se terminant par `/mcp` ou `/sse`. Volontaire : une panne visible vaut mieux qu'un serveur ouvert, ou qu'une ressource `…/mcp/mcp` qu'Entra refusera. |
| `AADSTS9010010` côté Claude.ai, **avant** tout écran de connexion | La portée demandée et le paramètre `resource` ne désignent pas la même application. Le serveur MCP n'est pas en cause : il n'a pas été appelé. Vérifier que l'URL `https` du serveur (`https://mcp.example.com/mcp`) figure bien parmi les URI d'ID d'application de l'inscription et porte la portée, et que `MCP_PUBLIC_URL` est la racine, sans `/mcp`. |
| La `resource` annoncée finit par `/mcp/mcp` | `MCP_PUBLIC_URL` porte déjà le chemin du transport. Depuis 0.3.0 le serveur refuse de démarrer dans ce cas ; avant, il servait ce document. |
| 401 systématique avec un jeton frais | Lire le journal `legi_mcp_auth.middleware` : il donne le motif exact (audience, `tid`, portée, groupe…). |
| `portée 'mcp.access' absente` | Le client demande `.default` ou une autre portée ; ou la portée n'est pas exposée dans l'inscription d'application. |
| `audience invalide` | Le client a demandé un jeton pour Graph et non pour notre API. Vérifier la portée demandée : `<MCP_PUBLIC_URL>/mcp/<portée>`. |
| Le `scope` du 401 et `scopes_supported` diffèrent | Ne devrait plus arriver : un test impose l'égalité stricte. Si cela se produit, c'est qu'une portée est construite ailleurs que par `ParametresAuth.scope_complet`. |
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

## Changements 0.3.0

Cette version change les **chaînes publiées** — la portée annoncée et l'adresse des
métadonnées. Ce n'est pas un correctif : il faut compléter l'inscription d'application
(un URI d'ID d'application à ajouter, rien à retirer) et revérifier chaque connecteur.
Motif : Entra v2.0 refuse par `AADSTS9010010` une portée `api://<client-id>/<portée>`
demandée avec un `resource` `https`, et c'est ce que le paquet publiait.

1. **Ressource canonique.** `CHEMIN_RESSOURCE = "/mcp"` et
   `ParametresAuth.resource_canonique` = `<MCP_PUBLIC_URL>/mcp`. C'est la **seule**
   ressource du serveur, **calculée** depuis la racine, jamais saisie.
2. **La portée se bâtit sur la ressource.** `scope_complet` vaut désormais
   `<resource_canonique>/<portée>` et non plus `<audience_uri>/<portée>`. `audience_uri`
   ne sert plus qu'aux audiences acceptées.
3. **Une seule portée, partout.** Le `scope` de l'en-tête `WWW-Authenticate` et le champ
   `scope` du corps du 401 sortent de cette même propriété, comme `scopes_supported`. Un
   test impose l'**égalité stricte** entre `scopes_supported[0]` et le `scope` de
   l'en-tête : Claude.ai lit l'en-tête en priorité, les deux ne valent que faites
   ensemble.
4. **Métadonnées sous le chemin de la ressource.** `url_metadonnees` vaut
   `<MCP_PUBLIC_URL>/.well-known/oauth-protected-resource/mcp` (RFC 9728 : le suffixe
   well-known s'insère avant le chemin de la ressource). La route `…/sse` et son document
   sont **supprimés**. La racine `…/oauth-protected-resource` est conservée mais sert le
   **même** document canonique, pour les seuls clients qui la sondent. Aucune
   redirection 3xx nulle part.
5. **Garde-fou au démarrage.** `MCP_PUBLIC_URL` se terminant par `/mcp` ou `/sse` fait
   lever `ConfigurationAuthInvalide` : c'est la racine du service qui est attendue, le
   paquet ajoute `/mcp` lui-même, et la valeur donnée produirait une ressource
   `…/mcp/mcp` refusée par Entra (`AADSTS9010010`).
6. **Ligne de contrôle, permanente et minimale.** Au premier jeton validé de chaque
   processus, une ligne INFO sur `legi_mcp_auth.validation` portant **uniquement** `aud`,
   `scp` et `ver` — jamais le jeton, jamais `oid`, `upn` ni `name`. Elle permet de
   constater en préproduction que `aud` vaut le client ID (donc que `ENTRA_AUDIENCE`
   n'a pas à être posée), que `ver` vaut `2.0` et que `scp` porte la portée du serveur.
7. **Audiences acceptées élargies.** `resource_canonique` s'ajoute aux candidats, après
   le client ID et `api://<client-id>`, sans en retirer aucun. Un jeton v2.0 porte le
   client ID en `aud` : c'est une tolérance, pas un changement d'attente.

Ce qu'il faut faire en reprenant une installation existante : **ajouter aux URI d'ID
d'application** de l'inscription l'URL `https` du serveur (`https://mcp.example.com/mcp`)
et y exposer la portée — `api://<client-id>` peut rester, il ne sert plus qu'à
l'audience —, vérifier que `MCP_PUBLIC_URL` est la **racine**, et reconnecter chaque
connecteur Claude.ai. Les modes `off` et
`jetons` sont inchangés — en mode `jetons`, le 401 ne porte toujours ni
`resource_metadata` ni `scope`.

## Versions

| Version | Contenu |
|---|---|
| `v0.3.0` | La portée publiée se bâtit sur la ressource (`<MCP_PUBLIC_URL>/mcp/<portée>`) et non sur `api://<client-id>`, qu'Entra refuse par `AADSTS9010010` quand le client envoie un `resource` `https`. Métadonnées déplacées sous `…/oauth-protected-resource/mcp`, route `…/sse` retirée, racine conservée servant le même document. Garde-fou au démarrage sur un `MCP_PUBLIC_URL` finissant par `/mcp` ou `/sse`. Ligne de contrôle `aud`/`scp`/`ver` au premier jeton validé. **Chaînes publiées modifiées** : reprendre l'inscription d'application et reconnecter les connecteurs. Modes `off` et `jetons` inchangés. |
| `v0.2.0` | Nouveau mode `MCP_AUTH_MODE=jetons` : les jetons d'administration seuls, sans configuration Entra ni métadonnées OAuth, pour un serveur à usage restreint ou une préproduction. Refuse de démarrer si la liste est vide ou si un jeton fait moins de 32 caractères. Aucun changement de comportement pour les modes `off` et `entra`. |
| `v0.1.1` | Correctif : une rotation de clé survenant dans les cinq minutes suivant le démarrage de la machine était bridée à tort (`time.monotonic()` part de zéro, et le sentinelle d'échec valait `0.0` — donc « échec à l'instant »). Sans effet en mode `off`. |
| `v0.1.0` | Version initiale. **Ne pas utiliser** : contient le défaut ci-dessus. |

## Licence

MIT.
