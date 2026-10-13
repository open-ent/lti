# Open ENT — module `lti` (LTI 1.3 / LTI Advantage)

Module Vert.x qui fait d'Open ENT une **Platform LTI 1.3** ([1EdTech](https://www.1edtech.org/standards/lti)).
Un élève ou un enseignant ouvre un outil pédagogique externe (Moodle, Canvas, H5P…) depuis l'ENT
**sans nouvelle connexion** ; l'outil reçoit son identité (pseudonymisée), sa classe et son rôle.

| Spécification | Support |
|---|---|
| LTI 1.3 Core (OIDC third-party initiated login, `LtiResourceLinkRequest`) | ✅ |
| LTI Deep Linking 2.0 (`LtiDeepLinkingRequest` / `LtiDeepLinkingResponse`) | ✅ `ltiResourceLink`, `link` |
| LTI Assignment and Grade Services 2.0 (lineitems, scores, results) | ✅ |
| LTI Names and Role Provisioning Services 2.0 (memberships) | ✅ |
| 1EdTech Security Framework (RS256, JWKS, `client_credentials` + `private_key_jwt`) | ✅ |
| LTI Dynamic Registration | ⏳ jalon suivant |

Contexte et feuille de route : `docs/international/interoperabilite-1edtech.md` dans `open-ent-mods`.

## Architecture

```
fr.openent.lti
├── Lti.java                 BaseServer : schéma SQL, contrôleurs
├── LtiContext.java          configuration et dépendances partagées
├── security/                JWT RS256, JWK/JWKS, clés de la plateforme, pseudonymes (JDK uniquement)
├── core/                    logique LTI pure, testée unitairement (claims, rôles, Deep Linking, AGS, NRPS, jetons)
├── service/                 PostgreSQL (schéma lti), Neo4j (annuaire), JWKS des outils, anti-rejeu
└── controller/
    ├── PlatformController   parcours navigateur : /tools, /launch, /auth, /deeplink, /resource-links, JWKS
    ├── ServiceController    services outil → ENT : /token, /ags/…, /nrps/…
    └── AdminController      registre des outils (super admin), activation par structure (ADML)
```

Aucune dépendance ajoutée au-delà de `org.entcore:common`.

## Points d'entrée (préfixe `/lti`)

| Méthode | Chemin | Accès | Rôle |
|---|---|---|---|
| GET | `/.well-known/jwks.json` | public | Clés publiques de la plateforme |
| GET | `/.well-known/openid-configuration` | public | Configuration OIDC / LTI de la plateforme |
| GET | `/tools` | connecté | Outils activés dans les structures de l'utilisateur (widget) |
| GET | `/launch/:toolId?context=&resourceLink=` | droit `lti.launch` | Démarre le lancement (redirection vers l'outil) |
| GET | `/deeplink/:toolId?context=&target=&targetId=` | droit `lti.deeplink` | Sélection de contenu dans l'outil |
| GET/POST | `/auth` | public (hint signé) | Point d'autorisation OIDC (`id_token` en `form_post`) |
| POST | `/deeplink/return` | public (JWT de l'outil) | Retour Deep Linking, crée les liens et colonnes de notes |
| GET / DELETE | `/resource-links` | connecté | Liens rattachés à un objet ENT |
| POST | `/token` | outil (`private_key_jwt`) | Jeton d'accès AGS / NRPS |
| GET/POST | `/ags/:contextId/lineitems` | Bearer | Colonnes de notes |
| GET/PUT/DELETE | `/ags/:contextId/lineitems/:id` | Bearer | Colonne de notes |
| POST | `/ags/:contextId/lineitems/:id/scores` | Bearer `score` | Publication d'un score |
| GET | `/ags/:contextId/lineitems/:id/results` | Bearer `result.readonly` | Résultats |
| GET | `/nrps/:contextId/memberships` | Bearer `contextmembership.readonly` | Membres de la classe / du groupe |
| GET/POST/PUT/DELETE | `/admin/tools[/:id]`, `/admin/platform` | super admin | Registre des outils |
| GET/POST/DELETE | `/admin/structures/:structureId/deployments[/:id]` | ADML | Activation par établissement |

Un **contexte LTI** est une classe ou un groupe ENT. AGS et NRPS ne sont accessibles que pour les contextes
dans lesquels l'outil a effectivement été lancé.

## Sécurité et données personnelles

- `sub` = HMAC-SHA256(sel propre à l'outil, id ENT) : un élève n'est pas corrélable d'un outil à l'autre.
- Nom et e-mail transmis uniquement si l'outil a `share_name` / `share_email`.
- `lti_message_hint` signé, valable 5 min, à usage unique ; `nonce`, `jti` des assertions et des réponses
  Deep Linking à usage unique. Le cookie de session ENT (SameSite=Strict) n'étant pas transmis lors du rappel
  inter-sites de l'outil, l'utilisateur est celui du hint ; si une session est présente, elle doit correspondre.
- `redirect_uri` comparée exactement à la liste enregistrée ; seuls RS256 et les clés RSA sont acceptés.
- Jetons d'accès signés par la plateforme, typés, avec scopes ⊆ scopes autorisés pour l'outil.
- L'anti-rejeu est en mémoire de la JVM : avec plusieurs réplicas du module, activer l'affinité de session
  (ou remplacer `ReplayGuard` par une implémentation Redis).

## Notes (AGS) → carnet de notes

Les scores sont stockés dans `lti.scores`. Chaque score `FullyGraded` est publié sur le bus Vert.x
(`lti.score.published`) avec la note ramenée au barème de la colonne, pour qu'un module de notes
(ex. `competences`) puisse l'intégrer.

## Configuration

`deployment/lti/conf.json.template` (port 8170). Bloc `lti` :

| Clé | Défaut | Description |
|---|---|---|
| `issuer` | `host` | Identifiant de la plateforme (URL publique de l'ENT) |
| `platform-name` | `Open ENT` | Nom transmis aux outils |
| `private-key` | — | Clé privée RSA PKCS#8 (PEM). **Obligatoire en production** ; sinon clé éphémère (dev) |
| `kid` | `openent-lti-1` | Identifiant de la clé courante |
| `previous-public-keys` | `[]` | JWK publiques encore publiées pendant une rotation |
| `access-token-ttl-seconds` | `3600` | Durée des jetons d'accès |
| `jwks-cache-seconds` | `600` | Cache des JWKS des outils |

Générer une clé : `openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out lti-private.pem`.

Le module utilise PostgreSQL (`"sql": true`, schéma `lti`, script `src/main/resources/sql/001-lti.sql`) et Neo4j.

## Enregistrer un outil (exemple Moodle 4.x)

1. Dans Moodle : *Administration du site → Plugins → Outils externes → Gérer les plateformes* (Moodle comme outil
   LTI 1.3 publié via *Publish as LTI tool*), relever l'URL d'initiation de login, l'URL de lancement et l'URL JWKS.
2. Dans l'ENT (super admin) :

```bash
curl -X POST https://ent.example.org/lti/admin/tools -H 'Content-Type: application/json' -H "X-XSRF-TOKEN: $XSRF" \
  -b "oneSessionId=$SESSION; XSRF-TOKEN=$XSRF" -d '{
    "name": "Moodle",
    "oidc_initiation_url": "https://moodle.example.org/enrol/lti/login.php?id=…",
    "target_link_uri": "https://moodle.example.org/enrol/lti/launch.php",
    "deep_linking_url": "https://moodle.example.org/enrol/lti/launch_deeplink.php",
    "jwks_url": "https://moodle.example.org/enrol/lti/jwks.php",
    "scopes": ["https://purl.imsglobal.org/spec/lti-ags/scope/lineitem",
               "https://purl.imsglobal.org/spec/lti-ags/scope/score",
               "https://purl.imsglobal.org/spec/lti-ags/scope/result.readonly",
               "https://purl.imsglobal.org/spec/lti-nrps/scope/contextmembership.readonly"],
    "share_name": true
  }'
```

   La réponse contient le `client_id` et les URL de la plateforme à saisir dans Moodle.
3. L'ADML active l'outil pour son établissement : `POST /lti/admin/structures/{structureId}/deployments {"toolId": "…"}`.
4. Attribuer les droits `lti.launch` (et `lti.deeplink` aux enseignants) dans la gestion des accès.

## Développement

```bash
mvn -B verify          # compilation + tests unitaires (aucun ENT requis)
```

Le parent Maven est `io.edifice:app-parent:1.2.0` (identique à `fr.openent:app-parent`, publié sur le Nexus public ODE).
