# LWS Client — Cross-Language API Contract

Status: v0.1.0 design contract for all seven clients (Java, JavaScript/TypeScript, C++, Rust, Go, Python, C#),
and for the WebAssembly component built from the Rust one (section 13).

Every client in this repository implements the **same capabilities** described here, using the
**same conceptual names**, while expressing them in the idioms of its language (naming case,
error handling, async model, iteration, builders/options). Where this document and a language's
idioms conflict, the idiom wins — but the capability, the wire behaviour, and the concept names
must stay recognisable across languages.

## 1. Specification baseline

The clients target the W3C Linked Web Storage (LWS) Working Group specifications as they stood on
**2026-10-05** (`w3c/lws-protocol` commit `ef02548`, "Switch baseline PATCH format from JSON Merge
Patch to JSON Patch (#255)"):

| Document | Status (2026-10-05) | Client coverage |
|---|---|---|
| Linked Web Storage Protocol 1.0 (`lws10-core`) | FPWD 2026-06-05, Editor's Draft 2026-10-05 | full |
| LWS Vocabulary (`lws10-vocab`) | Group Note Draft 2026-07-14 | constants |
| Authentication Suite: OpenID Connect (`lws10-authn-openid`) | WD 2026-08-03 | credential provider |
| Authentication Suite: SAML 2.0 (`lws10-authn-saml`) | WD | credential provider |
| Authentication Suite: Self-signed Identity using Controlled Identifiers (`lws10-authn-ssi-cid`) | WD 2026-04-23 | credential provider + key helpers |
| Authentication Suite: Self-signed Identity using did:key (`lws10-authn-ssi-did-key`) | Discontinued (subsumed by ssi-cid) | did:key subjects via the CID provider |
| Notification Suite: Webhooks (`lws10-notifications-webhook`) | Editor's Draft | subscribe/manage + signed-delivery verifier |
| Search and Type Index Services (`lws10-index`) | Editor's Draft | type index + type search (HTTP QUERY) |

Where the spec is silent or ambiguous, this contract records the decision (look for **Decision:**).

## 2. Shared constants

Every client exposes these values as named constants (grouped idiomatically: Java `final class`
constants, TS `const` objects, Python module constants/`StrEnum`, Rust `pub const` in modules,
Go `const` blocks, C++ `inline constexpr std::string_view` in namespaces, C# `const` members of nested
static classes).

```
# Namespaces / contexts
LWS_NS                    https://www.w3.org/ns/lws#
LWS_CONTEXT               https://www.w3.org/ns/lws/v1
CID_CONTEXT               https://www.w3.org/ns/cid/v1
ACTIVITYSTREAMS_CONTEXT   https://www.w3.org/ns/activitystreams

# Link relations
REL_STORAGE               https://www.w3.org/ns/lws#storage
REL_LINKSET               linkset
REL_UP                    up
REL_TYPE                  type
REL_FIRST / REL_NEXT / REL_PREV / REL_LAST    first / next / prev / last

# Resource types (full IRIs; short terms "Container", "DataResource", "StorageResource" are equivalent)
TYPE_CONTAINER            https://www.w3.org/ns/lws#Container
TYPE_DATA_RESOURCE        https://www.w3.org/ns/lws#DataResource
TYPE_STORAGE_RESOURCE     https://www.w3.org/ns/lws#StorageResource

# Media types
MEDIA_LWS_JSON            application/lws+json
MEDIA_LWS_CID             application/lws+cid
MEDIA_LINKSET_JSON        application/linkset+json
MEDIA_JSON_PATCH          application/json-patch+json
MEDIA_LWS_QUERY_JSON      application/lws-query+json
MEDIA_LD_JSON             application/ld+json
MEDIA_JSON                application/json
MEDIA_PROBLEM_JSON        application/problem+json
MEDIA_FORM                application/x-www-form-urlencoded

# Service types (storage description "service[].type")
SERVICE_STORAGE_ROOT      StorageRoot
SERVICE_NOTIFICATION      NotificationService
SERVICE_ACCESS_REQUEST    AccessRequestService
SERVICE_ACCESS_GRANT      AccessGrantService
SERVICE_TYPE_INDEX        TypeIndexService
SERVICE_TYPE_SEARCH       TypeSearchService
SUBSCRIPTION_WEBHOOK      WebhookSubscription

# OAuth / auth suites
GRANT_TYPE_TOKEN_EXCHANGE urn:ietf:params:oauth:grant-type:token-exchange
TOKEN_TYPE_ID_TOKEN       urn:ietf:params:oauth:token-type:id_token      (OpenID Connect suite)
TOKEN_TYPE_SAML2          urn:ietf:params:oauth:token-type:saml2         (SAML 2.0 suite)
TOKEN_TYPE_JWT            urn:ietf:params:oauth:token-type:jwt           (self-signed CID / did:key suites)
TOKEN_TYPE_ACCESS_TOKEN   urn:ietf:params:oauth:token-type:access_token
WELL_KNOWN_LWS_CONFIGURATION  /.well-known/lws-configuration
OPENID_PROVIDER_SERVICE   https://www.w3.org/ns/lws#OpenIdProvider

# Access requests / grants (ODRL-based Access Profile)
ACCESS_PROFILE            https://www.w3.org/ns/lws#AccessProfile
TYPE_ACCESS_REQUEST       AccessRequest
TYPE_ACCESS_GRANT         AccessGrant
TYPE_ACCESS_POLICY        AccessPolicy
ACTION_READ / ACTION_MODIFY / ACTION_CREATE / ACTION_DELETE        read / modify / create / delete
OPERAND_CLIENT / _FORMAT / _TYPE / _PURPOSE / _DATE_TIME           client / format / type / purpose / dateTime
OPERATOR_EQ / _IS_ANY_OF / _GTEQ / _LTEQ                           eq / isAnyOf / gteq / lteq
PUBLIC_AGENT              http://xmlns.com/foaf/0.1/Agent

# Prefer
PREFER_SET_LINKSET        set-linkset
PREFER_LINK_RELATIONS     https://www.w3.org/ns/lws#PreferLinkRelations

# Notifications
ACTIVITY_CREATE / ACTIVITY_UPDATE / ACTIVITY_DELETE                Create / Update / Delete
```

### Type matching

JSON documents use short terms (`"Container"`), compact IRIs (`"lws:Container"`) and full IRIs
(`"https://www.w3.org/ns/lws#Container"`) interchangeably. Models keep the **raw** `type` values
exactly as received (lossless round-trip) and every model with types offers a `hasType(t)`
helper (plus `isContainer()` / `isDataResource()` where relevant) that treats `Term`,
`lws:Term` and `https://www.w3.org/ns/lws#Term` as equal. A `type` that is a single string is
normalised to a one-element list.

## 3. HTTP primitives (internal but exported where useful)

All clients include small, well-tested parsers. They are exported (publicly usable) because
applications commonly need them.

### 3.1 Link header (RFC 8288)
* Parse any number of `Link` header field lines, each possibly holding several comma-separated
  link-values. Commas inside `<...>` and inside quoted strings must not split.
* Parameters: `name=token`, `name="quoted \"string\""`, and valueless `name`. Names are
  case-insensitive (lower-case them). `title*` (RFC 8187 ext-value) may be decoded when present.
* `rel` may contain several space-separated relation types — each produces a separate logical
  link. Relation types are compared case-insensitively for registered names; extension relation
  URIs are compared exactly.
* Targets are resolved against the request URL (or the `anchor` parameter if present).
* Model: `Link { href: absolute URI, rel: string, params: map<string,string> }` with helpers
  `type()` (the `type` param), `anchor()`.
* Serialisation (for request headers): `<href>; rel="rel"; name="value"` with `"` and `\` escaped.

### 3.2 WWW-Authenticate (RFC 9110 §11.6.1)
Parse all challenges, including several challenges in one field value
(`Bearer as_uri="…", realm="…", error="invalid_token", DPoP algs="ES256"`). Model:
`AuthChallenge { scheme (case-insensitive), params: map (lower-cased keys), token68?: string }`
with accessors `asUri()`, `realm()`, `error()`, `errorDescription()`.

### 3.3 Structured Fields (RFC 8941 / RFC 9651) — dictionary subset
Needed for `Signature-Input`, `Signature` and `Content-Digest`. Parse dictionaries whose members
are items or inner lists with parameters; bare items: integer, decimal, string, token, byte
sequence (`:base64:`), boolean (`?1`/`?0`). Serialise inner lists canonically
(`("a" "b");created=1;keyid="x"`) — this is how `@signature-params` is reproduced.

### 3.4 Problem details (RFC 9457)
If an error response has a `+json` body with `type`/`title`/`status`/`detail`/`instance`, parse it
into `ProblemDetails` (with extension members preserved) and attach it to the error.

### 3.5 JSON Patch (RFC 6902) and JSON Pointer (RFC 6901)
* `JsonPatch` builder: `add(path, value)`, `remove(path)`, `replace(path, value)`,
  `move(from, path)`, `copy(from, path)`, `test(path, value)`; serialises to a JSON array.
* `JsonPointer.escape(segment)` (`~` → `~0`, `/` → `~1`) and a builder from segments —
  necessary for linkset relation keys that are URIs, e.g.
  `/linkset/0/https:~1~1example.org~1rel/-`.

### 3.6 Slug (identity hint)
**Decision:** the core spec defines an optional *identity hint* input for create but does not
(yet) bind it to a header. Clients send it as the `Slug` header (RFC 5023 §9.7, the Solid
Protocol precedent). Non-ASCII and `%` characters are percent-encoded as UTF-8.

## 4. Client construction and configuration

The entry point is **`LwsClient`** (Go: `lws.Client`, Rust: `lws_client::Client`, C++:
`lws::Client`). It is immutable after construction and safe to share between threads/tasks.

Configuration (builder / options object / functional options, idiomatically):

| Option | Meaning | Default |
|---|---|---|
| HTTP engine | language-native HTTP client (injectable for testing/customisation) | native default |
| `authenticator` | pluggable `Authenticator` (see §6) | none (anonymous) |
| `userAgent` | `User-Agent` header | `lws-client-<lang>/0.1.0` |
| `defaultHeaders` | extra headers on every request | none |
| `timeout` | per-request timeout | language default / 30 s |

## 5. Operations

Names below are the canonical concept names. Languages apply their own case
(`readContainer` / `read_container` / `ReadContainer`). Every operation accepts an
optional per-call options value with at least `headers` (extra request headers) and, where
the language has a cancellation idiom (Go `context.Context`, C# `CancellationToken`, JS `AbortSignal`, Rust future
drop, Python asyncio cancellation), support for it.

URLs supplied by the caller may be relative only where the language's URL type allows it;
**every URL returned to the caller is absolute** (resolved against the response URL). This
matters: servers legitimately return relative `id`s (`"/alice/notes/"`), relative `Location`
headers and relative `Link` targets.

### 5.1 Discovery

| Operation | HTTP | Result |
|---|---|---|
| `discoverStorage(resourceUrl)` | `HEAD resourceUrl` (on 405/501 fall back to `GET`); find `Link rel="https://www.w3.org/ns/lws#storage"`; then `getStorageDescription(target)` | `StorageDescription` |
| `getStorageDescription(storageUrl)` | `GET` with `Accept: application/lws+cid, application/ld+json;q=0.9, application/json;q=0.8` | `StorageDescription` |

`StorageDescription` (a Controlled Identifier document specialisation):
* `id` (absolute URI), `types` (list), `services: List<Service>`, `capabilities: List<Capability>`,
  `verificationMethods: List<VerificationMethod>`, `authentication: List<string|VerificationMethod>`,
  raw JSON.
* `Service { id?, types, serviceEndpoint (absolute URI), raw/extra props (e.g. subscriptionType,
  conformsTo) }`; `Capability { id?, types, raw/extra props }`;
  `VerificationMethod { id, type, controller, publicKeyJwk (JSON object), raw }`.
* Helpers: `storageRoot()` (required — throw/err `ProtocolError` if missing), `service(type)`
  (first match or none), `services(type)`, `capability(type)`, `notificationService()`,
  `accessRequestService()`, `accessGrantService()`, `typeIndexService()`, `typeSearchService()`,
  `verificationMethod(idOrFragment)`.
* Validation: `type` must include `Storage`; otherwise `ProtocolError`.

### 5.2 Reading

| Operation | HTTP | Result |
|---|---|---|
| `head(url)` | `HEAD` | `ResourceMetadata` |
| `read(url, opts)` | `GET` (opts: `accept`, `range` (`bytes=` start/end), `ifNoneMatch`, `ifModifiedSince`, `prefer`) | `Resource` |
| `readContainer(url, opts)` | `GET` with `Accept: application/lws+json` | `ContainerPage` |
| `listContainer(url)` | follows `rel="next"` from `readContainer` lazily | lazy sequence of `ContainedResource` (Java `Stream`/`Iterable`, JS `AsyncIterable`, Python generator / async generator, Rust `Stream`, Go `iter.Seq2`, C++ input range, C# `IAsyncEnumerable`) |

`ResourceMetadata` (parsed response headers):
`url` (final URL), `status`, `etag` (raw, including quotes / `W/` — echo it verbatim in
`If-Match`), `lastModified`, `contentType`, `contentLength?`, `links: List<Link>`, `linkset?`
(rel=linkset), `parent?` (rel=up), `storage?` (rel=lws#storage), `types` (targets of rel=type),
`isContainer()` / `isDataResource()`, `allow: List<string>`, `acceptPatch: List<string>`,
`headers` (raw multimap), `link(rel)` / `links(rel)` helpers.

`Resource` = `ResourceMetadata` + body. Body access idiomatic: bytes, text (charset from
Content-Type, default UTF-8), JSON, and streaming where the language/HTTP stack supports it.
A `304 Not Modified` (conditional read) is **not an error**: it is returned as a result whose
`notModified` flag is true and whose body is empty. `206 Partial Content` is a normal success
(expose `Content-Range`).

`ContainerPage`: `id` (absolute), `types`, `totalItems?` (integer; MAY be approximate),
`items: List<ContainedResource>`, pagination `first? / next? / prev? / last?` (absolute URIs
from Link headers), `metadata: ResourceMetadata` (etag etc.), raw JSON.
`readContainer` accepts response content types `application/lws+json`, `application/ld+json`,
`application/json` (ignore parameters); anything else → `ProtocolError`. If the response's
rel=type links / body `type` show it is not a `Container`, → `ProtocolError`.

`ContainedResource`: `id` (absolute), `types`, `format?` (media type; MUST for DataResources),
`size?` (bytes), `modified?` (date-time; keep raw string too; an unparseable date MUST NOT fail
the listing), `isContainer()`, `isDataResource()`, `hasType(t)`, raw JSON.

### 5.3 Creating

| Operation | HTTP | Result |
|---|---|---|
| `create(containerUrl, body, contentType, opts)` | `POST containerUrl`, `Content-Type`, optional `Slug`, optional user `Link` headers (opts: `slug`, `links: List<Link>`, `types: List<URI>` → extra `Link: <t>; rel="type"`) | `CreateResult` |
| `createContainer(parentUrl, opts)` | `POST parentUrl` with `Link: <https://www.w3.org/ns/lws#Container>; rel="type"`, empty body (`Content-Length: 0`), optional `Slug`/links | `CreateResult` |

`CreateResult`: `location` (absolute; `201` without `Location` → `ProtocolError`),
`metadata: ResourceMetadata` (links from the 201: linkset, up, type), optional body.
Dynamic languages also provide convenience `createJson(containerUrl, value, opts)` /
`createText(...)` where idiomatic.

POST is **not** idempotent: never auto-retry a POST except for the single authentication retry
in §6 (which happens only after a `401`, i.e. when nothing was created).

### 5.4 Updating

| Operation | HTTP | Result |
|---|---|---|
| `update(url, body, contentType, opts)` | `PUT` full replacement (opts: `ifMatch`, `ifNoneMatch`, `links`, `setLinkset` → adds `Prefer: set-linkset` and sends `links` as `Link` headers) | `UpdateResult` |
| `patch(url, patch, opts)` | `PATCH`; `patch` is a `JsonPatch` (`Content-Type: application/json-patch+json`) **or** raw bytes + explicit content type (e.g. `application/sparql-update` when advertised in `Accept-Patch`) (opts: `ifMatch`, `links` + `setLinkset`) | `UpdateResult` |

`UpdateResult`: `status` (200/204), `etag?`, `metadata`, optional body.
**Decision:** the baseline patch format is JSON Patch (RFC 6902) — the 2026-10-05 change; JSON
Merge Patch is not a baseline format.

### 5.5 Deleting

| Operation | HTTP | Result |
|---|---|---|
| `delete(url, opts)` | `DELETE` (opts: `ifMatch`, `recursive` → `Depth: infinity`) | nothing (204) |

A non-empty container without `recursive` yields `409` → `ConflictError`.

### 5.6 Metadata (linksets, RFC 9264)

| Operation | HTTP | Result |
|---|---|---|
| `linksetUrl(resourceUrl)` | `HEAD`, rel=linkset | absolute URI (→ `ProtocolError` if absent) |
| `readLinkset(resourceUrl)` | discover via `HEAD`, then `GET linkset` with `Accept: application/linkset+json` | `LinksetDocument` |
| `updateLinkset(linksetUrl, linkset, opts{ifMatch})` | `PUT` `application/linkset+json` (only works if `Allow` lists PUT; otherwise surfaces `405`) | `UpdateResult` |
| `patchLinkset(linksetUrl, JsonPatch, opts{ifMatch})` | `PATCH` `application/json-patch+json` | `UpdateResult` |

`Linkset` model (`application/linkset+json`):
`{"linkset":[{"anchor":"…","<rel>":[{"href":"…","type":"…","title":"…", …}]}]}`
* `Linkset { contexts: List<LinkContext> }`, `LinkContext { anchor, relations: ordered map rel →
  List<LinkTarget{ href, attributes: map<string, JSON> }> }`.
* Helpers: `links()` (flattened `Link`s), `targets(rel)` / `targets(anchor, rel)`, mutating or
  copy-on-write builders `add(anchor, rel, href, attrs)`, `remove(anchor, rel, href?)`, JSON
  round-trip that preserves unknown members.
* `LinksetDocument { url (of the linkset resource), etag, linkset, allow, acceptPatch }`.

## 6. Authentication & authorization (OAuth 2.0 token exchange)

### 6.1 Pluggable `Authenticator`

```
Authenticator
  authorize(request)                         // before sending: may add Authorization
  handleChallenge(request, response) -> bool // on 401: obtain credentials; true = retry once
```
Provided implementations:
* `BearerTokenAuthenticator(token | tokenSupplier)` — send a known access token.
* `TokenExchangeAuthenticator(credentialProvider, options)` — the LWS flow below.
Users may implement their own (cookies, DPoP, mTLS…).

### 6.2 LWS flow (`TokenExchangeAuthenticator`)

1. A request returns `401` with `WWW-Authenticate: Bearer as_uri="…", realm="…"`.
   Pick the first `Bearer` challenge that has both `as_uri` and `realm`. If none → surface
   `UnauthorizedError` (with parsed challenges).
2. **Realm check (client MUST):** the request URL must be logically contained in `realm`: same
   scheme, host and port, and the request path equals the realm path or starts with the realm
   path (treated as a directory, i.e. ending in `/`). Otherwise → `AuthenticationError`.
   **Decision:** a challenge that fails this check (or steps 3–4) is not acted on at all. In particular
   a cached token the request carried is **not** dropped: a storage can hold a resource whose 401 names
   a realm that does not contain it (Touchstone's decoy), and believing it would cost the client a valid
   token.
3. **Transport security:** `as_uri` and the token endpoint MUST be `https`, except loopback hosts
   (`localhost`, `127.0.0.1`, `[::1]`) or when the option `allowInsecureHttp` is enabled.
4. Optional policy: `authorizationServerFilter(asUri, realm) -> bool` (default: allow). If it
   rejects → `AuthenticationError`. (Security note: a malicious storage can name any AS; tokens
   minted by the self-signed provider are audience-bound to that AS, but static OpenID/SAML
   tokens may not be — use the filter or audience-restricted tokens.)
5. **Metadata and token requests never follow a redirect**; a `3xx` there is an `AuthenticationError`.
   A `307`/`308` would carry the subject token, a credential, on to wherever it points, past step 3.
   Fetch AS metadata (RFC 8414 §3.1): for issuer `https://as.example` →
   `https://as.example/.well-known/lws-configuration`; for an issuer with a path
   `https://as.example/t1` → `https://as.example/.well-known/lws-configuration/t1`.
   The returned `issuer` MUST equal `as_uri` (ignoring one trailing `/`) else
   `AuthenticationError`. Cache metadata per issuer.
6. Ask the `CredentialProvider` for a subject token for this AS
   (`context: { issuer, realm, metadata }`). If metadata has `subject_token_types_supported`
   and it does not contain the provider's token type → `AuthenticationError`.
7. `POST token_endpoint` (`application/x-www-form-urlencoded`):
   `grant_type=urn:ietf:params:oauth:grant-type:token-exchange`, `resource=<realm>`,
   `subject_token=<token>`, `subject_token_type=<type>`.
   Error responses (RFC 6749 §5.2 `{"error": …}`) → `AuthenticationError` carrying `error`,
   `error_description`.
8. Response: `access_token`, `token_type` (must be `Bearer`, case-insensitive),
   `expires_in?`. Expiry = `expires_in`, else the access token's JWT `exp` (decode payload
   without verifying), else 300 s. Cache per `(issuer, realm)`; refresh 30 s before expiry.
9. Retry the original request **once** with `Authorization: Bearer <token>`.
10. Proactive auth: subsequent requests to URLs inside a cached realm send the cached token
    immediately. If such a request still gets `401` (e.g. `error="invalid_token"`), drop the
    cached token and run steps 1–9 once.
11. Never send a token to a URL outside its realm (also on redirects).
12. Concurrency: concurrent requests should share one in-flight exchange where practical;
    the token cache must be thread/task-safe.
13. Bodies: the auth retry requires a replayable body. Byte/string bodies are always
    replayable. For streaming bodies, if no token is cached the client may first issue `HEAD`
    on the target (or its container for POST) to establish a token; otherwise surface the 401.

### 6.3 `CredentialProvider` (authentication suites)

```
CredentialProvider
  tokenType: string
  getSubjectToken(context{issuer, realm, metadata}) -> string   (may be async)
```
* **`OpenIdCredentials`** (`lws10-authn-openid`): wraps an ID token or a supplier/callback that
  returns a fresh ID token (interactive OIDC login is out of scope — apps use their OIDC
  library). Token type `…:id_token`.
* **`SamlCredentials`** (`lws10-authn-saml`): wraps a SAML 2.0 assertion supplier. Token type
  `…:saml2`. The token is the **base64url-encoded** assertion (RFC 8693 §3); a helper encodes
  raw XML.
* **`SelfSignedCredentials`** (`lws10-authn-ssi-cid`, and did:key subjects): signs a JWT per
  request (cached until 60 s before expiry, per audience):
  * header: `{"alg": "<ES256|EdDSA>", "typ": "JWT", "kid": "<kid>"}`
  * claims: `sub = iss = client_id = <agent URI>`, `aud = [<AS issuer>]`, `iat = now`,
    `exp = now + lifetime` (default 300 s), `jti = random UUID`.
  * Algorithms: **ES256 (P-256) required**, **EdDSA (Ed25519) required where the platform
    provides it** (all seven do, via the chosen crypto stacks; C# takes Ed25519 from BouncyCastle, as
    .NET 10 has none). ECDSA signatures are JOSE raw
    `r‖s` (64 bytes), never DER.
  * Factories: `forAgent(agentUri, privateKey, kid)` (HTTPS/DID agent whose CID document lists
    the key) and `didKey(privateKey)` (derives the `did:key` identifier and
    `kid = did:key:z…#z…` automatically).
  * Key helpers: generate a P-256 / Ed25519 key pair; import/export JWK (public and private);
    `didKeyFromPublicKey(publicKey)`; `controlledIdentifierDocument(agentUri, publicJwk, kid)`
    producing the CID JSON (`@context` CID v1, `id`, `authentication: [{id: agent#kid, type:
    "JsonWebKey", controller: agent, publicKeyJwk}]`) that the agent must publish.
  * did:key encoding: multibase base58btc (`z` prefix) of multicodec varint prefix + public
    key. P-256: prefix `0x80 0x24` (p256-pub, 0x1200) + 33-byte compressed point → `zDn…`.
    Ed25519: prefix `0xed 0x01` + 32-byte key → `z6Mk…`.

## 7. Notifications

| Operation | HTTP | Result |
|---|---|---|
| `subscribe(serviceUrl, WebhookSubscriptionRequest{topics, inbox, expires?})` | `POST` `application/lws+json` body `{"@context":["https://www.w3.org/ns/lws/v1"],"type":"WebhookSubscription","topic":[…],"inbox":"…","expires":"…"}` | `Subscription { type, subscription (absolute URL; fall back to Location), expires?, raw }` (accept 200 or 201) |
| `listSubscriptions(serviceUrl)` | container listing of the endpoint | lazy sequence of `ContainedResource` |
| `getSubscription(url)` | `GET` | `Subscription` (raw JSON preserved) |
| `unsubscribe(url)` | `DELETE` | nothing |

The subscription `serviceUrl` normally comes from `storageDescription.notificationService()`;
clients should check that `subscriptionType` includes `WebhookSubscription` and raise
`UnsupportedError`/`ProtocolError` if not.

**Notification model**: `parseNotification(bytes|string|json) -> Notification`
`Notification { storage, activities: List<Activity>, raw }` (`activity` may be an object or an
array — always expose a list). `Activity { id, types, object: {id, types}, actor?, target?,
origin?, published (date-time + raw), raw }` with `isCreate()/isUpdate()/isDelete()`.
`type` must be `Notification`, else `ProtocolError`.

### 7.1 `WebhookVerifier` (RFC 9421 HTTP Message Signatures + RFC 9530 Content-Digest)

Input: method, full target URL (the **registered inbox URL**, configurable so it works behind
proxies), headers, raw body bytes. Options: `clock` (now), `maxAge` / `clockSkew` (default
300 s), `trustedStorages` (optional allow-list), an `LwsClient` (or fetcher) for retrieving
storage descriptions, key cache TTL (default 10 min).

Algorithm:
1. `Content-Digest` must be present; parse as SF dictionary; recognise `sha-256` and
   `sha-512`; at least one recognised algorithm must be present and **every** recognised one
   must match the body. Otherwise → `SignatureVerificationError`.
2. Parse `Signature-Input` and `Signature` (SF dictionaries). Choose the first label present in
   both whose params include `keyid`.
3. The covered components MUST include `@method`, `@scheme`, `@authority`, `@path`,
   `content-type`, `content-digest`; params MUST include `created` (integer) and `keyid`
   (string). Component identifiers with parameters (`;sf`, `;key`, `;req`, …) → unsupported →
   error. If `expires` is present it must not be in the past. `created` must be within
   `[now - maxAge, now + clockSkew]`.
4. `keyid` MUST be a URL with a fragment. Storage identifier = keyid without fragment. If
   `trustedStorages` is set, the storage identifier must be in it, compared as URLs (scheme and host
   case-insensitively, default ports dropped). An empty list trusts no storage.
5. Fetch the storage description (cache). Its `id` MUST equal the storage identifier.
6. Find the `verificationMethod` whose `id` equals the full keyid, or equals the fragment
   (`#frag` or `frag`), or resolves (relative to the storage id) to the keyid. It MUST be
   referenced from `authentication` (string reference resolved the same way, or embedded
   object with the same id). Use `publicKeyJwk`.
7. Build the signature base (RFC 9421 §2.5): one line per covered component
   `"<name>": <value>` (`@method` uppercased; `@scheme` lower-case; `@authority` lower-case
   host plus `:port` only if non-default; `@path` absolute path, empty → `/`; `@target-uri`,
   `@query` supported too; header fields: all values of that field joined with `, `,
   leading/trailing whitespace trimmed), followed by the final line
   `"@signature-params": <canonical serialisation of the inner list with its params>`.
   Lines are joined with `\n` (no trailing newline).
8. Verify: JWK `EC`/`P-256` → `ecdsa-p256-sha256` (raw `r‖s`); `OKP`/`Ed25519` → `ed25519`;
   `EC`/`P-384` → `ecdsa-p384-sha384` (optional). If the `alg` signature parameter is present
   it must match the key type. On failure with a cached key, refetch the description once
   (key rotation) and retry.
9. Parse the body as a `Notification`; its `storage` MUST equal the storage identifier.
10. Return the verified `Notification` (plus the `keyid` / storage used).

Languages with a natural server abstraction add adapters (Node `Request`/`IncomingMessage`,
Go `http.Handler` middleware, Python ASGI/WSGI-friendly function, Java `HttpExchange`, Rust
`http::Request`).

## 8. Access requests and grants

Models (JSON-LD `application/lws+json`, `@context: ["https://www.w3.org/ns/lws/v1"]`):
* `AccessRequest { types (incl. "AccessRequest"), storage, inbox?, access: List<AccessPolicy>, raw }`
* `AccessGrant { types (incl. "AccessGrant"), storage, inbox?, access: List<AccessPolicy>, raw }`
* `AccessPolicy { types (incl. "AccessPolicy"), actions: List<string>, assignee, target?:
  AccessTarget{type, values}, constraints: List<Constraint>}`
* `Constraint { leftOperand, operator, rightOperand: JSON (string | array | …) }` with
  convenience factories `purpose(uri)`, `purposeAnyOf(uris)`, `client(uri)`,
  `format(mediaType)`, `formatAnyOf(types)`, `type(uri)`, `typeAnyOf(uris)`,
  `notBefore(dateTime)` (`dateTime gteq`), `notAfter(dateTime)` (`dateTime lteq`).
* Builders validate required fields (`storage`, ≥1 `access`, ≥1 action, `assignee`).

| Operation | HTTP | Result |
|---|---|---|
| `requestAccess(serviceUrl, AccessRequest)` | `POST` `application/lws+json` | URI of the created request (`Location`) |
| `listAccessRequests(serviceUrl)` | container listing | lazy sequence of `ContainedResource` |
| `getAccessRequest(url)` | `GET` | `AccessRequest` |
| `cancelAccessRequest(url)` | `DELETE` | nothing |
| `grantAccess(serviceUrl, AccessGrant)` | `POST` | URI of the grant |
| `listAccessGrants(serviceUrl)` | container listing | lazy sequence |
| `getAccessGrant(url)` | `GET` | `AccessGrant` |
| `revokeAccessGrant(url)` | `DELETE` | nothing |

## 9. Type Index and Type Search services

| Operation | HTTP | Result |
|---|---|---|
| `readTypeIndex(serviceUrl or pageUrl)` | `GET`, `Accept: application/lws+json` | `TypeIndexPage { totalItems?, types: List<string>, first/next/prev/last }` |
| `listTypes(serviceUrl)` | follows `next` | lazy sequence of type IRIs |
| `searchTypes(serviceUrl, TypeQuery)` | **`QUERY`** (RFC 10008) with `Content-Type: application/lws-query+json`, `Accept: application/lws+json`; body is the filter JSON | `SearchPage` (= `ContainerPage` shape, `type: "ContainerPage"`, items carry at least `id`/`type`; `id` is the page's own URL when the body has none) |
| `searchAll(serviceUrl, TypeQuery)` | `QUERY` first page, then `GET` each opaque `next` link | lazy sequence of `ContainedResource` |
| `acceptedQueryFormats(serviceUrl)` | `OPTIONS`; parse `Accept-Query` (and `Allow`) | list of media types |

`TypeQuery` builder — conjunctive normal form:
* `allOf(t1, t2, …)` → each IRI becomes its own AND group: `"type": ["t1", "t2"]`
* `anyOf(t1, t2, …)` → one OR group: `"type": [["t1", "t2"]]`
* `relation(rel).allOf(...)` / `.anyOf(...)` for indexed descriptive relations (same grammar
  under key `rel`).
* Serialisation: plain JSON (no `@context`). A single-IRI OR group may be serialised as a plain
  string. Client-side validation mirrors server `400` rules: every value must be an absolute
  IRI (has a scheme), and no OR group may be empty. An empty query (`{}`) matches everything.
* A pagination link that has expired → `404`/`410` → `NotFoundError`/`GoneError`; callers
  restart the search.

## 10. Errors

A single hierarchy (or enum / sentinel set) mapping the LWS abstract responses:

| Error | When | LWS abstract response |
|---|---|---|
| `LwsError` (base) | everything below | |
| `HttpError(status, method, url, headers, problem?: ProblemDetails, body text (truncated))` | any non-success status | |
| ├ `BadRequestError` | 400 | |
| ├ `UnauthorizedError` (+ `challenges`) | 401 (after auth handling) | unknown requester |
| ├ `ForbiddenError` | 403 | not permitted |
| ├ `NotFoundError` | 404 | target not found |
| ├ `MethodNotAllowedError` (+ `allow`) | 405 | |
| ├ `NotAcceptableError` | 406 | |
| ├ `ConflictError` | 409 | conflict |
| ├ `GoneError` | 410 | |
| ├ `PreconditionFailedError` | 412 | |
| ├ `UnsupportedMediaTypeError` (+ `acceptPatch`, `acceptQuery`) | 415 | |
| ├ `UnprocessableContentError` | 422 | |
| ├ `NotImplementedError` | 501 | |
| └ `InsufficientStorageError` | 507 | quota exceeded |
| `AuthenticationError` (+ OAuth `error`, `errorDescription`) | token exchange / realm / metadata failures | |
| `ProtocolError` | server response violates the spec (missing Location, wrong media type, bad JSON) | |
| `SignatureVerificationError` | webhook verification failures | |

Other statuses map to the generic `HttpError` (5xx → "unknown error"). Transport errors use the
language's natural mechanism (wrapped in `LwsError` where that is idiomatic).
Language mapping: Java unchecked exceptions; TypeScript `Error` subclasses with `status`;
Python exception classes; Rust `enum Error` + `status()` + `is_not_found()`-style helpers;
Go `*HTTPError` + sentinels usable with `errors.Is` (`ErrNotFound`, `ErrConflict`, …) and
`errors.As`; C++ exception classes deriving from `lws::Error : std::runtime_error`; C# exceptions
deriving from `Ebremer.Lws.LwsException` (the 501 one is `HttpNotImplementedException`, so as not to clash
with `System.NotImplementedException`); the WebAssembly component one `error` record whose `error-kind`
names the class (`not-found`, `precondition-failed`, …, `authentication`, `protocol`, `transport`).

## 11. Testing requirements (all languages)

1. Unit tests for every parser (Link, WWW-Authenticate, SF dictionaries, problem details,
   container/storage/notification/linkset/access models, JSON Patch/Pointer, TypeQuery).
2. Tests that load the shared fixtures in `conformance/fixtures/` (see its README) — the same
   inputs and expected outputs for every language, including the RFC 9421 webhook vectors and
   did:key vectors.
3. In-process HTTP tests (mock transport or local server) for every operation, including the
   full `401 → metadata → token exchange → retry` flow, proactive token reuse, realm-check
   rejection, pagination across ≥3 pages, conditional requests (304, 412), and error mapping.
4. An interop test/example that runs the full scenario in `conformance/scenario.md` against the
   mock server in `testing/mock-server/` when `LWS_TEST_SERVER` is set (skipped otherwise).

## 12. Package identity

| Language | Package | Namespace / module | Min. runtime |
|---|---|---|---|
| Java | `com.ebremer:lws-client:0.1.0` (Maven) | `com.ebremer.lws` (JPMS module `com.ebremer.lws`) | Java 17 |
| JavaScript/TypeScript | `lws-client` (npm, ESM, typed) | `import { LwsClient } from "lws-client"` | Node 20+, modern browsers, Deno, Bun |
| C++ | CMake package `lws-client`, target `lws::client` | `namespace lws` | C++20 |
| Rust | crate `lws-client` | `lws_client` | Rust 1.85 (edition 2024) |
| Go | `github.com/ebremer/lws-client/go` | package `lws` | Go 1.23 |
| Python | `lws-client` (PyPI) | `import lws_client` | Python 3.10 |
| C# | `Ebremer.Lws.Client` (NuGet) | `namespace Ebremer.Lws` | .NET 10 |
| WebAssembly | `lws_client.wasm`, a WASI 0.2 component | WIT package `ebremer:lws@0.1.0`, world `lws-client` | a component host with `wasi:http` |

All code is MIT licensed; every package manifest declares `MIT` and every source tree points to
the repository root `LICENSE`.

## 13. The WebAssembly component

`wasm/` builds the Rust client for `wasm32-wasip2` into a WASI 0.2 component, so that one client serves
every language that can host components (Wasmtime embeddings, jco for JavaScript). It is the Rust
client, not a port: its behaviour on the wire is the Rust client's, and a change to the Rust client
reaches it by rebuilding. Its interface, [`wasm/wit/lws.wit`](../wasm/wit/lws.wit), follows this
contract:

- **Transport.** On WASI the crate sends requests through the host's `wasi:http/outgoing-handler`
  instead of reqwest (`rust/src/transport/`). The host does TLS and may refuse destinations. `wasi:http`
  follows no redirects, so the client's own redirect handling (re-authorizing every hop, never
  following one from an authorization server) applies unchanged. Request bodies are bytes.
- **Names.** The operations keep the concept names in kebab-case (`discover-storage`,
  `read-container`, `patch-linkset`, `search-all`, …) as functions of the `client` resource, built with
  `client.new(options)`; `options.auth` selects the authenticator of section 6 (`none`, `bearer`,
  `openid`, `saml`, `self-signed`, `did-key`).
- **Values.** URLs are strings, absolute in every result. Typed records carry the results of section 5
  (`metadata`, `read-result`, `page`, `item`, `created`, `updated`, `storage-description`, `subscription`).
  JSON-LD documents (storage descriptions in `raw`, access requests and grants, linksets, notifications)
  cross as JSON text, parsed and checked by the Rust models on the way in. JSON Patch is a list of
  typed `patch-operation`s, a type query a typed `type-query`, both rebuilt with the Rust builders.
- **Lazy sequences** are resources (`items`, `type-iris`) whose `next` fetches pages as needed.
- **Calls are synchronous.** WASI 0.2 exports are; a call blocks until `wasi:http` has the answer.
- **Credentials from the host.** An `openid` or `saml` client takes a fixed subject token, or asks the
  imported `token-source.subject-token` for each exchange (section 6.3's supplier/callback).
- **Webhooks.** The `webhook.verifier` resource is section 7.1's `WebhookVerifier`, fetching storage
  descriptions with a given client.

