# LWS Client — Cross-Language API Contract

Status: v0.1.0 design contract for all ten clients (Java, JavaScript/TypeScript, C++, Rust, Go, Python, C#, Swift, PHP, Kotlin),
and for the WebAssembly component built from the Rust one (section 13).

Every client in this repository implements the **same capabilities** described here, using the
**same conceptual names**, while expressing them in the idioms of its language (naming case,
error handling, async model, iteration, builders/options). Where this document and a language's
idioms conflict, the idiom wins — but the capability, the wire behaviour, and the concept names
must stay recognisable across languages.

## 1. Specification baseline

The clients target the W3C Linked Web Storage (LWS) Working Group specifications as they stood on
**2026-10-19** (`w3c/lws-protocol` commit `9a08ff6`, "Define how resources move between containers
(#237)", published as the Working Draft of 19 October 2026). Since the previous baseline (2026-10-05,
`ef02548`) three changes reach the clients: a `401` now leads to the authorization server through
OAuth 2.0 Protected Resource Metadata (RFC 9728, #256), with three checks a client must make before it
asks for a token (section 6.2); only `application/lws+json` is a required container media type (#253,
section 5.2); and resources move between containers by a change of their `up` link (#237, sections
5.1, 5.7 and 7).

| Document | Status (2026-10-19) | Client coverage |
|---|---|---|
| Linked Web Storage Protocol 1.0 (`lws10-core`) | WD 2026-10-19 | full |
| LWS Vocabulary (`lws10-vocab`) | Group Note Draft (vocabulary of 2026-10-19) | constants |
| Authentication Suite: OpenID Connect (`lws10-authn-openid`) | WD 2026-10-15 | credential provider |
| Authentication Suite: SAML 2.0 (`lws10-authn-saml`) | WD 2026-10-15 | credential provider |
| Authentication Suite: Self-signed Identity using Controlled Identifiers (`lws10-authn-ssi-cid`) | WD 2026-10-15 | credential provider + key helpers |
| Authentication Suite: Self-signed Identity using did:key (`lws10-authn-ssi-did-key`) | Discontinued (subsumed by ssi-cid) | did:key subjects via the CID provider |
| Notification Suite: Webhooks (`lws10-notifications-webhook`) | Editor's Draft | subscribe/manage + signed-delivery verifier |
| Search and Type Index Services (`lws10-index`) | Editor's Draft | type index + type search (HTTP QUERY) |

Where the spec is silent or ambiguous, this contract records the decision (look for **Decision:**).

## 2. Shared constants

Every client exposes these values as named constants (grouped idiomatically: Java `final class`
constants, TS `const` objects, Python module constants/`StrEnum`, Rust `pub const` in modules,
Go `const` blocks, C++ `inline constexpr std::string_view` in namespaces, C# `const` members of nested
static classes, Swift `static let` members of caseless enums such as `LinkRelation`, `MediaType`, `ResourceType`, PHP class
constants of final classes of the same names, `MediaType::LWS_JSON`, Kotlin `const val` members of objects of the same
names, `MediaType.LWS_JSON`).

```
# Namespaces / contexts
LWS_NS                    https://www.w3.org/ns/lws#
LWS_CONTEXT               https://www.w3.org/ns/lws/v1
LWS_PROFILE               https://www.w3.org/ns/lws/v1        (the "LWS profile": media type parameter profile="…")
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

# Capability types (storage description "capability[].type")
CAPABILITY_MOVE_RESOURCE  MoveResource

# OAuth / auth suites
GRANT_TYPE_TOKEN_EXCHANGE urn:ietf:params:oauth:grant-type:token-exchange
TOKEN_TYPE_ID_TOKEN       urn:ietf:params:oauth:token-type:id_token      (OpenID Connect suite)
TOKEN_TYPE_SAML2          urn:ietf:params:oauth:token-type:saml2         (SAML 2.0 suite)
TOKEN_TYPE_JWT            urn:ietf:params:oauth:token-type:jwt           (self-signed CID / did:key suites)
TOKEN_TYPE_ACCESS_TOKEN   urn:ietf:params:oauth:token-type:access_token
WELL_KNOWN_LWS_CONFIGURATION  /.well-known/lws-configuration
WELL_KNOWN_OAUTH_PROTECTED_RESOURCE  /.well-known/oauth-protected-resource     (RFC 9728)
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
ACTIVITY_CREATE / ACTIVITY_UPDATE / ACTIVITY_DELETE / ACTIVITY_MOVE    Create / Update / Delete / Move
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
(`Bearer resource_metadata="…", error="invalid_token", DPoP algs="ES256"`). Model:
`AuthChallenge { scheme (case-insensitive), params: map (lower-cased keys), token68?: string }`
with accessors `resourceMetadata()`, `error()`, `errorDescription()`, and `asUri()`, `realm()` for
the challenge of the drafts before 19 October 2026.

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
* Optional: `apply(document)` applies the patch atomically (RFC 6902 §4, §5), returning the patched
  copy or failing as a whole. The PHP client has it, for servers; the cases are
  `conformance/fixtures/json-patch-apply.json`.
* `JsonPointer.escape(segment)` (`~` → `~0`, `/` → `~1`) and a builder from segments —
  necessary for linkset relation keys that are URIs, e.g.
  `/linkset/0/https:~1~1example.org~1rel/-`.

### 3.6 Slug (identity hint)
**Decision:** the core spec defines an optional *identity hint* input for create but does not
(yet) bind it to a header. Clients send it as the `Slug` header (RFC 5023 §9.7, the Solid
Protocol precedent). Non-ASCII and `%` characters are percent-encoded as UTF-8.

## 4. Client construction and configuration

The entry point is **`LwsClient`** (Go: `lws.Client`, Rust: `lws_client::Client`, C++:
`lws::Client`, Swift: `LWSClient`, after the Swift API Design Guidelines' upper-case acronyms, PHP: `Ebremer\Lws\LwsClient`, Kotlin: `com.ebremer.lws.kotlin.LwsClient`, built with named arguments). It is immutable after construction and safe to share between threads/tasks.

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
drop, Python asyncio cancellation, Swift task cancellation), support for it. PHP calls are synchronous; each
takes its options as named arguments (`slug:`, `ifMatch:`, `headers:`, `timeout:`). Kotlin operations are `suspend`
functions, cancelled with their coroutine, with the options as named arguments (`slug =`, `ifMatch =`, `headers =`,
`timeout =`).

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
  `verificationMethod(idOrFragment)`, `moveCapability()`.
* Validation: `type` must include `Storage`; otherwise `ProtocolError`.

`moveCapability()` is the storage's `MoveResource` capability (lws10-core "Storage Description
Capabilities"), or none when it describes none: then the `up` link is not modifiable, and a client
MUST NOT assume it is. `MoveCapability { appliesTo: List<string>, preservesIdentifier?: bool, raw }`:
`appliesTo` is the property's values as received (a single string normalised to a list), and
`["DataResource"]` when the property is absent, which lws10-core makes mean data resources only;
`preservesIdentifier` is absent when the property is, and then a client MUST NOT assume identifiers
are kept. Helpers `movesDataResources()` and `movesContainers()` match `appliesTo` as in Type
matching (section 2). The cases are `conformance/fixtures/responses/storage-description.json`.

### 5.2 Reading

| Operation | HTTP | Result |
|---|---|---|
| `head(url)` | `HEAD` | `ResourceMetadata` |
| `read(url, opts)` | `GET` (opts: `accept`, `range` (`bytes=` start/end), `ifNoneMatch`, `ifModifiedSince`, `prefer`) | `Resource` |
| `readContainer(url, opts)` | `GET` with `Accept: application/lws+json` | `ContainerPage` |
| `listContainer(url)` | follows `rel="next"` from `readContainer` lazily | lazy sequence of `ContainedResource` (Java `Stream`/`Iterable`, JS `AsyncIterable`, Python generator / async generator, Rust `Stream`, Go `iter.Seq2`, C++ input range, C# `IAsyncEnumerable`, Swift `AsyncSequence`, PHP `IteratorAggregate` for `foreach`, Kotlin cold `Flow`) |

`ResourceMetadata` (parsed response headers):
`url` (final URL), `status`, `etag` (raw, including quotes / `W/` — echo it verbatim in
`If-Match`), `lastModified`, `contentType`, `contentLength?`, `links: List<Link>`, `linkset?`
(rel=linkset), `parent?` (rel=up), `storage?` (rel=lws#storage), `types` (targets of rel=type),
`isContainer()` / `isDataResource()`, `allow: List<string>`, `acceptPatch: List<string>`,
`headers` (raw multimap), `link(rel)` / `links(rel)` helpers.

`Resource` = `ResourceMetadata` + body (PHP: `ReadResult`, since `resource` is a reserved word there). Body access idiomatic: bytes, text (charset from
Content-Type, default UTF-8), JSON, and streaming where the language/HTTP stack supports it.
A `304 Not Modified` (conditional read) is **not an error**: it is returned as a result whose
`notModified` flag is true and whose body is empty. `206 Partial Content` is a normal success
(expose `Content-Range`).

`ContainerPage`: `id` (absolute), `types`, `totalItems?` (integer; MAY be approximate),
`items: List<ContainedResource>`, pagination `first? / next? / prev? / last?` (absolute URIs
from Link headers), `metadata: ResourceMetadata` (etag etc.), raw JSON.
`readContainer` asks for `application/lws+json`, the one container media type lws10-core requires a
server to honour (#253). It accepts response content types `application/lws+json`,
`application/ld+json` and `application/json` (ignore parameters), reading each as an
`application/lws+json` document; anything else → `ProtocolError`.
**Decision:** the drafts no longer make `application/ld+json` and `application/json` equivalent to
`application/lws+json`, and only an `application/lws+json` response is a container representation;
the clients keep reading the other two as one, a leniency towards servers of earlier drafts, which
fails with a `ProtocolError` where the document does not have the container's shape. A representation
in the *LWS profile* (an RDF media type with `profile="https://www.w3.org/ns/lws/v1"`, RDF isomorphic to
the `application/lws+json` one) is available through `read(url, accept)`; the clients do not parse RDF.
If the response's rel=type links / body `type` show it is not a `Container`, → `ProtocolError`.

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

### 5.7 Moving resources

| Operation | HTTP | Result |
|---|---|---|
| `move(resourceUrl, destinationUrl, opts)` | `readLinkset(resourceUrl)`, then `PATCH` the linkset with `application/json-patch+json` and `If-Match: <the linkset's ETag>` (opts: `ifMatch` overrides it, `headers`) | `MoveResult` |

lws10-core defines no method for a move: a client changes the `up` link in the resource's linkset to
the destination container, and the server moves the resource (and, for a container, everything in
it) atomically. `move` reads the linkset first, as JSON Patch addresses the `up` link by its position
and the conditional request needs the linkset's ETag:

1. The link context is the first whose `anchor` resolves (against the linkset's URL) to `resourceUrl`
   (scheme and host compared case-insensitively, default ports dropped), or the only context when it
   has no `anchor`. Its `up` link is its first `up` target with a string `href`. Without either →
   `ProtocolError`, and nothing is sent.
2. The patch is two operations: `test` that `/linkset/{i}/up/{j}/href` still holds the `href` as read
   (the raw string), and `replace` it with `destinationUrl` (absolute). The cases are
   `conformance/fixtures/move.json` (`patches`).
3. `PATCH` the linkset with it, conditional on the linkset's ETag when it had one (lws10-core: clients
   SHOULD make the request conditional).

`MoveResult { status, location (absolute URL of the resource after the move), linkset (absolute URL
of its linkset after the move), identifierPreserved (location == resourceUrl), etag?, metadata,
document? (the linkset in a 200's body) }`. A storage that keeps identifiers answers `204` (or `200`
with the linkset): `location` is `resourceUrl`. One that does not answers `200` with the updated
linkset, whose `anchor` is the new identifier, and `Content-Location`, the linkset's new URL:
`location` is the anchor of the body's first context with an `up` link, resolved against
`Content-Location` (else the linkset URL), and `linkset` is `Content-Location`. Without a
`preservesIdentifier: true`, a client MUST rely on this answer for the identifier (the cases are
`move.json`, `responses`).

`move` does not read the storage description: whether the storage allows moves is
`moveCapability()` (section 5.1), which an application checks first. A storage that does not refuses
the patch with a `4xx` (`409` → `ConflictError`), as it does a destination that is not an existing
container, or a container moved into itself or its own descendant. Moving needs delete on the resource
and create in the destination (`403` → `ForbiddenError`).

## 6. Authentication & authorization (OAuth 2.0 token exchange)

### 6.1 Pluggable `Authenticator`

```
Authenticator
  authorize(request)                         // before sending: may add Authorization
  handleChallenge(request, response) -> bool // on 401: obtain credentials; true = retry once
```
The one retry after a handled `401` may need credentials that `authorize` would not send, because the
request URL lies outside the token's scope (section 6.2, step 14). Each language gives the retry its own
hook: `authorizeRetry(request)`, which defaults to `authorize` (C++, Rust, Kotlin, Swift), headers that
`handleChallenge` sets being carried onto the retry (Java, C#), or the challenge handler handing the retry
its credentials (JavaScript's per-request context, Go's request context, Python's `challenge_flow` result,
PHP's authenticator state). Custom authenticators need not use it.

Provided implementations:
* `BearerTokenAuthenticator(token | tokenSupplier)` — send a known access token (optionally only to
  URLs inside a given realm).
* `TokenExchangeAuthenticator(credentialProvider, options)` — the LWS flow below.
Users may implement their own (cookies, DPoP, mTLS…).

### 6.2 LWS flow (`TokenExchangeAuthenticator`)

Since the drafts of 19 October 2026 a `401` names the requested resource's protected resource metadata
(RFC 9728), which names the authorization servers, and links to the storage that holds the resource,
which is what the token is for. Before it asks for a token a client MUST check what the `401` told it
against the URL that drew it (lws10-core "Discovery Validation by a Client"), as a malicious server could
otherwise have it get a token for another storage, and replay it there. The *request URL* below is the URL
of the request the `401` answered (after redirects, the last hop's). The steps, in this order:

1. A request returns `401`. Pick the first `Bearer` challenge with a `resource_metadata` parameter.
   If there is none, but there is a `Bearer` challenge with both `as_uri` and `realm`, follow the
   **challenge of the drafts before 19 October 2026** (below). If there is neither → surface
   `UnauthorizedError` (with parsed challenges).
2. **Metadata origin (client MUST):** the `resource_metadata` URL (resolved against the request URL)
   has the scheme and authority of the request URL: scheme and host compared case-insensitively, the
   port after the scheme's default is applied (`originChecks` in `responses/oauth.json`). Otherwise →
   `AuthenticationError`, and it is not fetched.
3. **Storage:** the `401`'s first `Link` with rel `https://www.w3.org/ns/lws#storage`, resolved
   against the request URL, is the storage. Without one → `AuthenticationError`.
4. **Protected resource metadata:** `GET` the `resource_metadata` URL with `Accept: application/json`,
   no credentials, following **no redirect**. Anything but a `200` JSON object → `AuthenticationError`.
   Parse it as `ProtectedResourceMetadata { resource, authorizationServers: List<string>, raw }`:
   `resource` a string (RFC 9728), `authorization_servers` a non-empty array of strings (lws10-core
   makes it REQUIRED), else `AuthenticationError` (the cases are `protectedResourceMetadata*` in
   `responses/oauth.json`). Not cached: it describes one resource.
5. **Metadata resource (client MUST):** `resource` is identical to the request URL, compared after
   lower-casing scheme and host and dropping a default port on both, and nothing else (no trailing
   slash, case or percent-encoding leniency; `resourceChecks` in `responses/oauth.json`). Otherwise →
   `AuthenticationError`.
6. **Storage root origin (client MUST):** obtain the storage's description (section 5.1: `GET` with the
   storage description `Accept`, no credentials, following no redirect), and its `StorageRoot`
   service's `serviceEndpoint` has the scheme and authority of the request URL. A description that
   cannot be read or parsed, has no `StorageRoot`, or whose root is on another origin →
   `AuthenticationError`. Descriptions are cached per storage URL for the authenticator's lifetime
   (lws10-core: a client can cache a storage description); `clear()` forgets them.
7. **Authorization server:** the first entry of `authorizationServers` that passes the transport
   check (step 8) and the filter (step 9) is the issuer; none → `AuthenticationError`.
8. **Transport security:** the issuer and the token endpoint MUST be `https`, except loopback hosts
   (`localhost`, `127.0.0.1`, `[::1]`) or when the option `allowInsecureHttp` is enabled. (The
   metadata and the storage description carry no credential; they are on the requested origin, or
   named by it.)
9. Optional policy: `authorizationServerFilter(issuer, storage) -> bool` (default: allow). (Security
   note: a malicious storage can name any AS; tokens minted by the self-signed provider are
   audience-bound to that AS, but static OpenID/SAML tokens may not be — use the filter or
   audience-restricted tokens.)
10. **Metadata and token requests never follow a redirect**; a `3xx` there is an
    `AuthenticationError`. A `307`/`308` would carry the subject token, a credential, on to wherever it
    points, past step 8. Fetch AS metadata (RFC 8414 §3.1): for issuer `https://as.example` →
    `https://as.example/.well-known/lws-configuration`; for an issuer with a path
    `https://as.example/t1` → `https://as.example/.well-known/lws-configuration/t1`. The returned
    `issuer` MUST equal the issuer (ignoring one trailing `/`) else `AuthenticationError`. Cache
    metadata per issuer.
11. Ask the `CredentialProvider` for a subject token for this AS
    (`context: { issuer, storage, metadata }`). If metadata has `subject_token_types_supported` and it
    does not contain the provider's token type → `AuthenticationError`.
12. `POST token_endpoint` (`application/x-www-form-urlencoded`):
    `grant_type=urn:ietf:params:oauth:grant-type:token-exchange`, `resource=<storage>` (the URL of
    step 3, absolute, not otherwise normalised), `subject_token=<token>`,
    `subject_token_type=<type>`. Error responses (RFC 6749 §5.2 `{"error": …}`) →
    `AuthenticationError` carrying `error`, `error_description`.
13. Response: `access_token`, `token_type` (must be `Bearer`, case-insensitive), `expires_in?`.
    Expiry = `expires_in`, else the access token's JWT `exp` (decode payload without verifying), else
    300 s. Cache per `(issuer, storage)`; refresh 30 s before expiry.
14. Retry the original request **once** with `Authorization: Bearer <token>`. The retry carries the
    token even when the request URL lies outside the token's scope (step 15), as that URL has just
    passed the checks. Later requests to URLs outside the scope get no token up front: their `401` runs
    steps 1–14 again, which reuse the cached token for the same issuer and storage without a new
    exchange.
15. **Proactive auth:** later requests send a cached token at once to URLs inside its *scope*: the
    storage URL and the storage root (step 6), each treated as a directory, as a realm was before: same
    scheme, host and port, and a path equal to the scope's or below it (a path not ending in `/`
    counting as one that does). Where several tokens' scopes contain a URL, the longest scope path wins.
    If such a request still gets `401` (e.g. `error="invalid_token"`), run steps 1–14; when they name
    the same issuer and storage, drop the cached token and exchange again, once.
16. Never send a token to a URL outside its scope (also on redirects), except in the retry of step 14.
17. Concurrency: concurrent requests should share one in-flight exchange where practical;
    the token cache must be thread/task-safe.
18. Bodies: the auth retry requires a replayable body. Byte/string bodies are always
    replayable. For streaming bodies, if no token is cached the client may first issue `HEAD`
    on the target (or its container for POST) to establish a token; otherwise surface the 401.

**Decision:** a challenge that fails a check (steps 2–10) is not acted on at all, and in particular a
cached token the request carried is **not** dropped: a storage can hold a resource whose `401` links to
another storage (Touchstone's decoy), and believing it would cost the client a valid token. The client
asks for no token for what that `401` named, and sends none there.

**The challenge of the drafts before 19 October 2026** (`Bearer as_uri="…", realm="…"`, without
`resource_metadata`) is still followed, so that the clients keep working with servers that have not
moved to RFC 9728; a challenge that has `resource_metadata` is never read this way, whatever else it
carries. **Realm check (client MUST in those drafts):** the request URL must be logically contained in
`realm`: same scheme, host and port, and the request path equals the realm path or starts with the
realm path (treated as a directory, i.e. ending in `/`). Otherwise → `AuthenticationError`. Then
`as_uri` is the issuer (steps 8–10), the realm the storage of steps 11–13 (`resource=<realm>`), and the
realm alone the token's scope (step 15). The cases of both are `conformance/fixtures/discovery.json`.

### 6.3 `CredentialProvider` (authentication suites)

```
CredentialProvider
  tokenType: string
  getSubjectToken(context{issuer, storage, metadata}) -> string   (may be async)
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
    provides it** (all ten do, via the chosen crypto stacks; Kotlin takes both from the JDK (`SHA256withECDSAinP1363Format`, `Ed25519`); PHP takes ES256 from ext-openssl and Ed25519 from ext-sodium; Swift takes both from swift-crypto, which is CryptoKit on Apple platforms; C# takes Ed25519 from BouncyCastle, as
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
origin?, published (date-time + raw), raw }` with `isCreate()/isUpdate()/isDelete()/isMove()`. A
`Move` (lws10-core, for storages that allow moves) has `origin`, the container the resource left,
`target`, the one it joined, and `object`, the resource as it is after the move (`move` in
`responses/notification.json`).
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
Go `http.Handler` middleware, Python ASGI/WSGI-friendly function, Java and Kotlin `HttpExchange`, Rust
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
| `AuthenticationError` (+ OAuth `error`, `errorDescription`) | token exchange, discovery check, realm check or metadata failures | |
| `ProtocolError` | server response violates the spec (missing Location, wrong media type, bad JSON) | |
| `SignatureVerificationError` | webhook verification failures | |

Other statuses map to the generic `HttpError` (5xx → "unknown error"). Transport errors use the
language's natural mechanism (wrapped in `LwsError` where that is idiomatic).
Language mapping: Java unchecked exceptions; TypeScript `Error` subclasses with `status`;
Python exception classes; Rust `enum Error` + `status()` + `is_not_found()`-style helpers;
Go `*HTTPError` + sentinels usable with `errors.Is` (`ErrNotFound`, `ErrConflict`, …) and
`errors.As`; C++ exception classes deriving from `lws::Error : std::runtime_error`; C# exceptions
deriving from `Ebremer.Lws.LwsException` (the 501 one is `HttpNotImplementedException`, so as not to clash
with `System.NotImplementedException`); Swift one `enum LWSError: Error` with a case per class (`.notFound`,
`.preconditionFailed`, …, each carrying the `HTTPError`; `.http`, `.authentication`, `.protocolError`,
`.signatureVerification`, `.transport`, and `.invalidArgument` for caller input); PHP exceptions deriving from
`Ebremer\Lws\Exception\LwsException` (a `\RuntimeException`) named `…Exception` (`NotFoundException`,
`PreconditionFailedException`, `HttpException`, `ProtocolException`, …), with PHP's own `\InvalidArgumentException` for
caller input; Kotlin a sealed hierarchy under `com.ebremer.lws.kotlin.LwsException` (a `RuntimeException`), with the
same `…Exception` names and Kotlin's own `IllegalArgumentException` for caller input; the WebAssembly component one
`error` record whose `error-kind`
names the class (`not-found`, `precondition-failed`, …, `authentication`, `protocol`, `transport`).

## 11. Testing requirements (all languages)

1. Unit tests for every parser (Link, WWW-Authenticate, SF dictionaries, problem details,
   container/storage/notification/linkset/access models, JSON Patch/Pointer, TypeQuery).
2. Tests that load the shared fixtures in `conformance/fixtures/` (see its README) — the same
   inputs and expected outputs for every language, including the RFC 9421 webhook vectors and
   did:key vectors.
3. In-process HTTP tests (mock transport or local server) for every operation, including the
   full `401 → protected resource metadata → storage description → AS metadata → token exchange →
   retry` flow with every case of `conformance/fixtures/discovery.json`, proactive token reuse,
   moves (`conformance/fixtures/move.json`), pagination across ≥3 pages, conditional requests (304,
   412), and error mapping.
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
| Swift | `lws-client` (SwiftPM; the manifest is the repository's root `Package.swift`) | `import LWS` | Swift 6.0, macOS 13 / iOS 16 / Linux |
| PHP | `ebremer/lws-client` (Composer; the manifest is the repository's root `composer.json`) | `namespace Ebremer\Lws` | PHP 8.2 with ext-curl, ext-openssl, ext-sodium |
| Kotlin | `com.ebremer:lws-client-kotlin:0.1.0` (Maven Central coordinates; built with Gradle) | `com.ebremer.lws.kotlin` | Kotlin 2.2, JDK 17 |
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

