# LWS mock server

A zero-dependency, in-memory [Linked Web Storage](https://www.w3.org/TR/lws10-core/) server for
testing LWS clients. It implements the LWS 1.0 core protocol (editor's draft of 2026-10-05) plus the
authentication, webhook notification, access request/grant and type index/search specifications, and
it is the target of every `lws-client` interop test (see [`conformance/scenario.md`](../../conformance/scenario.md)).

It is a **test tool**: single tenant, in-memory, no persistence, and OpenID Connect / SAML subject
tokens are accepted without signature verification. Do not expose it to untrusted networks.

## Usage

Requires Node.js 20 or later (Node 22+ recommended; the HTTP `QUERY` method must be supported by the
Node HTTP parser) and nothing else.

```sh
node testing/mock-server/server.mjs --port 8787
# LWS mock server listening on http://localhost:8787
```

| Option | Default | Meaning |
|---|---|---|
| `--port <n>` | `8787` | Port to listen on; `0` picks a free port |
| `--host <addr>` | IPv4 + IPv6 loopback | Interface to bind |
| `--base-url <url>` | `http://localhost:<port>` | Public base URL (origin only) used in every URL the server emits |
| `--page-size <n>` | `5` | Page size for containers, the type index and search results |
| `--no-auth` | off | Disable authentication; every request acts as `anonymous` |
| `--verbose` | off | Log requests, token exchanges and webhook deliveries |

Programmatic use (for tests):

```js
import { startServer } from "./testing/mock-server/lib/server.mjs";

const server = await startServer({ port: 0, pageSize: 5, auth: true });
console.log(server.url); // http://localhost:<port>
await server.close();
```

Run its own test suite with `npm test` (from this directory) — 102 tests covering every endpoint.

## Layout

| URL | Purpose |
|---|---|
| `{base}/` | Storage description (`application/lws+cid`, public). Storage id is `{base}/` |
| `{base}/root/` | Storage root container |
| `{base}/root/**.meta` | Linkset (metadata) resource of each storage resource (`/root/notes/.meta`, `/root/notes/a.txt.meta`) |
| `{base}/notifications/` | `NotificationService` (`WebhookSubscription`) |
| `{base}/access/requests/`, `{base}/access/grants/` | `AccessRequestService`, `AccessGrantService` |
| `{base}/types/index`, `{base}/types/search` | `TypeIndexService`, `TypeSearchService` |
| `{base}` | Authorization server issuer |
| `{base}/.well-known/lws-configuration` | Authorization server metadata (RFC 8414; also at `/.well-known/oauth-authorization-server`) |
| `{base}/oauth/token`, `{base}/oauth/jwks` | Token endpoint (RFC 8693 token exchange), JWKS |

## Behaviour

### Authentication and authorization

* Everything under `/root/`, `/notifications/`, `/access/` and `/types/` requires a Bearer access
  token. Without a valid one the response is `401` with
  `WWW-Authenticate: Bearer as_uri="{base}", realm="{base}/", error="invalid_token"` and
  `Link: <{base}/>; rel="https://www.w3.org/ns/lws#storage"`. `OPTIONS` is never authenticated.
* Token exchange (`POST /oauth/token`, form encoded): `grant_type` must be
  `urn:ietf:params:oauth:grant-type:token-exchange`; `resource` is required and must equal the realm
  `{base}/` exactly (otherwise `invalid_target`); `subject_token` and `subject_token_type` are required.
  Errors are RFC 6749 §5.2 JSON (`invalid_request`, `invalid_target`, `unsupported_grant_type`).
* Subject token types:
  * `urn:ietf:params:oauth:token-type:jwt` — self-signed credentials (lws10-authn-ssi-cid):
    `alg` must not be `none` (ES256, ES384, EdDSA/Ed25519 accepted); `sub`, `iss` and `client_id`
    must be identical; `aud` must include the issuer `{base}`; `exp` and `iat` are required (60 s skew).
    `did:key` subjects (P-256 and Ed25519) are verified with the key in the identifier (a `kid`, if
    present, must belong to that DID). `http(s)` subjects are dereferenced as a controlled identifier
    document whose `id` must equal the subject; the `kid` selects an `authentication` verification
    method by full id, `#fragment`, bare fragment or `publicKeyJwk.kid`. Documents stored in this
    server's own storage are read directly.
  * `urn:ietf:params:oauth:token-type:id_token` — **test mode**: signature not verified; `sub`, `iss`
    and `azp` (or `client_id`) are required; `alg: none` is rejected.
  * `urn:ietf:params:oauth:token-type:saml2` — **test mode**: base64url-encoded assertion, signature
    not verified; `NameID` becomes the subject, the `Recipient` the client.
* Access tokens are ES256 `at+jwt` (RFC 9068) with `iss`, `sub`, `client_id`, `aud` (= `{base}/`),
  `exp` (300 s), `iat` and `jti`. The storage validates signature, issuer, a single audience equal to
  the realm and the time claims. Any valid token has full access (single tenant).

### Storage resources

* `GET`/`HEAD` on data resources: stored bytes and `Content-Type`, `ETag`, `Last-Modified`,
  `Accept-Ranges: bytes`, `Allow`, `Accept-Patch` (JSON resources), and `Link` headers for `linkset`
  (with `type="application/linkset+json"`), `up`, `type` (`lws:DataResource` plus user types) and
  `https://www.w3.org/ns/lws#storage`. Single byte ranges → `206`/`416`. `If-None-Match` /
  `If-Modified-Since` → `304`.
* Containers return the LWS container representation; `application/lws+json`, `application/ld+json`
  (profile echoed) and `application/json` are equivalent and selected via `Accept` (`Vary: Accept`),
  anything else → `406`. Item ids are path-absolute references (`/root/notes/a.txt`), as in the spec
  examples, so clients must resolve them. Listings with more members than the page size are paginated
  with `?page=N` and `first`/`last`/`next`/`prev` links (relative references).
* `POST` to a container creates a resource: `Link: <https://www.w3.org/ns/lws#Container>; rel="type"`
  creates a container (body ignored), otherwise a data resource with the request `Content-Type`
  (default `application/octet-stream`). `Slug` (RFC 5023, percent-decoded) is sanitised to
  `[A-Za-z0-9._-]`, may not end in `.meta`, and is made unique (`hello.txt` → `hello-1.txt`). Other
  `Link` headers become user-managed metadata (extra `rel="type"` links become resource types;
  `up`, `linkset`, storage and pagination relations are ignored). Response: `201`, absolute
  `Location`, metadata `Link`s, `ETag`.
* `PUT` replaces a data resource (`404` if missing, `405` on containers); `PATCH` accepts only
  `application/json-patch+json` (`415` + `Accept-Patch` otherwise) on JSON resources (`415` for
  non-JSON), with RFC 6902 semantics: malformed patch → `400`, failed `test`/missing path → `409`.
  `If-Match`, `If-None-Match` and `If-Unmodified-Since` → `412`. `Prefer: set-linkset` with `Link`
  headers also replaces (PUT) or extends (PATCH) the linkset and returns `Preference-Applied`.
* `DELETE` removes a resource and its linkset; a non-empty container needs `Depth: infinity`
  (`409` otherwise, `400` for other `Depth` values); the root cannot be deleted (`405`).

### Linksets

`GET`/`HEAD` return `application/linkset+json` with a single context object whose `anchor` is the
absolute resource URL and whose members are the user-managed relations; `Allow: GET, HEAD, PUT, PATCH`
and `Accept-Patch: application/json-patch+json`. `PUT` (`application/linkset+json`) replaces and
`PATCH` (JSON Patch on the linkset document) modifies the metadata; both are conditional (`412`) and
the result must be a valid linkset for the same anchor (`422` otherwise). Server-managed relations are
silently dropped. `type` relations in the linkset are the resource's user types.

### Notifications (Webhook suite)

* `POST /notifications/` with `application/lws+json`
  `{"type":"WebhookSubscription","topic":[…],"inbox":"…","expires":"…"}` → `200`, `Location` and
  `{"@context", "type", "subscription", "topic", "inbox", "expires"}`. Topics must be existing
  resources of this storage; `expires` defaults to 24 h. `GET /notifications/` lists the caller's
  subscriptions as an LWS container; `GET`/`DELETE` manage one subscription (private to its creator).
* Every create (`Create`, `target` = container), content or linkset update (`Update`) and delete
  (`Delete`, `origin` = former container) is delivered to the inboxes of subscriptions covering the
  resource (container topics are recursive). Several activities produced by one request (e.g. a
  recursive delete) are batched into one envelope with an `activity` array.
* Deliveries are `POST`s with `Content-Type: application/lws+json`, `Content-Digest: sha-256=…`
  (RFC 9530) and an RFC 9421 signature over
  `("@method" "@scheme" "@authority" "@path" "content-type" "content-digest")` with `created`,
  `keyid="{base}/#webhook-key"` and `alg="ecdsa-p256-sha256"`. The key is published in the storage
  description's `verificationMethod` and referenced from `authentication`. Failed deliveries are
  retried twice (after 250 ms and 1 s).

### Access requests and grants

`POST` (`application/lws+json`) to `/access/requests/` or `/access/grants/` validates the document
(`@context` includes the LWS context, `type` includes `AccessRequest`/`AccessGrant`, `storage` equals
`{base}/`, a non-empty `access` array of `AccessPolicy` objects with actions from
`read`/`modify`/`create`/`delete`, a URI `assignee`, optional `target` and `constraint`s) and returns
`201` + `Location`; the stored document gains an `id`. `GET` lists (LWS container) or reads, `DELETE`
cancels/revokes. Creating a grant notifies the grant's `inbox`, or the inboxes of access requests for
the same assignee, with a signed `Create` notification.

### Type index and type search

* `GET /types/index` → `TypeIndex` of the distinct types (intrinsic `lws:Container` /
  `lws:DataResource` plus user types), paginated with absolute `?page=N` links,
  `Cache-Control: private`.
* `OPTIONS /types/search` → `204`, `Allow: OPTIONS, QUERY`, `Accept-Query: application/lws-query+json`.
* `QUERY /types/search` with an `application/lws-query+json` filter (conjunctive normal form over
  `type` and descriptive relations stored in linksets; structural relations are not indexed and
  unknown relations match nothing) → `ContainerPage` with absolute ids. Errors: missing
  `Content-Type` → `400`; other formats → `415` + `Accept-Query`; unacceptable `Accept` → `406`;
  malformed filters, empty groups and non-absolute IRIs → `400`; more than 32 groups / 128 IRIs →
  `422`. Results are snapshotted and paginated through opaque `?cursor=` links (`GET`), bound to the
  requesting subject and valid for 10 minutes; unknown or expired cursors → `404`.

### Errors and CORS

Errors are RFC 9457 `application/problem+json`. Requests carrying `Origin` get permissive CORS
headers (including preflight for `QUERY` and exposure of `Link`, `Location`, `ETag`,
`WWW-Authenticate`, `Accept-Patch`, `Accept-Query`, …) so browser clients can be tested too.

## License

MIT — see the repository [LICENSE](../../LICENSE).
