# The adapter protocol, `lws-driver/1`

The driver ([README.md](README.md)) controls each language's client through an **adapter**: a
small program, one per language, that runs the operations of [`design/client-api.md`](../design/client-api.md)
with that language's `lws-client` and reports what happened. The driver starts one adapter process
per client it is asked for, and talks to it over the process's standard streams. This document is
the whole contract between the two.

The adapter's job is to be a thin, faithful wrapper. It calls the library's own operations with the
library's own options, and reports the library's own results and errors. It never retries, falls
back or fixes anything up on the library's behalf. The point of driving a client is to see what the
**client** does on the wire.

## 1. Framing

- The driver writes requests to the adapter's **stdin**, and the adapter writes responses to its
  **stdout**: UTF-8 JSON, one object per line, terminated by `\n`. A JSON serializer escapes
  newlines inside strings, so a line is always one message.
- The adapter flushes stdout after every line.
- **stdout carries protocol messages only.** Logs, diagnostics and stack traces go to **stderr**,
  which the driver keeps as the adapter's log.
- The adapter handles one request at a time, in the order received. The driver never sends a second
  request before the first is answered.
- On end of input (stdin closed) the adapter exits with status 0.

## 2. Messages

**Hello.** Before reading anything, the adapter writes one line announcing itself:

```json
{"hello": {"protocol": "lws-driver/1", "language": "go", "library": "lws-client-go/0.1.0",
           "operations": ["configure", "discover_storage", "head", "read", "..."]}}
```

`operations` lists every operation of section 4 the adapter implements. The driver offers the
others for this language as unsupported.

**Request.**

```json
{"id": 7, "op": "read", "args": {"url": "https://storage.example/notes/a.txt"}}
```

`id` is an integer, `op` an operation name, `args` an object (possibly empty). A line that is not a JSON
object gets an `InvalidArguments` response with `"id": null`; an unknown `op` gets `Unsupported`.

**Response.** Exactly one per request, with the request's `id`:

```json
{"id": 7, "ok": true, "result": { ... }}
{"id": 7, "ok": false, "error": {"kind": "NotFoundError", "status": 404, "message": "GET https://… → 404"}}
```

A response that is not `ok` is an **outcome**, not a breakdown: a `ConflictError` from deleting a
non-empty container without `recursive` is exactly what a test may be looking for. The adapter
catches every error the library raises and reports it this way, and keeps running.

## 3. Conventions

**Absent values.** An optional argument or result member may be omitted or `null`; both mean
absent. Adapters omit them where that is natural.

**URLs** in arguments are absolute; a relative one where a request target is expected (`url`, `container`,
`parent`, `linksetUrl`, `serviceUrl`) is `InvalidArguments`. URLs in results are absolute, as the library
returns them.

**Numbers.** `limit`, `rangeStart`, `rangeEnd` and `timeoutSeconds` are non-negative integers
(`timeoutSeconds` positive); anything else is `InvalidArguments`.

**Argument documents** (`linkset`, `request`, `grant`, `patch`, `query`, `privateJwk`) that the library's
own parser or builder rejects are `InvalidArguments`, even when the parser reports them as a protocol error:
`ProtocolError` is for responses only.

**Request bodies** (`body` arguments) are one of:

| Form | Meaning |
|---|---|
| `{"text": "Hello"}` | the UTF-8 bytes of the string |
| `{"base64": "AAEC"}` | the decoded bytes (standard base64, padded) |
| `{"json": {"name": "Alice"}}` | the JSON serialization of the value; `contentType` defaults to `application/json` |

**Response bodies** (`body` in results) are `{"text": "…"}` when the content type is textual
(`text/*`, `application/json`, `application/xml`, or any type with a `+json` or `+xml` suffix, such as
`image/svg+xml`), and `{"base64": "…"}` otherwise, or when there is no content type. Text is the body
decoded as the library decodes it: by the response's `charset` where the library honours one, UTF-8
otherwise. base64 arguments are decoded strictly: a string outside the standard alphabet is
`InvalidArguments`.

**JSON Patch** arguments (`patch`) are an RFC 6902 operations array:
`[{"op": "replace", "path": "/age", "value": 31}]`. The adapter rebuilds it with the library's
`JsonPatch` builder (`add`, `remove`, `replace`, `move`, `copy`, `test`), so that the library
serializes and sends it with its own media type, `application/json-patch+json`.

**Type queries** (`query`) are the `application/lws-query+json` document itself: an object whose keys
are `type` or a relation IRI, each holding a list of AND groups, where a group is an IRI string or an
array of IRIs (an OR group). For example, `{"type": [["https://schema.org/Person", "http://xmlns.com/foaf/0.1/Person"], "https://www.w3.org/ns/lws#DataResource"]}`.
The adapter rebuilds it with the library's `TypeQuery` builder: a string group is `allOf(iri)` and an
array group `anyOf(iris…)`, on the key's relation, in order. `{}` is the empty query.

**Lazy sequences** (`list_*`, `search_all`) take an optional `limit` (default 1000). The adapter
pulls at most `limit + 1` items from the library's lazy sequence, returns the first `limit`, and sets
`truncated` to whether there was one more.

### 3.1 Shared result shapes

**Metadata**, the parsed response headers (`ResourceMetadata`):

```json
{"url": "https://…/a.txt", "status": 200,
 "etag": "\"3\"", "lastModified": "Tue, 06 Oct 2026 12:00:00 GMT",
 "contentType": "text/plain", "contentLength": 11,
 "links": [{"href": "https://…/a.txt.meta", "rel": "linkset", "params": {"type": "application/linkset+json"}}],
 "linkset": "https://…/a.txt.meta", "parent": "https://…/", "storage": "https://…/",
 "types": ["https://www.w3.org/ns/lws#DataResource"],
 "allow": ["GET", "HEAD", "PUT", "PATCH", "DELETE"], "acceptPatch": ["application/json-patch+json"]}
```

`etag` is verbatim, quotes and `W/` included. `lastModified` is the raw header value. `links` holds
every link, one per relation type, with `params` holding its parameters other than `rel`. `types`,
`links`, `allow` and `acceptPatch` are always present, possibly empty.

**Item**, one member of a listing (`ContainedResource`):

```json
{"id": "https://…/a.txt", "types": ["DataResource"], "format": "text/plain", "size": 11, "modified": "2026-10-06T12:00:00Z"}
```

`types` is the raw `type` values, as received. `modified` is the raw string.

**Page**, a container page or a page of search results (`ContainerPage`):

```json
{"id": "https://…/", "types": ["Container"], "totalItems": 8, "items": [Item, …],
 "first": "…", "next": "…", "prev": "…", "last": "…", "metadata": Metadata}
```

**Update**, the result of a PUT or PATCH (`UpdateResult`):

```json
{"status": 204, "etag": "\"4\"", "metadata": Metadata}
```

**Created**, the result of a create (`CreateResult`):

```json
{"location": "https://…/hello.txt", "metadata": Metadata}
```

**Storage**, a storage description (`StorageDescription`):

```json
{"id": "https://…/", "types": ["Storage"], "storageRoot": "https://…/root/",
 "services": [{"id": "…", "types": ["NotificationService"], "serviceEndpoint": "https://…/notifications/",
               "subscriptionType": ["WebhookSubscription"]}],
 "verificationMethods": [{"id": "https://…/#key-1", "type": "JsonWebKey", "controller": "https://…/"}],
 "raw": { … the document … }}
```

`storageRoot` is omitted when the description has none (the library's `storageRoot()` fails).
`subscriptionType` is present for services that carry it.

**Subscription**:

```json
{"subscription": "https://…/notifications/s1", "types": ["WebhookSubscription"], "expires": "…", "raw": { … }}
```

### 3.2 Errors

`error` is `{"kind": …, "message": …}` plus, where they apply, `status` (the HTTP status),
`problem` (the RFC 9457 problem details object), `allow` (for a 405), `acceptPatch` (for a 415),
`oauthError` and `oauthErrorDescription` (for an `AuthenticationError` from a token endpoint).
`status` appears on any error that came from an HTTP response and whose status the library exposes, an
`AuthenticationError` from a token endpoint included. When one error wraps another, the outer one, as the library raised it, decides the kind.
`kind` is the error's name in the API contract (section 10):

| `kind` | When |
|---|---|
| `BadRequestError` … `InsufficientStorageError` | the status-specific errors: 400, 401 (`UnauthorizedError`), 403, 404, 405, 406, 409, 410, 412, 415, 422, 501, 507 |
| `HttpError` | any other non-success status |
| `AuthenticationError` | token exchange, realm check or authorization server metadata failures |
| `ProtocolError` | a response that breaks the specification |
| `SignatureVerificationError` | a notification that fails verification |
| `TransportError` | no response: connection refused, TLS failure, timeout |
| `InvalidArguments` | the request's arguments are missing or malformed |
| `Unsupported` | the operation, or an option it was given, is not available in this library |
| `InternalError` | anything else, which is a bug in the adapter or the library |

## 4. Operations

| `op` | `args` | `result` |
|---|---|---|
| `configure` | `auth`, `allowInsecureHttp?`, `userAgent?`, `timeoutSeconds?`, `headers?` (object of name → value) | `{"library", "agent"?, "kid"?}` |
| `discover_storage` | `url` | Storage |
| `get_storage_description` | `url` | Storage |
| `head` | `url` | Metadata |
| `read` | `url`, `accept?`, `rangeStart?`, `rangeEnd?`, `ifNoneMatch?`, `prefer?` | `{"metadata", "notModified", "contentRange"?, "body"}` |
| `read_container` | `url` | Page |
| `list_container` | `url`, `limit?` | `{"items": [Item], "truncated"}` |
| `create` | `container`, `body?`, `contentType?`, `slug?`, `types?` (IRIs), `links?` (`[{"href", "rel"}]`) | Created |
| `create_container` | `parent`, `slug?` | Created |
| `update` | `url`, `body`, `contentType?`, `ifMatch?`, `ifNoneMatch?` | Update |
| `patch` | `url`, `patch`, `ifMatch?` | Update |
| `delete` | `url`, `recursive?`, `ifMatch?` | `{}` |
| `linkset_url` | `url` | `{"linkset"}` |
| `read_linkset` | `url` (the resource) | `{"url", "etag"?, "linkset" (the document), "allow", "acceptPatch"}` |
| `update_linkset` | `linksetUrl`, `linkset` (a `{"linkset": [...]}` document), `ifMatch?` | Update |
| `patch_linkset` | `linksetUrl`, `patch`, `ifMatch?` | Update |
| `subscribe` | `serviceUrl`, `topics` (URLs), `inbox`, `expires?` (RFC 3339) | Subscription |
| `list_subscriptions` | `serviceUrl`, `limit?` | `{"items", "truncated"}` |
| `get_subscription` | `url` | Subscription |
| `unsubscribe` | `url` | `{}` |
| `verify_notification` | `method`, `url` (the inbox URL as registered), `headers` (object of name → list of values), `bodyBase64`, `trustedStorages?` | `{"storage", "keyid", "activities": [{"id"?, "types", "object", "objectTypes"}], "raw"}` |
| `request_access` | `serviceUrl`, `request` (an `AccessRequest` document) | `{"location"}` |
| `get_access_request` | `url` | `{"document"}`: as the server sent it where the library keeps it, else the library's re-serialization |
| `list_access_requests` | `serviceUrl`, `limit?` | `{"items", "truncated"}` |
| `cancel_access_request` | `url` | `{}` |
| `grant_access` | `serviceUrl`, `grant` (an `AccessGrant` document) | `{"location"}` |
| `get_access_grant` | `url` | `{"document"}` |
| `list_access_grants` | `serviceUrl`, `limit?` | `{"items", "truncated"}` |
| `revoke_access_grant` | `url` | `{}` |
| `read_type_index` | `url` | `{"totalItems"?, "types", "first"?, "next"?, "prev"?, "last"?}` |
| `list_types` | `serviceUrl`, `limit?` | `{"types", "truncated"}` |
| `search_types` | `serviceUrl`, `query` | Page |
| `search_all` | `serviceUrl`, `query`, `limit?` | `{"items", "truncated"}` |
| `accepted_query_formats` | `serviceUrl` | `{"formats"}` |
| `shutdown` | none | `{}`, then the adapter exits with status 0 |

### 4.1 `configure`

`configure` builds the client every later operation uses. The driver sends it first. It may send it
again, which replaces the client and drops its cached tokens. An operation other than `configure`
or `shutdown` before the first `configure` uses a client with no authenticator.

`auth` is one of:

| `auth` | The library's authenticator |
|---|---|
| `{"type": "none"}` | none: anonymous requests |
| `{"type": "bearer", "token": "…", "realm"?: "https://…/"}` | `BearerTokenAuthenticator`; with `realm`, the token is sent only to URLs inside it |
| `{"type": "openid", "idToken": "…"}` | `TokenExchangeAuthenticator(OpenIdCredentials(idToken))` |
| `{"type": "selfSigned", "agent": "https://…/id/alice", "privateJwk": {…}, "kid"?: "…"}` | `TokenExchangeAuthenticator(SelfSignedCredentials.forAgent(agent, key, kid))`; `kid` defaults to the JWK's `kid` member, and the algorithm follows from the key (`EC` `P-256` → ES256, `OKP` `Ed25519` → EdDSA) |
| `{"type": "didKey", "algorithm"?: "ES256" \| "EdDSA"}` | `TokenExchangeAuthenticator(SelfSignedCredentials.didKey(newKey))`, with a freshly generated key (ES256 by default); the result's `agent` is the `did:key` and `kid` its key id |

`allowInsecureHttp` sets the token-exchange option of that name (section 6.2, step 3). `userAgent`,
`timeoutSeconds` and `headers` set the client options of section 4 of the contract. An option the
library lacks is `Unsupported`.

### 4.2 `verify_notification`

The driver receives the notification on its own inbox endpoint and passes the request on unchanged:
the method, the inbox URL as it was registered, every header field with all its values (a list of strings;
adapters also accept a single string), and the body bytes in base64. `trustedStorages`, when present, is
never empty: the driver leaves it out to accept any storage. An activity's `id` is omitted when the
notification gives none. The adapter verifies it with the library's `WebhookVerifier`, which fetches the
storage description through the configured client, and returns the verified notification, or
`SignatureVerificationError` (or `ProtocolError`) when it fails. The driver answers the delivery
`2xx` or `4xx` on the strength of that.

## 5. Checking an adapter

[`adapters/check.mjs`](adapters/check.mjs) runs an adapter against the mock server through this
protocol and checks every operation's result:

```sh
node driver/adapters/check.mjs -- <the adapter's command line>
```

It needs Node.js 22 or later. It starts the mock server on a free port, starts the adapter, and
prints one line per check.
