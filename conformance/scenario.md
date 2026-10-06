# Interop scenario

Every client ships an interop test (or example program) that runs this scenario against the
mock server in [`testing/mock-server`](../testing/mock-server). It is skipped unless the
environment variable `LWS_TEST_SERVER` is set to the server's base URL (e.g.
`http://localhost:8787`).

```sh
node testing/mock-server/server.mjs --port 8787        # prints: LWS mock server listening on http://localhost:8787
LWS_TEST_SERVER=http://localhost:8787 <language test command>
```

## Mock server layout

| URL | Purpose |
|---|---|
| `{base}/` | storage description (`application/lws+cid`, public); storage id is `{base}/` |
| `{base}/root/` | storage root container |
| `{base}/notifications/` | `NotificationService` (`WebhookSubscription`) |
| `{base}/access/requests/`, `{base}/access/grants/` | `AccessRequestService`, `AccessGrantService` |
| `{base}/types/index`, `{base}/types/search` | `TypeIndexService`, `TypeSearchService` |
| `{base}` | authorization server issuer; metadata at `{base}/.well-known/lws-configuration` |
| `{base}/oauth/token`, `{base}/oauth/jwks` | token endpoint (token exchange), JWKS |

Everything except the storage description, AS metadata, JWKS and token endpoint requires a
Bearer access token: unauthenticated requests get
`401` + `WWW-Authenticate: Bearer as_uri="{base}", realm="{base}/", error="invalid_token"`.
The token endpoint accepts self-signed JWTs (`urn:ietf:params:oauth:token-type:jwt`, verified
for `did:key` subjects and for HTTP(S) subjects whose controlled identifier document is
reachable), and — in test mode — unverified ID tokens and SAML assertions. Container listings
are paginated with a page size of 5 (`--page-size`). Webhooks are signed (RFC 9421,
`ecdsa-p256-sha256`) with a key published in the storage description.

## Steps

Use a unique container name per run: `interop-<lang>-<unix millis>`.

1. **Authenticate + discover.** Build a client with `TokenExchangeAuthenticator(
   SelfSignedCredentials.didKey(<new P-256 key>))`. `discoverStorage("{base}/root/")` → the
   storage description; assert `storageRoot() == {base}/root/` and that the notification,
   access request/grant, type index and type search services are present.
2. **Create a container** in the root with slug `interop-<lang>-<millis>` → `C`.
3. **Create text**: `create(C, "Hello, LWS!", "text/plain", slug "hello.txt")` → `H`.
4. **Read** `H`: body `Hello, LWS!`, ETag present, `isDataResource()`, `parent == C`,
   `linkset` present, `storage == {base}/`.
5. **Conditional read** with `ifNoneMatch = etag` → not modified (no error).
6. **Update** `H` with `ifMatch = etag` → `Hello again`; a second update with the *old* ETag →
   `PreconditionFailed` error.
7. **Create JSON** `{"name":"Alice","age":30}` as `application/json`, slug `profile.json`,
   extra type `https://schema.org/Person` → `P`. **Patch** with JSON Patch
   `replace /age 31`, `add /city "Boston"`; read back and compare.
8. **Linkset**: `readLinkset(P)`; `patchLinkset` adding
   `describedby → https://example.org/shapes/person` to the first context (with `ifMatch`);
   read again and find the link.
9. **Pagination**: create six more small text resources in `C` (8 members total).
   `readContainer(C)` → `totalItems == 8`, a `next` link; `listContainer(C)` yields 8 items
   with absolute ids including `H` and `P`.
10. **Type index / search**: `listTypes` includes `https://schema.org/Person`;
    `searchAll(TypeQuery.allOf("https://schema.org/Person"))` includes `P`;
    `acceptedQueryFormats` includes `application/lws-query+json`.
11. **Notifications** (languages with an easy local HTTP listener): start an inbox at
    `http://127.0.0.1:<port>/inbox`; `subscribe(notificationService, topics [C], inbox)`;
    update `H`; within 5 s receive a POST; verify it with `WebhookVerifier` (inbox URL as
    registered, `trustedStorages = [{base}/]`); expect an `Update` activity whose object is
    `H`. `listSubscriptions` contains the subscription; `unsubscribe`. Languages without a
    listener still subscribe, list and unsubscribe.
12. **Access requests/grants**: `requestAccess` (assignee = the agent's did:key, action
    `read`, target `C`, purpose constraint) → URL; `getAccessRequest` round-trips;
    `listAccessRequests` contains it; `grantAccess` (same policy) → URL; `getAccessGrant`;
    `revokeAccessGrant`; `cancelAccessRequest`.
13. **Delete**: `delete(C)` without recursion → `Conflict` error; `delete(C, recursive)` →
    success; `read(H)` → `NotFound` error.
