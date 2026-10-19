# lws-client (JavaScript / TypeScript)

A client for the **W3C Linked Web Storage (LWS)** protocol for browsers, Node.js, Deno and Bun.
Written in strict TypeScript, shipped as ESM with type declarations, and with **zero runtime
dependencies** — it uses the platform's `fetch`, WebCrypto, `URL` and streams.

It implements the LWS 1.0 specification family as of the Working Draft of 19 October 2026
(`w3c/lws-protocol` 9a08ff6): the core protocol (storage discovery, containers, CRUD, linkset
metadata, JSON Patch, moving resources between containers), OAuth 2.0 token-exchange
authorization discovered through protected resource metadata (RFC 9728) with the OpenID Connect,
SAML 2.0 and self-signed (controlled identifier / did:key) authentication suites, webhook
notifications with RFC 9421 signature verification, access requests/grants, and the Type Index /
Type Search services (HTTP `QUERY`).

MIT licensed — see [`../LICENSE`](../LICENSE).

## Install

```sh
npm install lws-client
```

Runtime support: Node.js ≥ 20, current Chrome/Edge/Firefox/Safari, Deno, Bun (Ed25519 needs a
WebCrypto implementation with Ed25519 support — all of the above have it).

## Quickstart

```ts
import {
  LwsClient, TokenExchangeAuthenticator, SelfSignedCredentials, generateKeyPair, JsonPatch,
} from "lws-client";

// An identity: here a did:key over a fresh P-256 key (see "Authentication" for others).
const credentials = SelfSignedCredentials.didKey(await generateKeyPair("ES256"));
const client = new LwsClient({ authenticator: new TokenExchangeAuthenticator(credentials) });

const storage = await client.discoverStorage("https://storage.example/alice/");
const root = storage.storageRoot();

const { location: notes } = await client.createContainer(root, { slug: "notes" });
const { location: todo } = await client.createJson(notes, { task: "write docs", done: false }, { slug: "todo.json" });

const res = await client.read(todo);
console.log(await res.json(), res.etag, res.parent);

await client.patch(todo, new JsonPatch().replace("/done", true), { ifMatch: res.etag });

for await (const item of client.listContainer(notes)) console.log(item.id, item.format, item.size);

await client.delete(notes, { recursive: true });
```

More in [`examples/`](examples): `quickstart.mjs`, `self-signed-auth.mjs`,
`webhook-receiver.mjs` (Node) and `browser.html`.

## Features

| Area | API |
|---|---|
| Discovery | `discoverStorage(url)`, `getStorageDescription(url)` → `StorageDescription` (`storageRoot()`, `service(type)`, `notificationService()`, `typeSearchService()`, `moveCapability()`, …) |
| Read | `head`, `read` (conditional `ifNoneMatch` → `notModified`, `range` → `206`), `readContainer`, `listContainer` (async iterable over all pages) |
| Write | `create`, `createJson`, `createText`, `createContainer` (`slug`, user `links`, extra `types`), `update` / `updateJson` (`ifMatch`, `setLinkset`), `patch` (JSON Patch or raw formats), `delete` (`recursive`) |
| Metadata | `linksetUrl`, `readLinkset` → `LinksetDocument`, `updateLinkset`, `patchLinkset`, `Linkset` model |
| Move | `move(resource, destination)` → `MoveResult` (`location`, `linkset`, `identifierPreserved`), `MoveCapability` |
| Auth | `Authenticator` interface, `TokenExchangeAuthenticator`, `BearerTokenAuthenticator`, `OpenIdCredentials`, `SamlCredentials`, `SelfSignedCredentials` (ES256, EdDSA, did:key) |
| Notifications | `subscribe`, `listSubscriptions`, `getSubscription`, `unsubscribe`, `parseNotification`, `WebhookVerifier`, `lws-client/node` handler |
| Access | `requestAccess`, `listAccessRequests`, `getAccessRequest`, `cancelAccessRequest`, `grantAccess`, `listAccessGrants`, `getAccessGrant`, `revokeAccessGrant`, `Constraints` |
| Type services | `readTypeIndex`, `listTypes`, `searchTypes` (HTTP `QUERY`), `searchAll`, `acceptedQueryFormats`, `TypeQuery` |
| Primitives | `parseLinkHeader`, `formatLink`, `parseWwwAuthenticate`, `ProtectedResourceMetadata`, structured fields (`parseDictionary`, …), `parseProblemDetails`, `JsonPatch`, `JsonPointer` |
| Errors | `LwsError` → `HttpError` (`NotFoundError`, `ConflictError`, `PreconditionFailedError`, `UnauthorizedError`, …), `AuthenticationError`, `ProtocolError`, `SignatureVerificationError` |

Every operation accepts `{ headers, signal }` (an `AbortSignal`); the client accepts
`{ fetch, authenticator, headers, userAgent, timeoutMs }`. Every URL the library returns is
absolute, even when the server sends relative ids, `Location` or `Link` targets.

## Moving resources

A storage that describes a `MoveResource` capability lets you move a resource (or a container
with everything in it) into another container. `move` reads the resource's linkset and patches
its `up` link, conditional on the linkset's ETag:

```ts
const move = storage.moveCapability();
if (move?.movesDataResources()) {
  const { location: archive } = await client.createContainer(root, { slug: "archive" });
  const { location, identifierPreserved } = await client.move(todo, archive);
  // Unless the storage preserves identifiers, the resource now has a new URL: use `location`.
}
```

A storage that does not allow the move refuses it (`409` → `ConflictError`), as it does a
destination that is not a container, or a container moved into itself.

## Authentication

On a `401` with `WWW-Authenticate: Bearer resource_metadata="…"`, the
`TokenExchangeAuthenticator` follows the discovery of the Working Draft of 19 October 2026: it
checks that the protected resource metadata (RFC 9728) is on the origin of the URL requested (the
last hop's, after redirects),
reads it and checks that it describes that very URL, reads the description of the storage the
`401` links to (`rel="https://www.w3.org/ns/lws#storage"`) and checks that its root is on the same
origin, then takes the first authorization server of the metadata that uses https and passes your
filter. Only then does it fetch that server's metadata (`/.well-known/lws-configuration`),
exchange a subject token from your credential provider for an access token for the storage
(RFC 8693), cache it per (authorization server, storage) and retry with it. Later requests inside
the storage or its root send the token immediately; elsewhere their `401` reuses it. A `401` that fails a check gets no token, and
costs the client none. The `as_uri`/`realm` challenge of earlier drafts is still followed, with
its realm check. Metadata, storage description and token requests never follow a redirect.

```ts
// OpenID Connect: pass the ID token you obtained with your OIDC library (or a callback).
new TokenExchangeAuthenticator(new OpenIdCredentials(() => oidc.getIdToken()));

// SAML 2.0: raw XML is base64url-encoded automatically.
new TokenExchangeAuthenticator(new SamlCredentials(assertionXml));

// Self-signed, HTTPS agent publishing a controlled identifier document:
const pair = await importKeyPair(privateJwk);
console.log(controlledIdentifierDocument("https://bot.example/agent", pair.publicJwk, "key-1"));
new TokenExchangeAuthenticator(SelfSignedCredentials.forAgent("https://bot.example/agent", pair, "key-1"));

// Restrict which authorization servers may receive your credentials (and for which storages):
new TokenExchangeAuthenticator(creds, { authorizationServerFilter: (issuer, storage) => issuer === "https://as.example" });
```

Plain `http` authorization servers are refused except on loopback hosts (or with
`allowInsecureHttp`). Implement `Authenticator` yourself for other schemes (cookies, DPoP…).

## Webhooks

```ts
import { WebhookVerifier } from "lws-client";
import { createWebhookHandler } from "lws-client/node";

const verifier = new WebhookVerifier({
  resolveStorageDescription: (id) => client.getStorageDescription(id),
  trustedStorages: [storage.id],
});
http.createServer(createWebhookHandler(verifier, (n) => console.log(n.activities), { inboxUrl })).listen(8790);
await client.subscribe(storage.notificationService()!, { topics: [storage.storageRoot()], inbox: inboxUrl });
```

`verify()` also accepts a Fetch API `Request` (Deno, Bun, Cloudflare Workers, Next.js route
handlers). It checks `Content-Digest`, the RFC 9421 signature over the required components,
the `created` window (300 s by default), that the key is an `authentication` key of the
storage, and that the notification's `storage` matches the signer.

## Development

```sh
npm install
npm run build        # dist/ (ESM + .d.ts)
npm test             # unit + fixture + in-process HTTP tests (Node ≥ 22 to run the suite)
npm run typecheck
```

The tests load the shared fixtures in [`../conformance/fixtures`](../conformance). The interop
scenario ([`../conformance/scenario.md`](../conformance/scenario.md)) runs against the mock
server when `LWS_TEST_SERVER` is set:

```sh
node ../testing/mock-server/server.mjs --port 8787 &
LWS_TEST_SERVER=http://localhost:8787 npm run test:interop
```
