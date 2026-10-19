# lws-client for Go

A Go client for the W3C **Linked Web Storage (LWS)** protocol — the LWS 1.0 core protocol plus the
OpenID Connect, SAML 2.0 and self-signed (Controlled Identifier / `did:key`) authentication suites,
Webhook notifications, access requests/grants and the Type Index / Type Search services — targeting
the W3C LWS Working Group specifications as of 2026-10-19 (the Working Draft of 19 October 2026,
`w3c/lws-protocol` commit `9a08ff6`).

* Zero dependencies — only the Go standard library (`net/http`, `encoding/json`, `crypto/*`, `iter`).
* `context.Context` on every network call, lazy pagination with `iter.Seq2`, `errors.Is` /
  `errors.As`-friendly errors.
* Transparent OAuth 2.0 token exchange, found through protected resource metadata (RFC 9728) and
  the discovery checks of lws10-core, with per-storage token caching and single-flight refresh.
* RFC 9421 / RFC 9530 webhook signature verification with an `http.Handler` helper.
* MIT licensed.

Requires Go 1.23 or later.

```sh
go get github.com/ebremer/lws-client/go
```

```go
import lws "github.com/ebremer/lws-client/go"
```

## Quickstart

```go
ctx := context.Background()

// Self-signed did:key credentials (lws10-authn-ssi-cid). The client exchanges them for access
// tokens automatically whenever the storage answers 401.
key, _ := lws.GenerateP256Key()
creds, _ := lws.NewDIDKeyCredentials(key, nil)
client := lws.NewClient(lws.WithAuthenticator(lws.NewTokenExchangeAuthenticator(creds, nil)))

storage, err := client.DiscoverStorage(ctx, "https://storage.example/root/")
if err != nil {
	log.Fatal(err)
}
root, _ := storage.StorageRoot()

// Create a container and a resource (the server assigns the final URI; Slug is a hint).
notes, _ := client.CreateContainer(ctx, root, lws.Slug("notes"))
note, _ := client.Create(ctx, notes.Location, strings.NewReader("milk\neggs\n"), "text/plain",
	lws.Slug("shopping.txt"))

// Read, then update conditionally.
res, _ := client.Read(ctx, note.Location)
fmt.Println(res.Text(), res.ETag, res.Parent)
_, err = client.Update(ctx, note.Location, strings.NewReader("milk\n"), "text/plain", lws.IfMatch(res.ETag))
if errors.Is(err, lws.ErrPreconditionFailed) {
	// someone else changed it
}

// JSON + JSON Patch (the LWS baseline patch format).
p, _ := client.CreateJSON(ctx, notes.Location, map[string]any{"name": "Alice", "age": 30},
	lws.Types("https://schema.org/Person"))
client.Patch(ctx, p.Location, lws.JSONPatch{}.Replace("/age", 31))

// Iterate over every member across all pages.
for item, err := range client.ListContainer(ctx, notes.Location) {
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(item.ID, item.Format, item.Size)
}

// Move a resource into another container, if the storage moves resources. A storage that does
// not keep identifiers gives it a new URL.
if move, ok := storage.MoveCapability(); ok && move.MovesDataResources() {
	archive, _ := client.CreateContainer(ctx, root, lws.Slug("archive"))
	moved, err := client.Move(ctx, note.Location, archive.Location)
	if err == nil {
		fmt.Println(moved.Location, moved.IdentifierPreserved)
	}
}

// Delete recursively.
client.Delete(ctx, notes.Location, lws.Recursive())
```

## API overview

### Client and options

| Constructor / option | Purpose |
|---|---|
| `lws.NewClient(opts ...Option) *Client` | safe for concurrent use |
| `WithHTTPClient(*http.Client)`, `WithAuthenticator(Authenticator)`, `WithUserAgent(string)`, `WithHeader(k, v)`, `WithTimeout(d)` | client options |

Per-call options (`...CallOption`): `Slug`, `Types`, `Links`, `IfMatch`, `IfNoneMatch`,
`IfModifiedSince`, `Accept`, `ByteRange`, `Prefer`, `SetLinkset`, `Recursive`, `Header`.
Each method documents the options it honours.

### Operations

| Area | Methods |
|---|---|
| Discovery | `DiscoverStorage(ctx, resourceURL)`, `GetStorageDescription(ctx, storageURL)` → `*StorageDescription` (`StorageRoot()`, `Service(type)`, `NotificationService()`, `AccessRequestService()`, `AccessGrantService()`, `TypeIndexService()`, `TypeSearchService()`, `Capability(type)`, `MoveCapability()` → `MoveCapability` (`AppliesTo`, `PreservesIdentifier`, `MovesDataResources()`, `MovesContainers()`), `VerificationMethod(id)`) |
| Read | `Head`, `Read` (→ `*Resource`, `NotModified` on 304), `ReadStream`, `ReadContainer` (→ `*ContainerPage`), `ListContainer` / `ListContainerPages` (`iter.Seq2`) |
| Write | `Create`, `CreateJSON`, `CreateContainer` (→ `*CreateResult`), `Update` (PUT), `Patch` (`JSONPatch`), `PatchRaw`, `Delete` |
| Metadata | `LinksetURL`, `ReadLinkset`, `ReadLinksetAt` (→ `*LinksetDocument`), `UpdateLinkset`, `PatchLinkset`; `Linkset` model with `Links`, `Targets`, `TargetsFor`, `Add`, `Remove` |
| Move | `Move(ctx, resourceURL, destinationURL)` (→ `*MoveResult`: `Location`, `Linkset`, `IdentifierPreserved`, `ETag`): reads the linkset and patches its `up` link, conditionally on its ETag; `MovePatch` builds that patch |
| Notifications | `Subscribe`, `SubscribeWebhook`, `ListSubscriptions`, `GetSubscription`, `Unsubscribe`; `ParseNotification` (activities with `IsCreate()`, `IsUpdate()`, `IsDelete()`, `IsMove()`); `WebhookVerifier` (`Verify`, `VerifyRequest`, `Handler`) |
| Access | `RequestAccess`, `ListAccessRequests`, `GetAccessRequest`, `CancelAccessRequest`, `GrantAccess`, `ListAccessGrants`, `GetAccessGrant`, `RevokeAccessGrant`; builders `NewAccessRequest`, `NewAccessGrant`, `NewAccessPolicy(...).WithTarget(...).WithConstraints(...)`, constraint helpers `PurposeConstraint`, `ClientConstraint`, `FormatAnyOf`, `TypeAnyOf`, `NotBefore`, `NotAfter`, … |
| Type index/search | `ReadTypeIndex`, `ListTypes`, `SearchTypes` (HTTP `QUERY`), `SearchPage`, `SearchAll`, `AcceptedQueryFormats`; `NewTypeQuery().AnyOf(...).AllOf(...).RelationAnyOf(rel, ...)` |

### Authentication

| Type | Suite / purpose |
|---|---|
| `TokenExchangeAuthenticator` | LWS flow: 401 challenge (`resource_metadata`) → protected resource metadata (RFC 9728) → storage description → AS metadata (`/.well-known/lws-configuration`) → RFC 8693 token exchange for the storage → retry; cached per (issuer, storage); options `AllowInsecureHTTP`, `AuthorizationServerFilter(issuer, storage)`, `HTTPClient`, `Clock` |
| `BearerTokenAuthenticator` | a known access token (optionally scoped to a realm) |
| `OpenIDCredentials` | OpenID Connect ID tokens (`urn:ietf:params:oauth:token-type:id_token`) |
| `SAMLCredentials` | SAML 2.0 assertions (`…:saml2`), `EncodeSAMLAssertion` |
| `SelfSignedCredentials` | self-signed JWTs (`…:jwt`), ES256 / EdDSA: `NewSelfSignedCredentials(agentURI, key, kid, opts)`, `NewDIDKeyCredentials(key, opts)` |

Key helpers: `GenerateP256Key`, `GenerateEd25519Key`, `JWK` (`PublicKey`, `PrivateKey`),
`JWKFromPublicKey`, `JWKFromPrivateKey`, `DIDKeyFromPublicKey`, `PublicKeyFromDIDKey`,
`DIDKeyVerificationMethod`, `NewControlledIdentifierDocument`, `SignJWT`, `VerifyJWT`, `DecodeJWT`.

Implement the two-method `Authenticator` interface for anything else (cookies, DPoP, mTLS …).

#### What happens on a 401

A storage answers `401` with `WWW-Authenticate: Bearer resource_metadata="…"` and a `Link` with rel
`https://www.w3.org/ns/lws#storage`. Before it asks for a token, the `TokenExchangeAuthenticator`
checks what the `401` told it against the URL that drew it (lws10-core "Discovery Validation by a
Client"): the metadata URL has the requested URL's scheme and authority (`SameOrigin`); the protected
resource metadata (`FetchProtectedResourceMetadata`, `ProtectedResourceMetadata`) names exactly that
URL (`SameResource`); and the root of the storage the `Link` names, read from its description (cached
until `ClearTokens`), is on the same origin. The first of the metadata's `authorization_servers` that
is `https` (or loopback, or `AllowInsecureHTTP`) and passes the filter is asked for a token whose
`resource` is the storage. The retry of the request carries the token, even to a URL outside the
storage and its root, as that URL has just passed the checks; later requests send it ahead only to URLs
inside the storage and its root, and nowhere else (not across redirects either). None of these requests
follows a redirect. A `401` that
fails a check gets an `*AuthenticationError`, no token request, and does not cost the client the token
it has.

From servers of the drafts before 19 October 2026, which send `Bearer as_uri="…", realm="…"` and no
`resource_metadata`, the challenge is still followed: the realm must contain the requested URL
(`RealmContains`), and is then the token's `resource` and the only place it is sent.

### Webhook receiver

```go
verifier := lws.NewWebhookVerifier(&lws.WebhookVerifierOptions{
	TrustedStorages: []string{storage.ID},
})
http.Handle("/inbox", verifier.Handler("https://receiver.example/inbox",
	func(ctx context.Context, n *lws.VerifiedNotification) {
		for _, a := range n.Notification.Activities {
			log.Println(a.Types, a.Object.ID)
		}
	}))
sub, _ := client.SubscribeWebhook(ctx, storage, lws.WebhookSubscriptionRequest{
	Topics: []string{notes.Location},
	Inbox:  "https://receiver.example/inbox",
})
```

The verifier checks `Content-Digest`, the covered components, the `created` window, resolves the
`keyid` against the storage description (which must list the key under `authentication`), verifies
ES256/Ed25519 signatures, refetches once on key rotation and checks that the notification's
`storage` matches the signing storage.

### Errors

Non-2xx responses return `*lws.HTTPError` (`StatusCode`, `Header`, `Problem` (RFC 9457),
`Challenges`, `Allow()`, `AcceptPatch()`, `AcceptQuery()`), which matches the sentinels
`ErrBadRequest`, `ErrUnauthorized`, `ErrForbidden`, `ErrNotFound`, `ErrMethodNotAllowed`,
`ErrNotAcceptable`, `ErrConflict`, `ErrGone`, `ErrPreconditionFailed`, `ErrUnsupportedMediaType`,
`ErrUnprocessableContent`, `ErrNotImplemented`, `ErrInsufficientStorage` via `errors.Is`.
Other failures: `*AuthenticationError` (OAuth `Code`/`Description`; also a failed discovery or realm
check), `*ProtocolError`, `*SignatureVerificationError`.

## Examples

```sh
node ../testing/mock-server/server.mjs --port 8787      # in another terminal
go run ./examples/quickstart -url http://localhost:8787/root/
go run ./examples/selfsigned -url http://localhost:8787/root/ -key agent.jwk
go run ./examples/webhook    -url http://localhost:8787/root/ -listen 127.0.0.1:9000
```

## Build and test

```sh
go vet ./...
go test ./...                    # unit + shared conformance fixtures (../conformance/fixtures), discovery.json through the authenticator
go test -race ./...              # requires cgo
LWS_TEST_SERVER=http://localhost:8787 go test -run TestInterop -v .   # interop scenario
```

## License

MIT — see [LICENSE](../LICENSE).
