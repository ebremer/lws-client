# LWS Client for Swift

A client for the [W3C Linked Web Storage (LWS) Protocol 1.0](https://www.w3.org/TR/lws10-core/) and its companion
specifications, as published by the LWS Working Group on 2026-10-05: discovery, resources and containers, linkset
metadata, OAuth 2.0 token exchange with the OpenID Connect / SAML 2.0 / self-signed (controlled identifier,
`did:key`) authentication suites, webhook notifications with RFC 9421 signature verification, access requests and
grants, and the type index / type search services.

* Swift 6 (language mode 6, strict concurrency); macOS 13, iOS 16, tvOS 16, watchOS 9, visionOS 1, and Linux
* `async throws` operations that honour task cancellation; listings are lazy `AsyncSequence`s; options and models are
  `Sendable` values; errors are one `LWSError` enum
* `URLSession` underneath (FoundationNetworking on Linux), behind a pluggable `HTTPTransport`; one dependency,
  [swift-crypto](https://github.com/apple/swift-crypto), which is CryptoKit on Apple platforms, for ES256 and EdDSA
* SwiftPM package `lws-client`, library product and module `LWS`
* MIT licensed (see [`../LICENSE`](../LICENSE))

## Install

The package is this repository. SwiftPM takes a package from a git repository only when its manifest is at the
root, so [`Package.swift`](../Package.swift) is there and points into `swift/`:

```swift
// Package.swift
dependencies: [
    .package(url: "https://github.com/ebremer/lws-client.git", from: "0.1.0"),
],
targets: [
    .target(name: "MyApp", dependencies: [.product(name: "LWS", package: "lws-client")]),
]
```

In Xcode: *File › Add Package Dependencies…*, `https://github.com/ebremer/lws-client.git`, product `LWS`. Until a
`0.1.0` tag exists, depend on a branch (`branch: "main"`) or a local checkout (`.package(path: "../lws-client")`).

## Quickstart

```swift
import Foundation
import LWS

// A did:key agent signs its own credential; the client exchanges it for access tokens on demand.
let me = try SelfSignedCredentials.didKey(.generateP256())
let client = LWSClient(authenticator: TokenExchangeAuthenticator(credentials: me))

let storage = try await client.discoverStorage(URL(string: "https://storage.example/root/")!)
let root = try storage.storageRoot()

let folder = try await client.createContainer(in: root, options: CreateOptions(slug: "notes"))
let note = try await client.createText(in: folder.location, text: "Hello, LWS!", options: CreateOptions(slug: "hello.txt"))

let r = try await client.read(note.location)
print(r.text, r.etag ?? "")

// Optimistic concurrency: throws LWSError.preconditionFailed if someone changed it meanwhile.
_ = try await client.update(note.location, body: Data("Hello again".utf8), contentType: "text/plain", options: UpdateOptions(ifMatch: r.etag))

let profile = try await client.createJSON(in: folder.location, json: ["name": "Alice", "age": 30], options: CreateOptions(slug: "profile.json")).location
_ = try await client.patch(profile, patch: JSONPatch().replace("/age", 31).add("/city", "Boston"))

for try await item in client.listContainer(folder.location) {   // lazy, follows rel="next"
    print(item.id, item.format ?? "")
}

try await client.delete(folder.location, options: DeleteOptions(recursive: true))   // Depth: infinity
```

Runnable versions live in [`Examples/`](Examples): `Quickstart`, `SelfSignedAuth` and `WebhookReceiver`
(`swift run Quickstart http://localhost:8787/root/` at the repository root).

## API at a glance

| Area | API |
|---|---|
| Client | `LWSClient(options: LWSClientOptions(transport:, authenticator:, userAgent:, defaultHeaders:, timeout:, maxRedirects:))`, `LWSClient(authenticator:)`, `withAuthenticator(_:)`; every operation takes options with `headers` and `timeout` |
| Discovery | `discoverStorage(_:)`, `getStorageDescription(_:)` → `StorageDescription` (`storageRoot()`, `notificationService`, `typeSearchService`, `service(_:)`, `verificationMethod(_:)`, …) |
| Read | `head`, `read` (`ReadOptions`: `accept`, `range` (`.bytes(0...99)`, `.from(n)`, `.suffix(n)`), `ifNoneMatch`, `ifModifiedSince`, `prefer`; a `304` is `notModified`), `readContainer`, `listContainer` (`PagedSequence`, an `AsyncSequence`) |
| Write | `create(in:body:contentType:options:)`, `createText(in:text:)`, `createJSON(in:json:)`, `createJSON(in:value:)` (any `Encodable`), `createContainer(in:)` (`CreateOptions`: `slug`, `links`, `types`), `update` (`UpdateOptions`: `ifMatch`, `ifNoneMatch`, `links`, `setLinkset`), `patch` (`JSONPatch` or any advertised format), `delete` (`recursive`) |
| Metadata | `linksetURL`, `readLinkset`, `readLinksetResource`, `updateLinkset`, `patchLinkset`; `Linkset` value (`links`, `targets`, `adding`, `removing`); `JSONPointer` |
| Auth | `Authenticator`; `TokenExchangeAuthenticator` (`TokenExchangeOptions`: `allowInsecureHttp`, `authorizationServerFilter`, `transport`, `refreshMargin`, `timeout`); `BearerTokenAuthenticator` (a token or a supplier, optional realm) |
| Auth suites | `OpenIDCredentials`, `SAMLCredentials`, `SelfSignedCredentials.forAgent(_:key:keyID:)` / `.didKey(_:)` (ES256, EdDSA); `SigningKey` / `VerificationKey` (generate, JWK import and export), `DIDKey`, `ControlledIdentifierDocument`, `JWT` |
| Notifications | `subscribe`, `listSubscriptions`, `getSubscription`, `unsubscribe`; `Notification.parse`; `WebhookVerifier` (RFC 9421 + RFC 9530) |
| Access | `requestAccess`, `listAccessRequests`, `getAccessRequest`, `cancelAccessRequest`, `grantAccess`, `listAccessGrants`, `getAccessGrant`, `revokeAccessGrant`; `AccessRequest`, `AccessGrant`, `AccessPolicy`, `AccessTarget`, `Constraint` factories |
| Type index / search | `readTypeIndex`, `listTypes`, `searchTypes` (HTTP `QUERY`), `searchAll`, `acceptedQueryFormats`; `TypeQuery` value (`allOf`, `anyOf`, `relation(_:)`) |
| HTTP primitives | `LinkHeader`/`Link` (RFC 8288), `WWWAuthenticate`/`AuthChallenge`, `StructuredFields` (RFC 8941/9651), `ProblemDetails` (RFC 9457), `Slug`, `HTTPHeaders` |
| JSON | `JSONValue` (with literals) and `JSONObject`, which keeps member order, so documents round-trip unchanged |
| Low level | `request(_:_:body:contentType:options:)` sends any method through the authentication and redirect pipeline |

Constants are grouped in caseless enums: `Vocabulary` (namespaces, contexts, type matching), `LinkRelation`,
`ResourceType`, `MediaType`, `ServiceType`, `SubscriptionType`, `TokenType`, `AccessAction`, `ConstraintOperand`,
`ConstraintOperator`, `Prefer`, `ActivityType`. Every returned URL is absolute.

## Errors

Every error the client throws is an `LWSError`:

| Case | Meaning |
|---|---|
| `.badRequest`, `.unauthorized`, `.forbidden`, `.notFound`, `.methodNotAllowed`, `.notAcceptable`, `.conflict`, `.gone`, `.preconditionFailed`, `.unsupportedMediaType`, `.unprocessableContent`, `.notImplemented`, `.insufficientStorage` | the status of the same name; each carries the `HTTPError` (`status`, `method`, `url`, `headers`, `problem`, `body`, `challenges`, `allow`, `acceptPatch`, `acceptQuery`) |
| `.http(HTTPError)` | any other error status (5xx: the LWS "unknown error") |
| `.authentication(AuthenticationError)` (`message`, `error`, `errorDescription`, `status`) | realm, HTTPS, filter or issuer checks failed, or the token exchange was refused |
| `.protocolError(String)` | the server response violates the specification |
| `.signatureVerification(String)` | a webhook delivery failed verification |
| `.transport(TransportError)` (`message`, `isTimeout`, `underlying`) | no response: connection failure or timeout |
| `.invalidArgument(String)` | a URL that is not absolute http(s), an invalid type query, key or policy |

```swift
do {
    _ = try await client.read(url)
} catch LWSError.notFound {
    print("no such resource")
} catch let e as LWSError where e.httpError != nil {
    print(e.status ?? 0, e.httpError?.problem?.title ?? e.description)
}
```

Cancelling the task throws `CancellationError`. `error.status` and `error.httpError` work across the cases.

## Authentication

```swift
// OpenID Connect: hand over the ID token your OIDC library obtained (or a closure that returns a fresh one).
let oidc = TokenExchangeAuthenticator(credentials: OpenIDCredentials(idToken: idToken))

// SAML 2.0: the assertion is base64url-encoded for the token exchange.
let saml = TokenExchangeAuthenticator(credentials: SAMLCredentials.fromXML(assertionXML))

// A self-signed agent with an HTTPS identifier: publish this document at the agent URL.
let key = SigningKey.generateEd25519()
let agent = URL(string: "https://bot.example/id")!
let cid = ControlledIdentifierDocument.create(agent: agent, key: key.publicKey, kid: "key-1")
let bot = TokenExchangeAuthenticator(
    credentials: SelfSignedCredentials.forAgent(agent, key: key, keyID: "https://bot.example/id#key-1"),
    options: TokenExchangeOptions(authorizationServerFilter: { asURI, _ in asURI.host?.hasSuffix(".example") == true }))

// Keep an identity across runs: persist key.jwk (secret) and reload it with SigningKey(jwk:).
```

Security behaviour: the challenge `realm` must contain the request URL, the authorization server must use HTTPS
(loopback hosts excepted, or `allowInsecureHttp` for tests) and pass the filter, and all of that is checked before a
cached token is touched, so a decoy `401` cannot evict a working token. Metadata and token requests never follow
redirects: a `3xx`, or a response from another URL than the one requested, is an authentication error, since a
redirect would carry the subject token elsewhere. The metadata `issuer` must equal `as_uri`. Storage requests follow
redirects in the client (at most 10), authorizing each hop for its own URL, so a token never leaves its realm; an
explicit `Authorization` header survives same-origin redirects only. `POST` is never sent twice except for the one
retry after a handled `401`. `TokenExchangeAuthenticator` is an actor: concurrent requests share one in-flight
exchange per realm.

## Webhooks

```swift
let verifier = WebhookVerifier(options: WebhookVerifierOptions(
    client: client,                         // fetches the storage description (the signing keys)
    trustedStorages: [storage.id]))         // when set (even empty), the signing storage must be in it
let v = try await verifier.verify(method: "POST", url: registeredInboxURL, headers: headers, body: body)
for a in v.notification.activities { print(a.types, a.object.id) }
```

Verify against the inbox URL as registered, not the URL a reverse proxy forwarded to: `@scheme`, `@authority` and
`@path` are signed. Any server can host the inbox (Vapor, Hummingbird, SwiftNIO…): pass the method, the registered
URL, the request headers (`HTTPHeaders`) and the body bytes. [`Examples/WebhookReceiver`](Examples/WebhookReceiver)
receives deliveries with a few lines of sockets.

## Transports

`LWSClientOptions.transport` and `TokenExchangeOptions.transport` take any `HTTPTransport`:

```swift
public protocol HTTPTransport: Sendable {
    func send(_ request: HTTPRequest) async throws -> HTTPResponse
}
```

The default, `URLSessionTransport`, owns a private `URLSession` (from `.ephemeral`, cookies and caching off) whose
delegate refuses every redirect. A transport must not follow redirects. On Linux, FoundationNetworking ignores a
per-task delegate, which is why the session-level one is used. The client's `timeout` is a hard limit on each request.

## Build and test

At the repository root (where `Package.swift` is):

```sh
swift build                                          # library, tests, examples and the driver adapter
swift test                                           # 84 tests (Swift Testing); the interop scenario is skipped
LWS_TEST_SERVER=http://localhost:8787 swift test     # also runs ../conformance/scenario.md against the mock server
```

Start the mock server first with `node testing/mock-server/server.mjs --port 8787` (Node 22+). The tests load the
shared fixtures in [`../conformance/fixtures`](../conformance/fixtures) (Link and `WWW-Authenticate` parsing,
structured fields, JSON Patch, type queries, did:key and JWT vectors, all 13 RFC 9421 webhook vectors, response
models) and run every operation against an in-process fake transport, including the full
`401 → metadata → token exchange → retry` flow and its security checks. The interop test receives the signed
notification on a local socket inbox and verifies it.

The [driver](../driver) adapter is the root package's `lws-driver-adapter-swift` product:

```sh
swift build -c release --product lws-driver-adapter-swift
node driver/adapters/check.mjs -- .build/release/lws-driver-adapter-swift
```

For a binary that needs only the system libcurl, add `--static-swift-stdlib`; with Swift 6.4 also add
`--build-system native` (the default build system does not link FoundationNetworking statically).

## License

MIT — see [LICENSE](../LICENSE).
