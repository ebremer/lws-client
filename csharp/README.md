# LWS Client for .NET (C#)

A client for the [W3C Linked Web Storage (LWS) Protocol 1.0](https://www.w3.org/TR/lws10-core/)
and its companion specifications, as published by the LWS Working Group in the Working Draft of
19 October 2026 (`w3c/lws-protocol` 9a08ff6): discovery, resources and containers, linkset metadata,
moving resources between containers, authorization server discovery through OAuth 2.0 Protected
Resource Metadata (RFC 9728) and the OAuth 2.0 token exchange with the OpenID Connect / SAML 2.0 /
self-signed (controlled identifier, `did:key`) authentication suites, webhook notifications with
RFC 9421 signature verification, access requests and grants, and the type index / type search
services.

* .NET 10 (`net10.0`); every operation is `async` and takes a `CancellationToken`, listings are `IAsyncEnumerable<T>`
* `HttpClient`, `System.Text.Json` and BCL `ECDsa`/`SHA256`/`SHA512` underneath; one dependency,
  [BouncyCastle.Cryptography](https://www.nuget.org/packages/BouncyCastle.Cryptography), for Ed25519 (.NET has none)
* NuGet package `Ebremer.Lws.Client`, root namespace `Ebremer.Lws`
* MIT licensed (see [`../LICENSE`](../LICENSE))

## Install

```sh
dotnet add package Ebremer.Lws.Client --version 0.1.0
```

Until the package is published, reference the project instead:
`dotnet add reference path/to/csharp/src/Ebremer.Lws.Client/Ebremer.Lws.Client.csproj`, or `dotnet pack` it
from this directory.

## Quickstart

```csharp
using System.Text.Json.Nodes;
using Ebremer.Lws;
using Ebremer.Lws.Auth;

// A did:key agent signs its own credential; the client exchanges it for access tokens on demand.
SelfSignedCredentials me = SelfSignedCredentials.DidKey(SigningKey.GenerateP256());
using var authenticator = new TokenExchangeAuthenticator(me);
using var client = new LwsClient(new LwsClientOptions { Authenticator = authenticator });

StorageDescription storage = await client.DiscoverStorageAsync(new Uri("https://storage.example/root/"));
Uri root = storage.GetStorageRoot();

CreateResult folder = await client.CreateContainerAsync(root, new CreateOptions { Slug = "notes" });
CreateResult note = await client.CreateTextAsync(folder.Location, "Hello, LWS!", options: new() { Slug = "hello.txt" });

Resource r = await client.ReadAsync(note.Location);
Console.WriteLine($"{r.GetText()} {r.ETag}");

// Optimistic concurrency: throws PreconditionFailedException if someone changed it meanwhile.
await client.UpdateAsync(note.Location, "Hello again"u8.ToArray(), "text/plain", new UpdateOptions { IfMatch = r.ETag });

Uri profile = (await client.CreateJsonAsync(folder.Location, new JsonObject { ["name"] = "Alice", ["age"] = 30 },
    new CreateOptions { Slug = "profile.json" })).Location;
await client.PatchAsync(profile, new JsonPatch().Replace("/age", 31).Add("/city", "Boston"));

await foreach (ContainedResource item in client.ListContainerAsync(folder.Location))   // lazy, follows rel="next"
    Console.WriteLine($"{item.Id} {item.Format}");

await client.DeleteAsync(folder.Location, new DeleteOptions { Recursive = true });     // Depth: infinity
```

Runnable versions live in [`examples/`](examples): `Quickstart`, `SelfSignedAuth` and `WebhookReceiver`
(`dotnet run --project examples/Quickstart -- http://localhost:8787/root/`).

## API at a glance

| Area | API |
|---|---|
| Client | `new LwsClient(LwsClientOptions { HttpClient \| HttpMessageHandler, Authenticator, UserAgent, DefaultHeaders, Timeout, MaxRedirects })`, `IDisposable`, `WithAuthenticator`; every operation takes `…Options` (`Headers`, `Timeout`) and a `CancellationToken` |
| Discovery | `DiscoverStorageAsync(resource)`, `GetStorageDescriptionAsync(storage)` → `StorageDescription` (`GetStorageRoot()`, `NotificationService`, `TypeSearchService`, `MoveCapability`, `GetService(type)`, `FindVerificationMethod(id)`, …) |
| Read | `HeadAsync`, `ReadAsync` (`ReadOptions`: `Accept`, `Range`, `IfNoneMatch`, `IfModifiedSince`, `Prefer`; a `304` is `NotModified`), `ReadStreamAsync`, `ReadContainerAsync`, `ListContainerAsync` (`IAsyncEnumerable`) |
| Write | `CreateAsync` (bytes or `Stream`), `CreateTextAsync`, `CreateJsonAsync`, `CreateContainerAsync` (`CreateOptions`: `Slug`, `Types`, `Links`), `UpdateAsync` (`UpdateOptions`: `IfMatch`, `IfNoneMatch`, `Links`, `SetLinkset`), `PatchAsync` (`JsonPatch` or any advertised format), `DeleteAsync` (`Recursive`) |
| Metadata | `LinksetUrlAsync`, `ReadLinksetAsync`, `ReadLinksetResourceAsync`, `UpdateLinksetAsync`, `PatchLinksetAsync`; immutable `Linkset` (`GetLinks`, `GetTargets`, `Add`, `Remove`); `JsonPointer` |
| Move | `MoveAsync(resource, destination)` (`MoveOptions`: `IfMatch`) → `MoveResult` (`Location`, `Linkset`, `IdentifierPreserved`, `ETag`, `Document`); `StorageDescription.MoveCapability` (`AppliesTo`, `PreservesIdentifier`, `MovesDataResources`, `MovesContainers`) |
| Auth | `IAuthenticator`; `TokenExchangeAuthenticator` (`TokenExchangeOptions`: `AllowInsecureHttp`, `AuthorizationServerFilter(issuer, storage)`, its own `HttpMessageHandler`/`HttpClient`, `RefreshMargin`, `Timeout`; `GetAccessTokenAsync(issuer, storage)`, `Clear()`); `ProtectedResourceMetadata`, `AuthorizationServerMetadata`; `BearerTokenAuthenticator` (a token or a supplier, optional realm) |
| Auth suites | `OpenIdCredentials`, `SamlCredentials`, `SelfSignedCredentials.ForAgent(...)` / `.DidKey(...)` (ES256, EdDSA); `SigningKey` / `VerificationKey` (generate, JWK import and export), `DidKey`, `ControlledIdentifierDocument`, `Jwt` |
| Notifications | `SubscribeAsync`, `ListSubscriptionsAsync`, `GetSubscriptionAsync`, `UnsubscribeAsync`; `Notification.Parse`; `WebhookVerifier` (RFC 9421 + RFC 9530), with an `HttpListenerRequest` overload |
| Access | `RequestAccessAsync`, `ListAccessRequestsAsync`, `GetAccessRequestAsync`, `CancelAccessRequestAsync`, `GrantAccessAsync`, `ListAccessGrantsAsync`, `GetAccessGrantAsync`, `RevokeAccessGrantAsync`; `AccessRequest`, `AccessGrant`, `AccessPolicy`, `AccessTarget`, `Constraint` factories |
| Type index / search | `ReadTypeIndexAsync`, `ListTypesAsync`, `SearchTypesAsync` (HTTP `QUERY`), `SearchAllAsync`, `AcceptedQueryFormatsAsync`; immutable `TypeQuery` (`AllOf`, `AnyOf`, `Relation(rel)`) |
| HTTP primitives (`Ebremer.Lws.Http`) | `LinkHeader`/`Link` (RFC 8288), `WwwAuthenticate`/`AuthChallenge`, `StructuredFields` (RFC 8941/9651), `ProblemDetails` (RFC 9457), `Slug`, `HeaderMap` |
| Low level | `RequestAsync(method, url, …)` sends any request through the authentication and redirect pipeline |

Namespaces: `Ebremer.Lws` (client, models, errors, `Lws` constants, `JsonPatch`, `TypeQuery`), `Ebremer.Lws.Auth`,
`Ebremer.Lws.Http`, `Ebremer.Lws.Notifications`, `Ebremer.Lws.Access`. Every returned URL is absolute.

## Errors

Every exception extends `LwsException`. Arguments that are not absolute http(s) URLs throw `ArgumentException`;
cancelling the token throws `OperationCanceledException`.

| Exception | Meaning |
|---|---|
| `HttpException` (`Status`, `Method`, `Uri`, `Headers`, `Problem`, `Body`) | any error status; subclasses `BadRequestException` 400, `UnauthorizedException` 401 (`Challenges`), `ForbiddenException` 403, `NotFoundException` 404, `MethodNotAllowedException` 405 (`Allow`), `NotAcceptableException` 406, `ConflictException` 409, `GoneException` 410, `PreconditionFailedException` 412, `UnsupportedMediaTypeException` 415 (`AcceptPatch`, `AcceptQuery`), `UnprocessableContentException` 422, `HttpNotImplementedException` 501, `InsufficientStorageException` 507 |
| `AuthenticationException` (`Error`, `ErrorDescription`, `Status`) | a discovery check (protected resource metadata, storage root), the realm check of the earlier challenge, or the HTTPS, filter or issuer checks failed, or the token exchange was refused |
| `ProtocolException` | the server response violates the specification |
| `SignatureVerificationException` | a webhook delivery failed verification |
| `LwsTransportException` | no response: connection failure or timeout (the `InnerException` is the `HttpRequestException`, `IOException` or `TimeoutException`) |

The 501 exception is `HttpNotImplementedException` rather than `NotImplementedException`, so that importing
`Ebremer.Lws` never clashes with `System.NotImplementedException`.

## Authentication

```csharp
// OpenID Connect: hand over the ID token your OIDC library obtained (or a callback that returns a fresh one).
var oidc = new TokenExchangeAuthenticator(new OpenIdCredentials(idToken));

// SAML 2.0: the assertion is base64url-encoded for the token exchange.
var saml = new TokenExchangeAuthenticator(SamlCredentials.FromXml(assertionXml));

// A self-signed agent with an HTTPS identifier: publish this document at the agent URL.
SigningKey key = SigningKey.GenerateEd25519();
JsonObject cid = ControlledIdentifierDocument.Create(new Uri("https://bot.example/id"), key.PublicKey, "key-1");
var bot = new TokenExchangeAuthenticator(
    SelfSignedCredentials.ForAgent(new Uri("https://bot.example/id"), key, "https://bot.example/id#key-1"),
    new TokenExchangeOptions { AuthorizationServerFilter = (issuer, storage) => issuer.Host.EndsWith(".example") });

// Keep an identity across runs: persist key.ToJwk() (secret) and reload it with SigningKey.FromJwk(jwk).
```

The flow: a storage answers `401` with `WWW-Authenticate: Bearer resource_metadata="…"` and a `Link` to its storage.
Before it asks for a token the authenticator checks what the `401` told it against the URL that drew it (lws10-core
"Discovery Validation by a Client"): the protected resource metadata (RFC 9728) is on the requested origin and names
exactly the requested URL, and the storage's root, from its storage description, is on that origin too. The issuer is
the first of the metadata's `authorization_servers` that uses HTTPS (loopback hosts excepted, or `AllowInsecureHttp`
for tests) and passes the filter, and its metadata `issuer` must match. The token is requested for the storage
(`resource=<storage>`), cached per issuer and storage, and sent ahead of a `401` to URLs inside the storage or its
root only (the longest such scope wins); the retry of the request that drew the `401` carries it even outside that
scope. All of that is checked before a cached token is touched, so a decoy `401` cannot evict a working token. The
challenge of the drafts before 19 October 2026 (`Bearer as_uri="…", realm="…"`) is still followed: the realm must
contain the request URL, and is the storage and the token's scope.

Protected resource metadata, storage description, metadata and token requests never follow redirects (a redirect
would carry the subject token elsewhere; a handler that follows redirects is refused); storage descriptions are cached
until `Clear()`. Storage requests follow redirects in the client (at most 10), authorizing each hop for its own URL,
so a token never leaves its scope; an explicit `Authorization` header survives same-origin redirects only. `POST` is
never sent twice except for the one retry after a handled `401`. A streamed request body cannot be replayed, so the
client establishes a token first with a `HEAD`.

## Moving resources

```csharp
StorageDescription storage = await client.DiscoverStorageAsync(note.Location);
if (storage.MoveCapability is { MovesDataResources: true })
{
    // Reads the linkset, then patches its up link (test + replace), conditional on the linkset's ETag.
    MoveResult moved = await client.MoveAsync(note.Location, archive);
    Uri now = moved.Location;   // a storage that does not keep identifiers gives the resource a new URL
}
```

Without a `MoveResource` capability the `up` link is not modifiable and the storage refuses the patch
(`ConflictException`), as it refuses a destination that is not a container or lies inside the moved container. Unless
the capability says `PreservesIdentifier: true`, rely on `MoveResult.Location` for the resource's URL after the move.

## Webhooks

```csharp
using var verifier = new WebhookVerifier(new WebhookVerifierOptions
{
    Client = client,                        // fetches the storage description (the signing keys)
    TrustedStorages = [storage.Id],         // when set (even empty), the signing storage must be in it
});
VerifiedNotification v = await verifier.VerifyAsync("POST", registeredInboxUrl, HeaderMap.From(headers), body);
foreach (Activity a in v.Notification.Activities) Console.WriteLine($"{string.Join(",", a.Types)} {a.Object.Id}");

// With HttpListener: await verifier.VerifyAsync(context.Request, registeredInboxUrl)
```

Verify against the inbox URL as registered, not the URL a reverse proxy forwarded to: `@scheme`, `@authority` and
`@path` are signed. ASP.NET Core applications pass `Request.Method`, the registered URL, the request headers
(`HeaderMap.From(...)`) and the body bytes.

## Build and test

```sh
dotnet build csharp                    # library, tests and examples (warnings are errors)
dotnet test csharp                     # 193 tests; the interop scenario is skipped
LWS_TEST_SERVER=http://localhost:8787 dotnet test csharp   # also runs ../conformance/scenario.md against the mock server
dotnet pack csharp/src/Ebremer.Lws.Client -c Release      # the NuGet package
```

Start the mock server first with `node testing/mock-server/server.mjs --port 8787` (Node 22+). The tests load the
shared fixtures in [`../conformance/fixtures`](../conformance/fixtures) (Link and `WWW-Authenticate` parsing,
structured fields, JSON Patch, type queries, did:key and JWT vectors, all 13 RFC 9421 webhook vectors, response
models, the discovery and move vectors) and run every operation against an in-process fake `HttpMessageHandler`,
including the full `401 → protected resource metadata → storage description → AS metadata → token exchange → retry`
flow with every case of `discovery.json`, its security checks, and moves.

The [driver](../driver) adapter builds against this library:

```sh
dotnet publish driver/adapters/csharp -c Release -r linux-x64 --self-contained -p:PublishSingleFile=true -o driver/adapters/csharp/bin
node driver/adapters/check.mjs -- driver/adapters/csharp/bin/lws-driver-adapter-csharp
```

The test project uses xUnit v3 (`xunit.v3` 4.0.1) through `xunit.runner.visualstudio` and `Microsoft.NET.Test.Sdk`,
so `dotnet test` runs it in VSTest mode without a `global.json`.

## License

MIT — see [LICENSE](../LICENSE).
