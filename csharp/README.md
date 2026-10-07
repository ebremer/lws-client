# LWS Client for .NET (C#)

A client for the [W3C Linked Web Storage (LWS) Protocol 1.0](https://www.w3.org/TR/lws10-core/)
and its companion specifications, as published by the LWS Working Group on 2026-10-05:
discovery, resources and containers, linkset metadata, OAuth 2.0 token exchange with the OpenID
Connect / SAML 2.0 / self-signed (controlled identifier, `did:key`) authentication suites, webhook
notifications with RFC 9421 signature verification, access requests and grants, and the type
index / type search services.

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
| Discovery | `DiscoverStorageAsync(resource)`, `GetStorageDescriptionAsync(storage)` → `StorageDescription` (`GetStorageRoot()`, `NotificationService`, `TypeSearchService`, `GetService(type)`, `FindVerificationMethod(id)`, …) |
| Read | `HeadAsync`, `ReadAsync` (`ReadOptions`: `Accept`, `Range`, `IfNoneMatch`, `IfModifiedSince`, `Prefer`; a `304` is `NotModified`), `ReadStreamAsync`, `ReadContainerAsync`, `ListContainerAsync` (`IAsyncEnumerable`) |
| Write | `CreateAsync` (bytes or `Stream`), `CreateTextAsync`, `CreateJsonAsync`, `CreateContainerAsync` (`CreateOptions`: `Slug`, `Types`, `Links`), `UpdateAsync` (`UpdateOptions`: `IfMatch`, `IfNoneMatch`, `Links`, `SetLinkset`), `PatchAsync` (`JsonPatch` or any advertised format), `DeleteAsync` (`Recursive`) |
| Metadata | `LinksetUrlAsync`, `ReadLinksetAsync`, `ReadLinksetResourceAsync`, `UpdateLinksetAsync`, `PatchLinksetAsync`; immutable `Linkset` (`GetLinks`, `GetTargets`, `Add`, `Remove`); `JsonPointer` |
| Auth | `IAuthenticator`; `TokenExchangeAuthenticator` (`TokenExchangeOptions`: `AllowInsecureHttp`, `AuthorizationServerFilter`, its own `HttpMessageHandler`/`HttpClient`, `RefreshMargin`, `Timeout`); `BearerTokenAuthenticator` (a token or a supplier, optional realm) |
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
| `AuthenticationException` (`Error`, `ErrorDescription`, `Status`) | realm, HTTPS, filter or issuer checks failed, or the token exchange was refused |
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
    new TokenExchangeOptions { AuthorizationServerFilter = (asUri, realm) => asUri.Host.EndsWith(".example") });

// Keep an identity across runs: persist key.ToJwk() (secret) and reload it with SigningKey.FromJwk(jwk).
```

Security behaviour: the challenge `realm` must contain the request URL, the authorization server must use HTTPS
(loopback hosts excepted, or `AllowInsecureHttp` for tests) and pass the filter, and all of that is checked before a
cached token is touched, so a decoy `401` cannot evict a working token. Metadata and token requests never follow
redirects (a redirect would carry the subject token elsewhere; a handler that follows redirects is refused). The
metadata `issuer` must equal `as_uri`. Storage requests follow redirects in the client (at most 10), authorizing each
hop for its own URL, so a token never leaves its realm; an explicit `Authorization` header survives same-origin
redirects only. `POST` is never sent twice except for the one retry after a handled `401`. A streamed request body
cannot be replayed, so the client establishes a token first with a `HEAD`.

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
dotnet test csharp                     # 150 tests; the interop scenario is skipped
LWS_TEST_SERVER=http://localhost:8787 dotnet test csharp   # also runs ../conformance/scenario.md against the mock server
dotnet pack csharp/src/Ebremer.Lws.Client -c Release      # the NuGet package
```

Start the mock server first with `node testing/mock-server/server.mjs --port 8787` (Node 22+). The tests load the
shared fixtures in [`../conformance/fixtures`](../conformance/fixtures) (Link and `WWW-Authenticate` parsing,
structured fields, JSON Patch, type queries, did:key and JWT vectors, all 13 RFC 9421 webhook vectors, response
models) and run every operation against an in-process fake `HttpMessageHandler`, including the full
`401 → metadata → token exchange → retry` flow and its security checks.

The [driver](../driver) adapter builds against this library:

```sh
dotnet publish driver/adapters/csharp -c Release -r linux-x64 --self-contained -p:PublishSingleFile=true -o driver/adapters/csharp/bin
node driver/adapters/check.mjs -- driver/adapters/csharp/bin/lws-driver-adapter-csharp
```

The test project uses xUnit v3 (`xunit.v3` 4.0.1) through `xunit.runner.visualstudio` and `Microsoft.NET.Test.Sdk`,
so `dotnet test` runs it in VSTest mode without a `global.json`.

## License

MIT — see [LICENSE](../LICENSE).
