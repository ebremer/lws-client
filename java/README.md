# LWS Client for Java

A client for the [W3C Linked Web Storage (LWS) Protocol 1.0](https://www.w3.org/TR/lws10-core/)
and its companion specifications, as published by the LWS Working Group on 2026-10-05:
discovery, resources and containers, linkset metadata, OAuth 2.0 token exchange with the OpenID
Connect / SAML 2.0 / self-signed (controlled identifier, `did:key`) authentication suites, webhook
notifications with RFC 9421 signature verification, access requests and grants, and the type
index / type search services.

* Java 17+ (uses records and sealed types; picks virtual threads automatically on Java 21+)
* `java.net.http.HttpClient` underneath; one runtime dependency: Jackson databind
* JPMS module `com.ebremer.lws`
* MIT licensed (see [`../LICENSE`](../LICENSE))

## Install

```xml
<dependency>
  <groupId>com.ebremer</groupId>
  <artifactId>lws-client</artifactId>
  <version>0.1.0</version>
</dependency>
```

Gradle: `implementation("com.ebremer:lws-client:0.1.0")`. Until the artifact is published, build it
locally with `mvn install` from this directory.

## Quickstart

```java
import com.ebremer.lws.*;
import com.ebremer.lws.auth.*;
import com.ebremer.lws.patch.JsonPatch;

// A did:key agent signs its own credential; the client exchanges it for access tokens on demand.
SelfSignedCredentials me = SelfSignedCredentials.didKey(KeyPairs.generateP256());
LwsClient client = LwsClient.builder()
        .authenticator(TokenExchangeAuthenticator.of(me))
        .build();

StorageDescription storage = client.discoverStorage(URI.create("https://storage.example/root/"));
URI root = storage.storageRoot();

CreateResult folder = client.createContainer(root, CreateOptions.slug("notes"));
CreateResult note = client.create(folder.location(), Body.of("Hello, LWS!"), "text/plain",
        CreateOptions.slug("hello.txt"));

Resource r = client.read(note.location());
System.out.println(r.text() + " " + r.etag().orElseThrow());

// Optimistic concurrency: throws PreconditionFailedException if someone changed it meanwhile.
client.update(note.location(), Body.of("Hello again"), "text/plain", UpdateOptions.ifMatch(r.etag().get()));

URI profile = client.createJson(folder.location(), Map.of("name", "Alice", "age", 30),
        CreateOptions.slug("profile.json")).location();
client.patch(profile, JsonPatch.builder().replace("/age", 31).add("/city", "Boston").build());

client.listContainer(folder.location())            // lazy Stream, follows rel="next" pages
      .forEach(item -> System.out.println(item.id() + " " + item.format().orElse("")));

client.delete(folder.location(), DeleteOptions.recursive());   // Depth: infinity
```

Runnable versions live in [`src/examples/java`](src/examples/java/com/ebremer/lws/examples):
`Quickstart`, `SelfSignedAuth` and `WebhookReceiver`.

## Features

| Area | API |
|---|---|
| Discovery | `discoverStorage(resource)`, `getStorageDescription(storage)` → `StorageDescription` (`storageRoot()`, `notificationService()`, `typeSearchService()`, …) |
| Read | `head`, `read` (conditional `304` → `notModified()`, byte ranges), `readStream`, `readContainer`, `listContainer` (lazy `Stream`) |
| Write | `create`, `createJson`, `createContainer` (identity hint via `Slug`, extra types and links), `update` (PUT), `patch` (JSON Patch or any advertised format), `delete` (recursive) |
| Metadata | `linksetUrl`, `readLinkset`, `readLinksetResource`, `updateLinkset`, `patchLinkset`; immutable `Linkset` model; `JsonPointer` escaping |
| Auth | pluggable `Authenticator`; `TokenExchangeAuthenticator` (401 → `/.well-known/lws-configuration` → RFC 8693 token exchange → retry, token cache, realm and HTTPS checks); `BearerTokenAuthenticator` |
| Auth suites | `OpenIdCredentials`, `SamlCredentials`, `SelfSignedCredentials` (ES256 / EdDSA, `did:key`); `KeyPairs`, `Jwk`, `DidKey`, `ControlledIdentifiers`, `Jwt` |
| Notifications | `subscribe`, `listSubscriptions`, `getSubscription`, `unsubscribe`; `Notification` model; `WebhookVerifier` (RFC 9421 + RFC 9530) and `HttpExchangeWebhooks` adapter |
| Access | `requestAccess`, `listAccessRequests`, `getAccessRequest`, `cancelAccessRequest`, `grantAccess`, `listAccessGrants`, `getAccessGrant`, `revokeAccessGrant`; builders with ODRL `Constraint` factories |
| Type index / search | `readTypeIndex`, `listTypes`, `searchTypes` (HTTP `QUERY`), `searchAll`, `acceptedQueryFormats`; `TypeQuery` builder |
| Async | `headAsync`, `readAsync`, `readContainerAsync`, `createAsync`, `createContainerAsync`, `updateAsync`, `patchAsync`, `deleteAsync`, `discoverStorageAsync`, `getStorageDescriptionAsync` |
| Parsers | `LinkHeader` (RFC 8288), `WwwAuthenticate`, `StructuredFields` (RFC 8941/9651), `ProblemDetails` (RFC 9457) |

## Errors

All exceptions are unchecked and extend `LwsException`:

| Exception | Meaning |
|---|---|
| `HttpStatusException` (`status()`, `problem()`, `headers()`) | any error status; subclasses `BadRequestException` 400, `UnauthorizedException` 401 (`challenges()`), `ForbiddenException` 403, `NotFoundException` 404, `MethodNotAllowedException` 405 (`allow()`), `NotAcceptableException` 406, `ConflictException` 409, `GoneException` 410, `PreconditionFailedException` 412, `UnsupportedMediaTypeException` 415 (`acceptPatch()`, `acceptQuery()`), `UnprocessableContentException` 422, `NotImplementedException` 501, `InsufficientStorageException` 507 |
| `AuthenticationException` (`error()`) | realm/HTTPS/issuer checks or the token exchange failed |
| `LwsProtocolException` | the server response violates the specification |
| `SignatureVerificationException` | a webhook delivery failed verification |
| `LwsTransportException` | I/O failure, timeout or interruption |

## Authentication

```java
// OpenID Connect: hand over the ID token your OIDC library obtained.
TokenExchangeAuthenticator oidc = TokenExchangeAuthenticator.of(OpenIdCredentials.from(() -> currentIdToken()));

// SAML 2.0: the assertion is base64url-encoded for the token exchange.
TokenExchangeAuthenticator saml = TokenExchangeAuthenticator.of(SamlCredentials.ofXml(assertionXml));

// Self-signed agent with an HTTPS identifier: publish this document at the agent URL.
KeyPair keys = KeyPairs.generateEd25519();
ObjectNode cid = ControlledIdentifiers.document(URI.create("https://bot.example/id"), keys.getPublic(), "key-1");
TokenExchangeAuthenticator bot = TokenExchangeAuthenticator.builder(
        SelfSignedCredentials.forAgent(URI.create("https://bot.example/id"), keys.getPrivate(), "key-1"))
    .authorizationServerFilter((as, realm) -> as.getHost().endsWith(".example"))   // optional allow-list
    .build();
```

Security behaviour: the challenge `realm` must contain the request URL, authorization servers must use
HTTPS (loopback hosts excepted, or `allowInsecureHttp(true)` for tests), the metadata `issuer` must
equal `as_uri`, tokens are only sent to URLs inside their realm, and redirects are followed by the
client itself so credentials are re-evaluated for every target.

## Webhooks

```java
WebhookVerifier verifier = WebhookVerifier.builder()
        .client(client)                                   // fetches the storage description (signing keys)
        .trustedStorages(List.of(storage.id()))
        .build();
VerifiedNotification v = verifier.verify("POST", registeredInboxUrl, requestHeaders, requestBody);
v.notification().activities().forEach(a -> System.out.println(a.types() + " " + a.object().id()));
```

## Build and test

```sh
mvn verify                                    # compile (release 17), 97 tests, package
LWS_TEST_SERVER=http://localhost:8787 mvn verify   # also run the cross-language interop scenario
```

The tests load the shared fixtures in [`../conformance/fixtures`](../conformance/fixtures) (Link and
`WWW-Authenticate` parsing, structured fields, JSON Patch, type queries, did:key and JWT vectors, all
13 RFC 9421 webhook vectors, response models) and run every operation against an in-process mock
server. The interop test follows [`../conformance/scenario.md`](../conformance/scenario.md) against
[`../testing/mock-server`](../testing/mock-server).
