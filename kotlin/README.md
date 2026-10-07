# LWS Client for Kotlin

A client for the [W3C Linked Web Storage (LWS) Protocol 1.0](https://www.w3.org/TR/lws10-core/) and its companion
specifications, as published by the LWS Working Group on 2026-10-05: discovery, resources and containers, linkset
metadata, OAuth 2.0 token exchange with the OpenID Connect / SAML 2.0 / self-signed (controlled identifier,
`did:key`) authentication suites, webhook notifications with RFC 9421 signature verification, access requests and
grants, and the type index / type search services.

* Kotlin 2.2 or later on JDK 17 or later; depends on kotlinx-coroutines and kotlinx-serialization-json only
* Operations are `suspend` functions, cancelled with the coroutine that calls them; options are named arguments
  (`slug =`, `ifMatch =`, `recursive =`, `headers =`, `timeout =`); listings are cold `Flow`s that fetch page after
  page as they are collected; errors are one sealed hierarchy under `LwsException`
* JSON is kotlinx.serialization's `JsonElement` (lossless: number literals, member order, `{}` and `[]` are kept);
  `Resource.decode<T>()` reads a body into a `@Serializable` class
* The JDK's `java.net.http.HttpClient` underneath (any method, `QUERY` included), behind a one-function
  `HttpTransport` for OkHttp, Ktor or a test double
* ES256 (P-256) and EdDSA (Ed25519) from the JDK's own providers
* Maven coordinates `com.ebremer:lws-client-kotlin`, package `com.ebremer.lws.kotlin`
* MIT licensed (see [`../LICENSE`](../LICENSE))

## Install

Before it is on Maven Central, build it from the repository into your local Maven repository:

```sh
cd kotlin && ./gradlew publishToMavenLocal
```

```kotlin
// build.gradle.kts
repositories { mavenLocal(); mavenCentral() }
dependencies { implementation("com.ebremer:lws-client-kotlin:0.1.0") }
```

A Gradle build can also use the checkout directly, with `includeBuild("path/to/lws-client/kotlin")` in its
`settings.gradle.kts` (that is how the driver adapter builds).

## Quickstart

```kotlin
import com.ebremer.lws.kotlin.LwsClient
import com.ebremer.lws.kotlin.PreconditionFailedException
import com.ebremer.lws.kotlin.auth.SelfSignedCredentials
import com.ebremer.lws.kotlin.auth.SigningKey
import com.ebremer.lws.kotlin.auth.TokenExchangeAuthenticator
import com.ebremer.lws.kotlin.json.jsonPatch
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import java.net.URI

fun main() = runBlocking {
    // A did:key agent signs its own credential; the client exchanges it for access tokens on demand.
    val me = SelfSignedCredentials.didKey(SigningKey.generateP256())
    val client = LwsClient(authenticator = TokenExchangeAuthenticator(me))

    val storage = client.discoverStorage(URI("https://storage.example/root/"))
    val root = storage.storageRoot()

    val note = client.createText(root, "Hello, LWS!", slug = "hello.txt").location
    val r = client.read(note)
    println("${r.text()} ${r.etag}")

    // Optimistic concurrency: the update fails if someone changed the note since it was read.
    try {
        client.updateText(note, "Hello again", ifMatch = r.etag)
    } catch (e: PreconditionFailedException) {
        println("Changed meanwhile (${e.status})")
    }

    val alice = buildJsonObject { put("name", "Alice"); put("age", 30) }
    val profile = client.createJson(root, alice, slug = "profile.json").location
    client.patch(profile, jsonPatch { replace("/age", 31); add("/city", "Boston") })

    client.listContainer(root).collect { item -> // follows rel="next" pages lazily
        println("${item.id} ${item.format}")
    }
    client.delete(note)
}
```

[`src/examples/kotlin`](src/examples/kotlin/com/ebremer/lws/kotlin/examples) has this as a program
([`Quickstart.kt`](src/examples/kotlin/com/ebremer/lws/kotlin/examples/Quickstart.kt)), plus
[`SelfSignedAuth.kt`](src/examples/kotlin/com/ebremer/lws/kotlin/examples/SelfSignedAuth.kt) (did:key and HTTPS
agents, the controlled identifier document to publish) and
[`WebhookReceiver.kt`](src/examples/kotlin/com/ebremer/lws/kotlin/examples/WebhookReceiver.kt) (an inbox that verifies
signed notifications). Run them with `./gradlew -q quickstart --args=http://localhost:8787/root/`,
`selfSignedAuth` and `webhookReceiver`.

## API at a glance

| Area | Functions of `LwsClient` |
|---|---|
| Discovery | `discoverStorage`, `getStorageDescription` |
| Reading | `head`, `read` (`accept =`, `range = ByteRange.of(0, 1023)`, `ifNoneMatch =`, `ifModifiedSince =`, `prefer =`), `readContainer`, `listContainer` |
| Creating | `create`, `createText`, `createJson`, `createContainer` (`slug =`, `types =`, `links =`) |
| Updating | `update`, `updateText`, `updateJson` (`ifMatch =`, `ifNoneMatch =`, `links =`, `setLinkset =`), `patch` (a `JsonPatch`, or bytes and a content type), `delete` (`ifMatch =`, `recursive =`) |
| Linksets | `linksetUrl`, `readLinkset`, `readLinksetResource`, `updateLinkset`, `patchLinkset` |
| Notifications | `subscribe`, `listSubscriptions`, `getSubscription`, `unsubscribe`; `WebhookVerifier` |
| Access | `requestAccess`, `listAccessRequests`, `getAccessRequest`, `cancelAccessRequest`, `grantAccess`, `listAccessGrants`, `getAccessGrant`, `revokeAccessGrant` |
| Type index and search | `readTypeIndex`, `listTypes`, `searchTypes` (HTTP `QUERY`), `searchAll`, `acceptedQueryFormats` |
| Anything else | `request(method, url, body, contentType)` through the same authentication and redirect pipeline |

The client is built with named arguments, `LwsClient(authenticator = …, userAgent = …, defaultHeaders = …,
timeout = 30.seconds, transport = …)`, and is immutable and safe to share between coroutines and threads. Every
operation also takes `headers =` (extra request headers) and `timeout =` (a `kotlin.time.Duration`). URLs are
`java.net.URI`s, and every URL in a result is absolute; type IRIs are strings. A conditional read answered `304`
is a `Resource` whose `notModified` is true, not an exception. Listings (`listContainer`, `listTypes`, `searchAll`,
…) are cold `Flow`s: nothing is fetched until they are collected, each collection starts over, and operators such
as `take(10)` fetch only the pages they need. Bodies are byte arrays, read whole.

### JSON

Documents are kotlinx.serialization's `JsonElement`s: the models keep what they parsed in `raw`, and linksets and
access documents encode back to the same JSON. `Resource.json()` parses a body and `Resource.decode<T>()` reads it
into a `@Serializable` class; values you send are `JsonElement`s (`buildJsonObject { … }`, or
`Json.encodeToJsonElement(value)`). `JsonPatch` takes strings, numbers and booleans directly:
`jsonPatch { replace("/done", true) }`.

## Errors

```
LwsException (sealed; a RuntimeException)
├── HttpException                 any error status: status, method, url, headers, problem (RFC 9457), body
│   ├── BadRequestException            400
│   ├── UnauthorizedException          401   challenges
│   ├── ForbiddenException             403
│   ├── NotFoundException              404
│   ├── MethodNotAllowedException      405   allow
│   ├── NotAcceptableException         406
│   ├── ConflictException              409
│   ├── GoneException                  410
│   ├── PreconditionFailedException    412
│   ├── UnsupportedMediaTypeException  415   acceptPatch, acceptQuery
│   ├── UnprocessableContentException  422
│   ├── NotImplementedException        501
│   └── InsufficientStorageException   507
├── AuthenticationException       the token exchange failed: oauthError, oauthErrorDescription, status
├── ProtocolException             the server broke the specification (no Location, wrong media type, bad JSON)
├── SignatureVerificationException  a webhook delivery that does not verify
└── TransportException            no response: refused, TLS, isTimeout
```

They are in `com.ebremer.lws.kotlin`. Arguments the caller gets wrong (a relative URL, an IRI that is not absolute
in a `TypeQuery`, a header value with a line break) raise Kotlin's own `IllegalArgumentException`, before any
request is sent. Cancelling the calling coroutine cancels the exchange in flight.

## Authentication

`TokenExchangeAuthenticator` runs the LWS flow: on a `401` with `WWW-Authenticate: Bearer as_uri="…", realm="…"` it
checks that the request lies inside the realm and that the authorization server uses HTTPS (loopback hosts
excepted), reads the server's metadata (never following a redirect), exchanges a subject token for an access
token, and sends the request once more. Tokens are reused for every URL inside their realm until 30 seconds before
they expire, and are never sent outside it, redirects included. Concurrent requests that meet the same challenge
share one exchange.

| Suite | Credentials |
|---|---|
| Self-signed, `did:key` | `SelfSignedCredentials.didKey(SigningKey.generateP256())` (or `generateEd25519()`) |
| Self-signed, HTTPS agent | `SelfSignedCredentials.forAgent(agentUrl, key, kid)`; publish `ControlledIdentifierDocument.create(agentUrl, key.publicKey, kid)` at the agent URL |
| OpenID Connect | `OpenIdCredentials(idToken)`, or `OpenIdCredentials { context -> … }` asked per authorization server |
| SAML 2.0 | `SamlCredentials.fromXml(assertion)` (base64url-encodes it), `SamlCredentials.fromEncoded(…)` |
| A known token | `BearerTokenAuthenticator(token, realm = URI("https://storage.example/"))` |

Keys round-trip as JWKs (`key.jwk()` and `SigningKey.fromJwk(jwk)`) and convert to and from JCA key pairs
(`SigningKey.of(keyPair)`, `key.toKeyPair()`). Options of the flow: `allowInsecureHttp =` (testing only),
`authorizationServerFilter =` (decide which servers may receive your credentials), `refreshMargin =`, `timeout =`,
`transport =`, `clock =`. Keys, tokens and credentials stay out of `toString()`.

## Webhooks

```kotlin
val verifier = WebhookVerifier(client, trustedStorages = listOf(URI("https://storage.example/")))

// In your server's handler for the inbox URL you subscribed with:
try {
    val verified = verifier.verify(method, URI("https://app.example/inbox"), headers, body)
    verified.notification.activities.forEach { println("${it.types} ${it.`object`.id}") }
    // answer 204
} catch (e: SignatureVerificationException) {
    // answer 401
}
```

`verify(method, url, headers, body)` takes the parts (the headers as `Headers` or a `Map<String, List<String>>`);
`verifyExchange(exchange, inboxUrl)` takes a request of the JDK's built-in `com.sun.net.httpserver` server. Pass the inbox URL as it was registered, not the one a proxy forwarded
to. The verifier checks the RFC 9530 digest, the RFC 9421 signature and its age, that the key is one the storage
lists under `authentication`, and that the notification comes from that storage; storage descriptions are cached,
and fetched again once when a signature fails, in case the storage rotated its keys.

## Transports

The client follows redirects itself, authorizing each hop for its own URL, so a transport must not follow them.

* `JdkHttpTransport` (the default): `java.net.http.HttpClient` with `Redirect.NEVER`; give it your own client for
  a proxy, an `SSLContext` or HTTP/1.1 only: `JdkHttpTransport(HttpClient.newBuilder().followRedirects(NEVER)…build())`.
* Your own: `HttpTransport` is a `fun interface` with one `suspend fun send(request: HttpRequest): HttpResponse`,
  a few lines over OkHttp or Ktor's client. Pass the same transport to `TokenExchangeAuthenticator(transport = …)`.

## Build and test

```sh
cd kotlin
./gradlew build                                       # tests (fixtures, HTTP, auth flow, webhook vectors), examples, jars
node ../testing/mock-server/server.mjs --port 8787 &
LWS_TEST_SERVER=http://localhost:8787 ./gradlew test  # adds the cross-language interop scenario
./gradlew -q quickstart --args=http://localhost:8787/root/
```

The compiler runs in explicit API mode with warnings as errors, against the Java 17 API (`-Xjdk-release=17`).

The driver adapter is [`../driver/adapters/kotlin`](../driver/adapters/kotlin): `kotlin/gradlew -p
driver/adapters/kotlin jar`, then `node driver/adapters/check.mjs -- java -jar
driver/adapters/kotlin/build/libs/lws-driver-adapter-kotlin.jar`.

## License

[MIT](../LICENSE).
