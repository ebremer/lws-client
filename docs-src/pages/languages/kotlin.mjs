// SPDX-License-Identifier: MIT
import { callout, code, table } from "../../lib.mjs";
import { sample } from "../../samples.mjs";

const s = (topic) => code(sample("kotlin", topic).lang, sample("kotlin", topic).code);

export default {
  path: "languages/kotlin.html",
  title: "Kotlin",
  description: "The LWS client for Kotlin 2.2+ on JDK 17+: installation with Gradle, suspend operations with named-argument options, cold Flow listings, the sealed LwsException hierarchy, kotlinx.serialization JSON, the JDK's java.net.http, and build instructions.",
  body: `
<h1><span class="lang-badge lang-kotlin">Kotlin</span> Kotlin</h1>
<div class="badges">
  <span class="badge accent">com.ebremer:lws-client-kotlin 0.1.0</span>
  <span class="badge">Kotlin 2.2+ · JDK 17+</span>
  <span class="badge">package com.ebremer.lws.kotlin</span>
  <span class="badge">kotlinx-coroutines, kotlinx-serialization-json</span>
</div>
<p class="lead">A coroutine-first Kotlin client for the JVM: server applications, command-line tools and desktop programs. Operations
are <code>suspend</code> functions, cancelled with the coroutine that calls them; options are named arguments (<code>slug =</code>,
<code>ifMatch =</code>, <code>recursive =</code>); listings are cold <code>Flow</code>s; errors are one sealed hierarchy under
<code>LwsException</code>; documents are kotlinx.serialization <code>JsonElement</code>s. HTTP and cryptography come from the JDK itself.</p>
<div id="toc" class="toc"></div>

<h2 id="install">Install</h2>
${s("install")}
<p>The build is Gradle (Kotlin DSL) with the wrapper, in <code>kotlin/</code>; the artifact is <code>com.ebremer:lws-client-kotlin</code>,
so it can sit next to the Java client (<code>com.ebremer:lws-client</code>) without a clash. A Gradle build can also include the
checkout directly with <code>includeBuild(…)</code>, which is how the driver adapter builds against it.</p>

<h2 id="first">First program</h2>
${s("first-program")}
<p>A complete program: <code>runBlocking</code> bridges into coroutines at <code>main</code>; inside a server framework you call the
operations from its own coroutines.</p>

<h2 id="configure">Configure the client</h2>
${s("client-config")}
<p><code>LwsClient</code> is immutable and safe to share between coroutines and threads: create one and pass it around.
<code>withAuthenticator(a)</code> returns a client with a different authenticator over the same transport. The client follows
redirects itself and authorizes each hop afresh, so its <code>HttpTransport</code> must not follow redirects. The default
<code>JdkHttpTransport</code> runs on <code>java.net.http.HttpClient</code> with <code>Redirect.NEVER</code> (any method, <code>QUERY</code>
included); give it your own <code>HttpClient</code> for a proxy, an <code>SSLContext</code> or HTTP/1.1 only. <code>HttpTransport</code> is a
<code>fun interface</code> with one <code>suspend fun send(request: HttpRequest): HttpResponse</code>, a few lines over OkHttp or Ktor's client;
pass the same transport to <code>TokenExchangeAuthenticator(transport = …)</code> for the metadata and token requests.</p>

<h2 id="idioms">Kotlin idioms</h2>
${table(
  ["Aspect", "How the Kotlin client does it"],
  [
    ["Calls", "<code>suspend</code> functions. Cancelling the calling coroutine (<code>withTimeout</code>, a cancelled scope) cancels the exchange in flight; the <code>timeout</code> option bounds each request and surfaces as <code>TransportException</code> with <code>isTimeout</code>. Concurrent requests that meet the same challenge share one token exchange"],
    ["Options", "Named arguments with defaults on every operation: <code>create(c, body, \"text/plain\", slug = \"a.txt\", types = listOf(…))</code>, <code>update(url, body, type, ifMatch = etag)</code>, <code>delete(url, recursive = true)</code>, <code>read(url, range = ByteRange.of(0, 1023))</code>. Every operation also takes <code>headers =</code> and <code>timeout =</code> (a <code>kotlin.time.Duration</code>)"],
    ["Pagination", "<code>listContainer</code>, <code>listTypes</code>, <code>searchAll</code>, <code>listSubscriptions</code>… return a cold <code>Flow</code>: nothing is fetched until it is collected, pages are fetched as collection advances, each collection starts over, and operators such as <code>take(10)</code> fetch only the pages they need"],
    ["Bodies", "<code>ByteArray</code>s, read whole, so every body can be replayed for the retry after a <code>401</code>. <code>createText</code> / <code>updateText</code>, <code>createJson</code> / <code>updateJson</code> for a <code>JsonElement</code>; <code>Resource.text()</code> (by the response charset), <code>bytes</code>, <code>json()</code> and <code>decode&lt;T&gt;()</code>"],
    ["JSON", "kotlinx.serialization's <code>JsonElement</code> tree, lossless (number literals, member order, <code>{}</code> and <code>[]</code>), so documents (linksets, access documents, <code>raw</code>) round-trip unchanged. Build values with <code>buildJsonObject { … }</code> or <code>Json.encodeToJsonElement(value)</code>; read a body into a <code>@Serializable</code> class with <code>decode&lt;T&gt;()</code>"],
    ["Models", "Classes with <code>val</code> properties (<code>meta.etag</code>, <code>page.items</code>, <code>item.isContainer</code>); computed values that can fail are functions (<code>storageRoot()</code>). URLs are <code>java.net.URI</code>s, absolute in every result; type IRIs are strings"],
    ["Errors", "<code>LwsException</code>, a sealed <code>RuntimeException</code>: <code>HttpException</code> with a subclass per status (<code>NotFoundException</code>, <code>ConflictException</code>, <code>PreconditionFailedException</code>, …), <code>AuthenticationException</code>, <code>ProtocolException</code>, <code>SignatureVerificationException</code>, <code>TransportException</code>, so a <code>when</code> over it is exhaustive. Caller mistakes are Kotlin's own <code>IllegalArgumentException</code>, thrown before any request"],
    ["Crypto", "The JDK's providers: <code>SHA256withECDSAinP1363Format</code> for ES256 (JOSE's raw <code>r‖s</code> directly), <code>Ed25519</code> for EdDSA, <code>MessageDigest</code> for SHA-256 and SHA-512. Keys convert to and from JCA key pairs (<code>SigningKey.of(keyPair)</code>, <code>toKeyPair()</code>)"],
    ["Secrets", "Keys, tokens and credentials stay out of <code>toString()</code>, so logging a client, an authenticator or a key shows no secret"],
  ],
)}

<h2 id="types">Types</h2>
${table(
  ["Package", "Types"],
  [
    ["<code>com.ebremer.lws.kotlin</code>", "<code>LwsClient</code>, <code>Resource</code>, <code>ResourceMetadata</code>, <code>CreateResult</code>, <code>UpdateResult</code>, <code>ByteRange</code>, <code>ContainerPage</code>, <code>ContainedResource</code>, <code>StorageDescription</code>, <code>Service</code>, <code>Capability</code>, <code>VerificationMethod</code>, <code>Linkset</code>, <code>LinkContext</code>, <code>LinkTarget</code>, <code>LinksetDocument</code>, <code>TypeIndexPage</code>, <code>TypeQuery</code>, the exceptions, <code>Vocabulary</code> (namespaces, type matching) and the constants <code>LinkRelation</code>, <code>ResourceType</code>, <code>MediaType</code>, <code>ServiceType</code>, <code>SubscriptionType</code>, <code>TokenType</code>, <code>AccessAction</code>, <code>ConstraintOperand</code>, <code>ConstraintOperator</code>, <code>Prefer</code>, <code>ActivityType</code>"],
    ["<code>….auth</code>", "<code>Authenticator</code>, <code>AuthRequest</code>, <code>AuthResponse</code>, <code>TokenExchangeAuthenticator</code>, <code>BearerTokenAuthenticator</code>, <code>CredentialProvider</code>, <code>CredentialContext</code>, <code>OpenIdCredentials</code>, <code>SamlCredentials</code>, <code>SelfSignedCredentials</code>, <code>SigningKey</code>, <code>VerificationKey</code>, <code>Jwt</code>, <code>DidKey</code>, <code>ControlledIdentifierDocument</code>, <code>AuthorizationServerMetadata</code>, <code>AccessToken</code>"],
    ["<code>….notify</code>", "<code>WebhookSubscriptionRequest</code>, <code>Subscription</code>, <code>Notification</code>, <code>Activity</code>, <code>ActivityObject</code>, <code>WebhookVerifier</code>, <code>VerifiedNotification</code>"],
    ["<code>….access</code>", "<code>AccessRequest</code>, <code>AccessGrant</code> (a sealed <code>AccessDocument</code>), <code>AccessPolicy</code>, <code>AccessTarget</code>, <code>Constraint</code>"],
    ["<code>….http</code>", "<code>HttpTransport</code>, <code>JdkHttpTransport</code>, <code>HttpRequest</code>, <code>HttpResponse</code>, <code>Headers</code>, <code>Link</code>, <code>LinkHeader</code>, <code>WwwAuthenticate</code>, <code>AuthChallenge</code>, <code>StructuredFields</code> and its <code>Sf…</code> values, <code>ProblemDetails</code>, <code>Slug</code>"],
    ["<code>….json</code>", "<code>JsonPatch</code>, the <code>jsonPatch { … }</code> builder, <code>JsonPointer</code>"],
  ],
)}
<p>The fragments on this site leave out their imports; the complete programs show them.</p>

<h2 id="notes">Notes and deviations</h2>
<ul>
  <li>The package is <code>com.ebremer.lws.kotlin</code>, not the Java client's <code>com.ebremer.lws</code>, so both libraries can be on one
  classpath. <code>Link.typeLink(iri)</code> builds a <code>rel="type"</code> link, since <code>type</code> is the property of the
  <code>type</code> attribute. A subscription's URL (the contract's <code>subscription</code>) is <code>Subscription.url</code>. An activity's
  object is <code>activity.&#96;object&#96;</code>, as <code>object</code> is a keyword.</li>
  <li>The contract's error classes are exception classes named <code>…Exception</code> (<code>NotFoundException</code>,
  <code>ProtocolException</code>); the 501 one is <code>NotImplementedException</code>, which shadows nothing that Kotlin imports by default.
  Their constructors are internal: <code>HttpException.fromResponse(…)</code> builds the right one, for a transport or a test double.</li>
  <li>Bodies are byte arrays: there is no streaming read or upload, so every body can be replayed for the single retry after a
  <code>401</code>. Read large resources in pieces with <code>range =</code>.</li>
  <li><code>JsonPatch</code>, <code>TypeQuery</code> and <code>Linkset</code> are builders that change in place:
  <code>doc.linkset.add(…)</code>, then <code>updateLinkset(doc.url, doc.linkset)</code>; <code>TypeQuery.copy()</code> takes a snapshot.
  <code>JsonPatch</code> has overloads for strings, numbers and booleans, and <code>jsonPatch { replace("/done", true) }</code> builds one.
  <code>TypeQuery</code>'s builders throw <code>IllegalArgumentException</code> for an IRI that is not absolute or an empty OR group.</li>
  <li><code>WebhookVerifier.verify(method, inbox, headers, body)</code> takes the parts of a delivery, the headers as <code>Headers</code> or a
  <code>Map&lt;String, List&lt;String&gt;&gt;</code>, so any server framework can pass its request on;
  <code>verifyExchange(exchange, inbox)</code> takes a request of the JDK's built-in <code>com.sun.net.httpserver</code> server. Pass the inbox
  URL as registered, not the one a proxy forwarded to.</li>
  <li>Clocks are <code>java.time.Clock</code>s (<code>TokenExchangeAuthenticator(clock = …)</code>, <code>WebhookVerifier(clock = …)</code>,
  <code>SelfSignedCredentials.withClock(…)</code>), for tests; instants are <code>java.time.Instant</code>s and durations
  <code>kotlin.time.Duration</code>s.</li>
  <li>Extras: <code>request(method, url, body, contentType)</code> sends any method through the authentication and redirect pipeline;
  <code>readLinksetResource(url)</code> reads a linkset at a known URL; <code>TokenExchangeAuthenticator.accessToken(asUri, realm)</code>
  obtains a token ahead of time.</li>
</ul>

<h2 id="build">Build, test and examples</h2>
${code("bash", `
cd kotlin
./gradlew build                                         # unit, fixture and HTTP tests, the examples, the jars
node ../testing/mock-server/server.mjs --port 8787 &
LWS_TEST_SERVER=http://localhost:8787 ./gradlew test    # adds the cross-language interop scenario

# Examples (src/examples/kotlin): Quickstart.kt, SelfSignedAuth.kt, WebhookReceiver.kt
./gradlew -q quickstart --args=http://localhost:8787/root/`)}
<p>The compiler runs in explicit API mode with warnings as errors, against the Java 17 API (<code>-Xjdk-release=17</code>) and the
Kotlin 2.2 language and API level, so the library works with Kotlin 2.2 and later on any JDK from 17.</p>
${callout("note", "Source", ' <a href="https://github.com/ebremer/lws-client/tree/main/kotlin">kotlin/</a> in the repository, with its own <a href="https://github.com/ebremer/lws-client/blob/main/kotlin/README.md">README</a> and <a href="https://github.com/ebremer/lws-client/tree/main/kotlin/src/examples/kotlin/com/ebremer/lws/kotlin/examples">examples</a>.')}
`,
};
