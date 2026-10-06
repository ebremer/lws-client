// SPDX-License-Identifier: MIT
import { callout, code, table } from "../../lib.mjs";
import { sample } from "../../samples.mjs";

const s = (topic) => code(sample("java", topic).lang, sample("java", topic).code);

export default {
  path: "languages/java.html",
  title: "Java",
  description: "The LWS client for Java 17+: installation, configuration, blocking and CompletableFuture APIs, lazy Streams, exceptions and build instructions.",
  body: `
<h1><span class="lang-badge lang-java">JV</span> Java</h1>
<div class="badges">
  <span class="badge accent">com.ebremer:lws-client:0.1.0</span>
  <span class="badge">Java 17+</span>
  <span class="badge">JPMS module com.ebremer.lws</span>
  <span class="badge">1 dependency: Jackson databind</span>
</div>
<p class="lead">A modern Java client built on <code>java.net.http.HttpClient</code>. It offers blocking calls that pair
well with virtual threads, <code>CompletableFuture</code> variants for the core operations, records for every model,
lazy <code>Stream</code>s for pagination, and JDK-only cryptography.</p>
<div id="toc" class="toc"></div>

<h2 id="install">Install</h2>
${s("install")}

<h2 id="first">First program</h2>
${s("first-program")}

<h2 id="configure">Configure the client</h2>
${s("client-config")}
<p><code>LwsClient</code> is immutable and thread-safe; build one and share it. <code>withAuthenticator(a)</code> returns a copy
with a different authenticator. The default <code>HttpClient</code> does not follow redirects itself. The client follows
them instead and re-checks credentials on each hop. If you supply your own <code>HttpClient</code> with redirects
enabled, you bypass that protection.</p>

<h2 id="idioms">Java idioms</h2>
${table(
  ["Aspect", "How the Java client does it"],
  [
    ["Calls", "Blocking methods (ideal with virtual threads) plus <code>headAsync</code>, <code>readAsync</code>, <code>readContainerAsync</code>, <code>createAsync</code>, <code>createContainerAsync</code>, <code>updateAsync</code>, <code>patchAsync</code>, <code>deleteAsync</code>, <code>discoverStorageAsync</code>"],
    ["Pagination", "<code>listContainer</code>, <code>listTypes</code>, <code>searchAll</code>, <code>listSubscriptions</code>… return lazy <code>Stream</code>s"],
    ["Options", "Immutable option objects with builders and static shortcuts: <code>CreateOptions.slug(…)</code>, <code>UpdateOptions.ifMatch(…)</code>, <code>DeleteOptions.recursive()</code>, <code>ReadOptions.ifNoneMatch(…)</code>"],
    ["Bodies", "<code>Body.of(String | byte[])</code>, <code>Body.ofJson(Object)</code>, <code>Body.ofFile(Path)</code>, <code>Body.ofInputStream(Supplier)</code>; all replayable, so the 401 retry always works"],
    ["Models", "Records with <code>Optional</code> / <code>OptionalLong</code> for absent values; JSON as Jackson <code>JsonNode</code>; <code>json(Class)</code> for data binding"],
    ["Errors", "Unchecked: <code>LwsException</code> → <code>HttpStatusException</code> → <code>NotFoundException</code>, <code>ConflictException</code>, …"],
    ["Crypto", "JDK only: <code>SHA256withECDSAinP1363Format</code>, <code>Ed25519</code>; also RSA public JWKs and P-384/RSA webhook signatures"],
  ],
)}

<h2 id="packages">Packages</h2>
${table(
  ["Package", "Contents"],
  [
    ["<code>com.ebremer.lws</code>", "<code>LwsClient</code>, options, <code>Body</code>, models (<code>Resource</code>, <code>ContainerPage</code>, <code>StorageDescription</code>, <code>Linkset</code>…), exceptions, <code>Lws</code> constants"],
    ["<code>com.ebremer.lws.auth</code>", "<code>Authenticator</code>, <code>TokenExchangeAuthenticator</code>, credentials, <code>KeyPairs</code>, <code>Jwk</code>, <code>Jwt</code>, <code>DidKey</code>, <code>ControlledIdentifiers</code>"],
    ["<code>com.ebremer.lws.notify</code>", "<code>WebhookSubscriptionRequest</code>, <code>Subscription</code>, <code>Notification</code>, <code>WebhookVerifier</code>, <code>HttpExchangeWebhooks</code>"],
    ["<code>com.ebremer.lws.access</code>", "<code>AccessRequest</code>, <code>AccessGrant</code>, <code>AccessPolicy</code>, <code>AccessTarget</code>, <code>Constraint</code>"],
    ["<code>com.ebremer.lws.index</code>", "<code>TypeQuery</code>, <code>TypeIndexPage</code>"],
    ["<code>com.ebremer.lws.patch</code> / <code>.http</code>", "<code>JsonPatch</code>, <code>JsonPointer</code> / <code>Link</code>, <code>LinkHeader</code>, <code>WwwAuthenticate</code>, <code>StructuredFields</code>, <code>ProblemDetails</code>"],
  ],
)}

<h2 id="notes">Notes and deviations</h2>
<ul>
  <li>The contract's <em>ProtocolError</em> is <code>LwsProtocolException</code> (to avoid clashing with
  <code>java.net.ProtocolException</code>). <em>HttpError</em> is <code>HttpStatusException</code>, and transport failures are
  <code>LwsTransportException</code>.</li>
  <li>Option getters are named <code>ifMatchValue()</code>, <code>slugValue()</code>… because the static factories use the plain names.</li>
  <li><code>ContainerPage.id()</code> is <code>Optional</code> because synthetic search pages have no id.</li>
  <li><code>readLinksetResource(linksetUrl)</code> complements <code>readLinkset(resourceUrl)</code> when you already know the linkset URL.</li>
  <li><code>Linkset</code> is immutable: <code>add</code>/<code>remove</code> return a new instance.</li>
  <li><code>HttpExchangeWebhooks</code> needs the <code>jdk.httpserver</code> module, which is declared <code>requires static</code>.</li>
</ul>

<h2 id="build">Build, test and examples</h2>
${code("bash", `
cd java
mvn verify                                          # compile (--release 17), unit + fixture + HTTP tests
node ../testing/mock-server/server.mjs --port 8787 &
LWS_TEST_SERVER=http://localhost:8787 mvn verify    # adds the cross-language interop scenario

# Examples (src/examples/java): Quickstart, SelfSignedAuth, WebhookReceiver
mvn -q dependency:build-classpath -Dmdep.outputFile=cp.txt
java -cp "target/classes:target/test-classes:$(cat cp.txt)" \\
     com.ebremer.lws.examples.Quickstart http://localhost:8787/root/   # use ';' on Windows`)}
${callout("note", "Source", ' <a href="https://github.com/ebremer/lws-client/tree/main/java">java/</a> in the repository, with its own <a href="https://github.com/ebremer/lws-client/blob/main/java/README.md">README</a>.')}
`,
};
