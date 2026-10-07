// SPDX-License-Identifier: MIT
import { callout, code, table } from "../../lib.mjs";
import { sample } from "../../samples.mjs";

const s = (topic) => code(sample("swift", topic).lang, sample("swift", topic).code);

export default {
  path: "languages/swift.html",
  title: "Swift",
  description: "The LWS client for Swift 6: installation with SwiftPM, configuration, async/await with task cancellation, AsyncSequence pagination, the LWSError enum and build instructions.",
  body: `
<h1><span class="lang-badge lang-swift">SW</span> Swift</h1>
<div class="badges">
  <span class="badge accent">lws-client 0.1.0 (SwiftPM)</span>
  <span class="badge">Swift 6, strict concurrency</span>
  <span class="badge">module LWS</span>
  <span class="badge">1 dependency: swift-crypto (CryptoKit)</span>
</div>
<p class="lead">A Swift client for Apple platforms and Linux, built on <code>URLSession</code>. Every operation is
<code>async throws</code> and honours task cancellation, listings are lazy <code>AsyncSequence</code>s for
<code>for try await</code>, options and models are <code>Sendable</code> value types, and errors are one
<code>LWSError</code> enum to match with <code>catch LWSError.notFound</code>.</p>
<div id="toc" class="toc"></div>

<h2 id="install">Install</h2>
${s("install")}
<p>The package's manifest is the repository's root <code>Package.swift</code> (SwiftPM takes packages from a git repository only
there); the sources are in <code>swift/</code>.</p>

<h2 id="first">First program</h2>
${s("first-program")}
<p>This is a complete <code>main.swift</code>: add it to an executable target that depends on the <code>LWS</code> product, and
<code>swift run</code> it.</p>

<h2 id="configure">Configure the client</h2>
${s("client-config")}
<p><code>LWSClient</code> is an immutable, <code>Sendable</code> class: create one and share it between tasks.
<code>withAuthenticator(a)</code> returns a client with a different authenticator over the same transport. The client follows
redirects itself and authorizes each hop afresh, so its <code>HTTPTransport</code> must not follow redirects. The default
<code>URLSessionTransport</code> owns a private <code>URLSession</code> whose delegate refuses them, with cookies and caching off; a
transport of your own (an AsyncHTTPClient adapter, a test double) implements one method,
<code>send(_ request: HTTPRequest) async throws -&gt; HTTPResponse</code>.</p>

<h2 id="idioms">Swift idioms</h2>
${table(
  ["Aspect", "How the Swift client does it"],
  [
    ["Calls", "Every operation is <code>async throws</code>. Cancelling the task throws <code>CancellationError</code>; a timeout (the <code>timeout</code> option, a hard limit per request) throws <code>LWSError.transport</code> with <code>isTimeout</code>"],
    ["Pagination", "<code>listContainer</code>, <code>listTypes</code>, <code>searchAll</code>, <code>listSubscriptions</code>… return a lazy <code>PagedSequence</code> (an <code>AsyncSequence</code>): <code>for try await item in …</code>, <code>where</code> clauses, or <code>collect()</code>. Pages are fetched as the iteration advances"],
    ["Options", "Value types with defaulted initializers: <code>CreateOptions(slug: …)</code>, <code>UpdateOptions(ifMatch: etag)</code>, <code>DeleteOptions(recursive: true)</code>, <code>ReadOptions(range: .bytes(0...1023))</code>. Every one also has <code>headers</code> and <code>timeout</code>"],
    ["Bodies", "<code>Data</code> in and out, always replayable; <code>createText</code>, <code>createJSON(json:)</code> and <code>createJSON(value:)</code> for any <code>Encodable</code>; <code>Resource.text</code>, <code>.json()</code> and <code>.decode(_:)</code> for any <code>Decodable</code>"],
    ["JSON", "<code>JSONValue</code>, an enum with literals (<code>[\"name\": \"Alice\", \"age\": 30]</code>), and <code>JSONObject</code>, which keeps member order so that documents (linksets, access documents, <code>raw</code>) round-trip unchanged"],
    ["Models", "<code>Sendable</code> structs; absent values are optionals; URLs are <code>URL</code>, absolute in every result"],
    ["Errors", "One <code>enum LWSError: Error</code>: a case per status (<code>.notFound</code>, <code>.conflict</code>, <code>.preconditionFailed</code>, … each with its <code>HTTPError</code>), <code>.http</code> for other statuses, <code>.authentication</code>, <code>.protocolError</code>, <code>.signatureVerification</code>, <code>.transport</code>, <code>.invalidArgument</code>. <code>status</code> and <code>httpError</code> help across cases"],
    ["Concurrency", "Swift 6 language mode with strict concurrency checking. <code>TokenExchangeAuthenticator</code>, <code>SelfSignedCredentials</code> and <code>WebhookVerifier</code> are actors: concurrent requests share one in-flight token exchange"],
    ["Crypto", "<a href=\"https://github.com/apple/swift-crypto\">swift-crypto</a>, which is CryptoKit on Apple platforms and BoringSSL elsewhere: P-256, P-384 and Ed25519 keys and signatures, SHA-256 and SHA-512"],
  ],
)}

<h2 id="types">Types</h2>
${table(
  ["Area", "Types"],
  [
    ["Client", "<code>LWSClient</code>, <code>LWSClientOptions</code>, <code>RequestOptions</code>, <code>ReadOptions</code>, <code>CreateOptions</code>, <code>UpdateOptions</code>, <code>DeleteOptions</code>, <code>ByteRange</code>, <code>PagedSequence</code>, <code>HTTPTransport</code>, <code>URLSessionTransport</code>"],
    ["Models", "<code>Resource</code>, <code>ResourceMetadata</code>, <code>CreateResult</code>, <code>UpdateResult</code>, <code>ContainerPage</code>, <code>ContainedResource</code>, <code>StorageDescription</code>, <code>Service</code>, <code>Linkset</code>, <code>LinksetDocument</code>, <code>TypeIndexPage</code>, <code>JSONPatch</code>, <code>JSONPointer</code>, <code>TypeQuery</code>, <code>JSONValue</code>"],
    ["Auth", "<code>Authenticator</code>, <code>TokenExchangeAuthenticator</code>, <code>BearerTokenAuthenticator</code>, <code>CredentialProvider</code>, <code>OpenIDCredentials</code>, <code>SAMLCredentials</code>, <code>SelfSignedCredentials</code>, <code>SigningKey</code>, <code>VerificationKey</code>, <code>JWT</code>, <code>DIDKey</code>, <code>ControlledIdentifierDocument</code>"],
    ["Notifications", "<code>WebhookSubscriptionRequest</code>, <code>Subscription</code>, <code>Notification</code>, <code>Activity</code>, <code>WebhookVerifier</code>, <code>VerifiedNotification</code>"],
    ["Access", "<code>AccessRequest</code>, <code>AccessGrant</code>, <code>AccessPolicy</code>, <code>AccessTarget</code>, <code>Constraint</code>"],
    ["HTTP", "<code>Link</code>, <code>LinkHeader</code>, <code>WWWAuthenticate</code>, <code>AuthChallenge</code>, <code>StructuredFields</code>, <code>ProblemDetails</code>, <code>HTTPHeaders</code>, <code>Slug</code>"],
    ["Constants", "<code>Vocabulary</code> (namespaces, contexts, type matching), <code>LinkRelation</code>, <code>ResourceType</code>, <code>MediaType</code>, <code>ServiceType</code>, <code>TokenType</code>, <code>AccessAction</code>, <code>ConstraintOperand</code>, <code>ConstraintOperator</code>, <code>Prefer</code>, <code>ActivityType</code>"],
  ],
)}

<h2 id="notes">Notes and deviations</h2>
<ul>
  <li>Names follow the Swift API Design Guidelines: acronyms are upper case (<code>LWSClient</code>, <code>JSONPatch</code>,
  <code>DIDKey</code>, <code>linksetURL</code>), and creation takes the container as a label: <code>create(in:body:contentType:)</code>,
  <code>createContainer(in:)</code>.</li>
  <li>The contract's error classes are the cases of <code>LWSError</code>; its <em>ProtocolError</em> is <code>.protocolError</code>, and an
  argument that is not an absolute http(s) URL is <code>.invalidArgument</code>, thrown before any request.</li>
  <li>Request and response bodies are <code>Data</code>: there is no streaming read or upload. Every body can therefore be replayed
  for the single retry after a <code>401</code>.</li>
  <li><code>storageRoot()</code> is a throwing method, because a description without a <code>StorageRoot</code> service is a protocol
  error. The other well-known services are optional properties (<code>notificationService</code>, <code>typeSearchService</code>…).</li>
  <li><code>TypeQuery</code>'s builders throw <code>.invalidArgument</code> for an IRI that is not absolute or an empty OR group, so a query
  is written <code>try TypeQuery().anyOf(…).allOf(…)</code>. <code>Linkset</code>, <code>JSONPatch</code> and <code>TypeQuery</code> are values:
  <code>adding</code>, <code>removing</code>, <code>add</code>, <code>replace</code>… return copies.</li>
  <li><code>WebhookVerifier.verify(method:url:headers:body:)</code> takes the parts of the request, so any server (Vapor, Hummingbird,
  SwiftNIO…) can host the inbox: pass the inbox URL as registered, not the one a proxy forwarded to.</li>
  <li>On Linux, <code>URLSession</code> comes from FoundationNetworking, over libcurl. A per-task delegate is ignored there, so the
  default transport refuses redirects with a session delegate, and an authorization server response from another URL than the one
  requested is refused as a followed redirect.</li>
  <li>Extras: <code>request(_:_:body:contentType:)</code> sends any method through the authentication and redirect pipeline;
  <code>readLinksetResource(_:)</code> reads a linkset at a known URL.</li>
</ul>

<h2 id="build">Build, test and examples</h2>
${code("bash", `
swift build                                          # at the repository root: library, tests, examples, driver adapter
swift test                                           # unit, fixture and HTTP tests (Swift Testing)
node testing/mock-server/server.mjs --port 8787 &
LWS_TEST_SERVER=http://localhost:8787 swift test     # adds the cross-language interop scenario

# Examples (swift/Examples/): Quickstart, SelfSignedAuth, WebhookReceiver
swift run Quickstart http://localhost:8787/root/`)}
${callout("note", "Source", ' <a href="https://github.com/ebremer/lws-client/tree/main/swift">swift/</a> in the repository, with its own <a href="https://github.com/ebremer/lws-client/blob/main/swift/README.md">README</a>.')}
`,
};
