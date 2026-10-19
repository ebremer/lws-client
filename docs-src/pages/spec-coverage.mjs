// SPDX-License-Identifier: MIT
import { callout, table } from "../lib.mjs";

const Y = "✓";

export default {
  path: "spec-coverage.html",
  title: "Spec coverage",
  description: "Which W3C Linked Web Storage documents and features the clients implement, the spec baseline date, and the interpretation decisions made where the drafts are silent.",
  body: `
<h1>Spec coverage</h1>
<p class="lead">The clients track the W3C Linked Web Storage Working Group drafts as of
<strong>19 October 2026</strong>: <a href="https://github.com/w3c/lws-protocol/commit/9a08ff6">w3c/lws-protocol@9a08ff6</a>,
"Define how resources move between containers", published as the Working Draft of 19 October 2026. Since the
5 October baseline, a <code>401</code> leads to the authorization server through protected resource metadata (RFC 9728),
only <code>application/lws+json</code> is a required container media type, and resources move between containers.</p>
<div id="toc" class="toc"></div>

<h2 id="documents">Documents</h2>
${table(
  ["Document", "Status at baseline", "Coverage"],
  [
    ['<a href="https://w3c.github.io/lws-protocol/lws10-core/">Linked Web Storage Protocol 1.0</a> (core)', "Working Draft 2026-10-19", "Full client side"],
    ['<a href="https://www.w3.org/TR/2026/DNOTE-lws10-vocab-20260714/">LWS Vocabulary</a>', "Group Note Draft (vocabulary of 2026-10-19)", "Constants for all terms"],
    ['<a href="https://w3c.github.io/lws-protocol/lws10-authn-openid/">Authentication Suite: OpenID Connect</a>', "Working Draft 2026-10-15", "<code>OpenIdCredentials</code>"],
    ['<a href="https://w3c.github.io/lws-protocol/lws10-authn-saml/">Authentication Suite: SAML 2.0</a>', "Working Draft 2026-10-15", "<code>SamlCredentials</code>"],
    ['<a href="https://w3c.github.io/lws-protocol/lws10-authn-ssi-cid/">Authentication Suite: Self-signed Identity using Controlled Identifiers</a>', "Working Draft 2026-10-15", "<code>SelfSignedCredentials</code> (ES256, EdDSA) and CID document helpers"],
    ['<a href="https://w3c.github.io/lws-protocol/lws10-authn-ssi-did-key/">Authentication Suite: did:key</a>', "Discontinued, subsumed by the CID suite", "did:key identities via <code>SelfSignedCredentials.didKey</code>"],
    ['<a href="https://w3c.github.io/lws-protocol/lws10-notifications-webhook/">Notification Suite: Webhooks</a>', "Editor's Draft", "Subscribe, list, cancel, and verify signed deliveries"],
    ['<a href="https://w3c.github.io/lws-protocol/lws10-index/">Search and Type Index Services</a>', "Editor's Draft", "Type index, type search (<code>QUERY</code>), <code>Accept-Query</code> discovery"],
  ],
)}

<h2 id="features">Feature matrix</h2>
<p>All ten clients implement the same feature set. Language-specific differences are listed under each
language guide.</p>
${table(
  ["Feature", "Spec section", "Java", "JS/TS", "C++", "Rust", "Go", "Python", "C#", "Swift", "PHP", "Kotlin"],
  [
    ["Storage discovery (<code>rel=lws#storage</code>) and storage description", "core §Discovery", Y, Y, Y, Y, Y, Y, Y, Y, Y, Y],
    ["Read / HEAD / range / conditional requests", "core §Read resource", Y, Y, Y, Y, Y, Y, Y, Y, Y, Y],
    ["Create data resources and containers (<code>Slug</code>, user links)", "core §Create resource", Y, Y, Y, Y, Y, Y, Y, Y, Y, Y],
    ["Replace (<code>PUT</code>) with <code>If-Match</code>; <code>Prefer: set-linkset</code>", "core §Update resource", Y, Y, Y, Y, Y, Y, Y, Y, Y, Y],
    ["JSON Patch (<code>PATCH</code>) and arbitrary advertised patch formats", "core §Update resource", Y, Y, Y, Y, Y, Y, Y, Y, Y, Y],
    ["Delete, recursive delete (<code>Depth: infinity</code>)", "core §Delete resource", Y, Y, Y, Y, Y, Y, Y, Y, Y, Y],
    ["Container listing and lazy pagination", "core §Containers, §Pagination", Y, Y, Y, Y, Y, Y, Y, Y, Y, Y],
    ["Linkset read / replace / patch", "core §Metadata", Y, Y, Y, Y, Y, Y, Y, Y, Y, Y],
    ["Moving resources (<code>MoveResource</code> capability, <code>up</code> link patch)", "core §Moving Resources", Y, Y, Y, Y, Y, Y, Y, Y, Y, Y],
    ["401 challenge → protected resource metadata → discovery checks → AS metadata → token exchange → retry", "core §Authorization", Y, Y, Y, Y, Y, Y, Y, Y, Y, Y],
    ["OpenID Connect, SAML 2.0, self-signed (CID, did:key) credentials", "authn suites", Y, Y, Y, Y, Y, Y, Y, Y, Y, Y],
    ["Webhook subscriptions", "core §Notifications, webhook suite", Y, Y, Y, Y, Y, Y, Y, Y, Y, Y],
    ["RFC 9421 webhook signature verification", "webhook suite §Authentication", Y, Y, Y, Y, Y, Y, Y, Y, Y, Y],
    ["Access requests and grants (ODRL access profile)", "core §Access Requests and Grants", Y, Y, Y, Y, Y, Y, Y, Y, Y, Y],
    ["Type index, type search with <code>QUERY</code>", "index", Y, Y, Y, Y, Y, Y, Y, Y, Y, Y],
    ["RFC 9457 problem details in errors", "core §REST binding", Y, Y, Y, Y, Y, Y, Y, Y, Y, Y],
  ],
)}

${callout("note", "C# specifics", ' The C# client gets Ed25519 (EdDSA) from BouncyCastle.Cryptography, because .NET 10 has none; everything else uses the BCL (<code>ECDsa</code>, <code>SHA256</code>/<code>SHA512</code>, <code>HttpClient</code>, <code>System.Text.Json</code>). Its 501 exception is <code>HttpNotImplementedException</code>, so that it never clashes with <code>System.NotImplementedException</code>. A subscription\'s URL (the contract\'s <code>subscription</code>) is <code>Subscription.Url</code>. See the <a href="languages/csharp.html#notes">C# guide</a>.')}
${callout("note", "Swift specifics", ' The Swift client gets its keys and signatures (P-256, P-384, Ed25519) and digests from swift-crypto, which is CryptoKit on Apple platforms, and its HTTP from <code>URLSession</code> (FoundationNetworking on Linux). Bodies are <code>Data</code>, so it has no streaming read or upload. Its errors are the cases of one <code>LWSError</code> enum. See the <a href="languages/swift.html#notes">Swift guide</a>.')}
${callout("note", "PHP specifics", ' The PHP client needs only the extensions most PHP builds bundle: ext-curl for HTTP (or any PSR-18 client through <code>Psr18Transport</code>), ext-openssl for P-256 and P-384 ECDSA, ext-sodium for Ed25519. Calls are synchronous, and bodies are strings, so it has no streaming read or upload. The contract\'s <code>Resource</code> is <code>ReadResult</code>, as <code>resource</code> is soft-reserved in PHP, and a subscription\'s URL is <code>Subscription::$url</code>. See the <a href="languages/php.html#notes">PHP guide</a>.')}
${callout("note", "Kotlin specifics", ' The Kotlin client runs on the JDK alone, beside kotlinx-coroutines and kotlinx-serialization-json: <code>java.net.http.HttpClient</code> for HTTP, the JDK\'s providers for P-256 (<code>SHA256withECDSAinP1363Format</code>) and Ed25519. Operations are <code>suspend</code> functions and listings cold <code>Flow</code>s; bodies are byte arrays, so it has no streaming read or upload. Its package is <code>com.ebremer.lws.kotlin</code>, beside the Java client\'s <code>com.ebremer.lws</code>, and a subscription\'s URL is <code>Subscription.url</code>. See the <a href="languages/kotlin.html#notes">Kotlin guide</a>.')}

<h2 id="decisions">Interpretation decisions</h2>
<p>The drafts are still evolving. Where they leave something open, the clients behave as follows, and
behave identically in every language.</p>
<dl class="defs">
  <dt>Identity hint on create → <code>Slug</code></dt>
  <dd>The core draft defines an optional identity hint for <em>create</em> but does not bind it to a
  header. The clients send <code>Slug</code> (RFC 5023 §9.7), as Solid servers expect,
  percent-encoding non-ASCII characters.</dd>
  <dt>Discovery checks</dt>
  <dd>Same scheme and authority means the scheme and host compared case-insensitively and the port after
  defaults. The protected resource metadata's <code>resource</code> must be the URL requested exactly, after
  only that normalisation: no trailing-slash or percent-encoding leniency. None of the discovery requests
  follows a redirect. Storage descriptions read for the check are cached.</dd>
  <dt>Where a token goes</dt>
  <dd>A token is for a storage, which is no path prefix in general. The clients send a cached token ahead to
  URLs inside the storage's URL or its root, each taken as a directory: same scheme, host and port, and a path
  equal to it or below it at a <code>/</code> boundary. Anywhere else they wait for a <code>401</code>: the retry of
a request that has just passed the checks carries the token, and later ones reuse it after their own checks, with no
new token request.</dd>
  <dt>A 401 that fails a check</dt>
  <dd>Gets no token request, and the token the request carried is kept: a storage may hold a resource whose
  <code>401</code> links to another storage.</dd>
  <dt>Challenges of earlier drafts</dt>
  <dd>A <code>Bearer</code> challenge with <code>as_uri</code> and <code>realm</code> and no
  <code>resource_metadata</code> is still followed: the URL must be inside the realm (same scheme, host and
  port, and a path equal to the realm path or below it at a <code>/</code> boundary, so <code>/storage_10/x</code>
  is <em>not</em> inside realm <code>/storage_1</code>), which is then the token's <code>resource</code> and scope.</dd>
  <dt>Authorization server metadata location</dt>
  <dd><code>/.well-known/lws-configuration</code> is resolved with RFC 8414 §3.1 path insertion, so
  issuers with a path work. The <code>issuer</code> in the metadata must equal the authorization server the
  protected resource metadata named (the first that passes the HTTPS check and your filter).</dd>
  <dt>Container media types</dt>
  <dd>The clients ask for <code>application/lws+json</code>, the one a server must honour, and read an
  <code>application/ld+json</code> or <code>application/json</code> answer as the same document, a leniency
  towards servers of earlier drafts. They do not parse RDF.</dd>
  <dt>Moves</dt>
  <dd><code>move</code> reads the linkset, then patches it with a <code>test</code> and a <code>replace</code> of the
  <code>up</code> link's <code>href</code>, conditional on the linkset's ETag. It takes the resource's identifier after
  the move from the answer: the anchor of a <code>200</code>'s linkset, else the URL it had. Whether a storage
  allows moves is the application's to check, with <code>moveCapability()</code>.</dd>
  <dt>Transport security for tokens</dt>
  <dd>Authorization servers and token endpoints must use HTTPS, except on loopback hosts or when
  explicitly allowed for testing.</dd>
  <dt>Token lifetime</dt>
  <dd>Taken from <code>expires_in</code>, else from the access token's <code>exp</code> claim, else 300 s.
  Tokens are refreshed 30 s before expiry and re-acquired once on <code>401 invalid_token</code>.</dd>
  <dt>Self-signed JWTs</dt>
  <dd><code>kid</code> is always included (for did:key: <code>did:key:z…#z…</code>), <code>aud</code> is the
  authorization server's issuer, the lifetime defaults to 300 s, and <code>jti</code> is a random UUID.</dd>
  <dt>Webhook verification strictness</dt>
  <dd>The signing key must be referenced from the storage description's <code>authentication</code>
  relationship. The notification's <code>storage</code> must equal the storage named by the
  <code>keyid</code>. <code>created</code> must fall within a 300 s window.</dd>
  <dt>Type matching</dt>
  <dd><code>Container</code>, <code>lws:Container</code> and <code>https://www.w3.org/ns/lws#Container</code>
  are treated as the same type. Models keep the raw values for lossless round-trips.</dd>
  <dt>Relative URLs</dt>
  <dd>Servers may return relative <code>id</code>s, <code>Location</code> headers and link targets. The
  clients always resolve them and only ever return absolute URLs.</dd>
</dl>
${callout("note", "Tracking the drafts", ' Spec changes are tracked against the <a href="https://github.com/w3c/lws-protocol">w3c/lws-protocol</a> repository. The shared <a href="testing.html">conformance fixtures</a> are updated first, then each client.')}
`,
};
