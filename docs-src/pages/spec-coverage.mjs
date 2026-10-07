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
<strong>5 October 2026</strong>: <a href="https://github.com/w3c/lws-protocol/commit/ef02548">w3c/lws-protocol@ef02548</a>,
"Switch baseline PATCH format from JSON Merge Patch to JSON Patch".</p>
<div id="toc" class="toc"></div>

<h2 id="documents">Documents</h2>
${table(
  ["Document", "Status at baseline", "Coverage"],
  [
    ['<a href="https://w3c.github.io/lws-protocol/lws10-core/">Linked Web Storage Protocol 1.0</a> (core)', "First Public Working Draft 2026-06-05; Editor's Draft 2026-10-05", "Full client side"],
    ['<a href="https://www.w3.org/TR/2026/DNOTE-lws10-vocab-20260714/">LWS Vocabulary</a>', "Group Note Draft 2026-07-14", "Constants for all terms"],
    ['<a href="https://w3c.github.io/lws-protocol/lws10-authn-openid/">Authentication Suite: OpenID Connect</a>', "Working Draft 2026-08-03", "<code>OpenIdCredentials</code>"],
    ['<a href="https://w3c.github.io/lws-protocol/lws10-authn-saml/">Authentication Suite: SAML 2.0</a>', "Working Draft", "<code>SamlCredentials</code>"],
    ['<a href="https://w3c.github.io/lws-protocol/lws10-authn-ssi-cid/">Authentication Suite: Self-signed Identity using Controlled Identifiers</a>', "Working Draft 2026-04-23", "<code>SelfSignedCredentials</code> (ES256, EdDSA) and CID document helpers"],
    ['<a href="https://w3c.github.io/lws-protocol/lws10-authn-ssi-did-key/">Authentication Suite: did:key</a>', "Discontinued, subsumed by the CID suite", "did:key identities via <code>SelfSignedCredentials.didKey</code>"],
    ['<a href="https://w3c.github.io/lws-protocol/lws10-notifications-webhook/">Notification Suite: Webhooks</a>', "Editor's Draft", "Subscribe, list, cancel, and verify signed deliveries"],
    ['<a href="https://w3c.github.io/lws-protocol/lws10-index/">Search and Type Index Services</a>', "Editor's Draft", "Type index, type search (<code>QUERY</code>), <code>Accept-Query</code> discovery"],
  ],
)}

<h2 id="features">Feature matrix</h2>
<p>All eight clients implement the same feature set. Language-specific differences are listed under each
language guide.</p>
${table(
  ["Feature", "Spec section", "Java", "JS/TS", "C++", "Rust", "Go", "Python", "C#", "Swift"],
  [
    ["Storage discovery (<code>rel=lws#storage</code>) and storage description", "core §Discovery", Y, Y, Y, Y, Y, Y, Y, Y],
    ["Read / HEAD / range / conditional requests", "core §Read resource", Y, Y, Y, Y, Y, Y, Y, Y],
    ["Create data resources and containers (<code>Slug</code>, user links)", "core §Create resource", Y, Y, Y, Y, Y, Y, Y, Y],
    ["Replace (<code>PUT</code>) with <code>If-Match</code>; <code>Prefer: set-linkset</code>", "core §Update resource", Y, Y, Y, Y, Y, Y, Y, Y],
    ["JSON Patch (<code>PATCH</code>) and arbitrary advertised patch formats", "core §Update resource", Y, Y, Y, Y, Y, Y, Y, Y],
    ["Delete, recursive delete (<code>Depth: infinity</code>)", "core §Delete resource", Y, Y, Y, Y, Y, Y, Y, Y],
    ["Container listing and lazy pagination", "core §Containers, §Pagination", Y, Y, Y, Y, Y, Y, Y, Y],
    ["Linkset read / replace / patch", "core §Metadata", Y, Y, Y, Y, Y, Y, Y, Y],
    ["401 challenge → AS metadata → token exchange → retry", "core §Authorization", Y, Y, Y, Y, Y, Y, Y, Y],
    ["OpenID Connect, SAML 2.0, self-signed (CID, did:key) credentials", "authn suites", Y, Y, Y, Y, Y, Y, Y, Y],
    ["Webhook subscriptions", "core §Notifications, webhook suite", Y, Y, Y, Y, Y, Y, Y, Y],
    ["RFC 9421 webhook signature verification", "webhook suite §Authentication", Y, Y, Y, Y, Y, Y, Y, Y],
    ["Access requests and grants (ODRL access profile)", "core §Access Requests and Grants", Y, Y, Y, Y, Y, Y, Y, Y],
    ["Type index, type search with <code>QUERY</code>", "index", Y, Y, Y, Y, Y, Y, Y, Y],
    ["RFC 9457 problem details in errors", "core §REST binding", Y, Y, Y, Y, Y, Y, Y, Y],
  ],
)}

${callout("note", "C# specifics", ' The C# client gets Ed25519 (EdDSA) from BouncyCastle.Cryptography, because .NET 10 has none; everything else uses the BCL (<code>ECDsa</code>, <code>SHA256</code>/<code>SHA512</code>, <code>HttpClient</code>, <code>System.Text.Json</code>). Its 501 exception is <code>HttpNotImplementedException</code>, so that it never clashes with <code>System.NotImplementedException</code>. A subscription\'s URL (the contract\'s <code>subscription</code>) is <code>Subscription.Url</code>. See the <a href="languages/csharp.html#notes">C# guide</a>.')}
${callout("note", "Swift specifics", ' The Swift client gets its keys and signatures (P-256, P-384, Ed25519) and digests from swift-crypto, which is CryptoKit on Apple platforms, and its HTTP from <code>URLSession</code> (FoundationNetworking on Linux). Bodies are <code>Data</code>, so it has no streaming read or upload. Its errors are the cases of one <code>LWSError</code> enum. See the <a href="languages/swift.html#notes">Swift guide</a>.')}

<h2 id="decisions">Interpretation decisions</h2>
<p>The drafts are still evolving. Where they leave something open, the clients behave as follows, and
behave identically in every language.</p>
<dl class="defs">
  <dt>Identity hint on create → <code>Slug</code></dt>
  <dd>The core draft defines an optional identity hint for <em>create</em> but does not bind it to a
  header. The clients send <code>Slug</code> (RFC 5023 §9.7), as Solid servers expect,
  percent-encoding non-ASCII characters.</dd>
  <dt>Realm containment</dt>
  <dd>The draft says the request URI must be "logically contained" in the challenge's
  <code>realm</code>. The clients require the same scheme, host and port, and a path equal to the
  realm path or below it at a <code>/</code> boundary. So <code>/storage_10/x</code> is <em>not</em>
  inside realm <code>/storage_1</code>.</dd>
  <dt>Authorization server metadata location</dt>
  <dd><code>/.well-known/lws-configuration</code> is resolved with RFC 8414 §3.1 path insertion, so
  issuers with a path work. The <code>issuer</code> in the metadata must equal the challenge's
  <code>as_uri</code>.</dd>
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
