// SPDX-License-Identifier: MIT
import { SITE, tabs } from "../lib.mjs";
import { S } from "../samples.mjs";

const LANGS = [
  ["java", "Java", "JV", "languages/java.html", "com.ebremer:lws-client", "Java 17+ · records, lazy Streams, CompletableFuture variants, JDK crypto"],
  ["js", "JavaScript / TypeScript", "TS", "languages/javascript.html", "lws-client (npm)", "Node 20+, browsers, Deno, Bun · zero dependencies, fetch + WebCrypto"],
  ["cpp", "C++", "C++", "languages/cpp.html", "CMake lws::client", "C++20 · pluggable transport, optional libcurl/OpenSSL, lazy ranges"],
  ["rust", "Rust", "RS", "languages/rust.html", "lws-client (crate)", "Rust 1.85+ · async/tokio, Streams, RustCrypto, request builders"],
  ["go", "Go", "GO", "languages/go.html", "github.com/ebremer/lws-client/go", "Go 1.23+ · zero dependencies, context, iter.Seq2, errors.Is"],
  ["python", "Python", "PY", "languages/python.html", "lws-client (PyPI)", "Python 3.10+ · sync and async clients, typed dataclasses"],
  ["csharp", "C#", "C#", "languages/csharp.html", "Ebremer.Lws.Client (NuGet)", ".NET 10 · async/await, CancellationToken, IAsyncEnumerable, nullable annotations"],
  ["swift", "Swift", "SW", "languages/swift.html", "lws-client (SwiftPM)", "Swift 6 · async/await, AsyncSequence listings, Sendable values, URLSession, CryptoKit"],
  ["wasm", "WebAssembly", "WA", "languages/wasm.html", "lws_client.wasm (WASI 0.2 component)", "Any component host with wasi:http: jco, Wasmtime · the Rust client behind a WIT interface"],
];

const FEATURES = [
  ["discovery.html", "Storage discovery", "Find the storage description, root container and services from any resource URL."],
  ["resources.html", "Resources", "Create, read, replace, JSON Patch and delete, with ETags, ranges and conditional requests."],
  ["containers.html", "Containers", "Typed listings with lazy, link-based pagination in each language's iteration idiom."],
  ["metadata.html", "Metadata", "Read, replace and patch RFC 9264 linksets; atomic content + link updates."],
  ["authentication.html", "Authentication", "Automatic 401 → token exchange with OpenID Connect, SAML or self-signed did:key identities."],
  ["notifications.html", "Notifications", "Webhook subscriptions and RFC 9421 signature verification of every delivery."],
  ["access.html", "Access requests", "ODRL-based access requests and grants with purpose, client, format and time constraints."],
  ["type-index.html", "Type search", "Type index and conjunctive-normal-form type search over the HTTP QUERY method."],
];

export default {
  path: "index.html",
  title: "Overview",
  wide: true,
  description: "Idiomatic W3C Linked Web Storage (LWS) clients for Java, JavaScript/TypeScript, C++, Rust, Go, Python, C# and Swift, sharing one API design, one conformance suite and one interop scenario.",
  body: `
<section class="hero">
  <div class="badges">
    <span class="badge accent">MIT licensed</span>
    <span class="badge">LWS drafts as of ${SITE.specBaseline}</span>
    <span class="badge">8 languages · 1 API design</span>
    <span class="badge">v${SITE.version}</span>
  </div>
  <h1>Linked Web Storage clients for <span class="accent">eight languages</span></h1>
  <p class="lead">Read and write data in any W3C Linked Web Storage (LWS) server from Java, JavaScript/TypeScript,
  C++, Rust, Go, Python, C# or Swift. Each client is idiomatic to its language, and all eight share the same concepts,
  wire behaviour and conformance tests. The Rust client also comes as a WebAssembly component, for any language
  that can host one.</p>
  <div class="hero-actions">
    <a class="btn primary" href="getting-started.html">Get started →</a>
    <a class="btn" href="concepts.html">Learn the concepts</a>
    <a class="btn" href="${SITE.repo}">View on GitHub</a>
  </div>
</section>

<div class="split">
  <div>
    <h2 id="at-a-glance">At a glance</h2>
    <ul>
      <li><strong>Complete client side of LWS 1.0:</strong> discovery, CRUD, containers, linksets,
      notifications, access requests and grants, type index and search.</li>
      <li><strong>Authorization handled for you.</strong> On a <code>401</code> the client checks the realm,
      discovers the authorization server and performs an OAuth 2.0 token exchange. It then caches the token per realm.</li>
      <li><strong>Every authentication suite:</strong> OpenID Connect, SAML 2.0, and self-signed identities
      (controlled identifier documents and <code>did:key</code>) with ES256 and EdDSA.</li>
      <li><strong>Verified webhooks:</strong> RFC 9421 HTTP Message Signatures and RFC 9530
      <code>Content-Digest</code>, checked against the storage's published keys.</li>
      <li><strong>One contract, eight idioms:</strong> the same concept names everywhere, expressed with each
      language's async model, iteration and error style.</li>
    </ul>
  </div>
  <div>
    <h2 id="example">A taste</h2>
    ${tabs(S.hero)}
  </div>
</div>

<h2 id="features">What's covered</h2>
<div class="cards">
${FEATURES.map(([href, title, text]) => `  <a class="card" href="${href}"><h3>${title}</h3><p>${text}</p></a>`).join("\n")}
</div>

<h2 id="languages">Pick your language</h2>
<div class="cards">
${LANGS.map(([key, name, badge, href, pkg, notes]) => `  <a class="card" href="${href}"><h3><span class="lang-badge lang-${key}">${badge}</span>${name}</h3><p>${notes}</p><div class="meta">${pkg}</div></a>`).join("\n")}
</div>

<h2 id="how-it-works">How it works</h2>
<ol class="steps">
  <li><strong>Discover.</strong> Every LWS response links to its storage
  (<code>rel="https://www.w3.org/ns/lws#storage"</code>). The storage description lists the root container
  and optional services such as notifications, access requests and type search.</li>
  <li><strong>Authenticate.</strong> Choose a credential provider: an OpenID Connect ID token, a SAML
  assertion, or a self-signed key. The client exchanges it for short-lived access tokens when it is challenged.</li>
  <li><strong>Read and write.</strong> Containers list their members as <code>application/lws+json</code>;
  data resources are plain HTTP resources with ETags; metadata lives in linksets and changes through JSON Patch.</li>
  <li><strong>React.</strong> Subscribe a webhook inbox to a container and verify each signed notification
  before trusting it.</li>
</ol>

<h2 id="quality">Built to agree with each other</h2>
<p>The clients share <a href="testing.html#fixtures">language-neutral conformance fixtures</a>, including 13
RFC 9421 webhook vectors and the did:key specification vector. They also all pass the same
<a href="testing.html#interop">end-to-end interop scenario</a> against a bundled mock LWS server.
Every code sample on this site is type-checked or compiled against the real libraries before it is published.
The getting-started program is also run against the mock server in all eight languages.</p>
<p>The baseline is the W3C LWS Working Group's documents as of ${SITE.specBaseline}, including the switch of
the baseline <code>PATCH</code> format to JSON Patch. See <a href="spec-coverage.html">spec coverage</a> for
details and interpretation decisions.</p>
`,
};
