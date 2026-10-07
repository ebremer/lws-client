// SPDX-License-Identifier: MIT
import { callout, code, tabs } from "../lib.mjs";
import { S } from "../samples.mjs";

export default {
  path: "getting-started.html",
  title: "Getting started",
  description: "Install an LWS client for Java, JavaScript/TypeScript, C++, Rust, Go, Python or C# and run your first authenticated request against a Linked Web Storage server.",
  body: `
<h1>Getting started</h1>
<p class="lead">Install the client for your language, start the bundled mock server, and run a
first program that authenticates, discovers a storage and writes a resource. It takes about
five minutes.</p>
<div id="toc" class="toc"></div>

<h2 id="requirements">Requirements</h2>
<ul>
  <li><strong>Java</strong> 17+ (one runtime dependency: Jackson databind)</li>
  <li><strong>JavaScript/TypeScript</strong>: Node.js 20+, any modern browser, Deno or Bun (no runtime dependencies)</li>
  <li><strong>C++</strong>: a C++20 compiler and CMake 3.21+. nlohmann/json is required; libcurl and OpenSSL are optional.</li>
  <li><strong>Rust</strong> 1.85+ (edition 2024, tokio)</li>
  <li><strong>Go</strong> 1.23+ (no third-party dependencies)</li>
  <li><strong>Python</strong> 3.10+ (httpx; the <code>crypto</code> extra adds <code>cryptography</code>)</li>
  <li><strong>C#</strong>: .NET 10 (one dependency: BouncyCastle.Cryptography, for Ed25519)</li>
</ul>

<h2 id="install">Install</h2>
${callout("note", "Package registries", " The packages are not on Maven Central, npm, crates.io, PyPI or NuGet yet. Until they are, install from the GitHub repository as shown. The registry names are already reserved in each manifest, so switching later is a one-line change.")}
${tabs(S.install)}

<h2 id="mock-server">Start a server to talk to</h2>
<p>The repository includes a complete in-memory LWS server for development. It needs Node.js 22+ and has
no dependencies:</p>
${code("bash", `
git clone https://github.com/ebremer/lws-client.git
node lws-client/testing/mock-server/server.mjs --port 8787
# LWS mock server listening on http://localhost:8787`)}
<p>Its storage root is <code>http://localhost:8787/root/</code>. Every request needs an access
token, which is exactly what the client's authenticator takes care of.</p>

<h2 id="first-program">Your first program</h2>
<p>The program below generates a self-signed <code>did:key</code> identity, lets the client handle
the 401 → token exchange flow, discovers the storage from a resource URL, creates a container and
a text file, and reads the file back with its metadata.</p>
${tabs(S["first-program"])}
<p>Expected output (identifiers vary):</p>
${code("text", `
agent:   did:key:zDnaeYo3bnXyXXgYpknupHmZN6wBoSkPXpoqfqwPYQdTRTZJS
storage: http://localhost:8787/  root: http://localhost:8787/root/
created: http://localhost:8787/root/hello-world/hello.txt
Hello, LWS!  (etag "y3Np7XKGTBSEU-c181QlqW", parent http://localhost:8787/root/hello-world/)`)}

<h2 id="what-happened">What just happened</h2>
<ol class="steps">
  <li><strong>Identity.</strong> <code>SelfSignedCredentials.didKey</code> created an agent whose
  identifier is derived from a fresh P-256 public key. It signs short-lived JWT credentials
  (<code>sub = iss = client_id</code>) as described in the self-signed authentication suite.</li>
  <li><strong>Challenge.</strong> The first request got <code>401</code> with
  <code>WWW-Authenticate: Bearer as_uri="…", realm="…"</code>. The authenticator checked that the URL
  is inside the realm and fetched <code>/.well-known/lws-configuration</code>.</li>
  <li><strong>Token exchange.</strong> It posted the signed credential to the token endpoint (RFC 8693),
  received an access token for the realm, cached it, and retried the request. Later requests
  send the token immediately.</li>
  <li><strong>Discovery.</strong> The response's <code>Link: rel="https://www.w3.org/ns/lws#storage"</code>
  led to the storage description, whose <code>StorageRoot</code> service is the root container.</li>
  <li><strong>Create and read.</strong> <code>POST</code> to the container returned <code>201 Created</code>
  with a <code>Location</code>. <code>GET</code> returned the content plus an ETag and
  <code>up</code>/<code>linkset</code>/<code>type</code> links.</li>
</ol>

<h2 id="next">Next steps</h2>
<div class="cards">
  <a class="card" href="resources.html"><h3>Reading &amp; writing</h3><p>Conditional updates, JSON Patch, ranges, deletes.</p></a>
  <a class="card" href="authentication.html"><h3>Authentication</h3><p>OpenID Connect, SAML, self-signed agents and custom authenticators.</p></a>
  <a class="card" href="notifications.html"><h3>Notifications</h3><p>Subscribe to changes and verify signed webhooks.</p></a>
  <a class="card" href="api-reference.html"><h3>API cross-reference</h3><p>The same concept in all seven languages.</p></a>
</div>
`,
};
