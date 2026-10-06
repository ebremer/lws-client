// SPDX-License-Identifier: MIT
import { callout, code, table } from "../../lib.mjs";
import { sample } from "../../samples.mjs";

const s = (topic) => code(sample("rust", topic).lang, sample("rust", topic).code);

export default {
  path: "languages/rust.html",
  title: "Rust",
  description: "The async Rust LWS client: tokio and reqwest, request builders, Streams for pagination, RustCrypto signing and a single Error enum.",
  body: `
<h1><span class="lang-badge lang-rust">RS</span> Rust</h1>
<div class="badges">
  <span class="badge accent">lws-client 0.1.0</span>
  <span class="badge">Rust 1.85+ (edition 2024)</span>
  <span class="badge">tokio · reqwest · RustCrypto</span>
  <span class="badge">#![forbid(unsafe_code)]</span>
</div>
<p class="lead">An async client built on reqwest. It uses request builders you can <code>.await</code> directly,
<code>futures::Stream</code> pagination, serde-based models and one <code>Error</code> enum with convenience predicates.
<code>Client</code> is <code>Clone + Send + Sync</code>.</p>
<div id="toc" class="toc"></div>

<h2 id="install">Install</h2>
${s("install")}
${table(
  ["Feature", "Default", "Enables"],
  [
    ["<code>rustls</code>", "yes", "TLS through rustls (reqwest's default backend)"],
    ["<code>native-tls</code>", "no", "TLS through the platform library instead"],
    ["<code>crypto</code>", "yes", "<code>SelfSignedCredentials</code>, keys, did:key, JWTs and <code>WebhookVerifier</code> (p256, ed25519-dalek, sha2)"],
  ],
)}

<h2 id="first">First program</h2>
${s("first-program")}

<h2 id="configure">Configure the client</h2>
${s("client-config")}

<h2 id="idioms">Rust idioms</h2>
${table(
  ["Aspect", "How the Rust client does it"],
  [
    ["Calls", "<code>async</code>; operations with options return request builders (<code>ReadRequest</code>, <code>CreateRequest</code>, <code>UpdateRequest</code>, <code>PatchRequest</code>, <code>DeleteRequest</code>) that implement <code>IntoFuture</code>, so call <code>.await</code> directly or <code>.send().await</code>"],
    ["Pagination", "<code>LwsStream&lt;T&gt;</code>, a <code>futures::Stream</code> of <code>Result&lt;T&gt;</code>: <code>try_next</code>, <code>try_collect</code> (bring <code>futures_util::TryStreamExt</code>)"],
    ["URLs and bodies", "Any <code>impl IntoUrl</code> (<code>Url</code>, <code>&amp;str</code>, <code>String</code>); bodies <code>impl Into&lt;Body&gt;</code> (bytes, strings; <code>Body::from_reqwest</code> for streams)"],
    ["Models", "Plain structs with public fields; datetimes as <code>SystemTime</code> plus the raw string"],
    ["Errors", "<code>lws_client::Error</code> with one variant per status (each holding <code>Box&lt;HttpError&gt;</code>) and helpers <code>status()</code>, <code>problem()</code>, <code>is_not_found()</code>, <code>is_conflict()</code>, <code>is_precondition_failed()</code>…"],
    ["Extensibility", "<code>Authenticator</code> and <code>CredentialProvider</code> are object-safe traits returning <code>BoxFuture</code>s (use <code>Arc&lt;dyn …&gt;</code>)"],
  ],
)}

<h2 id="modules">Modules</h2>
${table(
  ["Module", "Contents"],
  [
    ["crate root", "<code>Client</code>, builders, models, <code>JsonPatch</code>/<code>JsonPointer</code>, <code>TypeQuery</code>, <code>WebhookVerifier</code>, <code>Error</code>/<code>Result</code>, re-exported <code>Url</code>"],
    ["<code>auth</code>", "<code>Authenticator</code>, <code>RequestParts</code>/<code>ResponseParts</code>, <code>BoxFuture</code>, token exchange, credential providers, OAuth helpers"],
    ["<code>crypto</code>", "<code>SigningKey</code>, <code>VerifyingKey</code>, <code>Jwk</code>, <code>DidKey</code>, <code>controlled_identifier_document</code>, <code>jwt</code>"],
    ["<code>access</code>, <code>notification</code>, <code>index</code>, <code>webhook</code>", "Access documents, subscriptions and notifications, type index/search, signature verification"],
    ["<code>headers</code>, <code>constants</code>, <code>types</code>, <code>datetime</code>", "Link / WWW-Authenticate / structured-field / problem parsers, vocabulary constants, type matching, RFC 3339"],
  ],
)}

<h2 id="notes">Notes and deviations</h2>
<ul>
  <li><code>JsonPatch::move_value</code> (<code>move</code> is a keyword) and <code>Constraint::resource_type</code>.</li>
  <li><code>url::ParseError</code> converts into <code>Error::InvalidInput</code>, so <code>Url::parse(…)?</code> works in functions returning <code>lws_client::Result</code>.</li>
  <li><code>Resource::text()</code> decodes UTF-8 only. <code>title*</code> link parameters are kept raw.</li>
  <li>The webhook verifier supports P-256 and Ed25519.</li>
  <li>The built-in HTTP client follows redirects itself (up to 5 hops) and re-authorizes on every
  hop, so a token is only sent to URLs inside its realm. If you pass your own
  <code>reqwest::Client</code> through <code>http_client()</code>, its redirect policy applies instead.</li>
  <li>Streaming uploads need reqwest's <code>stream</code> feature in your crate (<code>Body::from_reqwest</code>). The client sends a <code>HEAD</code> first to obtain a token.</li>
</ul>

<h2 id="build">Build, test and examples</h2>
${code("bash", `
cd rust
cargo test                                   # unit, fixture, HTTP (wiremock) tests and doctests
cargo clippy --all-targets -- -D warnings
cargo doc --no-deps
node ../testing/mock-server/server.mjs --port 8787 &
LWS_TEST_SERVER=http://localhost:8787 cargo test --test interop

cargo run --example quickstart -- http://localhost:8787/root/     # LWS_DID_KEY_AUTH=1 to authenticate
cargo run --example did_key_auth -- http://localhost:8787/root/
cargo run --example webhook_receiver -- http://localhost:8787/root/`)}
${callout("note", "Source", ' <a href="https://github.com/ebremer/lws-client/tree/main/rust">rust/</a> in the repository, with its own <a href="https://github.com/ebremer/lws-client/blob/main/rust/README.md">README</a>.')}
`,
};
