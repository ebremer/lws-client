// SPDX-License-Identifier: MIT
import { callout, code, table } from "../../lib.mjs";

export default {
  path: "languages/wasm.html",
  title: "WebAssembly",
  description: "The Rust LWS client as a WebAssembly component (WASI 0.2): its WIT interface, use from JavaScript through jco and from Rust through Wasmtime, and build instructions.",
  body: `
<h1><span class="lang-badge lang-wasm">WA</span> WebAssembly</h1>
<div class="badges">
  <span class="badge accent">lws_client.wasm 0.1.0</span>
  <span class="badge">WASI 0.2 component</span>
  <span class="badge">WIT package ebremer:lws@0.1.0</span>
  <span class="badge">about 1.1 MB</span>
</div>
<p class="lead">The <a href="rust.html">Rust client</a> built for <code>wasm32-wasip2</code> into a WebAssembly component,
behind a WIT interface. One client for every language that can host components: JavaScript through
<a href="https://github.com/bytecodealliance/jco">jco</a>, and Rust, Python, Go or .NET through
<a href="https://wasmtime.dev/">Wasmtime</a>. It behaves on the wire exactly as the Rust client does. Only the transport
differs: the component sends its requests through the host's <code>wasi:http</code>, so the host does TLS and decides
which hosts the component may reach.</p>
<div id="toc" class="toc"></div>

<h2 id="build">Build</h2>
${code("bash", `
rustup target add wasm32-wasip2                    # Rust 1.87 or later
cd wasm
cargo build --release --target wasm32-wasip2
# target/wasm32-wasip2/release/lws_client.wasm`)}
<p>The component imports <code>wasi:http</code>, <code>wasi:io</code>, <code>wasi:clocks</code>, <code>wasi:random</code>,
<code>wasi:cli</code> (environment, exit, standard streams) and <code>ebremer:lws/token-source</code>. It needs no files and
no sockets.</p>

<h2 id="interface">The interface</h2>
<p><a href="https://github.com/ebremer/lws-client/blob/main/wasm/wit/lws.wit">wasm/wit/lws.wit</a> defines the world
<code>lws-client</code>:</p>
${table(
  ["Interface", "What"],
  [
    ["<code>types</code>", "The values: <code>metadata</code>, <code>read-result</code>, <code>page</code>, <code>item</code>, <code>created</code>, <code>updated</code>, <code>storage-description</code>, <code>linkset-document</code>, <code>subscription</code>, <code>patch-operation</code>, <code>type-query</code>, and <code>error</code> with its <code>error-kind</code>"],
    ["<code>client</code> (export)", "The <code>client</code> resource, made by <code>client.new(options)</code>, with the operations of the API contract under their kebab-case names: <code>discover-storage</code>, <code>read</code>, <code>list-container</code>, <code>create</code>, <code>patch-linkset</code>, <code>subscribe</code>, <code>search-all</code>, … Lazy listings are the <code>items</code> and <code>type-iris</code> resources, read with <code>next</code>"],
    ["<code>webhook</code> (export)", "The <code>verifier</code> resource: verifies signed notification deliveries (RFC 9421, RFC 9530) with the storage's published keys"],
    ["<code>token-source</code> (import)", "Subject tokens from the host, for an <code>openid</code> or <code>saml</code> client made with <code>subject-token.host</code>"],
  ],
)}
${table(
  ["Aspect", "How the component does it"],
  [
    ["Calls", "Synchronous: a call blocks until the host's <code>wasi:http</code> has the answer (WASI 0.2 exports are synchronous). A host that runs a storage in the same thread blocks itself"],
    ["Authentication", "<code>options.auth</code>: <code>none</code>, <code>bearer</code>, <code>openid</code>, <code>saml</code>, <code>self-signed</code> (an agent and a private JWK) or <code>did-key</code> (a fresh key). The 401 → token exchange → retry flow is the Rust client's"],
    ["Values", "URLs are strings, absolute in every result. JSON-LD documents (storage descriptions, access requests and grants, linksets, notifications) cross as JSON text; everything else is typed. JSON Patch is a list of typed operations"],
    ["Errors", "Every operation returns <code>result&lt;_, error&gt;</code>. An <code>error</code> has its <code>error-kind</code> (<code>not-found</code>, <code>precondition-failed</code>, …, <code>authentication</code>, <code>protocol</code>, <code>transport</code>), a message, and for an error response the status, headers and problem details"],
    ["Bodies", "<code>list&lt;u8&gt;</code>, in and out. Request bodies are never streamed"],
    ["Timeouts", "<code>options.timeout-ms</code> becomes the host's connect, first-byte and between-bytes timeouts"],
  ],
)}

<h2 id="javascript">From JavaScript</h2>
<p><code>jco transpile</code> turns the component into an ES module that runs on Node.js with
<code>@bytecodealliance/preview2-shim</code>. Give it a <code>token-source</code> module, even one with no tokens:</p>
${code("bash", `
npm install @bytecodealliance/jco @bytecodealliance/preview2-shim
npx jco transpile lws_client.wasm -o lws --name lws-client --map 'ebremer:lws/token-source=../token-source.js'`)}
${code("js", `
// token-source.js
export function subjectToken(kind, issuer, realm) {
  throw \`no \${kind} token for \${realm}\`;
}`)}
${code("js", `
import { client } from "./lws/lws-client.js";

const lws = client.Client.new({ auth: { tag: "did-key", val: "es256" }, headers: [], allowInsecureHttp: false });
const storage = lws.discoverStorage("https://storage.example/root/");
const notes = lws.createContainer(storage.storageRoot, { slug: "notes", types: [], links: [], headers: [] }).location;
const hello = lws.create(notes, new TextEncoder().encode("Hello, LWS!"), "text/plain",
  { slug: "hello.txt", types: [], links: [], headers: [] }).location;
console.log(new TextDecoder().decode(lws.read(hello, { headers: [] }).body));

const items = lws.listContainer(notes);
for (let item; (item = items.next()) !== undefined; ) console.log(item.id, item.types);

try {
  lws.update(hello, new TextEncoder().encode("again"), "text/plain",
    { ifMatch: '"stale"', links: [], setLinkset: false, headers: [] });
} catch (e) {
  console.log(e.payload.kind, e.payload.http?.status); // precondition-failed 412
}`)}
<p>Variant tags and enum values are kebab-case (<code>"did-key"</code>, <code>"precondition-failed"</code>), record fields
camelCase, and an <code>error</code> is thrown with the record as its <code>payload</code>.</p>

<h2 id="rust">From Rust, with Wasmtime</h2>
${code("rust", `
let engine = Engine::default();
let component = Component::from_file(&engine, "lws_client.wasm")?;
let mut linker = Linker::new(&engine);
wasmtime_wasi::p2::add_to_linker_sync(&mut linker)?;
wasmtime_wasi_http::p2::add_only_http_to_linker_sync(&mut linker)?;
LwsClient::add_to_linker::<Host, HasSelf<Host>>(&mut linker, |host| host)?;

let mut store = Store::new(&engine, host);
let lws = LwsClient::instantiate(&mut store, &component, &linker)?;
let client = lws.ebremer_lws_client().client();
let me = client.call_new(&mut store, &options)??;
let metadata = client.call_head(&mut store, me, "https://storage.example/root/")??;`)}
<p><code>LwsClient</code> comes from <code>wasmtime::component::bindgen!</code> on <code>wasm/wit</code>. The driver's
WebAssembly adapter, <a href="https://github.com/ebremer/lws-client/blob/main/driver/adapters/wasm/src/runtime.rs">driver/adapters/wasm</a>,
is a complete host. To limit where the component's requests go, implement <code>WasiHttpHooks::send_request</code>.</p>

<h2 id="test">Test</h2>
<p>The component is tested through its interface, as a host uses it: the driver's WebAssembly adapter runs it in Wasmtime,
and <code>check.mjs</code> takes it through every operation against the mock server.</p>
${code("bash", `
cargo build --release --manifest-path driver/adapters/wasm/Cargo.toml
node driver/adapters/check.mjs -- driver/adapters/wasm/target/release/lws-driver-adapter-wasm wasm/target/wasm32-wasip2/release/lws_client.wasm
# wasm: 35 passed, 0 failed, 0 skipped`)}
${callout("note", "Source", ' <a href="https://github.com/ebremer/lws-client/tree/main/wasm">wasm/</a> in the repository, with its own <a href="https://github.com/ebremer/lws-client/blob/main/wasm/README.md">README</a>.')}
`,
};
