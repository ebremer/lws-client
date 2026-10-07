# lws-client (WebAssembly component)

The Rust client of [`../rust`](../rust) built as a **WebAssembly component** for WASI 0.2
(`wasm32-wasip2`), behind the interface in [`wit/lws.wit`](wit/lws.wit). It is one client for every
language that can host components: Rust, Python, Go and .NET through
[Wasmtime](https://wasmtime.dev/), and JavaScript through [jco](https://github.com/bytecodealliance/jco).

It is the same client as the Rust crate, with the same behaviour on the wire. The difference is the
transport: on `wasm32-wasip2` the crate sends its requests through the host's `wasi:http` instead of
reqwest (see `rust/src/transport/`). The host does TLS, and decides which hosts the component may
reach.

## Build

Rust 1.87 or later, with the target:

```sh
rustup target add wasm32-wasip2
cargo build --release --target wasm32-wasip2
# target/wasm32-wasip2/release/lws_client.wasm  (about 1.1 MB)
```

The component imports `wasi:http` (`outgoing-handler`, `types`), `wasi:io`, `wasi:clocks`,
`wasi:random`, `wasi:cli` (environment, exit, standard streams) and `ebremer:lws/token-source`. It
needs no files and no sockets.

## The interface

[`wit/lws.wit`](wit/lws.wit) defines the world `lws-client`:

| Interface | What |
|---|---|
| `types` | the values: `metadata`, `read-result`, `page`, `item`, `storage-description`, `linkset-document`, `subscription`, `patch-operation`, `type-query`, and `error` with its `error-kind` |
| `client` (export) | the `client` resource and the operations of the [API contract](../design/client-api.md), from `discover-storage` to `search-all`; the lazy listings are the `items` and `type-iris` resources |
| `webhook` (export) | the `verifier` resource: verifies signed notification deliveries (RFC 9421, RFC 9530) |
| `token-source` (import) | subject tokens from the host, for an `openid` or `saml` client created with `subject-token.host` |

URLs are strings. JSON-LD documents (storage descriptions, access requests and grants, linksets,
notifications) cross as JSON text, `type json = string`. Everything else is typed. Every operation
returns `result<_, error>`; an error response's `error` carries the status, the headers and the
problem details (RFC 9457).

Calls are synchronous: a call blocks until the host's `wasi:http` has the answer. A host that runs a
storage in the same thread as the component (a test server in the same Node.js process, say) blocks
itself.

## From JavaScript (Node.js 22+)

`jco transpile` turns the component into an ES module that runs on
[`@bytecodealliance/preview2-shim`](https://www.npmjs.com/package/@bytecodealliance/preview2-shim). Give
it a `token-source` module, even one that has no tokens:

```js
// token-source.js
export function subjectToken(kind, issuer, realm) {
  throw `no ${kind} token for ${realm}`;
}
```

```sh
npm install @bytecodealliance/jco @bytecodealliance/preview2-shim
npx jco transpile lws_client.wasm -o lws --name lws-client --map 'ebremer:lws/token-source=../token-source.js'
```

```js
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
}
```

Variant tags and enum values are kebab-case (`"did-key"`, `"precondition-failed"`); record fields
are camelCase; an `error` is thrown, with the record as its `payload`.

## From Rust (Wasmtime)

Generate the bindings with `wasmtime::component::bindgen!` from `wit/`, link WASI and `wasi:http`, and
implement `token-source`. [`driver/adapters/wasm/src/runtime.rs`](../driver/adapters/wasm/src/runtime.rs)
is a complete host:

```rust
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
let metadata = client.call_head(&mut store, me, "https://storage.example/root/")??;
```

To limit where the component's requests go, implement `WasiHttpHooks::send_request` and refuse the
others.

## Testing

The component is tested through its interface, as a host uses it: the driver's WebAssembly adapter,
[`driver/adapters/wasm`](../driver/adapters/wasm), runs it in Wasmtime, and `check.mjs` takes the adapter
through every operation against the mock server.

```sh
cargo build --release --manifest-path ../driver/adapters/wasm/Cargo.toml
node ../driver/adapters/check.mjs -- ../driver/adapters/wasm/target/release/lws-driver-adapter-wasm target/wasm32-wasip2/release/lws_client.wasm
# wasm: 35 passed, 0 failed, 0 skipped
```

## Differences from the Rust crate

- Request bodies are bytes: there is no streaming request body.
- A timeout is the host's connect, first-byte and between-bytes timeout, not one for the whole request.
- The `reqwest`-specific parts of the crate's API (`ClientBuilder::http_client`, `Body::from_reqwest`,
  `StreamingResource::into_response`) are not there, and `Error::Transport` carries a `TransportError`.
- The component's `user-agent` default is the crate's, `lws-client-rust/<version>`.
