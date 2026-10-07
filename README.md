# lws-client

**W3C Linked Web Storage (LWS) clients for Java, JavaScript/TypeScript, C++, Rust, Go, Python, C# and Swift, and a
WebAssembly component.**

[![License: MIT](https://img.shields.io/badge/license-MIT-0b7a6d.svg)](LICENSE)
![Spec baseline](https://img.shields.io/badge/LWS%20spec-2026--10--05-0a6c94.svg)
[![Docs](https://img.shields.io/badge/docs-ebremer.github.io%2Flws--client-555.svg)](https://ebremer.github.io/lws-client/)

[Linked Web Storage](https://w3c.github.io/lws-protocol/lws10-core/) is the W3C Working Group's protocol
for giving applications secure, permissioned access to data that users keep in a storage of their
choosing. It is the standards-track successor of the Solid Protocol. This repository contains eight
independent, idiomatic client libraries that share one API design, one set of conformance fixtures
and one interop test suite, and the Rust one built as a WebAssembly component for any language that
can host components.

📖 **Documentation:** <https://ebremer.github.io/lws-client/>

## Features

Every client implements the full client side of the LWS drafts as of **2026-10-05**:

- **Discovery:** `rel="https://www.w3.org/ns/lws#storage"`, storage descriptions (`application/lws+cid`),
  services and capabilities.
- **Resources:** create (including containers and `Slug` hints), read, `HEAD`, ranges, conditional requests,
  `PUT` with `If-Match`, JSON Patch (the baseline `PATCH` format), recursive delete.
- **Containers:** `application/lws+json` listings with lazy, link-based pagination.
- **Metadata:** linkset resources (RFC 9264), read, replace and patch, plus `Prefer: set-linkset`.
- **Authorization:** automatic `401` → authorization server metadata → OAuth 2.0 token exchange
  (RFC 8693) → retry, with realm checks, token caching and proactive reuse.
- **Authentication suites:** OpenID Connect, SAML 2.0, and self-signed identities (controlled
  identifier documents and `did:key`) with ES256 and EdDSA.
- **Notifications:** webhook subscriptions, plus verification of signed deliveries
  (RFC 9421 HTTP Message Signatures with RFC 9530 `Content-Digest`).
- **Access requests and grants:** the ODRL-based access profile.
- **Type index and type search:** using the HTTP `QUERY` method with `application/lws-query+json`.
- **Errors:** typed errors per status with RFC 9457 problem details.

## Languages

| Language | Directory | Package | Requires | Highlights |
|---|---|---|---|---|
| Java | [`java/`](java) | `com.ebremer:lws-client` | Java 17+ | JPMS module, records, lazy `Stream`s, `*Async` variants, JDK crypto |
| JavaScript / TypeScript | [`js/`](js) | `lws-client` (npm) | Node 20+, browsers, Deno, Bun | Zero dependencies, `fetch` + WebCrypto, `for await` pagination |
| C++ | [`cpp/`](cpp) | CMake `lws::client` | C++20, CMake 3.21+ | Pluggable transport, optional libcurl/OpenSSL, lazy ranges |
| Rust | [`rust/`](rust) | `lws-client` (crate) | Rust 1.85+ | async/tokio, `Stream` pagination, RustCrypto, `thiserror` |
| Go | [`go/`](go) | `github.com/ebremer/lws-client/go` | Go 1.23+ | Zero dependencies, `context`, `iter.Seq2`, `errors.Is` sentinels |
| Python | [`python/`](python) | `lws-client` (PyPI) | Python 3.10+ | Sync and async clients over one sans-I/O core, typed dataclasses |
| C# | [`csharp/`](csharp) | `Ebremer.Lws.Client` (NuGet) | .NET 10 | `async` throughout with `CancellationToken`, `IAsyncEnumerable` listings, records; Ed25519 from BouncyCastle |
| Swift | [`swift/`](swift) | `lws-client` (SwiftPM, product `LWS`) | Swift 6.0+; macOS 13, iOS 16, Linux | `async`/`await` with task cancellation, `AsyncSequence` listings, `Sendable` values, `URLSession`; CryptoKit (swift-crypto) |
| WebAssembly | [`wasm/`](wasm) | `lws_client.wasm` (WASI 0.2 component) | A component host with `wasi:http`: Wasmtime, or jco for Node.js | The Rust client behind a WIT interface ([`wasm/wit/lws.wit`](wasm/wit/lws.wit)); requests and TLS through the host's `wasi:http` |

The APIs use the same concept names everywhere (`discoverStorage`, `readContainer`, `listContainer`,
`create`, `update`, `patch`, `readLinkset`, `subscribe`, `searchTypes`, …). Casing and error handling
follow each language's conventions; see the
[API cross-reference](https://ebremer.github.io/lws-client/api-reference.html).

## Quick look

<details open>
<summary><b>TypeScript</b></summary>

```ts
import { LwsClient, TokenExchangeAuthenticator, SelfSignedCredentials, generateKeyPair, JsonPatch } from "lws-client";

const credentials = SelfSignedCredentials.didKey(await generateKeyPair("ES256"));
const client = new LwsClient({ authenticator: new TokenExchangeAuthenticator(credentials) });

const storage = await client.discoverStorage("https://storage.example/root/");
const { location } = await client.createJson(storage.storageRoot(), { task: "write docs", done: false }, { slug: "todo.json" });
await client.patch(location, new JsonPatch().replace("/done", true));

for await (const item of client.listContainer(storage.storageRoot())) console.log(item.id, item.format);
```
</details>

<details>
<summary><b>Python</b></summary>

```python
from lws_client import LwsClient, SelfSignedCredentials, SigningKey, TokenExchangeAuthenticator, JsonPatch

credentials = SelfSignedCredentials.did_key(SigningKey.generate())
with LwsClient(authenticator=TokenExchangeAuthenticator(credentials)) as client:
    storage = client.discover_storage("https://storage.example/root/")
    todo = client.create_json(storage.storage_root(), {"task": "write docs", "done": False}, slug="todo.json")
    client.patch(todo.location, JsonPatch().replace("/done", True))
    for item in client.list_container(storage.storage_root()):
        print(item.id, item.format)
```
</details>

<details>
<summary><b>Go</b></summary>

```go
key, _ := lws.GenerateP256Key()
creds, _ := lws.NewDIDKeyCredentials(key, nil)
client := lws.NewClient(lws.WithAuthenticator(lws.NewTokenExchangeAuthenticator(creds, nil)))

storage, err := client.DiscoverStorage(ctx, "https://storage.example/root/")
if err != nil { return err }
root, _ := storage.StorageRoot()
todo, err := client.CreateJSON(ctx, root, map[string]any{"task": "write docs", "done": false}, lws.Slug("todo.json"))
if err != nil { return err }
_, err = client.Patch(ctx, todo.Location, lws.JSONPatch{}.Replace("/done", true))

for item, err := range client.ListContainer(ctx, root) {
    if err != nil { return err }
    fmt.Println(item.ID, item.Format)
}
```
</details>

<details>
<summary><b>Java</b></summary>

```java
SelfSignedCredentials me = SelfSignedCredentials.didKey(KeyPairs.generateP256());
LwsClient client = LwsClient.builder().authenticator(TokenExchangeAuthenticator.of(me)).build();

StorageDescription storage = client.discoverStorage(URI.create("https://storage.example/root/"));
URI todo = client.createJson(storage.storageRoot(), Map.of("task", "write docs", "done", false),
        CreateOptions.slug("todo.json")).location();
client.patch(todo, JsonPatch.builder().replace("/done", true).build());

client.listContainer(storage.storageRoot()).forEach(item -> System.out.println(item.id()));
```
</details>

<details>
<summary><b>C++</b></summary>

```cpp
lws::ClientOptions options;
options.authenticator = std::make_shared<lws::TokenExchangeAuthenticator>(
    lws::SelfSignedCredentials::did_key(lws::PrivateKey::generate(lws::KeyAlgorithm::ES256)));
lws::Client client(options);

const auto storage = client.discover_storage("https://storage.example/root/");
const auto todo = client.create_json(storage.storage_root(), {{"task", "write docs"}, {"done", false}}, {.slug = "todo.json"});
client.patch(todo.location, lws::JsonPatch{}.replace("/done", true));

for (const auto& item : client.list_container(storage.storage_root())) std::cout << item.id << '\n';
```
</details>

<details>
<summary><b>Rust</b></summary>

```rust
use futures_util::TryStreamExt;
use lws_client::{crypto::SigningKey, Client, JsonPatch, SelfSignedCredentials, TokenExchangeAuthenticator};

let credentials = SelfSignedCredentials::did_key(SigningKey::generate_p256()?);
let client = Client::builder().authenticator(TokenExchangeAuthenticator::new(credentials)).build()?;

let storage = client.discover_storage("https://storage.example/root/").await?;
let root = storage.storage_root()?.clone();
let todo = client.create_json(&root, &serde_json::json!({"task": "write docs", "done": false}))
    .slug("todo.json").await?.location;
client.patch(&todo, &JsonPatch::new().replace("/done", true)).await?;

let items: Vec<_> = client.list_container(&root).try_collect().await?;
```
</details>

<details>
<summary><b>C#</b></summary>

```csharp
SelfSignedCredentials me = SelfSignedCredentials.DidKey(SigningKey.GenerateP256());
using var client = new LwsClient(new LwsClientOptions { Authenticator = new TokenExchangeAuthenticator(me) });

StorageDescription storage = await client.DiscoverStorageAsync(new Uri("https://storage.example/root/"));
Uri todo = (await client.CreateJsonAsync(storage.GetStorageRoot(), new JsonObject { ["task"] = "write docs", ["done"] = false },
    new CreateOptions { Slug = "todo.json" })).Location;
await client.PatchAsync(todo, new JsonPatch().Replace("/done", true));

await foreach (ContainedResource item in client.ListContainerAsync(storage.GetStorageRoot())) Console.WriteLine(item.Id);
```
</details>

<details>
<summary><b>Swift</b></summary>

```swift
let me = try SelfSignedCredentials.didKey(.generateP256())
let client = LWSClient(authenticator: TokenExchangeAuthenticator(credentials: me))

let storage = try await client.discoverStorage(URL(string: "https://storage.example/root/")!)
let todo = try await client.createJSON(in: try storage.storageRoot(), json: ["task": "write docs", "done": false],
                                       options: CreateOptions(slug: "todo.json")).location
_ = try await client.patch(todo, patch: JSONPatch().replace("/done", true))

for try await item in client.listContainer(try storage.storageRoot()) { print(item.id) }
```
</details>

<details>
<summary><b>WebAssembly (from JavaScript, through jco)</b></summary>

```js
import { client } from "./lws/lws-client.js"; // npx jco transpile lws_client.wasm -o lws …

const lws = client.Client.new({ auth: { tag: "did-key", val: "es256" }, headers: [], allowInsecureHttp: false });
const storage = lws.discoverStorage("https://storage.example/root/");
const todo = lws.create(storage.storageRoot, new TextEncoder().encode('{"task":"write docs","done":false}'),
  "application/json", { slug: "todo.json", types: [], links: [], headers: [] }).location;
lws.patch(todo, [{ op: "replace", path: "/done", value: "true" }], { links: [], setLinkset: false, headers: [] });

const items = lws.listContainer(storage.storageRoot);
for (let item; (item = items.next()) !== undefined; ) console.log(item.id, item.format);
```
</details>

## Try it locally

The repository ships a zero-dependency [mock LWS server](testing/mock-server) (Node.js 22+) that
implements the server side of every feature above, including real token exchange and signed webhooks:

```sh
node testing/mock-server/server.mjs --port 8787
# LWS mock server listening on http://localhost:8787   (storage root: /root/)
```

Each language directory has a `README.md` with build, test and example commands.

## Driving the clients

[`driver/`](driver) is an MCP server (Spring AI) that controls all eight clients, and the component, through a
small adapter per language, so that a test service such as [Touchstone](https://github.com/ebremer/touchstone) can make any
of them perform LWS operations and judge what it sends. See [`driver/README.md`](driver/README.md).

## Repository layout

```
design/            Cross-language API contract (client-api.md)
conformance/       Shared fixtures (JSON test vectors) and the interop scenario
testing/           Mock LWS server used for interop tests
java/ js/ cpp/ rust/ go/ python/ csharp/ swift/   The eight clients (Package.swift, at the root, builds swift/)
wasm/              The Rust client as a WebAssembly component (its interface: wasm/wit/lws.wit)
driver/            MCP server that drives every client, and one adapter per language
docs/              GitHub Pages site (generated from docs-src/ with `node docs-src/build.mjs`)
```

## Spec baseline

The clients target the W3C LWS Working Group documents as of 2026-10-05
([w3c/lws-protocol@ef02548](https://github.com/w3c/lws-protocol/commit/ef02548)):
LWS Protocol 1.0 (FPWD 2026-06-05 plus the editor's draft), the OpenID Connect, SAML 2.0 and
self-signed (CID) authentication suites, the Webhook notification suite, the Search and Type Index
services, and the LWS vocabulary. Interpretation decisions for points the drafts leave open are listed
in [`design/client-api.md`](design/client-api.md) and on the
[spec coverage page](https://ebremer.github.io/lws-client/spec-coverage.html).

This is an independent implementation, not a W3C publication.

## License

[MIT](LICENSE). This covers all eight clients, the component, the mock server, the fixtures and the
documentation.
