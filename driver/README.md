# lws-client driver

An [MCP](https://modelcontextprotocol.io/) server that controls all ten lws-client libraries, and the Rust one
as a WebAssembly component too, so that a test
service can make each client do exactly what a test needs. The motivating user is
[Touchstone](https://github.com/ebremer/touchstone): its client sessions record and judge every request a
client sends, and with the driver Touchstone no longer has to wait for a developer to run the client by
hand. It starts a client in the language under test, tells it what to do, arms a task or a fault between
steps, and judges the traffic.

The server is a Spring Boot 4.1 application built on **Spring AI 2.0.1** (its MCP server, Streamable HTTP
or stdio). Behind it, each language has an **adapter**: a small program, written in that language with that
language's lws-client, that runs operations it is sent on stdin and reports what happened on stdout. The
adapters' contract is [PROTOCOL.md](PROTOCOL.md).

```
 Touchstone (or any MCP client)
        │  MCP: start_client, read, create, patch_linkset, subscribe, …
        ▼
 ┌─────────────────────────────┐   lws-driver/1 (JSON lines on stdin/stdout)   ┌───────────────────┐
 │ lws-client-driver           │ ─────────────────────────────────────────────▶ │ adapter (Go)      │──▶ lws-client-go ──▶ storage
 │ Spring AI MCP server        │ ─────────────────────────────────────────────▶ │ adapter (Python)  │──▶ lws_client    ──▶ storage
 │ + webhook inboxes           │                       …                        │ …                 │
 └─────────────────────────────┘                                                └───────────────────┘
```

Every adapter is a thin, faithful wrapper: it calls the library's own operation with the library's own
options and reports the library's own result or error. Nothing is retried or smoothed over, because the
point is to see what the **client** sends.

## Layout

| Path | What |
|---|---|
| [`PROTOCOL.md`](PROTOCOL.md) | the adapter protocol, `lws-driver/1` |
| [`server/`](server) | the MCP server (Maven, Spring Boot 4.1.1, Spring AI 2.0.1, Java 17) |
| [`adapters/<language>/`](adapters) | one adapter per language: `java`, `js`, `python`, `go`, `rust`, `cpp`, `csharp`, `swift`, `php`, `kotlin`, and `wasm` for the component |
| [`adapters/check.mjs`](adapters/check.mjs) | checks an adapter against the mock server, through the protocol |
| [`touchstone/`](touchstone) | plays Touchstone's part: drives each language through a Touchstone client session |
| [`pom.xml`](pom.xml) | builds the Java library, the Java adapter and the server together |

## Build

Build each language's library first, as its own README says. Then the adapters, from the repository
root:

| Adapter | Build | Command the driver runs (from `driver/`) |
|---|---|---|
| Java | `mvn -f driver/pom.xml package` (also builds the server) | `java -jar adapters/java/target/lws-driver-adapter-java.jar` |
| JavaScript | `cd js && npm ci && npm run build` (the adapter imports `js/dist`) | `node adapters/js/adapter.mjs` (Node 20+) |
| Python | `pip install -e "python[crypto]"` into the Python that runs it | `python3 adapters/python/adapter.py` |
| Go | `cd driver/adapters/go && go build -o bin/lws-driver-adapter-go .` | `adapters/go/bin/lws-driver-adapter-go` |
| Rust | `cargo build --release --manifest-path driver/adapters/rust/Cargo.toml` | `adapters/rust/target/release/lws-driver-adapter-rust` |
| C++ | `cmake -S driver/adapters/cpp -B driver/adapters/cpp/build -G Ninja && cmake --build driver/adapters/cpp/build` | `adapters/cpp/build/lws-driver-adapter-cpp` |
| C# | `dotnet publish driver/adapters/csharp -c Release -r linux-x64 --self-contained -p:PublishSingleFile=true -o driver/adapters/csharp/bin` (.NET 10 SDK) | `adapters/csharp/bin/lws-driver-adapter-csharp` |
| Swift | `swift build -c release --product lws-driver-adapter-swift` at the repository root (Swift 6.0+); `--static-swift-stdlib --build-system native` makes a binary that needs only the system libcurl | `../.build/release/lws-driver-adapter-swift` |
| PHP | nothing to build: the adapter loads the library from `php/src` (or through `vendor/autoload.php` after `composer install`); PHP 8.2+ with ext-curl, ext-openssl and ext-sodium | `php adapters/php/adapter.php` |
| Kotlin | `kotlin/gradlew -p driver/adapters/kotlin jar` (JDK 17+; the build includes the library in `kotlin/`) | `java -jar adapters/kotlin/build/libs/lws-driver-adapter-kotlin.jar` |
| WebAssembly | `cargo build --release --target wasm32-wasip2 --manifest-path wasm/Cargo.toml`, then `cargo build --release --manifest-path driver/adapters/wasm/Cargo.toml` (Rust 1.96+) | `adapters/wasm/target/release/lws-driver-adapter-wasm ../wasm/target/wasm32-wasip2/release/lws_client.wasm` |

Check an adapter with the mock server (Node 22+):

```sh
node driver/adapters/check.mjs -- driver/adapters/go/bin/lws-driver-adapter-go
# ...
# go: 35 passed, 0 failed, 0 skipped
```

## Run

```sh
cd driver
java -jar server/target/lws-client-driver.jar
# MCP (Streamable HTTP) at http://127.0.0.1:18095/mcp
```

The commands above are the defaults, in [`application.yaml`](server/src/main/resources/application.yaml).
Override any of them, for example to use a virtual environment's Python:

```sh
java -jar server/target/lws-client-driver.jar \
    --lws.driver.languages.python.command=/opt/venv/bin/python,adapters/python/adapter.py
```

`list_languages` says which adapters are built and ready; with `probe` it starts each once and lists the
operations its library lacks.

For an MCP client that starts the driver itself, there is a stdio mode. It has no HTTP server, so no
inboxes:

```sh
java -jar server/target/lws-client-driver.jar --spring.profiles.active=stdio
```

### Settings

| Setting | Default | Meaning |
|---|---|---|
| `server.address`, `server.port` | `127.0.0.1`, `18095` | where the MCP endpoint and the inboxes listen |
| `lws.driver.token` | none | the bearer token the MCP endpoint requires. **Required** unless `server.address` is loopback: the server refuses to start otherwise |
| `lws.driver.allowed-targets` | any | URL prefixes the clients may be pointed at, such as a Touchstone service's base |
| `lws.driver.allowed-origins` | none | browser origins allowed to call `/mcp`; a request with any other `Origin` is refused (DNS rebinding) |
| `lws.driver.public-base-url` | `http://<server.address>:<port>` | the driver's URL as a storage reaches it, for inbox URLs |
| `lws.driver.home` | `.` | the driver directory; relative adapter commands resolve against it |
| `lws.driver.operation-timeout` | `60s` | an adapter that takes longer is stopped |
| `lws.driver.max-clients`, `lws.driver.idle-timeout` | `16`, `2h` | how many clients may run, and when an unused one is stopped |

Whoever can call the MCP endpoint can make the clients send requests with the credentials they were
given. Keep it on loopback, or behind the token and the target allow-list.

## The tools

**The driver's own:**

| Tool | |
|---|---|
| `list_languages` | the languages, whether each adapter is ready, and (with `probe`) its library and unsupported operations |
| `start_client` | starts a client: a language and one identity (`none`, `bearer`, `openid` with an ID Token, `selfSigned` with an agent and a private JWK, or a fresh `didKey`). Returns its id |
| `list_clients`, `stop_client`, `client_log` | the running clients, stopping one, its adapter's stderr |
| `open_inbox`, `inbox_deliveries` | a webhook inbox on the driver's HTTP server, and what was delivered to it |

**One per LWS operation**, each taking `client` and the operation's arguments of PROTOCOL.md §4:
`discover_storage`, `get_storage_description`, `head`, `read`, `read_container`, `list_container`, `create`,
`create_container`, `update`, `patch`, `delete`, `linkset_url`, `read_linkset`, `update_linkset`,
`patch_linkset`, `subscribe`, `list_subscriptions`, `get_subscription`, `unsubscribe`,
`verify_notification`, `request_access`, `get_access_request`, `list_access_requests`,
`cancel_access_request`, `grant_access`, `get_access_grant`, `list_access_grants`, `revoke_access_grant`,
`read_type_index`, `list_types`, `search_types`, `search_all`, `accepted_query_formats`.

An operation tool returns the adapter's response as structured content (and as JSON text):
`{"ok": true, "result": …}`, or `{"ok": false, "error": {"kind": "ConflictError", "status": 409, …}}`. An
error outcome is something the client did, which a test may well be looking for. `Unsupported` means
that language's library lacks the operation. A **tool error** (`isError`) means the driver itself could
not do it: an unknown client, an adapter that will not start or stopped answering, a target outside the
allowed ones.

### Inboxes

`open_inbox` gives a client an inbox at `<public-base-url>/inbox/<client>/<secret>`, and `subscribe` uses
it when no inbox is given. A delivery to it is verified with the client's own `WebhookVerifier`, in a
second adapter process so that a delivery never waits for the client. It is answered `202` when it
verifies and `401` when its signature does not. `inbox_deliveries` returns each delivery, its verdict and
the inbox's answer. The storage must be able to reach the inbox: a local Touchstone needs
`--allow-private-inboxes`, and a public one needs the driver behind a public https URL.

## Testing against Touchstone

[`touchstone/run-sessions.mjs`](touchstone/run-sessions.mjs) does what a Touchstone server will do with
the driver. For each language it:

1. starts a client session and a client with alice's self-issued credentials;
2. walks the client through every client rule: discovery, containers, conditional reads and writes, JSON
   Patch, linksets, pagination, type index and search, notifications, access requests and grants, the
   decoy, and the OpenID Connect suite (it signs in at the session's provider and hands a second client
   the ID Token);
3. starts each checklist task and arms each fault along the way (a refused linkset PUT, a lost create, an
   expired search page, an expired token, four forged notifications);
4. prints the session's verdict and saves the JSON, JUnit and EARL results.

```sh
# Touchstone's client service, locally (in the touchstone repository):
java -jar harness-clients/target/touchstone-clients.jar --port 18090 \
    --definitions definitions --catalog catalog --allow-private-inboxes
# The driver (in driver/):
java -jar server/target/lws-client-driver.jar
# Every language that list_languages says is ready:
node driver/touchstone/run-sessions.mjs --out results/
```

[`touchstone/mcp-client.mjs`](touchstone/mcp-client.mjs) is the dependency-free MCP client it uses.

## Adding an operation

Follow [CONTRIBUTING.md](../CONTRIBUTING.md), then:
- add the operation to PROTOCOL.md §4 and to the tool catalog,
  [`operations.json`](server/src/main/resources/operations.json);
- implement it in all ten adapters (for `wasm`, in the component's interface, wasm/wit/lws.wit, first);
- add a check to `adapters/check.mjs`.

`OperationCatalogTest` fails until the catalog and PROTOCOL.md agree.
