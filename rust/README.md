# lws-client (Rust)

An async Rust client for the W3C **Linked Web Storage (LWS) Protocol 1.0** and its companion
specifications — authentication suites (OpenID Connect, SAML 2.0, self-signed controlled
identifiers / `did:key`), webhook notifications, access requests/grants, and the Search and Type
Index services — tracking the Working Group drafts as of **2026-10-05**.

Part of the [lws-client](https://github.com/ebremer/lws-client) family (Java, JavaScript, C++, Rust,
Go, Python). MIT licensed — see the repository [LICENSE](../LICENSE).

* Async on Tokio + `reqwest` (HTTP/2, rustls by default); `Client` is `Clone + Send + Sync`.
* Request builders you can `.await` directly: `client.read(url).if_none_match(etag).await?`.
* Lazy pagination as `futures` streams; every returned URL is absolute.
* Automatic LWS OAuth 2.0 token exchange on `401`, with per-realm token caching.
* Self-signed ES256 / EdDSA identities (`did:key` or HTTPS agents) — no OIDC provider needed for bots.
* RFC 9421 / RFC 9530 webhook signature verification.
* `#![forbid(unsafe_code)]`, minimal dependencies (RustCrypto for crypto, no date/time crate in the API).

## Install

```toml
[dependencies]
lws-client = { git = "https://github.com/ebremer/lws-client" }
tokio = { version = "1", features = ["macros", "rt-multi-thread"] }
futures-util = "0.3"   # for TryStreamExt on listings
```

MSRV: Rust 1.85 (edition 2024).

| Feature | Default | Enables |
|---|---|---|
| `rustls` | ✓ | TLS via rustls (reqwest's default backend) |
| `native-tls` | | TLS via the platform library |
| `crypto` | ✓ | `SelfSignedCredentials`, `crypto` (keys, JWK, did:key, JWT), `WebhookVerifier` |

**WebAssembly.** The crate also builds for `wasm32-wasip2` (WASI 0.2, Rust 1.87+), where it sends its
requests through the host's `wasi:http` instead of reqwest: the host does TLS, request bodies are bytes,
the reqwest-specific API (`ClientBuilder::http_client`, `Body::from_reqwest`,
`StreamingResource::into_response`) is absent and `Error::Transport` carries a `TransportError`.
[`../wasm`](../wasm) builds it into a WebAssembly component with a WIT interface.

## Quick start

```rust
use futures_util::TryStreamExt;
use lws_client::{Client, JsonPatch, SelfSignedCredentials, TokenExchangeAuthenticator, crypto::SigningKey};

#[tokio::main]
async fn main() -> lws_client::Result<()> {
    // A bot identity: did:key derived from a fresh P-256 key.
    let credentials = SelfSignedCredentials::did_key(SigningKey::generate_p256()?);
    let client = Client::builder()
        .authenticator(TokenExchangeAuthenticator::new(credentials))
        .build()?;

    // HEAD → rel="https://www.w3.org/ns/lws#storage" → storage description.
    // The 401 → metadata → token exchange → retry dance happens automatically.
    let storage = client.discover_storage("https://storage.example/root/").await?;
    let root = storage.storage_root()?.clone();

    let notes = client.create_container(&root).slug("notes").await?.location;
    let hello = client.create(&notes, "Hello, LWS!", "text/plain").slug("hello.txt").await?.location;

    let doc = client.read(&hello).await?;
    println!("{} (etag {:?})", doc.text()?, doc.metadata.etag);

    // Optimistic concurrency: a stale ETag yields Error::PreconditionFailed.
    let etag = doc.metadata.etag.clone().unwrap_or_default();
    client.update(&hello, "Hello again", "text/plain").if_match(&etag).await?;

    let profile = client
        .create_json(&notes, &serde_json::json!({"name": "Alice", "age": 30}))
        .resource_type("https://schema.org/Person")
        .await?
        .location;
    client.patch(&profile, &JsonPatch::new().replace("/age", 31)).await?;

    let mut members = client.list_container(&notes);
    while let Some(item) = members.try_next().await? {
        println!("{} {:?} {:?}", item.id, item.types, item.size);
    }

    client.delete(&notes).recursive(true).await?; // Depth: infinity
    Ok(())
}
```

## Guide

### Discovery

```rust
let storage = client.discover_storage(any_resource_url).await?;   // or client.get_storage_description(storage_url)
storage.storage_root()?;                 // required StorageRoot service
storage.notification_service();          // Option<&Service>
storage.type_search_service();
storage.service("DataSharingService");   // any service type; terms and full IRIs both match
storage.capability("https://feature.example/PatchSupport");
```

### Reading

```rust
let meta = client.head(&url).await?;                          // ResourceMetadata
meta.etag; meta.linkset(); meta.parent(); meta.storage(); meta.types(); meta.is_container();

let r = client.read(&url).accept("text/plain").await?;        // Resource { metadata, body, not_modified }
let r = client.read(&url).if_none_match(&etag).await?;        // 304 → r.not_modified == true (not an error)
let r = client.read(&url).range(0, Some(1023)).await?;        // 206 → r.is_partial()
let mut s = client.read(&url).send_streaming().await?;        // large bodies
while let Some(chunk) = s.chunk().await? { /* … */ }

let page = client.read_container(&container).await?;          // ContainerPage { items, total_items, next, … }
let all: Vec<_> = client.list_container(&container).try_collect().await?; // follows rel="next"
```

### Writing

```rust
client.create(&container, bytes, "image/png").slug("cat.png").link(link).resource_type(type_iri).await?;
client.create_container(&container).slug("photos").await?;
client.update(&url, body, "text/plain").if_match(&etag).await?;              // PUT
client.patch(&url, &JsonPatch::new().add("/tags/-", "lws")).if_match(&etag).await?;
client.patch_with(&url, sparql, "application/sparql-update").await?;          // if advertised in Accept-Patch
client.update(&url, body, "text/plain").link(l).set_linkset(true).await?;    // Prefer: set-linkset
client.delete(&url).if_match(&etag).await?;
client.delete(&container).recursive(true).await?;                             // Depth: infinity
```

The identity hint is sent as `Slug` (RFC 5023; percent-encoded) — the core draft defines the
hint but not yet its header.

### Metadata (linksets)

```rust
let doc = client.read_linkset(&resource).await?;               // LinksetDocument { url, etag, linkset, allow, accept_patch }
let patch = JsonPatch::new().add(
    JsonPointer::root().push("linkset").push(0).push("license"),
    serde_json::json!([{"href": "https://creativecommons.org/licenses/by/4.0/"}]),
);
client.patch_linkset(&doc.url, &patch).if_match(doc.etag.as_deref().unwrap_or("*")).await?;

let mut ls = doc.linkset.clone();
ls.add(anchor, "describedby", "https://example.org/shape", None);
client.update_linkset(&doc.url, &ls).if_match(&etag).await?;   // only if Allow lists PUT
```

### Authentication

| Need | Use |
|---|---|
| Bots / server-side agents with their own key | `SelfSignedCredentials::did_key(key)` or `SelfSignedCredentials::for_agent("https://id.example/bot", key, "key-1")` |
| Users signed in with OpenID Connect | `OpenIdCredentials::new(id_token)` / `OpenIdCredentials::from_fn(\|ctx\| async { … })` |
| SAML 2.0 identity providers | `SamlCredentials::from_xml(assertion_xml)` |
| A token you already have | `BearerTokenAuthenticator::new(token).with_realm(storage_url)` |
| Something else (DPoP, cookies, mTLS) | implement `auth::Authenticator` |

`TokenExchangeAuthenticator` implements the LWS flow: on `401` with
`WWW-Authenticate: Bearer as_uri="…", realm="…"` it verifies the request URL lies inside the realm,
fetches `/.well-known/lws-configuration` (RFC 8414, issuer checked), exchanges the subject token
(RFC 8693, `resource = realm`), caches the access token per realm and retries once. Later requests
inside the realm send the cached token up front; a rejected token is dropped and re-exchanged once.
`http` authorization servers are refused except on loopback (or with `allow_insecure_http`), and
`authorization_server_filter` lets you pin trusted authorization servers.

Redirects are followed by the client itself (at most 5 hops): `GET`/`HEAD`/`OPTIONS`/`QUERY` follow
301/302/303/307/308, other methods only 307/308 (with a replayable body), and 303 becomes `GET`.
Credentials are re-evaluated on every hop, so an access token is only sent to URLs inside its realm
and an explicit `Authorization` header never crosses origins. If you pass your own `reqwest::Client`
via `http_client`, its redirect policy applies instead.

Key helpers (`crypto` module): `SigningKey::generate_p256/generate_ed25519`, `to_jwk`/`from_jwk`,
`did_key()`, `VerifyingKey::from_did_key`, `controlled_identifier_document(agent, jwk, kid)` (the
CID document an HTTPS agent publishes), and `jwt::{sign, verify, decode_unverified}`.

### Notifications

```rust
let req = WebhookSubscriptionRequest::new([container.clone()], inbox_url.clone())
    .expires(SystemTime::now() + Duration::from_secs(3600));
let sub = client.subscribe_storage(&storage, &req).await?;   // checks WebhookSubscription support
client.unsubscribe(&sub.subscription).await?;

// In your inbox handler:
let verifier = WebhookVerifier::builder().client(Client::new()).trusted_storage(storage.id.clone()).build();
let verified = verifier.verify("POST", &inbox_url, &headers, &body).await?;   // or verify_request(&inbox_url, &http_request)
for a in &verified.notification.activities {
    if a.is_update() { println!("{} changed", a.object.id); }
}
```

The verifier checks `Content-Digest` (sha-256/sha-512), the RFC 9421 signature over `@method`,
`@scheme`, `@authority`, `@path`, `content-type` and `content-digest`, the `created` window
(±300 s by default), resolves `keyid` to the storage description's `verificationMethod` (which must
be referenced from `authentication`), refetches once on failure (key rotation), and requires the
notification's `storage` to match the signing storage.

### Access requests and grants

```rust
let policy = AccessPolicy::builder(agent_id)
    .actions(["read"])
    .target_resources([project_url.as_str()])
    .constraint(Constraint::purpose("https://purpose.example/collaboration"))
    .constraint(Constraint::not_after("2026-12-31T23:59:59Z"))
    .build()?;
let request = AccessRequest::builder(storage.id.as_str()).inbox(my_inbox).policy(policy).build()?;
let url = client.request_access(&storage.access_request_service().unwrap().service_endpoint, &request).await?;
```

Also `list_access_requests`, `get_access_request`, `cancel_access_request`, `grant_access`,
`list_access_grants`, `get_access_grant`, `revoke_access_grant`.

### Type index and search

```rust
let types: Vec<String> = client.list_types(&index_service).try_collect().await?;
let query = TypeQuery::new()
    .any_of(["https://schema.org/Person", "http://xmlns.com/foaf/0.1/Person"])   // OR group
    .all_of(["https://www.w3.org/ns/lws#DataResource"])                          // AND
    .relation("describedby").all_of(["https://example.org/shapes/person"]);
let people: Vec<_> = client.search_all(&search_service, &query).try_collect().await?; // QUERY, then GET next pages
let formats = client.accepted_query_formats(&search_service).await?;               // OPTIONS → Accept-Query
```

### Errors

`lws_client::Error` has one variant per LWS response — `BadRequest`, `Unauthorized`, `Forbidden`,
`NotFound`, `MethodNotAllowed`, `NotAcceptable`, `Conflict`, `Gone`, `PreconditionFailed`,
`UnsupportedMediaType`, `UnprocessableContent`, `NotImplemented`, `InsufficientStorage`, `Http`
(other statuses) — each carrying an `HttpError` (status, headers, RFC 9457 `problem`, `allow()`,
`accept_patch()`, `accept_query()`, auth `challenges`), plus `Authentication`, `Protocol`,
`SignatureVerification`, `InvalidInput`, `Crypto` and `Transport`. Helpers: `status()`,
`problem()`, `is_not_found()`, `is_conflict()`, `is_precondition_failed()`, …

## Examples

```sh
node ../testing/mock-server/server.mjs --port 8787 &          # the repository's LWS mock server
cargo run --example quickstart -- http://localhost:8787/root/  # LWS_DID_KEY_AUTH=1 to authenticate
cargo run --example did_key_auth -- http://localhost:8787/root/
cargo run --example webhook_receiver -- http://localhost:8787/root/
```

## Building and testing

```sh
cargo test                                   # unit, conformance fixtures, HTTP tests, doctests
cargo test --no-default-features --features rustls
cargo clippy --all-targets -- -D warnings
cargo clippy --target wasm32-wasip2 -- -D warnings   # the WASI transport (rustup target add wasm32-wasip2)
cargo doc --no-deps --open

# End-to-end interop scenario (conformance/scenario.md) against the mock server:
node ../testing/mock-server/server.mjs --port 8787 &
LWS_TEST_SERVER=http://localhost:8787 cargo test --test interop -- --nocapture
```

The `fixtures` test runs the shared, language-neutral vectors in
[`conformance/fixtures`](../conformance/fixtures) (Link / WWW-Authenticate / structured-field
parsing, JSON Patch, type queries, did:key, JWTs, 13 RFC 9421 webhook vectors and response models).

## License

MIT — see [LICENSE](../LICENSE).
