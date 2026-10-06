# lws-client for C++

A C++20 client for the [W3C Linked Web Storage (LWS)](https://www.w3.org/TR/lws10-core/) protocol,
tracking the LWS Working Group specifications as of **2026-10-05** (core protocol editor's draft,
OpenID Connect / SAML 2.0 / self-signed CID authentication suites, webhook notifications,
type index and type search). It is one of six sibling clients in
[ebremer/lws-client](https://github.com/ebremer/lws-client) that share one API contract
([`design/client-api.md`](../design/client-api.md)) and one conformance suite.

* **Synchronous, exception-based, value-semantic.** `lws::Client` is cheap to copy and safe to
  share between threads.
* **Pluggable HTTP.** The core depends only on [nlohmann/json]; HTTP goes through the abstract
  `lws::HttpTransport` (bring Boost.Beast, cpp-httplib, Qt, …). A libcurl transport is built in.
* **Full LWS feature set.** Discovery, CRUD, lazy container pagination (a C++20 input range),
  linksets (RFC 9264) with JSON Patch, the OAuth 2.0 token-exchange authorization flow,
  OpenID / SAML / self-signed (`did:key` and HTTPS) credentials, webhook subscriptions and
  RFC 9421 signature verification, access requests and grants, type index and HTTP `QUERY` search.

MIT licensed — see [LICENSE](../LICENSE).

## Requirements

| | |
|---|---|
| Compiler | C++20 (GCC 12+, Clang 16+, MSVC 19.36+; tested with MinGW-w64 GCC 15.2) |
| Build | CMake ≥ 3.21 |
| Required | [nlohmann/json] ≥ 3.11 (found, or fetched with `FetchContent`) |
| Optional | libcurl (`LWS_WITH_CURL`, default transport), OpenSSL 3 (`LWS_WITH_OPENSSL`, crypto) |
| Tests | GoogleTest (found, or fetched) |

## Building

With [vcpkg](https://vcpkg.io) (manifest mode — dependencies come from [`vcpkg.json`](vcpkg.json)):

```sh
cd cpp
cmake --preset debug          # needs VCPKG_ROOT; or pass -DCMAKE_TOOLCHAIN_FILE=…/vcpkg.cmake
cmake --build --preset debug
ctest --preset debug
```

MinGW-w64 (the configuration this library is developed with):

```sh
cmake -S cpp -B cpp/build/mingw -G Ninja -DCMAKE_BUILD_TYPE=Debug -DCMAKE_CXX_COMPILER=g++ \
      -DCMAKE_TOOLCHAIN_FILE=$VCPKG_ROOT/scripts/buildsystems/vcpkg.cmake \
      -DVCPKG_TARGET_TRIPLET=x64-mingw-static -DVCPKG_HOST_TRIPLET=x64-mingw-static \
      -DVCPKG_MANIFEST_FEATURES=tests
cmake --build cpp/build/mingw
ctest --test-dir cpp/build/mingw --output-on-failure
```

Core only (no curl, no OpenSSL; nlohmann/json and GoogleTest fetched automatically):
`cmake --preset minimal`.

| CMake option | Default | Meaning |
|---|---|---|
| `LWS_WITH_CURL` | `ON` | Build `lws::CurlTransport` and `make_default_transport()` |
| `LWS_WITH_OPENSSL` | `ON` | Build `PrivateKey`/`PublicKey`, `SelfSignedCredentials`, `WebhookVerifier` |
| `LWS_BUILD_TESTS` | top-level | GoogleTest suite |
| `LWS_BUILD_EXAMPLES` | top-level | Programs in [`examples/`](examples) |
| `LWS_FETCH_DEPS` | `ON` | Fall back to `FetchContent` for nlohmann/json / GoogleTest |

The generated `lws/config.hpp` exposes `LWS_WITH_CURL` / `LWS_WITH_OPENSSL` as 0/1 macros.

## Using it in your project

Installed package:

```cmake
find_package(lws-client 0.1 CONFIG REQUIRED)
target_link_libraries(app PRIVATE lws::client)
```

As a subproject (no install step):

```cmake
include(FetchContent)
FetchContent_Declare(lws_client
    GIT_REPOSITORY https://github.com/ebremer/lws-client.git
    GIT_TAG        main
    SOURCE_SUBDIR  cpp)
FetchContent_MakeAvailable(lws_client)
target_link_libraries(app PRIVATE lws::client)
```

When linking static OpenSSL/curl on Windows, use the vcpkg toolchain (it adds the Winsock /
CryptoAPI system libraries that CMake's stock `FindOpenSSL` omits).

## Quickstart

```cpp
#include <lws/lws.hpp>

lws::Client client;  // libcurl transport, anonymous

lws::StorageDescription storage = client.discover_storage("https://storage.example/alice/");
std::string root = storage.storage_root();

auto folder = client.create_container(root, {.slug = "notes"});
auto note = client.create(folder.location, "milk\neggs\n", "text/plain", {.slug = "shopping.txt"});

lws::Resource r = client.read(note.location);            // r.body, r.etag, r.parent, r.linkset …
client.update(note.location, "milk\neggs\nbread\n", "text/plain", {.if_match = r.etag});

auto profile = client.create_json(folder.location, {{"name", "Alice"}, {"age", 30}});
client.patch(profile.location, lws::JsonPatch{}.replace("/age", 31).add("/city", "Boston"));

for (const lws::ContainedResource& item : client.list_container(folder.location))  // lazy pages
    std::cout << item.id << ' ' << item.format.value_or("") << '\n';

client.remove(folder.location, {.recursive = true});     // Depth: infinity
```

### Authentication

On the first `401`, `TokenExchangeAuthenticator` validates the `realm`, discovers the authorization
server (`/.well-known/lws-configuration`), exchanges a credential for an access token (RFC 8693)
and retries; tokens are cached per realm and sent proactively afterwards.

```cpp
// Self-signed identity (lws10-authn-ssi-cid) with a did:key agent:
auto key = lws::PrivateKey::generate(lws::KeyAlgorithm::ES256);    // or EdDSA; or PrivateKey::from_jwk / from_pem
auto creds = lws::SelfSignedCredentials::did_key(key);              // creds->agent_id() == "did:key:zDn…"

// …or an HTTPS agent that publishes lws::controlled_identifier_document(agent, key.public_jwk(), "key-1"):
// auto creds = lws::SelfSignedCredentials::for_agent("https://id.example/bot", key, "key-1");
// OpenID Connect: std::make_shared<lws::OpenIdCredentials>(id_token)
// SAML 2.0:       std::make_shared<lws::SamlCredentials>(lws::SamlCredentials::from_xml(assertion))

lws::TokenExchangeOptions auth_options;
auth_options.authorization_server_filter = [](std::string_view as, std::string_view) {
    return as == "https://auth.example";                            // optional trust policy
};
lws::Client client({.authenticator = std::make_shared<lws::TokenExchangeAuthenticator>(creds, auth_options)});
```

`BearerTokenAuthenticator(token, realm)` sends a token you already have. Implement
`lws::Authenticator` for anything else (DPoP, cookies, mTLS).

### Metadata (linksets)

```cpp
lws::LinksetDocument doc = client.read_linkset(profile.location);
client.patch_linkset(doc.url,
    lws::JsonPatch{}.add("/linkset/0/describedby", {{{"href", "https://example.org/shapes/person"}}}),
    {.if_match = doc.etag});
```

### Notifications and webhook verification

```cpp
auto sub = client.subscribe(storage, {.topics = {folder.location}, .inbox = "https://me.example/inbox"});
// … later
client.unsubscribe(sub.subscription);

// In the inbox handler (any HTTP server):
lws::WebhookVerifier verifier(lws::Client{}, {.trusted_storages = {storage.id}});
lws::VerifiedNotification n = verifier.verify("POST", "https://me.example/inbox", headers, body);
for (const lws::Activity& a : n.notification.activities) { /* a.is_update(), a.object.id … */ }
```

### Access requests, type index and search

```cpp
std::string request_url = client.request_access(storage.access_request_service()->service_endpoint,
    {.storage = storage.id,
     .access = {{.actions = {"read"}, .assignee = creds->agent_id(),
                 .target = lws::AccessTarget{.values = {folder.location}},
                 .constraints = {lws::Constraint::purpose("https://purpose.example/research")}}}});

for (const std::string& type : client.list_types(storage.type_index_service()->service_endpoint)) { … }

auto query = lws::TypeQuery{}.any_of({"https://schema.org/Person", "http://xmlns.com/foaf/0.1/Person"})
                             .all_of({"https://www.w3.org/ns/lws#DataResource"});
for (const auto& hit : client.search_all(storage.type_search_service()->service_endpoint, query)) { … }
```

## API overview

| Area | API |
|---|---|
| Client | `Client(ClientOptions)`; `ClientOptions{transport, authenticator, user_agent, default_headers, timeout, max_redirects}` |
| Discovery | `discover_storage(url)`, `get_storage_description(url)` → `StorageDescription{id, types, services, capabilities, verification_methods, authentication}` with `storage_root()`, `service(type)`, `notification_service()`, `access_request_service()`, `access_grant_service()`, `type_index_service()`, `type_search_service()`, `capability(type)`, `verification_method(id)` |
| Read | `head(url)` → `ResourceMetadata`; `read(url, ReadOptions{accept, range, if_none_match, if_modified_since, prefer})` → `Resource` (`body`, `text()`, `json()`, `not_modified`, `content_range`); `read_container(url)` → `ContainerPage`; `list_container(url)` → `ContainerRange` |
| Write | `create(container, body, content_type, CreateOptions{slug, links, types})`, `create_json`, `create_container` → `CreateResult{location, metadata}`; `update(url, body, type, UpdateOptions{if_match, if_none_match, links, set_linkset})`, `patch(url, JsonPatch)`, `patch(url, body, type)` → `UpdateResult`; `remove(url, DeleteOptions{if_match, recursive})` |
| Linksets | `linkset_url`, `read_linkset` → `LinksetDocument{url, etag, linkset, allow, accept_patch}`, `update_linkset`, `patch_linkset`; `Linkset` with `links()`, `targets()`, `add()`, `remove()` |
| Auth | `Authenticator`, `BearerTokenAuthenticator`, `TokenExchangeAuthenticator(TokenExchangeOptions{allow_insecure_http, authorization_server_filter, …})`, `CredentialProvider`, `OpenIdCredentials`, `SamlCredentials`, `SelfSignedCredentials::{did_key, for_agent}` |
| Keys | `PrivateKey::{generate, from_jwk, from_pem}`, `public_jwk()`, `private_jwk()`, `to_pem()`, `sign()`, `did_key()`; `PublicKey::{from_jwk, verify}`; `did_key_from_public_jwk()`, `controlled_identifier_document()`; `sign_jwt`, `verify_jwt`, `decode_jwt_payload` |
| Notifications | `subscribe(service_url or StorageDescription, WebhookSubscriptionRequest{topics, inbox, expires})` → `Subscription`; `list_subscriptions`, `get_subscription`, `unsubscribe`; `parse_notification()` → `Notification{storage, activities}`; `WebhookVerifier(Client or fetcher, WebhookVerifierOptions)` `.verify(...)` → `VerifiedNotification` |
| Access | `request_access`, `list_access_requests`, `get_access_request`, `cancel_access_request`, `grant_access`, `list_access_grants`, `get_access_grant`, `revoke_access_grant`; `AccessRequest`, `AccessGrant`, `AccessPolicy`, `AccessTarget`, `Constraint::{purpose, client, format, type, not_before, not_after, …}` |
| Types | `read_type_index`, `list_types` → `TypeRange`; `search_types(url, TypeQuery)` (HTTP `QUERY`) → `SearchPage`; `search_all`; `accepted_query_formats` |
| Low level | `execute(HttpRequest)`, `execute_checked(HttpRequest)`, `parse_link_header(s)`, `parse_www_authenticate`, `sf::parse_dictionary`, `JsonPointer`, `resolve_url`, `url_within_realm` |
| Errors | `Error` ← `HttpError` (← `BadRequestError`, `UnauthorizedError`, `ForbiddenError`, `NotFoundError`, `MethodNotAllowedError`, `NotAcceptableError`, `ConflictError`, `GoneError`, `PreconditionFailedError`, `UnsupportedMediaTypeError`, `UnprocessableContentError`, `NotImplementedError`, `InsufficientStorageError`), `AuthenticationError`, `ProtocolError` (← `ParseError`), `SignatureVerificationError`, `TransportError` |

Naming follows C++ conventions (`snake_case`); `delete` is a keyword, so the delete operation is
`Client::remove`.

## Tests and interop

`ctest` runs 73 tests: every parser and model against the shared fixtures in
[`../conformance/fixtures`](../conformance) (including all 13 RFC 9421 webhook vectors and the
did:key/JWT vectors), every client operation against an in-process mock transport, the full
401 → metadata → token exchange → retry flow, and the end-to-end interop scenario, which runs when
`LWS_TEST_SERVER` points at the [mock server](../testing/mock-server):

```sh
node testing/mock-server/server.mjs --port 8787 &
LWS_TEST_SERVER=http://localhost:8787 ctest --test-dir cpp/build/mingw --output-on-failure
```

## Examples

| Program | Shows |
|---|---|
| [`quickstart.cpp`](examples/quickstart.cpp) | discovery, CRUD, JSON Patch, lazy listing, recursive delete |
| [`did_key_auth.cpp`](examples/did_key_auth.cpp) | self-signed did:key credentials and the token exchange flow |
| [`verify_webhook.cpp`](examples/verify_webhook.cpp) | verifying a signed webhook delivery in an inbox handler |

[nlohmann/json]: https://github.com/nlohmann/json
