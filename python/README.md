# lws-client (Python)

A typed, sync **and** async Python client for the W3C
[Linked Web Storage (LWS)](https://www.w3.org/TR/lws10-core/) protocol, tracking the LWS Working
Group specifications as of **2026-10-05**:

- LWS Protocol 1.0 core — discovery, containers, CRUD, linksets (metadata), pagination
- Authentication suites — OpenID Connect, SAML 2.0, self-signed controlled identifiers (incl. `did:key`)
- OAuth 2.0 token exchange authorization (`/.well-known/lws-configuration`)
- Webhook notifications — subscriptions plus RFC 9421 / RFC 9530 delivery verification
- Access requests and grants (ODRL-based access profile)
- Type Index and Type Search services (HTTP `QUERY`)

Part of the [lws-client](https://github.com/ebremer/lws-client) family (Java, JavaScript, C++, Rust,
Go, Python) sharing one API design. MIT licensed.

## Install

```sh
pip install lws-client              # core (depends only on httpx)
pip install "lws-client[crypto]"    # + self-signed credentials, key helpers, webhook verification
```

Python 3.10+. The `crypto` extra adds [`cryptography`](https://cryptography.io/) and is needed for
`SelfSignedCredentials`, `SigningKey`/`VerifyingKey`, JWT signing/verification and
`WebhookVerifier`. did:key encoding/decoding is pure Python.

## Quick start

```python
from lws_client import LwsClient, JsonPatch

with LwsClient() as client:
    storage = client.discover_storage("https://storage.example/root/")
    root = storage.storage_root()

    folder = client.create_container(root, slug="notes")
    note = client.create_text(folder.location, "milk\neggs\n", slug="shopping.txt")

    res = client.read(note.location)
    print(res.text, res.etag, res.parent, res.linkset)

    client.update(note.location, "milk\neggs\nbread\n", "text/plain", if_match=res.etag)

    profile = client.create_json(folder.location, {"name": "Alice", "age": 30},
                                 types=["https://schema.org/Person"])
    client.patch(profile.location, JsonPatch().replace("/age", 31))

    for item in client.list_container(folder.location):   # follows rel="next" lazily
        print(item.id, item.format, item.size, item.modified)

    client.delete(folder.location, recursive=True)          # Depth: infinity
```

### Async

```python
import asyncio
from lws_client import AsyncLwsClient

async def main() -> None:
    async with AsyncLwsClient() as client:
        storage = await client.discover_storage("https://storage.example/root/")
        async for item in client.list_container(storage.storage_root()):
            print(item.id)

asyncio.run(main())
```

`AsyncLwsClient` has exactly the same methods as `LwsClient`; listings return async iterators.
Both are built on one sans-I/O core, so their behaviour is identical.

## Authentication

LWS storages answer unauthenticated requests with
`401` + `WWW-Authenticate: Bearer as_uri="…", realm="…"`. `TokenExchangeAuthenticator` handles
the whole flow: realm check, authorization server metadata, RFC 8693 token exchange with a subject
token from a *credential provider*, token caching and proactive reuse, single-flight refresh.

```python
from lws_client import (LwsClient, TokenExchangeAuthenticator, SelfSignedCredentials,
                        OpenIdCredentials, SamlCredentials, SigningKey)

# Self-signed did:key identity (bots, scripts) — lws10-authn-ssi-cid
key = SigningKey.generate("ES256")               # or "EdDSA"
auth = TokenExchangeAuthenticator(SelfSignedCredentials.did_key(key))

# HTTPS agent publishing a controlled identifier document
auth = TokenExchangeAuthenticator(
    SelfSignedCredentials.for_agent("https://bot.example/agent", key, "https://bot.example/agent#key-1"))

# OpenID Connect ID token (obtained by your OIDC library); callables may be async
auth = TokenExchangeAuthenticator(OpenIdCredentials(lambda ctx: my_oidc.id_token()))

# SAML 2.0 assertion (raw XML is base64url-encoded automatically)
auth = TokenExchangeAuthenticator(SamlCredentials(assertion_xml))

client = LwsClient(authenticator=auth)
```

Options: `allow_insecure_http` (loopback is always allowed),
`authorization_server_filter=lambda as_uri, realm: ...` (policy for which authorization servers may
receive credentials), `refresh_skew`. `BearerTokenAuthenticator(token, realm=...)` sends a known
token. Custom schemes subclass `Authenticator` (`authorize` / `handle_challenge`, sync or async).

Key helpers: `SigningKey.generate/from_jwk/from_pem`, `.public_jwk()`, `.private_jwk()`,
`.did_key()`, `did_key_from_jwk`, `did_key_to_jwk`, `controlled_identifier_document(agent, jwk, kid)`,
`encode_jwt`, `verify_jwt`.

## Metadata (linksets)

```python
doc = client.read_linkset(resource_url)            # discovers rel="linkset"
doc.linkset.targets("describedby")
client.patch_linkset(doc.url,
                     JsonPatch().add("/linkset/0/license", [{"href": "https://creativecommons.org/licenses/by/4.0/"}]),
                     if_match=doc.etag)
doc.linkset.add(resource_url, "describedby", "https://example.org/shape")
client.update_linkset(doc.url, doc.linkset, if_match=doc.etag)   # PUT, if the server allows it
```

Use `JsonPointer.from_segments("linkset", 0, "https://example.org/rel", "-")` for relation URIs.

## Notifications

```python
from lws_client import WebhookVerifier

service = storage.service("NotificationService")
sub = client.subscribe(service, [folder_url], "https://me.example/inbox", expires="2026-12-31T00:00:00Z")

verifier = WebhookVerifier(client=client, trusted_storages=[storage.id])
# in your HTTP handler, verify against the *registered* inbox URL:
verified = verifier.verify("POST", "https://me.example/inbox", request_headers, request_body)
for activity in verified.notification.activities:
    print(activity.types, activity.object.id)

client.unsubscribe(sub)
```

`AsyncWebhookVerifier` offers `verify` and `verify_asgi(scope, receive, inbox_url)`.

## Access requests and grants

```python
from lws_client import AccessRequest, AccessPolicy, AccessTarget, Constraint

policy = AccessPolicy(actions=["read"], assignee="https://id.example/agent",
                      target=AccessTarget("StorageResource", [folder_url]),
                      constraints=[Constraint.purpose("https://purpose.example/research"),
                                   Constraint.not_after("2026-12-31T00:00:00Z")])
url = client.request_access(storage.access_request_service(),
                            AccessRequest(storage=storage.id, access=[policy]))
```

Also `list_access_requests`, `get_access_request`, `cancel_access_request`, `grant_access`,
`list_access_grants`, `get_access_grant`, `revoke_access_grant`.

## Type index and search

```python
from lws_client import TypeQuery

types = list(client.list_types(storage.type_index_service()))
query = TypeQuery().any_of("https://schema.org/Person", "http://xmlns.com/foaf/0.1/Person") \
                   .all_of("https://www.w3.org/ns/lws#DataResource")
for hit in client.search_all(storage.type_search_service(), query):   # HTTP QUERY
    print(hit.id)
```

## Errors

All errors derive from `LwsError`. HTTP failures raise `HttpError` subclasses carrying `status`,
`method`, `url`, `headers` and parsed RFC 9457 `problem` details: `BadRequestError`,
`UnauthorizedError` (`.challenges`), `ForbiddenError`, `NotFoundError` (`GoneError` is a subclass),
`MethodNotAllowedError` (`.allow`), `NotAcceptableError`, `ConflictError`, `PreconditionFailedError`,
`UnsupportedMediaTypeError` (`.accept_patch`, `.accept_query`), `UnprocessableContentError`,
`NotImplementedByServerError`, `InsufficientStorageError`. Also `AuthenticationError`,
`ProtocolError`, `UnsupportedError`, `SignatureVerificationError`, `TransportError`.
A conditional read answered with `304` is **not** an error: `resource.not_modified` is `True`.

## API overview

| Area | `LwsClient` / `AsyncLwsClient` methods |
|---|---|
| Discovery | `discover_storage`, `get_storage_description`, `authenticate` |
| Read | `head`, `read`, `read_json`, `stream`, `read_container`, `container_pages`, `list_container` |
| Create | `create`, `create_json`, `create_text`, `create_container` |
| Update / delete | `update` (PUT), `patch` (JSON Patch or raw), `delete` |
| Metadata | `linkset_url`, `read_linkset`, `read_linkset_at`, `update_linkset`, `patch_linkset` |
| Notifications | `subscribe`, `list_subscriptions`, `get_subscription`, `unsubscribe` |
| Access | `request_access`, `list_access_requests`, `get_access_request`, `cancel_access_request`, `grant_access`, `list_access_grants`, `get_access_grant`, `revoke_access_grant` |
| Type services | `read_type_index`, `list_types`, `search_types`, `search_pages`, `search_all`, `accepted_query_formats` |

## Development

```sh
cd python
python -m venv .venv
.venv/bin/pip install -e ".[dev]"          # Windows: .venv\Scripts\pip
.venv/bin/pytest                            # unit + shared conformance fixtures
.venv/bin/mypy                              # strict
.venv/bin/ruff check src tests examples

# interop scenario against the mock server
node ../testing/mock-server/server.mjs --port 8787 &
LWS_TEST_SERVER=http://localhost:8787 .venv/bin/pytest tests/test_interop.py
```

Examples live in [`examples/`](examples): `quickstart.py`, `async_usage.py`,
`self_signed_identity.py`, `webhook_receiver.py`.

## License

MIT — see [LICENSE](LICENSE).
