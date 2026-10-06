# SPDX-License-Identifier: MIT
"""Authentication flow edge cases and error mapping."""

from __future__ import annotations

import json
from collections.abc import Callable

import httpx
import pytest
from fakeserver import FakeLws

from lws_client import (
    AsyncLwsClient,
    AuthenticationError,
    BadRequestError,
    BearerTokenAuthenticator,
    ConflictError,
    CredentialContext,
    ForbiddenError,
    GoneError,
    HttpError,
    InsufficientStorageError,
    LwsClient,
    MethodNotAllowedError,
    NotAcceptableError,
    NotFoundError,
    NotImplementedByServerError,
    OpenIdCredentials,
    PreconditionFailedError,
    SamlCredentials,
    SelfSignedCredentials,
    SigningKey,
    TokenExchangeAuthenticator,
    TransportError,
    UnauthorizedError,
    UnprocessableContentError,
    UnsupportedMediaTypeError,
    encode_saml_assertion,
)

Handler = Callable[[httpx.Request], httpx.Response]


def make(handler: Handler, auth: object = None) -> LwsClient:
    return LwsClient(authenticator=auth,  # type: ignore[arg-type]
                     http_client=httpx.Client(transport=httpx.MockTransport(handler)))


def self_signed() -> TokenExchangeAuthenticator:
    return TokenExchangeAuthenticator(SelfSignedCredentials.did_key(SigningKey.generate()))


def test_invalid_cached_token_triggers_one_reexchange() -> None:
    fake = FakeLws(auth=True)
    with make(fake, self_signed()) as client:
        client.head(fake.root)
        assert len(fake.token_requests) == 1
        fake.tokens.clear()  # server forgets the token -> 401 invalid_token
        client.head(fake.root)
        assert len(fake.token_requests) == 2
        # a second rejection is surfaced, not looped
        fake.tokens.clear()
        original = fake._authorization_server

        def no_tokens(request: httpx.Request, path: str) -> httpx.Response:
            response = original(request, path)
            fake.tokens.clear()
            return response

        fake._authorization_server = no_tokens  # type: ignore[method-assign]
        with pytest.raises(UnauthorizedError) as excinfo:
            client.head(fake.root)
        assert excinfo.value.challenges[0].as_uri == fake.as_base


def challenge_server(challenge: str, metadata: dict[str, object] | None = None,
                     token_status: int = 200) -> Handler:
    def handler(request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        if url.endswith("/.well-known/lws-configuration"):
            return httpx.Response(200, json=metadata or {
                "issuer": "https://as.example", "token_endpoint": "https://as.example/token"})
        if url == "https://as.example/token":
            if token_status != 200:
                return httpx.Response(token_status, json={"error": "invalid_grant",
                                                          "error_description": "nope"})
            return httpx.Response(200, json={"access_token": "t", "token_type": "Bearer"})
        if request.headers.get("authorization") == "Bearer t":
            return httpx.Response(200)
        return httpx.Response(401, headers={"WWW-Authenticate": challenge})
    return handler


def test_realm_check_rejects_foreign_realm() -> None:
    handler = challenge_server('Bearer as_uri="https://as.example", realm="https://storage.example/alice/"')
    with make(handler, self_signed()) as client, pytest.raises(AuthenticationError, match="realm"):
        client.head("https://storage.example/bob/x")


def test_insecure_authorization_server_rejected() -> None:
    handler = challenge_server('Bearer as_uri="http://as.example", realm="https://storage.example/"')
    with make(handler, self_signed()) as client, pytest.raises(AuthenticationError, match="insecure"):
        client.head("https://storage.example/x")
    allowed = TokenExchangeAuthenticator(SelfSignedCredentials.did_key(SigningKey.generate()),
                                         allow_insecure_http=True)
    meta = {"issuer": "http://as.example", "token_endpoint": "http://as.example/token"}
    handler = challenge_server('Bearer as_uri="http://as.example", realm="https://storage.example/"',
                               meta)
    with make(handler, allowed) as client, pytest.raises(AuthenticationError):
        client.head("https://storage.example/x")  # passes the https check; stub has no http AS


def test_issuer_mismatch_and_policy_filter() -> None:
    handler = challenge_server('Bearer as_uri="https://as.example", realm="https://storage.example/"',
                               {"issuer": "https://evil.example",
                                "token_endpoint": "https://as.example/token"})
    with make(handler, self_signed()) as client, pytest.raises(AuthenticationError, match="issuer"):
        client.head("https://storage.example/x")
    guarded = TokenExchangeAuthenticator(SelfSignedCredentials.did_key(SigningKey.generate()),
                                         authorization_server_filter=lambda as_uri, realm: False)
    handler = challenge_server('Bearer as_uri="https://as.example", realm="https://storage.example/"')
    with make(handler, guarded) as client, pytest.raises(AuthenticationError, match="policy"):
        client.head("https://storage.example/x")


def test_token_error_and_unsupported_token_type() -> None:
    handler = challenge_server('Bearer as_uri="https://as.example", realm="https://storage.example/"',
                               token_status=400)
    with make(handler, self_signed()) as client, pytest.raises(AuthenticationError) as excinfo:
        client.head("https://storage.example/x")
    assert excinfo.value.error == "invalid_grant" and excinfo.value.error_description == "nope"
    handler = challenge_server(
        'Bearer as_uri="https://as.example", realm="https://storage.example/"',
        {"issuer": "https://as.example", "token_endpoint": "https://as.example/token",
         "subject_token_types_supported": ["urn:ietf:params:oauth:token-type:saml2"]})
    with make(handler, self_signed()) as client, pytest.raises(AuthenticationError, match="subject"):
        client.head("https://storage.example/x")


def test_no_bearer_challenge_surfaces_401() -> None:
    handler = challenge_server('Basic realm="x"')
    with make(handler, self_signed()) as client, pytest.raises(UnauthorizedError):
        client.head("https://storage.example/x")


def test_openid_and_saml_credentials() -> None:
    fake = FakeLws(auth=True)
    seen: list[CredentialContext] = []

    def id_token(ctx: CredentialContext) -> str:
        seen.append(ctx)
        return "eyJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJ4In0.sig"

    with make(fake, TokenExchangeAuthenticator(OpenIdCredentials(id_token))) as client:
        client.head(fake.root)
    assert seen[0].issuer == fake.as_base and seen[0].realm == fake.storage_id
    form = fake.token_requests[-1]
    assert form["subject_token_type"] == ["urn:ietf:params:oauth:token-type:id_token"]
    assert form["resource"] == [fake.storage_id]

    xml = "<samlp:Response>…</samlp:Response>"
    with make(fake, TokenExchangeAuthenticator(SamlCredentials(xml))) as client:
        client.head(fake.root)
    form = fake.token_requests[-1]
    assert form["subject_token_type"] == ["urn:ietf:params:oauth:token-type:saml2"]
    assert form["subject_token"] == [encode_saml_assertion(xml)]


def test_async_supplier_requires_async_client() -> None:
    fake = FakeLws(auth=True)

    async def id_token(ctx: CredentialContext) -> str:
        return "a.b.c"

    auth = TokenExchangeAuthenticator(OpenIdCredentials(id_token))
    with make(fake, auth) as client, pytest.raises(TypeError, match="AsyncLwsClient"):
        client.head(fake.root)


@pytest.mark.anyio
async def test_async_supplier_with_async_client() -> None:
    fake = FakeLws(auth=True)

    async def id_token(ctx: CredentialContext) -> str:
        return "a.b.c"

    async with AsyncLwsClient(
        authenticator=TokenExchangeAuthenticator(OpenIdCredentials(id_token)),
        http_client=httpx.AsyncClient(transport=httpx.MockTransport(fake)),
    ) as client:
        meta = await client.head(fake.root)
    assert meta.is_container


def test_bearer_token_authenticator_realm() -> None:
    seen: list[str | None] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request.headers.get("authorization"))
        return httpx.Response(200)

    auth = BearerTokenAuthenticator("abc", realm="https://storage.example/")
    with make(handler, auth) as client:
        client.head("https://storage.example/x")
        client.head("https://other.example/x")
    assert seen == ["Bearer abc", None]


def test_redirect_does_not_leak_token() -> None:
    fake = FakeLws(auth=True)
    seen: dict[str, str | None] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.host == "cdn.example":
            seen["cdn"] = request.headers.get("authorization")
            return httpx.Response(200, content=b"moved", headers={"Content-Type": "text/plain"})
        if request.url.path == "/root/moved" and fake._authorized(request):
            seen["origin"] = request.headers.get("authorization")
            return httpx.Response(302, headers={"Location": "https://cdn.example/blob"})
        return fake(request)

    with make(handler, self_signed()) as client:
        res = client.read("https://storage.example/root/moved")
    assert res.text == "moved" and res.url == "https://cdn.example/blob"
    assert seen["origin"] and seen["cdn"] is None


@pytest.mark.parametrize(
    ("status", "cls"),
    [
        (400, BadRequestError), (401, UnauthorizedError), (403, ForbiddenError),
        (404, NotFoundError), (405, MethodNotAllowedError), (406, NotAcceptableError),
        (409, ConflictError), (410, GoneError), (412, PreconditionFailedError),
        (415, UnsupportedMediaTypeError), (422, UnprocessableContentError),
        (501, NotImplementedByServerError), (507, InsufficientStorageError), (500, HttpError),
    ],
)
def test_error_mapping(status: int, cls: type[HttpError]) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(status, headers={"Allow": "GET, HEAD"}, text="nope")

    with make(handler) as client, pytest.raises(cls) as excinfo:
        client.read("https://storage.example/x")
    assert excinfo.value.status == status
    assert excinfo.value.method == "GET" and excinfo.value.url == "https://storage.example/x"
    if status == 405:
        assert excinfo.value.allow == ["GET", "HEAD"]  # type: ignore[attr-defined]
    assert issubclass(GoneError, NotFoundError)


def test_transport_error_wrapped() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("refused", request=request)

    with make(handler) as client, pytest.raises(TransportError):
        client.head("https://storage.example/")


def test_discover_falls_back_to_get_and_missing_location() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "HEAD":
            return httpx.Response(405)
        if request.url.path == "/":
            return httpx.Response(200, headers={"Content-Type": "application/lws+cid"}, content=json.dumps({
                "id": "https://s.example/", "type": ["Storage"],
                "service": [{"type": "StorageRoot", "serviceEndpoint": "/r/"}]}).encode())
        if request.method == "POST":
            return httpx.Response(201)
        return httpx.Response(200, headers={
            "Link": '<https://s.example/>; rel="https://www.w3.org/ns/lws#storage"'})

    with make(handler) as client:
        assert client.discover_storage("https://s.example/r/x").storage_root() == "https://s.example/r/"
        from lws_client import ProtocolError

        with pytest.raises(ProtocolError, match="Location"):
            client.create("https://s.example/r/", b"x", "text/plain")
