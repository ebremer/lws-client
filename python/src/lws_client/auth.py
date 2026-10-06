# SPDX-License-Identifier: MIT
"""Authentication and authorization (lws10-core §Authorization, authentication suites).

* :class:`Authenticator` — pluggable hook: ``authorize`` before a request and
  ``handle_challenge`` on ``401``.
* :class:`BearerTokenAuthenticator` — send a known access token.
* :class:`TokenExchangeAuthenticator` — the LWS flow: ``401`` challenge (``as_uri``,
  ``realm``) → authorization server metadata (``/.well-known/lws-configuration``) →
  OAuth 2.0 Token Exchange (RFC 8693) with a subject token from a
  :class:`CredentialProvider` → retry with ``Authorization: Bearer``.
* Credential providers for the authentication suites: :class:`OpenIdCredentials`,
  :class:`SamlCredentials`, :class:`SelfSignedCredentials`.
"""

from __future__ import annotations

import base64
import json
import threading
import time
from collections.abc import Awaitable, Callable, Generator, Mapping
from dataclasses import dataclass, field
from typing import Any, Protocol, Union, runtime_checkable
from urllib.parse import urlencode, urlsplit

import httpx

from ._flow import Exclusive, Flow, Invoke, Send
from ._util import b64url_decode, is_loopback, origin_parts, with_path
from .constants import GRANT_TYPE_TOKEN_EXCHANGE, WELL_KNOWN_LWS_CONFIGURATION, MediaType, TokenType
from .crypto import (
    SigningKey,
    did_key_from_jwk,
    did_key_kid,
    encode_jwt,
    self_signed_claims,
)
from .errors import AuthenticationError
from .headers import AuthChallenge, parse_www_authenticate

__all__ = [
    "Authenticator",
    "BearerTokenAuthenticator",
    "TokenExchangeAuthenticator",
    "AuthorizationServerMetadata",
    "AccessToken",
    "CredentialContext",
    "CredentialProvider",
    "OpenIdCredentials",
    "SamlCredentials",
    "SelfSignedCredentials",
    "encode_saml_assertion",
    "realm_contains",
    "metadata_url",
    "parse_token_response_expiry",
]


# --- helpers ------------------------------------------------------------------------


def realm_contains(realm: str, url: str) -> bool:
    """True if ``url`` is logically contained in ``realm``: same scheme, host and port, and
    the path equals the realm path or lies below it (the realm path is treated as a
    directory)."""
    if origin_parts(realm) != origin_parts(url):
        return False
    realm_path = urlsplit(realm).path or "/"
    path = urlsplit(url).path or "/"
    if path == realm_path:
        return True
    prefix = realm_path if realm_path.endswith("/") else realm_path + "/"
    return path.startswith(prefix)


def metadata_url(issuer: str) -> str:
    """Authorization server metadata URL for ``issuer`` (RFC 8414 §3.1 path insertion)."""
    parts = urlsplit(issuer)
    path = parts.path.rstrip("/")
    return with_path(issuer, WELL_KNOWN_LWS_CONFIGURATION + path)


def _same_issuer(a: str, b: str) -> bool:
    return a == b or a.rstrip("/") == b.rstrip("/")


def encode_saml_assertion(assertion: str | bytes) -> str:
    """Base64url-encode (without padding) a SAML 2.0 assertion for token exchange."""
    raw = assertion.encode("utf-8") if isinstance(assertion, str) else assertion
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _jwt_exp(token: str) -> float | None:
    parts = token.split(".")
    if len(parts) != 3:
        return None
    try:
        claims = json.loads(b64url_decode(parts[1]))
    except ValueError:
        return None
    exp = claims.get("exp") if isinstance(claims, dict) else None
    return float(exp) if isinstance(exp, (int, float)) and not isinstance(exp, bool) else None


# --- models -------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class AuthorizationServerMetadata:
    """RFC 8414 metadata published at ``/.well-known/lws-configuration``."""

    issuer: str
    token_endpoint: str
    jwks_uri: str | None = None
    grant_types_supported: tuple[str, ...] = ()
    subject_token_types_supported: tuple[str, ...] | None = None
    subject_identifier_types_supported: tuple[str, ...] | None = None
    raw: Mapping[str, Any] = field(default_factory=dict)

    @classmethod
    def from_json(cls, data: Mapping[str, Any]) -> AuthorizationServerMetadata:
        issuer = data.get("issuer")
        token_endpoint = data.get("token_endpoint")
        if not isinstance(issuer, str) or not isinstance(token_endpoint, str):
            raise AuthenticationError("authorization server metadata lacks issuer/token_endpoint")

        def strings(name: str) -> tuple[str, ...] | None:
            value = data.get(name)
            if not isinstance(value, list):
                return None
            return tuple(v for v in value if isinstance(v, str))

        jwks = data.get("jwks_uri")
        return cls(
            issuer=issuer,
            token_endpoint=token_endpoint,
            jwks_uri=jwks if isinstance(jwks, str) else None,
            grant_types_supported=strings("grant_types_supported") or (),
            subject_token_types_supported=strings("subject_token_types_supported"),
            subject_identifier_types_supported=strings("subject_identifier_types_supported"),
            raw=dict(data),
        )


@dataclass(frozen=True, slots=True)
class AccessToken:
    """An access token obtained from an authorization server."""

    value: str
    token_type: str
    expires_at: float
    issuer: str
    realm: str

    def expired(self, skew: float = 0.0, now: float | None = None) -> bool:
        return (time.time() if now is None else now) >= self.expires_at - skew


@dataclass(frozen=True, slots=True)
class CredentialContext:
    """What a credential provider knows about the token exchange it is asked to support."""

    issuer: str
    realm: str
    metadata: AuthorizationServerMetadata


@runtime_checkable
class CredentialProvider(Protocol):
    """Supplies subject tokens (authentication credentials) for token exchange."""

    @property
    def token_type(self) -> str: ...

    def get_subject_token(self, context: CredentialContext) -> str | Awaitable[str]: ...


TokenSource = Union[str, Callable[[CredentialContext], str | Awaitable[str]]]


class _MappedAwaitable:
    """``await`` an inner awaitable and transform its result; ``close()`` closes the inner
    coroutine so an unused awaitable never leaks a "never awaited" warning."""

    __slots__ = ("_fn", "_inner")

    def __init__(self, inner: Awaitable[str], fn: Callable[[str], str]) -> None:
        self._inner = inner
        self._fn = fn

    def __await__(self) -> Generator[Any, None, str]:
        value = yield from self._inner.__await__()
        return self._fn(value)

    def close(self) -> None:
        close = getattr(self._inner, "close", None)
        if callable(close):
            close()


class _SuppliedCredentials:
    __slots__ = ("_source",)
    _TOKEN_TYPE = ""

    def __init__(self, source: TokenSource) -> None:
        self._source = source

    @property
    def token_type(self) -> str:
        return self._TOKEN_TYPE

    def _transform(self, token: str) -> str:
        return token

    def get_subject_token(self, context: CredentialContext) -> str | Awaitable[str]:
        if isinstance(self._source, str):
            return self._transform(self._source)
        result = self._source(context)
        if isinstance(result, str):
            return self._transform(result)
        return _MappedAwaitable(result, self._transform)


class OpenIdCredentials(_SuppliedCredentials):
    """lws10-authn-openid: an OpenID Connect ID token (``…:token-type:id_token``).

    ``source`` is the ID token or a callable (sync or async) receiving a
    :class:`CredentialContext` and returning a fresh ID token — interactive login is left to
    your OIDC library.
    """

    __slots__ = ()
    _TOKEN_TYPE = TokenType.ID_TOKEN


class SamlCredentials(_SuppliedCredentials):
    """lws10-authn-saml: a SAML 2.0 assertion (``…:token-type:saml2``).

    ``source`` returns either raw assertion XML (starting with ``<``, which is
    base64url-encoded automatically) or an already base64url-encoded assertion.
    """

    __slots__ = ()
    _TOKEN_TYPE = TokenType.SAML2

    def _transform(self, token: str) -> str:
        return encode_saml_assertion(token) if token.lstrip().startswith("<") else token


class SelfSignedCredentials:
    """lws10-authn-ssi-cid: a JWT signed by the agent itself (``…:token-type:jwt``).

    Claims: ``sub = iss = client_id = agent``, ``aud = [authorization server]``, ``iat``,
    ``exp`` (``lifetime`` seconds later) and a random ``jti``. Tokens are cached per
    audience until 60 s before expiry.
    """

    __slots__ = ("_cache", "_lock", "agent", "key", "kid", "lifetime")

    def __init__(self, agent: str, key: SigningKey, kid: str, lifetime: int = 300) -> None:
        self.agent = agent
        self.key = key
        self.kid = kid
        self.lifetime = lifetime
        self._cache: dict[str, tuple[str, float]] = {}
        self._lock = threading.Lock()

    @classmethod
    def for_agent(
        cls, agent: str, key: SigningKey, kid: str, lifetime: int = 300
    ) -> SelfSignedCredentials:
        """An HTTPS (or DID) agent whose controlled identifier document lists ``kid``."""
        return cls(agent, key, kid, lifetime)

    @classmethod
    def did_key(cls, key: SigningKey, lifetime: int = 300) -> SelfSignedCredentials:
        """A ``did:key`` agent derived from ``key``; ``kid = did:key:z…#z…``."""
        did = did_key_from_jwk(key.public_jwk())
        return cls(did, key, did_key_kid(did), lifetime)

    @property
    def token_type(self) -> str:
        return TokenType.JWT

    @property
    def agent_id(self) -> str:
        return self.agent

    def create_token(self, audience: str, now: float | None = None) -> str:
        """Sign a fresh credential for ``audience`` (an authorization server issuer)."""
        claims = self_signed_claims(self.agent, [audience], self.lifetime, now)
        return encode_jwt({"alg": self.key.alg, "typ": "JWT", "kid": self.kid}, claims, self.key)

    def get_subject_token(self, context: CredentialContext) -> str:
        now = time.time()
        with self._lock:
            cached = self._cache.get(context.issuer)
            if cached and cached[1] - 60 > now:
                return cached[0]
        token = self.create_token(context.issuer, now)
        with self._lock:
            self._cache[context.issuer] = (token, now + self.lifetime)
        return token


# --- authenticators -----------------------------------------------------------------


class Authenticator:
    """Base class for pluggable authentication.

    Simple authenticators override :meth:`authorize` and/or :meth:`handle_challenge` (they
    may be ``async def`` when used with :class:`~lws_client.AsyncLwsClient`). Authenticators
    that must perform HTTP requests override the generator methods
    :meth:`authorize_flow` / :meth:`challenge_flow`, which yield sans-I/O effects that the
    client performs.
    """

    def authorize(self, request: httpx.Request) -> Awaitable[None] | None:
        """Add credentials to ``request`` before it is sent."""
        return None

    def handle_challenge(
        self, request: httpx.Request, response: httpx.Response
    ) -> bool | Awaitable[bool]:
        """Handle a ``401``; return ``True`` to retry the request once."""
        return False

    def has_credentials_for(self, url: str) -> bool:
        """Whether a request to ``url`` would currently be sent with credentials. Used to
        decide on a pre-flight ``HEAD`` before sending a non-replayable streaming body."""
        return True

    def authorize_flow(self, request: httpx.Request) -> Flow[None]:
        yield Invoke(self.authorize, (request,))

    def challenge_flow(self, request: httpx.Request, response: httpx.Response) -> Flow[bool]:
        return bool((yield Invoke(self.handle_challenge, (request, response))))


class BearerTokenAuthenticator(Authenticator):
    """Send a known access token (or one returned by a sync/async callable).

    If ``realm`` is given, the token is only sent to URLs inside that realm.
    """

    def __init__(
        self,
        token: str | Callable[[], str | Awaitable[str]],
        *,
        realm: str | None = None,
    ) -> None:
        self._token = token
        self.realm = realm

    def has_credentials_for(self, url: str) -> bool:
        return self.realm is None or realm_contains(self.realm, url)

    def authorize_flow(self, request: httpx.Request) -> Flow[None]:
        if not self.has_credentials_for(str(request.url)):
            return
        token = self._token if isinstance(self._token, str) else (yield Invoke(self._token))
        request.headers["Authorization"] = f"Bearer {token}"


class TokenExchangeAuthenticator(Authenticator):
    """The LWS OAuth 2.0 token-exchange flow (design contract §6.2).

    :param credentials: supplies the subject token (authentication credential).
    :param allow_insecure_http: allow ``http`` authorization servers (loopback hosts are
        always allowed, for testing).
    :param authorization_server_filter: ``(as_uri, realm) -> bool`` policy deciding whether
        credentials may be presented to an authorization server named by a storage.
    :param refresh_skew: seconds before expiry at which cached tokens are refreshed.
    """

    def __init__(
        self,
        credentials: CredentialProvider,
        *,
        allow_insecure_http: bool = False,
        authorization_server_filter: Callable[[str, str], bool] | None = None,
        refresh_skew: float = 30.0,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self.credentials = credentials
        self.allow_insecure_http = allow_insecure_http
        self.authorization_server_filter = authorization_server_filter
        self.refresh_skew = refresh_skew
        self._clock = clock
        self._tokens: dict[tuple[str, str], AccessToken] = {}
        self._metadata: dict[str, AuthorizationServerMetadata] = {}
        self._lock = threading.Lock()

    # -- cache ---------------------------------------------------------------------------

    def _entry_for(self, url: str) -> AccessToken | None:
        """The cached token whose realm contains ``url`` (longest realm wins)."""
        with self._lock:
            matches = [t for t in self._tokens.values() if realm_contains(t.realm, url)]
        if not matches:
            return None
        return max(matches, key=lambda t: len(t.realm))

    def has_credentials_for(self, url: str) -> bool:
        entry = self._entry_for(url)
        return entry is not None and not entry.expired(self.refresh_skew, self._clock())

    def cached_token(self, url: str) -> AccessToken | None:
        """The cached access token that would be sent to ``url``, if any."""
        return self._entry_for(url)

    def clear(self) -> None:
        """Forget all cached tokens and authorization server metadata."""
        with self._lock:
            self._tokens.clear()
            self._metadata.clear()

    # -- flows ---------------------------------------------------------------------------

    def authorize_flow(self, request: httpx.Request) -> Flow[None]:
        url = str(request.url)
        entry = self._entry_for(url)
        if entry is None:
            return
        if entry.expired(self.refresh_skew, self._clock()):
            entry = yield Exclusive(
                ("lws-token", entry.issuer, entry.realm),
                self._obtain(entry.issuer, entry.realm, failed=entry.value),
            )
        request.headers["Authorization"] = f"Bearer {entry.value}"

    def challenge_flow(self, request: httpx.Request, response: httpx.Response) -> Flow[bool]:
        challenge = self._select(parse_www_authenticate(response.headers.get_list("www-authenticate")))
        if challenge is None:
            return False
        issuer, realm = str(challenge.as_uri), str(challenge.realm)
        url = str(request.url)
        if not realm_contains(realm, url):
            raise AuthenticationError(
                f"request URL {url} is not within the challenge realm {realm}; refusing to "
                "obtain credentials"
            )
        self._check_secure(issuer, "authorization server")
        if self.authorization_server_filter is not None and not self.authorization_server_filter(
            issuer, realm
        ):
            raise AuthenticationError(f"authorization server {issuer} rejected by policy")
        sent = request.headers.get("authorization", "")
        failed = sent[7:] if sent.lower().startswith("bearer ") else None
        if failed:
            self._drop(failed)
        yield Exclusive(("lws-token", issuer, realm), self._obtain(issuer, realm, failed=failed))
        return True

    @staticmethod
    def _select(challenges: list[AuthChallenge]) -> AuthChallenge | None:
        for ch in challenges:
            if ch.is_scheme("Bearer") and ch.as_uri and ch.realm:
                return ch
        return None

    def _check_secure(self, url: str, what: str) -> None:
        scheme = urlsplit(url).scheme.lower()
        if scheme == "https" or (scheme == "http" and (is_loopback(url) or self.allow_insecure_http)):
            return
        raise AuthenticationError(f"refusing insecure {what} URL {url} (https is required)")

    def _drop(self, token: str) -> None:
        with self._lock:
            for key, entry in list(self._tokens.items()):
                if entry.value == token:
                    del self._tokens[key]

    def _metadata_flow(self, issuer: str) -> Flow[AuthorizationServerMetadata]:
        with self._lock:
            cached = self._metadata.get(issuer)
        if cached is not None:
            return cached
        url = metadata_url(issuer)
        response = yield Send(httpx.Request("GET", url, headers={"Accept": MediaType.JSON}))
        if response.status_code != 200:
            raise AuthenticationError(
                f"authorization server metadata {url} returned {response.status_code}",
                status=response.status_code,
            )
        try:
            data = response.json()
        except ValueError as exc:
            raise AuthenticationError(f"authorization server metadata {url} is not JSON") from exc
        if not isinstance(data, dict):
            raise AuthenticationError(f"authorization server metadata {url} is not a JSON object")
        metadata = AuthorizationServerMetadata.from_json(data)
        if not _same_issuer(metadata.issuer, issuer):
            raise AuthenticationError(
                f"metadata issuer {metadata.issuer!r} does not match as_uri {issuer!r}"
            )
        self._check_secure(metadata.token_endpoint, "token endpoint")
        with self._lock:
            self._metadata[issuer] = metadata
        return metadata

    def _obtain(self, issuer: str, realm: str, failed: str | None) -> Flow[AccessToken]:
        with self._lock:
            current = self._tokens.get((issuer, realm))
        if (
            current is not None
            and current.value != failed
            and not current.expired(self.refresh_skew, self._clock())
        ):
            return current  # another request refreshed it meanwhile
        metadata = yield from self._metadata_flow(issuer)
        token_type = self.credentials.token_type
        supported = metadata.subject_token_types_supported
        if supported is not None and token_type not in supported:
            raise AuthenticationError(
                f"authorization server {issuer} does not accept subject tokens of type "
                f"{token_type} (supported: {', '.join(supported)})"
            )
        context = CredentialContext(issuer=issuer, realm=realm, metadata=metadata)
        subject_token = yield Invoke(self.credentials.get_subject_token, (context,))
        form = urlencode(
            {
                "grant_type": GRANT_TYPE_TOKEN_EXCHANGE,
                "resource": realm,
                "subject_token": subject_token,
                "subject_token_type": token_type,
            }
        )
        response = yield Send(
            httpx.Request(
                "POST",
                metadata.token_endpoint,
                headers={"Content-Type": MediaType.FORM, "Accept": MediaType.JSON},
                content=form.encode("ascii"),
            )
        )
        token = self._parse_token_response(response, issuer, realm)
        with self._lock:
            self._tokens[(issuer, realm)] = token
        return token

    def _parse_token_response(
        self, response: httpx.Response, issuer: str, realm: str
    ) -> AccessToken:
        try:
            data = response.json()
        except ValueError:
            data = None
        if response.status_code != 200:
            error = data.get("error") if isinstance(data, dict) else None
            description = data.get("error_description") if isinstance(data, dict) else None
            message = f"token exchange at {issuer} failed with {response.status_code}"
            if error:
                message += f": {error}"
            if description:
                message += f" ({description})"
            raise AuthenticationError(
                message,
                error=error if isinstance(error, str) else None,
                error_description=description if isinstance(description, str) else None,
                status=response.status_code,
            )
        if not isinstance(data, dict) or not isinstance(data.get("access_token"), str):
            raise AuthenticationError("token response has no access_token")
        token_type = data.get("token_type")
        if not isinstance(token_type, str) or token_type.lower() != "bearer":
            raise AuthenticationError(f"unsupported token_type {token_type!r} (Bearer required)")
        expires_at = parse_token_response_expiry(data, self._clock())
        return AccessToken(data["access_token"], "Bearer", expires_at, issuer, realm)


def parse_token_response_expiry(body: Mapping[str, Any], now: float) -> float:
    """Expiry (unix seconds) of a token response: ``expires_in``, else the JWT ``exp``,
    else 300 s from ``now``."""
    expires_in = body.get("expires_in")
    if isinstance(expires_in, (int, float)) and not isinstance(expires_in, bool):
        return now + float(expires_in)
    token = body.get("access_token")
    exp = _jwt_exp(token) if isinstance(token, str) else None
    return exp if exp is not None else now + 300.0
