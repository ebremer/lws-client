# SPDX-License-Identifier: MIT
"""Authentication and authorization (lws10-core §Authorization, authentication suites).

* :class:`Authenticator` — pluggable hook: ``authorize`` before a request and
  ``handle_challenge`` on ``401``.
* :class:`BearerTokenAuthenticator` — send a known access token.
* :class:`TokenExchangeAuthenticator` — the LWS flow: ``401`` challenge
  (``resource_metadata``) → protected resource metadata (RFC 9728) and the discovery checks →
  authorization server metadata (``/.well-known/lws-configuration``) → OAuth 2.0 Token
  Exchange (RFC 8693) with a subject token from a :class:`CredentialProvider` → retry with
  ``Authorization: Bearer``.
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
from ._util import (
    b64url_decode,
    is_loopback,
    normalize_url,
    origin_parts,
    resolve,
    url_origin,
    with_path,
)
from .constants import (
    GRANT_TYPE_TOKEN_EXCHANGE,
    WELL_KNOWN_LWS_CONFIGURATION,
    MediaType,
    Rel,
    TokenType,
)
from .crypto import (
    SigningKey,
    did_key_from_jwk,
    did_key_kid,
    encode_jwt,
    self_signed_claims,
)
from .errors import AuthenticationError, ProtocolError
from .headers import AuthChallenge, parse_link_header, parse_www_authenticate
from .models import STORAGE_ACCEPT, StorageDescription

__all__ = [
    "Authenticator",
    "BearerTokenAuthenticator",
    "TokenExchangeAuthenticator",
    "AuthorizationServerMetadata",
    "ProtectedResourceMetadata",
    "AccessToken",
    "CredentialContext",
    "CredentialProvider",
    "OpenIdCredentials",
    "SamlCredentials",
    "SelfSignedCredentials",
    "encode_saml_assertion",
    "realm_contains",
    "same_origin",
    "same_resource",
    "metadata_url",
    "parse_token_response_expiry",
]


# --- helpers ------------------------------------------------------------------------


def realm_contains(realm: str, url: str) -> bool:
    """True if ``url`` is logically contained in ``realm``: same scheme, host and port, and
    the path equals the realm path or lies below it (the realm path is treated as a
    directory). A token's scopes contain URLs in the same way."""
    if origin_parts(realm) != origin_parts(url):
        return False
    realm_path = urlsplit(realm).path or "/"
    path = urlsplit(url).path or "/"
    if path == realm_path:
        return True
    return path.startswith(_directory(realm_path))


def _directory(path: str) -> str:
    return path if path.endswith("/") else path + "/"


def same_origin(a: str, b: str) -> bool:
    """True if ``a`` and ``b`` have the same scheme and authority: scheme and host compared
    case-insensitively, a missing port taken as the scheme's default (lws10-core "Discovery
    Validation by a Client")."""
    origin = url_origin(a)
    return origin is not None and origin == url_origin(b)


def same_resource(requested: str, resource: str) -> bool:
    """True if a protected resource metadata ``resource`` is identical to the ``requested`` URL
    (RFC 9728 §3.3): compared after lower-casing scheme and host and dropping a default port,
    and nothing else — no trailing slash, case or percent-encoding leniency."""
    normalized = normalize_url(requested)
    return normalized is not None and normalized == normalize_url(resource)


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
class ProtectedResourceMetadata:
    """RFC 9728 protected resource metadata, named by the ``resource_metadata`` of a ``401``
    challenge: the resource it describes and its authorization servers, in order."""

    resource: str
    authorization_servers: tuple[str, ...]
    raw: Mapping[str, Any] = field(default_factory=dict)

    @classmethod
    def from_json(cls, data: Any) -> ProtectedResourceMetadata:
        """Parse a metadata document; raises :class:`AuthenticationError` unless ``resource`` is
        a string and ``authorization_servers`` a non-empty array of strings (lws10-core makes it
        REQUIRED)."""
        if not isinstance(data, Mapping):
            raise AuthenticationError("protected resource metadata is not a JSON object")
        resource = data.get("resource")
        if not isinstance(resource, str):
            raise AuthenticationError("protected resource metadata has no resource")
        servers = data.get("authorization_servers")
        if not (isinstance(servers, list) and servers and all(isinstance(s, str) for s in servers)):
            raise AuthenticationError("protected resource metadata names no authorization_servers")
        return cls(resource=resource, authorization_servers=tuple(servers), raw=dict(data))


@dataclass(frozen=True, slots=True)
class AccessToken:
    """An access token obtained from an authorization server for a storage.

    It is sent ahead to URLs inside its ``scopes``: the storage URL and the storage root, each
    treated as a directory, or the realm for the challenge of the drafts before 19 October 2026.
    """

    value: str
    token_type: str
    expires_at: float
    issuer: str
    storage: str
    scopes: tuple[str, ...] = ()

    def expired(self, skew: float = 0.0, now: float | None = None) -> bool:
        return (time.time() if now is None else now) >= self.expires_at - skew


@dataclass(frozen=True, slots=True)
class CredentialContext:
    """What a credential provider knows about the token exchange it is asked to support: the
    authorization server and the storage the token is for."""

    issuer: str
    storage: str
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

    def challenge_flow(
        self, request: httpx.Request, response: httpx.Response
    ) -> Flow[bool | str]:
        """``True`` to retry the request once, or the ``Authorization`` header value to retry it
        with (the request is then sent without :meth:`authorize_flow`)."""
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

    On a ``401`` it follows the challenge's ``resource_metadata`` (RFC 9728), and makes the
    discovery checks of lws10-core before it asks for a token: the metadata is on the requested
    origin and describes the requested URL, and the storage the ``401`` links to has its root on
    the requested origin. A challenge that fails a check gets no token, and does not cost the
    client the token it has. A ``401`` with the ``as_uri`` and ``realm`` of the drafts before
    19 October 2026, and no ``resource_metadata``, is still followed after the realm check.

    :param credentials: supplies the subject token (authentication credential).
    :param allow_insecure_http: allow ``http`` authorization servers (loopback hosts are
        always allowed, for testing).
    :param authorization_server_filter: ``(issuer, storage) -> bool`` policy deciding whether
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
        self._descriptions: dict[str, StorageDescription] = {}
        self._lock = threading.Lock()

    # -- cache ---------------------------------------------------------------------------

    def _entry_for(self, url: str) -> AccessToken | None:
        """The cached token with a scope that contains ``url`` (the longest scope path wins)."""
        with self._lock:
            tokens = list(self._tokens.values())
        best: AccessToken | None = None
        longest = -1
        for token in tokens:
            for scope in token.scopes:
                length = len(_directory(urlsplit(scope).path))
                if length > longest and realm_contains(scope, url):
                    best, longest = token, length
        return best

    def has_credentials_for(self, url: str) -> bool:
        entry = self._entry_for(url)
        return entry is not None and not entry.expired(self.refresh_skew, self._clock())

    def cached_token(self, url: str) -> AccessToken | None:
        """The cached access token that would be sent to ``url``, if any."""
        return self._entry_for(url)

    def clear(self) -> None:
        """Forget all cached tokens, authorization server metadata and storage descriptions."""
        with self._lock:
            self._tokens.clear()
            self._metadata.clear()
            self._descriptions.clear()

    # -- flows ---------------------------------------------------------------------------

    def authorize_flow(self, request: httpx.Request) -> Flow[None]:
        url = str(request.url)
        entry = self._entry_for(url)
        if entry is None:
            return
        if entry.expired(self.refresh_skew, self._clock()):
            entry = yield Exclusive(
                ("lws-token", entry.issuer, entry.storage),
                self._obtain(entry.issuer, entry.storage, entry.scopes, failed=entry.value),
            )
        request.headers["Authorization"] = f"Bearer {entry.value}"

    def challenge_flow(
        self, request: httpx.Request, response: httpx.Response
    ) -> Flow[bool | str]:
        challenges = [
            ch
            for ch in parse_www_authenticate(response.headers.get_list("www-authenticate"))
            if ch.is_scheme("Bearer")
        ]
        url = str(request.url)
        current = next((ch for ch in challenges if ch.resource_metadata), None)
        if current is not None:
            issuer, storage, scopes = yield from self._discover(url, current, response)
        else:
            legacy = next((ch for ch in challenges if ch.as_uri and ch.realm), None)
            if legacy is None:
                return False
            issuer, storage, scopes = self._legacy(url, legacy)
        sent = request.headers.get("authorization", "")
        failed = sent[7:] if sent.lower().startswith("bearer ") else None
        token = yield Exclusive(
            ("lws-token", issuer, storage), self._obtain(issuer, storage, scopes, failed=failed)
        )
        # The retry carries the token obtained for the URL that drew the 401, inside its scopes
        # or not (a storage with opaque identifiers).
        return f"Bearer {token.value}"

    def _discover(
        self, url: str, challenge: AuthChallenge, response: httpx.Response
    ) -> Flow[tuple[str, str, tuple[str, ...]]]:
        """The issuer, the storage and the token's scopes for a ``401`` with
        ``resource_metadata``, after the discovery checks of lws10-core."""
        prm_url = resolve(url, str(challenge.resource_metadata))
        if not same_origin(prm_url, url):
            raise AuthenticationError(
                f"the protected resource metadata {prm_url} is not on the origin of {url}; "
                "refusing to obtain credentials"
            )
        storage = next(
            (link.href for link in parse_link_header(response.headers.get_list("link"), url)
             if link.rel == Rel.STORAGE),
            None,
        )
        if storage is None:
            raise AuthenticationError(f"the 401 from {url} links to no storage (rel={Rel.STORAGE})")
        metadata = yield from self._resource_metadata_flow(prm_url)
        if not same_resource(url, metadata.resource):
            raise AuthenticationError(
                f"the protected resource metadata {prm_url} describes {metadata.resource}, not "
                f"{url}; refusing to obtain credentials"
            )
        root = yield Exclusive(("lws-storage", storage), self._storage_root_flow(storage))
        if not same_origin(root, url):
            raise AuthenticationError(
                f"the root {root} of storage {storage} is not on the origin of {url}; refusing "
                "to obtain credentials"
            )
        refused: list[str] = []
        for issuer in metadata.authorization_servers:
            if not self._secure(issuer):
                refused.append(f"{issuer} is insecure (https is required)")
            elif not self._allowed(issuer, storage):
                refused.append(f"{issuer} is rejected by policy")
            else:
                return issuer, storage, (storage, root)
        raise AuthenticationError(
            f"no authorization server of {prm_url} can be used: {'; '.join(refused)}"
        )

    def _legacy(self, url: str, challenge: AuthChallenge) -> tuple[str, str, tuple[str, ...]]:
        """The challenge of the drafts before 19 October 2026: the realm must contain ``url``,
        and is then the token's storage and its only scope."""
        issuer, realm = str(challenge.as_uri), str(challenge.realm)
        if not realm_contains(realm, url):
            raise AuthenticationError(
                f"request URL {url} is not within the challenge realm {realm}; refusing to "
                "obtain credentials"
            )
        self._check_secure(issuer, "authorization server")
        if not self._allowed(issuer, realm):
            raise AuthenticationError(f"authorization server {issuer} rejected by policy")
        return issuer, realm, (realm,)

    def _secure(self, url: str) -> bool:
        scheme = urlsplit(url).scheme.lower()
        return scheme == "https" or (
            scheme == "http" and (is_loopback(url) or self.allow_insecure_http)
        )

    def _check_secure(self, url: str, what: str) -> None:
        if not self._secure(url):
            raise AuthenticationError(f"refusing insecure {what} URL {url} (https is required)")

    def _allowed(self, issuer: str, storage: str) -> bool:
        policy = self.authorization_server_filter
        return policy is None or policy(issuer, storage)

    @staticmethod
    def _get_json(url: str, accept: str, what: str) -> Flow[Any]:
        """``GET`` a discovery document: without credentials, following no redirect."""
        response = yield Send(httpx.Request("GET", url, headers={"Accept": accept}))
        if response.status_code != 200:
            raise AuthenticationError(
                f"{what} {url} returned {response.status_code}", status=response.status_code
            )
        try:
            return response.json()
        except ValueError as exc:
            raise AuthenticationError(f"{what} {url} is not JSON") from exc

    def _resource_metadata_flow(self, url: str) -> Flow[ProtectedResourceMetadata]:
        # Not cached: it describes one resource.
        data = yield from self._get_json(url, MediaType.JSON, "protected resource metadata")
        return ProtectedResourceMetadata.from_json(data)

    def _storage_root_flow(self, storage: str) -> Flow[str]:
        """The root of ``storage``, from its description, which is cached for the
        authenticator's lifetime."""
        with self._lock:
            description = self._descriptions.get(storage)
        if description is not None:
            return description.storage_root()
        data = yield from self._get_json(storage, STORAGE_ACCEPT, "storage description")
        try:
            description = StorageDescription.from_json(data, storage)
            root = description.storage_root()
        except ProtocolError as exc:
            raise AuthenticationError(f"storage description {storage}: {exc}") from exc
        with self._lock:
            self._descriptions[storage] = description
        return root

    def _metadata_flow(self, issuer: str) -> Flow[AuthorizationServerMetadata]:
        with self._lock:
            cached = self._metadata.get(issuer)
        if cached is not None:
            return cached
        url = metadata_url(issuer)
        data = yield from self._get_json(url, MediaType.JSON, "authorization server metadata")
        if not isinstance(data, dict):
            raise AuthenticationError(f"authorization server metadata {url} is not a JSON object")
        metadata = AuthorizationServerMetadata.from_json(data)
        if not _same_issuer(metadata.issuer, issuer):
            raise AuthenticationError(
                f"metadata issuer {metadata.issuer!r} does not match the authorization server "
                f"{issuer!r}"
            )
        self._check_secure(metadata.token_endpoint, "token endpoint")
        with self._lock:
            self._metadata[issuer] = metadata
        return metadata

    def _obtain(
        self, issuer: str, storage: str, scopes: tuple[str, ...], failed: str | None
    ) -> Flow[AccessToken]:
        key = (issuer, storage)
        with self._lock:
            current = self._tokens.get(key)
        if (
            current is not None
            and current.value != failed
            and not current.expired(self.refresh_skew, self._clock())
        ):
            return current  # another request obtained it meanwhile
        metadata = yield from self._metadata_flow(issuer)
        if current is not None:
            with self._lock:
                if self._tokens.get(key) is current:
                    del self._tokens[key]  # refused by the storage, or expired: exchange again
        token_type = self.credentials.token_type
        supported = metadata.subject_token_types_supported
        if supported is not None and token_type not in supported:
            raise AuthenticationError(
                f"authorization server {issuer} does not accept subject tokens of type "
                f"{token_type} (supported: {', '.join(supported)})"
            )
        context = CredentialContext(issuer=issuer, storage=storage, metadata=metadata)
        subject_token = yield Invoke(self.credentials.get_subject_token, (context,))
        form = urlencode(
            {
                "grant_type": GRANT_TYPE_TOKEN_EXCHANGE,
                "resource": storage,
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
        token = self._parse_token_response(response, issuer, storage, scopes)
        with self._lock:
            self._tokens[key] = token
        return token

    def _parse_token_response(
        self, response: httpx.Response, issuer: str, storage: str, scopes: tuple[str, ...]
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
        return AccessToken(data["access_token"], "Bearer", expires_at, issuer, storage, scopes)


def parse_token_response_expiry(body: Mapping[str, Any], now: float) -> float:
    """Expiry (unix seconds) of a token response: ``expires_in``, else the JWT ``exp``,
    else 300 s from ``now``."""
    expires_in = body.get("expires_in")
    if isinstance(expires_in, (int, float)) and not isinstance(expires_in, bool):
        return now + float(expires_in)
    token = body.get("access_token")
    exp = _jwt_exp(token) if isinstance(token, str) else None
    return exp if exp is not None else now + 300.0
