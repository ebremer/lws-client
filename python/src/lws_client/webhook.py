# SPDX-License-Identifier: MIT
"""Verification of signed webhook deliveries (lws10-notifications-webhook).

A notification server signs each delivery with HTTP Message Signatures (RFC 9421) over
``@method @scheme @authority @path content-type content-digest`` and a ``Content-Digest``
(RFC 9530). The verifying key is published in the storage description named by the
signature's ``keyid``. :class:`WebhookVerifier` / :class:`AsyncWebhookVerifier` implement
the receiver algorithm of design contract §7.1 and return the verified notification.

Requires the ``cryptography`` extra.
"""

from __future__ import annotations

import hashlib
import hmac
import threading
import time
from collections.abc import Awaitable, Callable, Iterable, Mapping
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Union
from urllib.parse import urlsplit, urlunsplit

import httpx

from ._flow import Flow, Invoke
from ._util import authority
from .crypto import VerifyingKey
from .errors import LwsError, SignatureVerificationError
from .models import StorageDescription, id_matches
from .notifications import Notification, parse_notification
from .structured_fields import (
    InnerList,
    Item,
    StructuredFieldError,
    Token,
    parse_dictionary,
    serialize_inner_list,
)

if TYPE_CHECKING:
    from .client import AsyncLwsClient, LwsClient

__all__ = [
    "VerifiedNotification",
    "WebhookVerifier",
    "AsyncWebhookVerifier",
    "REQUIRED_COMPONENTS",
    "signature_base",
    "verify_content_digest",
    "read_asgi_request",
]

REQUIRED_COMPONENTS = (
    "@method", "@scheme", "@authority", "@path", "content-type", "content-digest",
)
_DIGESTS = {"sha-256": hashlib.sha256, "sha-512": hashlib.sha512}
_ALG_FOR_KEY = {"ES256": "ecdsa-p256-sha256", "ES384": "ecdsa-p384-sha384", "EdDSA": "ed25519"}

HeadersLike = Union[Mapping[str, str], Iterable[tuple[str, str]], httpx.Headers]
DescriptionLike = Union[StorageDescription, Mapping[str, Any]]


def _headers(headers: HeadersLike) -> httpx.Headers:
    if isinstance(headers, httpx.Headers):
        return headers
    if isinstance(headers, Mapping):
        return httpx.Headers(dict(headers))
    return httpx.Headers(list(headers))


@dataclass(frozen=True, slots=True)
class VerifiedNotification:
    """A notification whose delivery signature has been verified."""

    notification: Notification
    keyid: str
    storage: str
    label: str


def verify_content_digest(header: str | None, body: bytes) -> None:
    """Check an RFC 9530 ``Content-Digest`` (``sha-256`` / ``sha-512``) against ``body``.

    At least one recognised algorithm must be present and every recognised one must match.
    """
    if not header:
        raise SignatureVerificationError("missing Content-Digest")
    try:
        digests = parse_dictionary(header)
    except StructuredFieldError as exc:
        raise SignatureVerificationError(f"malformed Content-Digest: {exc}") from exc
    checked = 0
    for name, member in digests.items():
        algo = _DIGESTS.get(name)
        if algo is None:
            continue
        if not isinstance(member, Item) or not isinstance(member.value, bytes):
            raise SignatureVerificationError(f"Content-Digest {name} is not a byte sequence")
        if not hmac.compare_digest(member.value, algo(body).digest()):
            raise SignatureVerificationError(f"Content-Digest {name} does not match the body")
        checked += 1
    if checked == 0:
        raise SignatureVerificationError("Content-Digest has no supported algorithm")


def _component_value(name: str, method: str, url: str, headers: httpx.Headers) -> str:
    parts = urlsplit(url)
    if name == "@method":
        return method.upper()
    if name == "@scheme":
        return parts.scheme.lower()
    if name == "@authority":
        return authority(url)
    if name == "@path":
        return parts.path or "/"
    if name == "@query":
        return "?" + parts.query
    if name == "@target-uri":
        return url
    if name == "@request-target":
        return (parts.path or "/") + (f"?{parts.query}" if parts.query else "")
    if name.startswith("@"):
        raise SignatureVerificationError(f"unsupported derived component {name}")
    values = headers.get_list(name)
    if not values:
        raise SignatureVerificationError(f"covered header {name!r} is missing")
    return ", ".join(v.strip() for v in values)


def signature_base(
    method: str, url: str, headers: HeadersLike, signature_params: InnerList
) -> str:
    """Build the RFC 9421 signature base for ``signature_params`` (the parsed inner list
    from ``Signature-Input``)."""
    hdrs = _headers(headers)
    lines = []
    for item in signature_params.items:
        if not isinstance(item.value, str) or isinstance(item.value, Token):
            raise SignatureVerificationError("component identifiers must be strings")
        if item.params:
            raise SignatureVerificationError(
                f"component parameters are not supported ({item.value})"
            )
        name = item.value.lower()
        lines.append(f'"{name}": {_component_value(name, method, url, hdrs)}')
    lines.append(f'"@signature-params": {serialize_inner_list(signature_params)}')
    return "\n".join(lines)


async def read_asgi_request(
    scope: Mapping[str, Any], receive: Callable[[], Awaitable[Mapping[str, Any]]]
) -> tuple[str, list[tuple[str, str]], bytes]:
    """Read ``(method, headers, body)`` from an ASGI HTTP scope/receive pair."""
    body = bytearray()
    while True:
        message = await receive()
        body.extend(message.get("body", b""))
        if not message.get("more_body"):
            break
    headers = [(k.decode("latin-1"), v.decode("latin-1")) for k, v in scope.get("headers", [])]
    return str(scope.get("method", "POST")), headers, bytes(body)


def _normal_url(url: str) -> str:
    """A URL as two spellings of it share it: scheme and host lower-cased, no default port, path ``/``."""
    try:
        parts = urlsplit(url)
        host = (parts.hostname or "").lower()
        port = parts.port
    except ValueError:
        return url
    if ":" in host:
        host = f"[{host}]"
    scheme = parts.scheme.lower()
    if port is not None and (scheme, port) not in (("http", 80), ("https", 443)):
        host = f"{host}:{port}"
    return urlunsplit((scheme, host, parts.path or "/", parts.query, parts.fragment))


class _VerifierCore:
    def __init__(
        self,
        *,
        fetch: Callable[[str], Any] | None,
        trusted_storages: Iterable[str] | None,
        max_age: float,
        clock_skew: float,
        clock: Callable[[], float],
        key_cache_ttl: float,
    ) -> None:
        self._fetch = fetch
        # Given at all, the list is an allow-list: an empty one trusts no storage.
        self.trusted_storages = (
            frozenset(_normal_url(u) for u in trusted_storages) if trusted_storages is not None else None
        )
        self.max_age = max_age
        self.clock_skew = clock_skew
        self.clock = clock
        self.key_cache_ttl = key_cache_ttl
        self._cache: dict[str, tuple[StorageDescription, float]] = {}
        self._lock = threading.Lock()

    def clear_cache(self) -> None:
        with self._lock:
            self._cache.clear()

    def _description_flow(self, storage_id: str, refresh: bool) -> Flow[tuple[StorageDescription, bool]]:
        now = time.monotonic()
        if not refresh:
            with self._lock:
                cached = self._cache.get(storage_id)
            if cached and now - cached[1] < self.key_cache_ttl:
                return cached[0], True
        if self._fetch is None:
            raise SignatureVerificationError("no storage description fetcher configured")
        try:
            result = yield Invoke(self._fetch, (storage_id,))
        except SignatureVerificationError:
            raise
        except LwsError as exc:
            raise SignatureVerificationError(
                f"cannot retrieve storage description {storage_id}: {exc}"
            ) from exc
        try:
            description = (
                result
                if isinstance(result, StorageDescription)
                else StorageDescription.from_json(result, storage_id)
            )
        except LwsError as exc:
            raise SignatureVerificationError(f"invalid storage description: {exc}") from exc
        if description.id != storage_id:
            raise SignatureVerificationError(
                f"storage description id {description.id!r} does not match {storage_id!r}"
            )
        with self._lock:
            self._cache[storage_id] = (description, now)
        return description, False

    def verify_flow(
        self, method: str, url: str, headers: HeadersLike, body: bytes
    ) -> Flow[VerifiedNotification]:
        hdrs = _headers(headers)
        verify_content_digest(hdrs.get("content-digest"), body)
        try:
            inputs = parse_dictionary(", ".join(hdrs.get_list("signature-input")))
            signatures = parse_dictionary(", ".join(hdrs.get_list("signature")))
        except StructuredFieldError as exc:
            raise SignatureVerificationError(f"malformed signature headers: {exc}") from exc

        label: str | None = None
        params: InnerList | None = None
        signature: bytes | None = None
        for name, member in inputs.items():
            sig = signatures.get(name)
            if (
                isinstance(member, InnerList)
                and isinstance(member.params.get("keyid"), str)
                and isinstance(sig, Item)
                and isinstance(sig.value, bytes)
            ):
                label, params, signature = name, member, sig.value
                break
        if label is None or params is None or signature is None:
            raise SignatureVerificationError("no usable signature with a keyid")

        covered = [i.value for i in params.items]
        missing = [c for c in REQUIRED_COMPONENTS if c not in covered]
        if missing:
            raise SignatureVerificationError(f"signature does not cover {', '.join(missing)}")
        created = params.params.get("created")
        if not isinstance(created, int) or isinstance(created, bool):
            raise SignatureVerificationError("signature has no integer 'created' parameter")
        now = self.clock()
        if created > now + self.clock_skew:
            raise SignatureVerificationError("signature created in the future")
        if created < now - self.max_age:
            raise SignatureVerificationError("signature is too old")
        expires = params.params.get("expires")
        if isinstance(expires, int) and not isinstance(expires, bool) and expires < now:
            raise SignatureVerificationError("signature has expired")

        keyid = str(params.params["keyid"])
        if "#" not in keyid or not keyid.split("#", 1)[1]:
            raise SignatureVerificationError("keyid must be a URL with a fragment")
        storage_id = keyid.split("#", 1)[0]
        if self.trusted_storages is not None and _normal_url(storage_id) not in self.trusted_storages:
            raise SignatureVerificationError(f"storage {storage_id} is not trusted")

        base = signature_base(method, url, hdrs, params)
        refresh = False
        while True:
            description, from_cache = yield from self._description_flow(storage_id, refresh)
            try:
                self._verify_with(description, keyid, params, base, signature)
                break
            except SignatureVerificationError:
                if from_cache and not refresh:
                    refresh = True  # the key may have rotated: fetch once more
                    continue
                raise

        try:
            notification = parse_notification(body)
        except LwsError as exc:
            raise SignatureVerificationError(f"invalid notification body: {exc}") from exc
        if notification.storage != storage_id:
            raise SignatureVerificationError(
                f"notification storage {notification.storage!r} does not match keyid storage "
                f"{storage_id!r}"
            )
        return VerifiedNotification(notification, keyid, storage_id, label)

    @staticmethod
    def _verify_with(
        description: StorageDescription,
        keyid: str,
        params: InnerList,
        base: str,
        signature: bytes,
    ) -> None:
        vm = None
        for candidate in description.verification_methods:
            if id_matches(candidate.id, keyid, description.id):
                vm = candidate
                break
        if vm is None or vm.public_key_jwk is None:
            raise SignatureVerificationError(f"verification method {keyid} not found")
        if not description.is_authentication_method(vm.id):
            raise SignatureVerificationError(
                f"verification method {keyid} is not referenced from 'authentication'"
            )
        try:
            key = VerifyingKey.from_jwk(vm.public_key_jwk)
        except (ValueError, KeyError) as exc:
            raise SignatureVerificationError(f"unusable key {keyid}: {exc}") from exc
        alg = params.params.get("alg")
        if alg is not None and alg != _ALG_FOR_KEY.get(key.alg):
            raise SignatureVerificationError(f"alg {alg!r} does not match the {key.alg} key")
        if not key.verify(signature, base.encode("utf-8")):
            raise SignatureVerificationError("signature does not verify")


class WebhookVerifier:
    """Verify signed webhook deliveries synchronously.

    :param client: an :class:`~lws_client.LwsClient` used to fetch storage descriptions
        (an anonymous client is created if neither ``client`` nor ``fetch`` is given).
    :param fetch: alternative ``storage_id -> StorageDescription | dict`` callable.
    :param trusted_storages: optional allow-list of storage identifiers.
    :param max_age: maximum age of ``created`` in seconds (default 300).
    :param clock_skew: tolerated future skew of ``created`` in seconds (default 300).
    :param clock: returns the current unix time (seconds).
    :param key_cache_ttl: how long storage descriptions are cached (default 600 s).
    """

    def __init__(
        self,
        *,
        client: LwsClient | None = None,
        fetch: Callable[[str], DescriptionLike] | None = None,
        trusted_storages: Iterable[str] | None = None,
        max_age: float = 300.0,
        clock_skew: float = 300.0,
        clock: Callable[[], float] = time.time,
        key_cache_ttl: float = 600.0,
    ) -> None:
        self._owned_client: LwsClient | None = None
        if fetch is None:
            if client is None:
                from .client import LwsClient

                client = self._owned_client = LwsClient()
            fetch = client.get_storage_description
        self._core = _VerifierCore(
            fetch=fetch,
            trusted_storages=trusted_storages,
            max_age=max_age,
            clock_skew=clock_skew,
            clock=clock,
            key_cache_ttl=key_cache_ttl,
        )

    def verify(
        self, method: str, url: str, headers: HeadersLike, body: bytes | str
    ) -> VerifiedNotification:
        """Verify a delivery. ``url`` is the **registered inbox URL** (not necessarily the
        URL seen behind a proxy). Raises :class:`SignatureVerificationError`."""
        raw = body.encode("utf-8") if isinstance(body, str) else body
        return _run_sync(self._core.verify_flow(method, url, headers, raw))

    def clear_cache(self) -> None:
        self._core.clear_cache()

    def close(self) -> None:
        if self._owned_client is not None:
            self._owned_client.close()


class AsyncWebhookVerifier:
    """Asynchronous counterpart of :class:`WebhookVerifier` (``fetch`` may be async)."""

    def __init__(
        self,
        *,
        client: AsyncLwsClient | None = None,
        fetch: Callable[[str], DescriptionLike | Awaitable[DescriptionLike]] | None = None,
        trusted_storages: Iterable[str] | None = None,
        max_age: float = 300.0,
        clock_skew: float = 300.0,
        clock: Callable[[], float] = time.time,
        key_cache_ttl: float = 600.0,
    ) -> None:
        self._owned_client: AsyncLwsClient | None = None
        if fetch is None:
            if client is None:
                from .client import AsyncLwsClient

                client = self._owned_client = AsyncLwsClient()
            fetch = client.get_storage_description
        self._core = _VerifierCore(
            fetch=fetch,
            trusted_storages=trusted_storages,
            max_age=max_age,
            clock_skew=clock_skew,
            clock=clock,
            key_cache_ttl=key_cache_ttl,
        )

    async def verify(
        self, method: str, url: str, headers: HeadersLike, body: bytes | str
    ) -> VerifiedNotification:
        raw = body.encode("utf-8") if isinstance(body, str) else body
        return await _run_async(self._core.verify_flow(method, url, headers, raw))

    async def verify_asgi(
        self,
        scope: Mapping[str, Any],
        receive: Callable[[], Awaitable[Mapping[str, Any]]],
        inbox_url: str,
    ) -> VerifiedNotification:
        """Read and verify a delivery from an ASGI ``scope``/``receive`` pair."""
        method, headers, body = await read_asgi_request(scope, receive)
        return await self.verify(method, inbox_url, headers, body)

    def clear_cache(self) -> None:
        self._core.clear_cache()

    async def aclose(self) -> None:
        if self._owned_client is not None:
            await self._owned_client.aclose()


def _run_sync(flow: Flow[VerifiedNotification]) -> VerifiedNotification:
    value: Any = None
    error: BaseException | None = None
    while True:
        try:
            effect = flow.throw(error) if error is not None else flow.send(value)
        except StopIteration as stop:
            result: VerifiedNotification = stop.value
            return result
        value, error = None, None
        try:
            assert isinstance(effect, Invoke)
            value = effect.fn(*effect.args)
            if hasattr(value, "__await__"):
                raise TypeError("asynchronous fetch used with WebhookVerifier")
        except Exception as exc:
            error = exc


async def _run_async(flow: Flow[VerifiedNotification]) -> VerifiedNotification:
    value: Any = None
    error: BaseException | None = None
    while True:
        try:
            effect = flow.throw(error) if error is not None else flow.send(value)
        except StopIteration as stop:
            result: VerifiedNotification = stop.value
            return result
        value, error = None, None
        try:
            assert isinstance(effect, Invoke)
            value = effect.fn(*effect.args)
            if hasattr(value, "__await__"):
                value = await value
        except Exception as exc:
            error = exc
