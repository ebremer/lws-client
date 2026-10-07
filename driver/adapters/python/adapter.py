# SPDX-License-Identifier: MIT
"""The Python adapter of the lws-client driver.

Runs the operations of driver/PROTOCOL.md with the synchronous ``LwsClient`` of the ``lws_client``
package (../../../python), speaking the line-delimited JSON protocol ``lws-driver/1`` on stdin and
stdout. Install the package first (``pip install -e "python[crypto]"``), then run this module with
that interpreter.
"""

from __future__ import annotations

import base64
import binascii
import json
import logging
import re
import sys
import traceback
from collections.abc import Callable, Iterable
from typing import Any, BinaryIO, TypeVar

import httpx
import lws_client
from lws_client import (
    AccessGrant,
    AccessRequest,
    AuthenticationError,
    Authenticator,
    BadRequestError,
    BearerTokenAuthenticator,
    ConflictError,
    ContainedResource,
    ContainerPage,
    CreateResult,
    ForbiddenError,
    GoneError,
    HttpError,
    InsufficientStorageError,
    JsonPatch,
    Link,
    Linkset,
    LwsClient,
    MethodNotAllowedError,
    NotAcceptableError,
    NotFoundError,
    NotImplementedByServerError,
    OpenIdCredentials,
    PreconditionFailedError,
    ProblemDetails,
    ProtocolError,
    Resource,
    ResourceMetadata,
    SearchPage,
    SelfSignedCredentials,
    Service,
    SignatureVerificationError,
    SigningKey,
    StorageDescription,
    Subscription,
    TokenExchangeAuthenticator,
    TransportError,
    TypeQuery,
    UnauthorizedError,
    UnprocessableContentError,
    UnsupportedError,
    UnsupportedMediaTypeError,
    UpdateResult,
    WebhookVerifier,
    generate_key,
)

PROTOCOL = "lws-driver/1"
LIBRARY = f"lws-client-python/{lws_client.__version__}"

Json = dict[str, Any]
Operation = Callable[[Json], Json]
T = TypeVar("T")


class AdapterError(Exception):
    """An error the adapter reports itself: ``InvalidArguments`` or ``Unsupported``."""

    def __init__(self, kind: str, message: str) -> None:
        super().__init__(message)
        self.kind = kind


def invalid(message: str) -> AdapterError:
    return AdapterError("InvalidArguments", message)


# ---------------------------------------------------------------------------------------------
# Arguments


_SCHEME = re.compile(r"[A-Za-z][A-Za-z0-9+.-]*:")


def req_str(args: Json, name: str) -> str:
    value = opt_str(args, name)
    if value is None:
        raise invalid(f"missing argument '{name}'")
    return value


def req_url(args: Json, name: str) -> str:
    """A request target (``url``, ``container``, ``parent``, ``linksetUrl``, ``serviceUrl``): an
    absolute URL. A relative one is malformed (PROTOCOL.md section 3), not the library's to resolve."""
    value = req_str(args, name)
    if not _SCHEME.match(value):
        raise invalid(f"argument '{name}' must be an absolute URL, not {value!r}")
    return value


def opt_str(args: Json, name: str) -> str | None:
    value = args.get(name)
    if value is not None and not isinstance(value, str):
        raise invalid(f"argument '{name}' must be a string")
    return value


def opt_bool(args: Json, name: str) -> bool | None:
    value = args.get(name)
    if value is not None and not isinstance(value, bool):
        raise invalid(f"argument '{name}' must be a boolean")
    return value


def opt_int(args: Json, name: str, minimum: int = 0) -> int | None:
    """An integer of at least ``minimum`` (PROTOCOL.md section 3, Numbers). A JSON number with no
    fraction (``2.0``) counts as an integer, as it does for the drivers that cannot tell them apart."""
    value = args.get(name)
    if value is None:
        return None
    if isinstance(value, float) and value.is_integer():
        value = int(value)
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        what = "a non-negative integer" if minimum == 0 else f"an integer of at least {minimum}"
        raise invalid(f"argument '{name}' must be {what}")
    return value


def req_dict(args: Json, name: str) -> Json:
    value = opt_dict(args, name)
    if value is None:
        raise invalid(f"missing argument '{name}'")
    return value


def opt_dict(args: Json, name: str) -> Json | None:
    value = args.get(name)
    if value is not None and not isinstance(value, dict):
        raise invalid(f"argument '{name}' must be an object")
    return value


def opt_list(args: Json, name: str) -> list[Any] | None:
    value = args.get(name)
    if value is not None and not isinstance(value, list):
        raise invalid(f"argument '{name}' must be an array")
    return value


def opt_str_list(args: Json, name: str) -> list[str] | None:
    value = opt_list(args, name)
    if value is not None and not all(isinstance(v, str) for v in value):
        raise invalid(f"argument '{name}' must be an array of strings")
    return value


def req_str_list(args: Json, name: str) -> list[str]:
    value = opt_str_list(args, name)
    if value is None:
        raise invalid(f"missing argument '{name}'")
    return value


def limit_of(args: Json) -> int:
    limit = opt_int(args, "limit")
    return 1000 if limit is None else limit


def body_of(body: Any, content_type: str | None) -> tuple[bytes, str]:
    """A ``body`` argument as bytes, with the content type it implies."""
    if body is None:
        return b"", content_type if content_type is not None else "application/octet-stream"
    if not isinstance(body, dict):
        raise invalid("argument 'body' must be an object")
    try:
        if isinstance(body.get("text"), str):
            return body["text"].encode("utf-8"), content_type if content_type is not None else "text/plain"
        if isinstance(body.get("base64"), str):
            data = base64.b64decode(body["base64"], validate=True)
            return data, content_type if content_type is not None else "application/octet-stream"
    except (binascii.Error, UnicodeEncodeError) as exc:
        raise invalid(f"argument 'body': {exc}") from exc
    if "json" in body:
        try:
            text = json.dumps(body["json"], ensure_ascii=False, separators=(",", ":"), allow_nan=False)
            data = text.encode("utf-8")
        except (TypeError, ValueError) as exc:
            raise invalid(f"argument 'body': {exc}") from exc
        return data, content_type if content_type is not None else "application/json"
    raise invalid("argument 'body' must have text, base64 or json")


def _pointer(op: Json, name: str) -> str:
    value = op.get(name)
    if not isinstance(value, str):
        raise invalid(f"a '{op['op']}' patch operation needs a string '{name}'")
    return value


def _value(op: Json) -> Any:
    if "value" not in op:
        raise invalid(f"a '{op['op']}' patch operation needs a 'value'")
    return op["value"]


def patch_of(operations: Any) -> JsonPatch:
    """Rebuilds an RFC 6902 operations array with the library's ``JsonPatch`` builder."""
    if not isinstance(operations, list):
        raise invalid("argument 'patch' must be an array of operations")
    patch = JsonPatch()
    for op in operations:
        if not isinstance(op, dict) or not isinstance(op.get("op"), str):
            raise invalid("a patch operation must be an object with an op")
        name = op["op"]
        if name == "add":
            patch.add(_pointer(op, "path"), _value(op))
        elif name == "remove":
            patch.remove(_pointer(op, "path"))
        elif name == "replace":
            patch.replace(_pointer(op, "path"), _value(op))
        elif name == "move":
            patch.move(_pointer(op, "from"), _pointer(op, "path"))
        elif name == "copy":
            patch.copy(_pointer(op, "from"), _pointer(op, "path"))
        elif name == "test":
            patch.test(_pointer(op, "path"), _value(op))
        else:
            raise invalid(f"unknown patch operation '{name}'")
    return patch


def query_of(query: Json) -> TypeQuery:
    """Rebuilds an ``application/lws-query+json`` document with the library's ``TypeQuery``:
    a string group is ``all_of(iri)``, an array group ``any_of(*iris)``, on the key's relation."""
    q = TypeQuery()
    for key, groups in query.items():
        if not isinstance(groups, list):
            raise invalid(f"query member '{key}' must be a list of groups")
        for group in groups:
            try:
                if isinstance(group, str):
                    q.all_of(group, key=key)
                elif isinstance(group, list) and all(isinstance(iri, str) for iri in group):
                    q.any_of(*group, key=key)
                else:
                    raise invalid(f"a group of query member '{key}' must be an IRI or a list of IRIs")
            except ValueError as exc:
                raise invalid(f"query member '{key}': {exc}") from exc
    return q


def links_of(links: list[Any] | None) -> list[Link]:
    out: list[Link] = []
    for link in links or []:
        if not isinstance(link, dict) or not all(isinstance(link.get(m), str) for m in ("href", "rel")):
            raise invalid("argument 'links' must be an array of {href, rel} objects")
        out.append(Link(link["href"], link["rel"]))
    return out


def headers_of(args: Json) -> list[tuple[str, str]]:
    """The ``headers`` of a notification delivery: name → list of values (or a single value)."""
    headers = req_dict(args, "headers")
    pairs: list[tuple[str, str]] = []
    for name, values in headers.items():
        if isinstance(values, str):
            values = [values]
        if not isinstance(values, list) or not all(isinstance(v, str) for v in values):
            raise invalid(f"header '{name}' must be a list of strings")
        pairs.extend((name, v) for v in values)
    return pairs


# ---------------------------------------------------------------------------------------------
# Results


def members(**values: Any) -> Json:
    """An object of the given members, leaving out the absent (``None``) ones."""
    return {name: value for name, value in values.items() if value is not None}


def _is_textual(content_type: str) -> bool:
    essence = content_type.split(";", 1)[0].strip().lower()
    return (
        essence.startswith("text/")
        or essence in ("application/json", "application/xml")
        or essence.endswith(("+json", "+xml"))
    )


def body_result(resource: Resource) -> Json:
    """A read's body: for a textual content type the text as the library decodes it (by the
    response's charset, UTF-8 by default), otherwise base64. A 304's body is empty."""
    if resource.content_type and _is_textual(resource.content_type):
        try:
            return {"text": resource.text}
        except LookupError:
            # A charset Python does not know, so one the library cannot honour: UTF-8 (section 3).
            return {"text": resource.content.decode("utf-8", "replace")}
    return {"base64": base64.b64encode(resource.content).decode("ascii")}


def metadata_result(m: ResourceMetadata) -> Json:
    return members(
        url=m.url,
        status=m.status,
        etag=m.etag,
        lastModified=m.headers.get("last-modified"),
        contentType=m.content_type,
        contentLength=m.content_length,
        links=[{"href": link.href, "rel": link.rel, "params": dict(link.params)} for link in m.links],
        linkset=m.linkset,
        parent=m.parent,
        storage=m.storage,
        types=list(m.types),
        allow=m.allow,
        acceptPatch=m.accept_patch,
    )


def item_result(i: ContainedResource) -> Json:
    return members(id=i.id, types=list(i.types), format=i.format, size=i.size, modified=i.modified_raw)


def page_result(p: ContainerPage | SearchPage) -> Json:
    return members(
        id=p.id if isinstance(p, ContainerPage) else None,
        types=list(p.types),
        totalItems=p.total_items,
        items=[item_result(i) for i in p.items],
        first=p.first,
        next=p.next,
        prev=p.prev,
        last=p.last,
        metadata=metadata_result(p.metadata),
    )


def update_result(u: UpdateResult) -> Json:
    return members(status=u.status, etag=u.etag, metadata=metadata_result(u.metadata))


def created_result(c: CreateResult) -> Json:
    return {"location": c.location, "metadata": metadata_result(c.metadata)}


def service_result(s: Service) -> Json:
    return members(
        id=s.id,
        types=list(s.types),
        serviceEndpoint=s.service_endpoint,
        subscriptionType=list(s.subscription_types) if "subscriptionType" in s.raw else None,
    )


def storage_result(s: StorageDescription) -> Json:
    try:
        storage_root: str | None = s.storage_root()
    except ProtocolError:
        storage_root = None
    return members(
        id=s.id,
        types=list(s.types),
        storageRoot=storage_root,
        services=[service_result(svc) for svc in s.services],
        verificationMethods=[
            members(id=vm.id, type=vm.type, controller=vm.controller) for vm in s.verification_methods
        ],
        raw=dict(s.raw),
    )


def subscription_result(s: Subscription) -> Json:
    return members(subscription=s.subscription, types=[s.type], expires=s.expires_raw, raw=dict(s.raw))


def take(iterable: Iterable[T], limit: int) -> tuple[list[T], bool]:
    """Pulls at most ``limit + 1`` items: the first ``limit``, and whether there was one more."""
    items: list[T] = []
    iterator = iter(iterable)
    try:
        for item in iterator:
            if len(items) == limit:
                return items, True
            items.append(item)
        return items, False
    finally:
        close = getattr(iterator, "close", None)
        if callable(close):
            close()


def listing(iterable: Iterable[ContainedResource], limit: int) -> Json:
    items, truncated = take(iterable, limit)
    return {"items": [item_result(i) for i in items], "truncated": truncated}


# ---------------------------------------------------------------------------------------------
# Errors

# The status-specific errors, by the name the API contract gives them (section 10). GoneError
# comes before NotFoundError, of which it is a subclass in this library.
_HTTP_KINDS: tuple[tuple[type[HttpError], str], ...] = (
    (BadRequestError, "BadRequestError"),
    (UnauthorizedError, "UnauthorizedError"),
    (ForbiddenError, "ForbiddenError"),
    (GoneError, "GoneError"),
    (NotFoundError, "NotFoundError"),
    (MethodNotAllowedError, "MethodNotAllowedError"),
    (NotAcceptableError, "NotAcceptableError"),
    (ConflictError, "ConflictError"),
    (PreconditionFailedError, "PreconditionFailedError"),
    (UnsupportedMediaTypeError, "UnsupportedMediaTypeError"),
    (UnprocessableContentError, "UnprocessableContentError"),
    (NotImplementedByServerError, "NotImplementedError"),
    (InsufficientStorageError, "InsufficientStorageError"),
)


def problem_result(p: ProblemDetails) -> Json:
    """The RFC 9457 problem details object: the standard members present, and the extensions."""
    standard = members(type=p.type, title=p.title, status=p.status, detail=p.detail, instance=p.instance)
    return {**dict(p.extensions), **standard}


def error_result(exc: BaseException) -> Json:
    if isinstance(exc, AdapterError):
        return {"kind": exc.kind, "message": str(exc)}
    if isinstance(exc, HttpError):
        kind = next((name for cls, name in _HTTP_KINDS if isinstance(exc, cls)), "HttpError")
        error: Json = {"kind": kind, "status": exc.status, "message": str(exc)}
        if exc.problem is not None:
            error["problem"] = problem_result(exc.problem)
        if isinstance(exc, MethodNotAllowedError):
            error["allow"] = exc.allow
        if isinstance(exc, UnsupportedMediaTypeError):
            error["acceptPatch"] = exc.accept_patch
        return error
    if isinstance(exc, AuthenticationError):
        return members(
            kind="AuthenticationError",
            status=exc.status,
            message=str(exc),
            oauthError=exc.error,
            oauthErrorDescription=exc.error_description,
        )
    if isinstance(exc, SignatureVerificationError):
        return {"kind": "SignatureVerificationError", "message": str(exc)}
    if isinstance(exc, (ProtocolError, UnsupportedError)):
        # UnsupportedError is this library's "the server does not offer that" (contract section 7:
        # "raise UnsupportedError/ProtocolError"); it is the server's shortcoming, not the library's.
        return {"kind": "ProtocolError", "message": str(exc)}
    if isinstance(exc, TransportError):
        return {"kind": "TransportError", "message": str(exc)}
    if isinstance(exc, httpx.InvalidURL):
        return {"kind": "InvalidArguments", "message": str(exc)}
    if isinstance(exc, httpx.HTTPError):
        # httpx errors the library does not wrap itself (it wraps httpx.TransportError).
        return {"kind": "TransportError", "message": f"{type(exc).__name__}: {exc}"}
    if isinstance(exc, ImportError):
        # The optional 'cryptography' package is missing: signing and verification are unavailable.
        return {"kind": "Unsupported", "message": str(exc)}
    message = "".join(traceback.format_exception(type(exc), exc, exc.__traceback__))
    print(message, file=sys.stderr)
    return {"kind": "InternalError", "message": message}


# ---------------------------------------------------------------------------------------------
# The operations


class Adapter:
    """The client every operation uses, and the operations of PROTOCOL.md section 4."""

    def __init__(self) -> None:
        self.client = LwsClient()
        self.operations: dict[str, Operation] = {
            "configure": self.configure,
            "discover_storage": self.discover_storage,
            "get_storage_description": self.get_storage_description,
            "head": self.head,
            "read": self.read,
            "read_container": self.read_container,
            "list_container": self.list_container,
            "create": self.create,
            "create_container": self.create_container,
            "update": self.update,
            "patch": self.patch,
            "delete": self.delete,
            "linkset_url": self.linkset_url,
            "read_linkset": self.read_linkset,
            "update_linkset": self.update_linkset,
            "patch_linkset": self.patch_linkset,
            "subscribe": self.subscribe,
            "list_subscriptions": self.list_subscriptions,
            "get_subscription": self.get_subscription,
            "unsubscribe": self.unsubscribe,
            "verify_notification": self.verify_notification,
            "request_access": self.request_access,
            "get_access_request": self.get_access_request,
            "list_access_requests": self.list_access_requests,
            "cancel_access_request": self.cancel_access_request,
            "grant_access": self.grant_access,
            "get_access_grant": self.get_access_grant,
            "list_access_grants": self.list_access_grants,
            "revoke_access_grant": self.revoke_access_grant,
            "read_type_index": self.read_type_index,
            "list_types": self.list_types,
            "search_types": self.search_types,
            "search_all": self.search_all,
            "accepted_query_formats": self.accepted_query_formats,
            "shutdown": self.shutdown,
        }

    def close(self) -> None:
        self.client.close()

    # -- configure -------------------------------------------------------------------------

    def configure(self, args: Json) -> Json:
        auth = args.get("auth")
        if auth is None:
            auth = {"type": "none"}
        if not isinstance(auth, dict):
            raise invalid("argument 'auth' must be an object")
        exchange_options: dict[str, Any] = {}
        allow_insecure_http = opt_bool(args, "allowInsecureHttp")
        if allow_insecure_http is not None:
            exchange_options["allow_insecure_http"] = allow_insecure_http
        result: Json = {"library": LIBRARY}
        authenticator: Authenticator | None = None
        auth_type = auth.get("type")
        if auth_type == "none":
            pass
        elif auth_type == "bearer":
            authenticator = BearerTokenAuthenticator(req_str(auth, "token"), realm=opt_str(auth, "realm"))
        elif auth_type == "openid":
            credentials = OpenIdCredentials(req_str(auth, "idToken"))
            authenticator = TokenExchangeAuthenticator(credentials, **exchange_options)
        elif auth_type == "selfSigned":
            agent = req_str(auth, "agent")
            jwk = req_dict(auth, "privateJwk")
            kid = opt_str(auth, "kid")
            if kid is None:
                kid = jwk.get("kid")
            if not isinstance(kid, str):
                raise invalid("selfSigned needs 'kid', or a 'kid' in the private JWK")
            key = self._import_key(jwk)
            signed = SelfSignedCredentials.for_agent(agent, key, kid)
            authenticator = TokenExchangeAuthenticator(signed, **exchange_options)
            result.update(agent=agent, kid=kid)
        elif auth_type == "didKey":
            algorithm = opt_str(auth, "algorithm")
            if algorithm is None:
                algorithm = "ES256"
            if algorithm not in ("ES256", "EdDSA"):
                raise invalid(f"unknown algorithm '{algorithm}'")
            try:
                did_key = SelfSignedCredentials.did_key(generate_key(algorithm))
            except ImportError as exc:
                raise AdapterError("Unsupported", str(exc)) from exc
            authenticator = TokenExchangeAuthenticator(did_key, **exchange_options)
            result.update(agent=did_key.agent, kid=did_key.kid)
        else:
            raise invalid(f"unknown auth type '{auth_type}'")

        options: Json = {"authenticator": authenticator}
        user_agent = opt_str(args, "userAgent")
        if user_agent is not None:
            options["user_agent"] = user_agent
        timeout = opt_int(args, "timeoutSeconds", minimum=1)
        if timeout is not None:
            options["timeout"] = float(timeout)
        headers = opt_dict(args, "headers")
        if headers is not None:
            if not all(isinstance(v, str) for v in headers.values()):
                raise invalid("argument 'headers' must map header names to strings")
            options["default_headers"] = headers
        previous, self.client = self.client, LwsClient(**options)
        previous.close()
        return result

    @staticmethod
    def _import_key(jwk: Json) -> SigningKey:
        try:
            return SigningKey.from_jwk(jwk)
        except ImportError as exc:
            raise AdapterError("Unsupported", str(exc)) from exc
        except (ValueError, KeyError, TypeError) as exc:
            raise invalid(f"argument 'privateJwk' is not a usable private key: {exc!r}") from exc

    # -- discovery and reading -------------------------------------------------------------

    def discover_storage(self, args: Json) -> Json:
        return storage_result(self.client.discover_storage(req_url(args, "url")))

    def get_storage_description(self, args: Json) -> Json:
        return storage_result(self.client.get_storage_description(req_url(args, "url")))

    def head(self, args: Json) -> Json:
        return metadata_result(self.client.head(req_url(args, "url")))

    def read(self, args: Json) -> Json:
        url = req_url(args, "url")
        start = opt_int(args, "rangeStart")
        end = opt_int(args, "rangeEnd")
        if start is None and end is not None:
            raise invalid("rangeEnd needs rangeStart")
        resource = self.client.read(
            url,
            accept=opt_str(args, "accept"),
            range=None if start is None else (start, end),
            if_none_match=opt_str(args, "ifNoneMatch"),
            prefer=opt_str(args, "prefer"),
        )
        return members(
            metadata=metadata_result(resource),
            notModified=resource.not_modified,
            contentRange=resource.content_range,
            body=body_result(resource),
        )

    def read_container(self, args: Json) -> Json:
        return page_result(self.client.read_container(req_url(args, "url")))

    def list_container(self, args: Json) -> Json:
        url = req_url(args, "url")
        return listing(self.client.list_container(url), limit_of(args))

    # -- creating, updating, deleting ------------------------------------------------------

    def create(self, args: Json) -> Json:
        container = req_url(args, "container")
        data, content_type = body_of(args.get("body"), opt_str(args, "contentType"))
        result = self.client.create(
            container,
            data,
            content_type,
            slug=opt_str(args, "slug"),
            links=links_of(opt_list(args, "links")),
            types=opt_str_list(args, "types") or (),
        )
        return created_result(result)

    def create_container(self, args: Json) -> Json:
        parent = req_url(args, "parent")
        return created_result(self.client.create_container(parent, slug=opt_str(args, "slug")))

    def update(self, args: Json) -> Json:
        url = req_url(args, "url")
        if args.get("body") is None:
            raise invalid("missing argument 'body'")
        data, content_type = body_of(args["body"], opt_str(args, "contentType"))
        result = self.client.update(
            url,
            data,
            content_type,
            if_match=opt_str(args, "ifMatch"),
            if_none_match=opt_str(args, "ifNoneMatch"),
        )
        return update_result(result)

    def patch(self, args: Json) -> Json:
        url = req_url(args, "url")
        patch = patch_of(args.get("patch"))
        return update_result(self.client.patch(url, patch, if_match=opt_str(args, "ifMatch")))

    def delete(self, args: Json) -> Json:
        url = req_url(args, "url")
        recursive = bool(opt_bool(args, "recursive"))
        self.client.delete(url, if_match=opt_str(args, "ifMatch"), recursive=recursive)
        return {}

    # -- linksets --------------------------------------------------------------------------

    def linkset_url(self, args: Json) -> Json:
        return {"linkset": self.client.linkset_url(req_url(args, "url"))}

    def read_linkset(self, args: Json) -> Json:
        doc = self.client.read_linkset(req_url(args, "url"))
        return members(
            url=doc.url,
            etag=doc.etag,
            linkset=doc.linkset.to_json(),
            allow=doc.allow,
            acceptPatch=doc.accept_patch,
        )

    def update_linkset(self, args: Json) -> Json:
        linkset_url = req_url(args, "linksetUrl")
        try:
            linkset = Linkset.from_json(req_dict(args, "linkset"))
        except (ProtocolError, ValueError, TypeError) as exc:
            raise invalid(f"argument 'linkset': {exc}") from exc
        return update_result(
            self.client.update_linkset(linkset_url, linkset, if_match=opt_str(args, "ifMatch"))
        )

    def patch_linkset(self, args: Json) -> Json:
        linkset_url = req_url(args, "linksetUrl")
        patch = patch_of(args.get("patch"))
        return update_result(
            self.client.patch_linkset(linkset_url, patch, if_match=opt_str(args, "ifMatch"))
        )

    # -- notifications ---------------------------------------------------------------------

    def subscribe(self, args: Json) -> Json:
        service_url = req_url(args, "serviceUrl")
        topics = req_str_list(args, "topics")
        inbox = req_str(args, "inbox")
        subscription = self.client.subscribe(service_url, topics, inbox, expires=opt_str(args, "expires"))
        return subscription_result(subscription)

    def list_subscriptions(self, args: Json) -> Json:
        service_url = req_url(args, "serviceUrl")
        return listing(self.client.list_subscriptions(service_url), limit_of(args))

    def get_subscription(self, args: Json) -> Json:
        return subscription_result(self.client.get_subscription(req_url(args, "url")))

    def unsubscribe(self, args: Json) -> Json:
        self.client.unsubscribe(req_url(args, "url"))
        return {}

    def verify_notification(self, args: Json) -> Json:
        method = req_str(args, "method")
        url = req_str(args, "url")
        headers = headers_of(args)
        try:
            body = base64.b64decode(req_str(args, "bodyBase64"), validate=True)
        except binascii.Error as exc:
            raise invalid(f"argument 'bodyBase64': {exc}") from exc
        trusted = opt_str_list(args, "trustedStorages")
        if trusted is not None and not trusted:
            # Section 4.2: the driver leaves trustedStorages out to accept any storage, so an empty
            # list is malformed (and the library would read it as "no allow-list").
            raise invalid("argument 'trustedStorages' must not be empty; leave it out to accept any storage")
        verifier = WebhookVerifier(client=self.client, trusted_storages=trusted)
        verified = verifier.verify(method, url, headers, body)
        return {
            "storage": verified.storage,
            "keyid": verified.keyid,
            "activities": [
                members(
                    id=a.id or None,
                    types=list(a.types),
                    object=a.object.id,
                    objectTypes=list(a.object.types),
                )
                for a in verified.notification.activities
            ],
            "raw": dict(verified.notification.raw),
        }

    # -- access requests and grants --------------------------------------------------------

    def request_access(self, args: Json) -> Json:
        service_url = req_url(args, "serviceUrl")
        try:
            request = AccessRequest.from_json(req_dict(args, "request"))
        except (ProtocolError, ValueError, TypeError) as exc:
            raise invalid(f"argument 'request': {exc}") from exc
        return {"location": self.client.request_access(service_url, request)}

    def get_access_request(self, args: Json) -> Json:
        return {"document": self.client.get_access_request(req_url(args, "url")).to_json()}

    def list_access_requests(self, args: Json) -> Json:
        service_url = req_url(args, "serviceUrl")
        return listing(self.client.list_access_requests(service_url), limit_of(args))

    def cancel_access_request(self, args: Json) -> Json:
        self.client.cancel_access_request(req_url(args, "url"))
        return {}

    def grant_access(self, args: Json) -> Json:
        service_url = req_url(args, "serviceUrl")
        try:
            grant = AccessGrant.from_json(req_dict(args, "grant"))
        except (ProtocolError, ValueError, TypeError) as exc:
            raise invalid(f"argument 'grant': {exc}") from exc
        return {"location": self.client.grant_access(service_url, grant)}

    def get_access_grant(self, args: Json) -> Json:
        return {"document": self.client.get_access_grant(req_url(args, "url")).to_json()}

    def list_access_grants(self, args: Json) -> Json:
        service_url = req_url(args, "serviceUrl")
        return listing(self.client.list_access_grants(service_url), limit_of(args))

    def revoke_access_grant(self, args: Json) -> Json:
        self.client.revoke_access_grant(req_url(args, "url"))
        return {}

    # -- type index and search -------------------------------------------------------------

    def read_type_index(self, args: Json) -> Json:
        page = self.client.read_type_index(req_url(args, "url"))
        return members(
            totalItems=page.total_items,
            types=list(page.types),
            first=page.first,
            next=page.next,
            prev=page.prev,
            last=page.last,
        )

    def list_types(self, args: Json) -> Json:
        service_url = req_url(args, "serviceUrl")
        types, truncated = take(self.client.list_types(service_url), limit_of(args))
        return {"types": types, "truncated": truncated}

    def search_types(self, args: Json) -> Json:
        service_url = req_url(args, "serviceUrl")
        query = query_of(req_dict(args, "query"))
        return page_result(self.client.search_types(service_url, query))

    def search_all(self, args: Json) -> Json:
        service_url = req_url(args, "serviceUrl")
        query = query_of(req_dict(args, "query"))
        return listing(self.client.search_all(service_url, query), limit_of(args))

    def accepted_query_formats(self, args: Json) -> Json:
        return {"formats": self.client.accepted_query_formats(req_url(args, "serviceUrl"))}

    def shutdown(self, args: Json) -> Json:
        return {}


# ---------------------------------------------------------------------------------------------
# The protocol loop


class Writer:
    """Writes protocol messages, one JSON object per line, to the real standard output."""

    def __init__(self, out: BinaryIO) -> None:
        self._out = out

    def write(self, message: Json) -> None:
        try:
            line = self._encode(message)
        except (TypeError, ValueError) as exc:
            # A result that cannot be serialized (a non-finite number, say) is a bug: report it.
            fallback = {"kind": "InternalError", "message": f"the result is not serializable: {exc}"}
            line = self._encode({"id": message.get("id"), "ok": False, "error": fallback})
        self._out.write(line)
        self._out.flush()

    @staticmethod
    def _encode(message: Json) -> bytes:
        text = json.dumps(message, ensure_ascii=False, allow_nan=False, separators=(",", ":"))
        try:
            return text.encode("utf-8") + b"\n"
        except UnicodeEncodeError:
            # Lone surrogates (from \ud800-style escapes in a server's JSON) cannot be UTF-8.
            ascii_text = json.dumps(message, ensure_ascii=True, allow_nan=False, separators=(",", ":"))
            return ascii_text.encode("ascii") + b"\n"


def serve(adapter: Adapter, requests: BinaryIO, writer: Writer) -> None:
    writer.write(
        {
            "hello": {
                "protocol": PROTOCOL,
                "language": "python",
                "library": LIBRARY,
                "operations": list(adapter.operations),
            }
        }
    )
    for raw in requests:
        line = raw.decode("utf-8", "replace").strip()
        if not line:
            continue
        try:
            request = json.loads(line)
        except ValueError:
            writer.write({"id": None, "ok": False, "error": error_result(invalid("the request is not JSON"))})
            continue
        if not isinstance(request, dict):
            error = error_result(invalid("the request is not a JSON object"))
            writer.write({"id": None, "ok": False, "error": error})
            continue
        request_id = request.get("id")
        op = request.get("op")
        args = request.get("args")
        if args is None:
            args = {}
        operation = adapter.operations.get(op) if isinstance(op, str) else None
        if operation is None:
            error = {"kind": "Unsupported", "message": f"unknown operation {op!r}"}
            writer.write({"id": request_id, "ok": False, "error": error})
            continue
        try:
            if not isinstance(args, dict):
                raise invalid("args must be an object")
            response: Json = {"id": request_id, "ok": True, "result": operation(args)}
        except Exception as exc:
            response = {"id": request_id, "ok": False, "error": error_result(exc)}
        writer.write(response)
        if op == "shutdown":
            break


def main() -> int:
    # stdout carries protocol messages only: keep the real one for the writer, and send print()
    # and logging to stderr, which the driver keeps as the adapter's log.
    writer = Writer(sys.stdout.buffer)
    sys.stdout = sys.stderr
    logging.basicConfig(stream=sys.stderr, level=logging.WARNING)
    adapter = Adapter()
    try:
        serve(adapter, sys.stdin.buffer, writer)
    finally:
        adapter.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
