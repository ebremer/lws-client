# SPDX-License-Identifier: MIT
"""Sans-I/O core: request building, the authenticated/redirect-following execution flow,
and every LWS operation written once as a generator flow (see :mod:`lws_client._flow`)."""

from __future__ import annotations

import json
from collections.abc import Iterable, Mapping, Sequence
from datetime import datetime
from email.utils import format_datetime as http_date
from typing import Any, Union

import httpx

from ._flow import Flow, Send
from ._util import json_dumps, resolve, split_header_list
from .access import AccessGrant, AccessRequest
from .auth import Authenticator
from .constants import (
    PREFER_SET_LINKSET,
    SUBSCRIPTION_WEBHOOK,
    USER_AGENT,
    MediaType,
    Rel,
    Types,
)
from .errors import ProtocolError, UnsupportedError, error_for_response
from .headers import Link, encode_slug
from .json_patch import JsonPatch
from .linkset import Linkset, LinksetDocument
from .models import (
    ContainerPage,
    CreateResult,
    Resource,
    ResourceMetadata,
    SearchPage,
    Service,
    StorageDescription,
    TypeIndexPage,
    UpdateResult,
    parse_json_body,
)
from .notifications import Subscription, WebhookSubscriptionRequest
from .type_index import TypeQuery

Body = Union[bytes, bytearray, memoryview, str, Iterable[bytes], Any]
HeaderInput = Union[Mapping[str, str], Sequence[tuple[str, str]], None]
ServiceRef = Union[str, Service]

_REDIRECTS = {301, 302, 303, 307, 308}
_SAFE = {"GET", "HEAD", "OPTIONS", "QUERY"}
_STORAGE_ACCEPT = f"{MediaType.LWS_CID}, {MediaType.LD_JSON};q=0.9, {MediaType.JSON};q=0.8"
_MAX_REDIRECTS = 10


def endpoint(service: ServiceRef) -> str:
    return service.service_endpoint if isinstance(service, Service) else service


def _replayable(body: Any) -> bool:
    return body is None or isinstance(body, (bytes, bytearray, memoryview, str))


def _content(body: Any) -> Any:
    if isinstance(body, str):
        return body.encode("utf-8")
    if isinstance(body, (bytearray, memoryview)):
        return bytes(body)
    return body


class Core:
    """Configuration plus the flows of all operations."""

    def __init__(
        self,
        authenticator: Authenticator | None,
        user_agent: str | None,
        default_headers: HeaderInput,
    ) -> None:
        self.authenticator = authenticator
        self.user_agent = user_agent or USER_AGENT
        self.default_headers = httpx.Headers(default_headers or {})

    # -- requests ------------------------------------------------------------------------

    def request(
        self,
        method: str,
        url: str,
        *,
        headers: HeaderInput = None,
        content: Any = None,
        accept: str | None = None,
        content_type: str | None = None,
    ) -> httpx.Request:
        hdrs = httpx.Headers({"User-Agent": self.user_agent})
        hdrs.update(self.default_headers)
        if accept:
            hdrs["Accept"] = accept
        if content_type:
            hdrs["Content-Type"] = content_type
        if headers:
            hdrs.update(httpx.Headers(headers))
        return httpx.Request(method, url, headers=hdrs, content=_content(content))

    def execute(
        self, request: httpx.Request, *, stream: bool = False, replayable: bool = True
    ) -> Flow[httpx.Response]:
        """Send ``request`` with authentication (one retry after a ``401``) and redirect
        handling for safe methods (tokens are re-evaluated per hop)."""
        auth = self.authenticator
        if auth is not None and not replayable and not auth.has_credentials_for(str(request.url)):
            # Establish credentials before streaming a body that cannot be re-sent.
            yield from self.execute(self.request("HEAD", str(request.url)))
        redirects = 0
        retried = False
        while True:
            if auth is not None:
                yield from auth.authorize_flow(request)
            response: httpx.Response = yield Send(request, stream)
            status = response.status_code
            if status == 401 and auth is not None and not retried and replayable:
                retried = True
                if (yield from auth.challenge_flow(request, response)):
                    request = self._clone(request, request.method, str(request.url))
                    continue
                return response
            location = response.headers.get("location")
            if (
                status in _REDIRECTS
                and location
                and request.method in _SAFE
                and redirects < _MAX_REDIRECTS
            ):
                redirects += 1
                retried = False
                target = resolve(str(request.url), location)
                method = "GET" if status == 303 and request.method != "HEAD" else request.method
                request = self._clone(request, method, target)
                continue
            return response

    @staticmethod
    def _clone(request: httpx.Request, method: str, url: str) -> httpx.Request:
        headers = httpx.Headers(request.headers)
        for name in ("authorization", "host", "content-length", "transfer-encoding"):
            if name in headers:
                del headers[name]
        content = request.content if method == request.method else None
        return httpx.Request(method, url, headers=headers, content=content)

    def call(
        self, request: httpx.Request, *, ok: Iterable[int] = (), replayable: bool = True
    ) -> Flow[httpx.Response]:
        """Execute and raise the mapped :class:`HttpError` for unsuccessful statuses."""
        response = yield from self.execute(request, replayable=replayable)
        if not (response.is_success or response.status_code in ok):
            raise error_for_response(response, request.method)
        return response

    # -- discovery -----------------------------------------------------------------------

    def get_storage_description(
        self, storage_url: str, headers: HeaderInput = None
    ) -> Flow[StorageDescription]:
        req = self.request("GET", storage_url, headers=headers, accept=_STORAGE_ACCEPT)
        response = yield from self.call(req)
        data = parse_json_body(response.content, "storage description")
        return StorageDescription.from_json(data, str(response.url))

    def discover_storage(
        self, resource_url: str, headers: HeaderInput = None
    ) -> Flow[StorageDescription]:
        response = yield from self.execute(self.request("HEAD", resource_url, headers=headers))
        if response.status_code in (405, 501):
            response = yield from self.execute(self.request("GET", resource_url, headers=headers))
        metadata = ResourceMetadata.from_response(response)
        storage = metadata.storage
        if storage is None:
            if not response.is_success:
                raise error_for_response(response)
            raise ProtocolError(f"{resource_url} advertises no storage (Link rel=lws#storage)")
        return (yield from self.get_storage_description(storage, headers))

    # -- reading -------------------------------------------------------------------------

    def head(self, url: str, headers: HeaderInput = None) -> Flow[ResourceMetadata]:
        response = yield from self.call(self.request("HEAD", url, headers=headers))
        return ResourceMetadata.from_response(response)

    def read_request(
        self,
        url: str,
        *,
        accept: str | None = None,
        range: str | tuple[int, int | None] | None = None,
        if_none_match: str | None = None,
        if_modified_since: datetime | str | None = None,
        prefer: str | None = None,
        headers: HeaderInput = None,
    ) -> httpx.Request:
        hdrs: dict[str, str] = {}
        if range is not None:
            if isinstance(range, tuple):
                start, end = range
                hdrs["Range"] = f"bytes={start}-{'' if end is None else end}"
            else:
                hdrs["Range"] = range if range.startswith("bytes=") else f"bytes={range}"
        if if_none_match:
            hdrs["If-None-Match"] = if_none_match
        if if_modified_since is not None:
            hdrs["If-Modified-Since"] = (
                if_modified_since
                if isinstance(if_modified_since, str)
                else http_date(if_modified_since, usegmt=True)
            )
        if prefer:
            hdrs["Prefer"] = prefer
        req = self.request("GET", url, headers=hdrs, accept=accept)
        if headers:
            req.headers.update(httpx.Headers(headers))
        return req

    def read(self, request: httpx.Request) -> Flow[Resource]:
        response = yield from self.call(request, ok=(304,))
        return self.to_resource(response, response.content)

    @staticmethod
    def to_resource(response: httpx.Response, content: bytes) -> Resource:
        meta = ResourceMetadata.from_response(response)
        return Resource(
            url=meta.url,
            status=meta.status,
            headers=meta.headers,
            links=meta.links,
            etag=meta.etag,
            last_modified=meta.last_modified,
            content_type=meta.content_type,
            content_length=meta.content_length,
            content=content if response.status_code != 304 else b"",
            not_modified=response.status_code == 304,
        )

    def read_container(self, url: str, headers: HeaderInput = None) -> Flow[ContainerPage]:
        req = self.request("GET", url, headers=headers, accept=MediaType.LWS_JSON)
        response = yield from self.call(req)
        return ContainerPage.parse(ResourceMetadata.from_response(response), response.content)

    # -- creating ------------------------------------------------------------------------

    @staticmethod
    def _link_headers(links: Iterable[Link], types: Iterable[str] = ()) -> list[tuple[str, str]]:
        out = [("Link", link.serialize()) for link in links]
        out.extend(("Link", Link(t, Rel.TYPE).serialize()) for t in types)
        return out

    def create(
        self,
        container_url: str,
        body: Body,
        content_type: str | None,
        *,
        slug: str | None = None,
        links: Iterable[Link] = (),
        types: Iterable[str] = (),
        headers: HeaderInput = None,
    ) -> Flow[CreateResult]:
        extra = self._link_headers(links, types)
        if slug:
            extra.append(("Slug", encode_slug(slug)))
        req = self.request(
            "POST", container_url, headers=extra, content=body, content_type=content_type
        )
        if headers:
            req.headers.update(httpx.Headers(headers))
        response = yield from self.call(req, replayable=_replayable(body))
        return self._create_result(response)

    def create_container(
        self,
        parent_url: str,
        *,
        slug: str | None = None,
        links: Iterable[Link] = (),
        headers: HeaderInput = None,
    ) -> Flow[CreateResult]:
        extra = self._link_headers([Link(Types.CONTAINER, Rel.TYPE), *links])
        if slug:
            extra.append(("Slug", encode_slug(slug)))
        req = self.request("POST", parent_url, headers=extra, content=b"")
        if headers:
            req.headers.update(httpx.Headers(headers))
        response = yield from self.call(req)
        return self._create_result(response)

    @staticmethod
    def _create_result(response: httpx.Response) -> CreateResult:
        location = response.headers.get("location")
        if not location:
            raise ProtocolError(f"{response.status_code} response to POST has no Location header")
        return CreateResult(
            location=resolve(str(response.url), location),
            metadata=ResourceMetadata.from_response(response),
            content=response.content,
        )

    # -- updating ------------------------------------------------------------------------

    def _conditional(
        self,
        if_match: str | None,
        if_none_match: str | None,
        links: Iterable[Link],
        set_linkset: bool,
    ) -> list[tuple[str, str]]:
        hdrs: list[tuple[str, str]] = []
        if if_match:
            hdrs.append(("If-Match", if_match))
        if if_none_match:
            hdrs.append(("If-None-Match", if_none_match))
        hdrs.extend(self._link_headers(links))
        if set_linkset:
            hdrs.append(("Prefer", PREFER_SET_LINKSET))
        return hdrs

    def update(
        self,
        url: str,
        body: Body,
        content_type: str | None,
        *,
        if_match: str | None = None,
        if_none_match: str | None = None,
        links: Iterable[Link] = (),
        set_linkset: bool = False,
        headers: HeaderInput = None,
    ) -> Flow[UpdateResult]:
        extra = self._conditional(if_match, if_none_match, links, set_linkset)
        req = self.request("PUT", url, headers=extra, content=body, content_type=content_type)
        if headers:
            req.headers.update(httpx.Headers(headers))
        response = yield from self.call(req, replayable=_replayable(body))
        return UpdateResult(response.status_code, ResourceMetadata.from_response(response),
                            response.content)

    def patch(
        self,
        url: str,
        patch: JsonPatch | Sequence[Mapping[str, Any]] | bytes | str,
        *,
        content_type: str | None = None,
        if_match: str | None = None,
        links: Iterable[Link] = (),
        set_linkset: bool = False,
        headers: HeaderInput = None,
    ) -> Flow[UpdateResult]:
        body: bytes
        if isinstance(patch, JsonPatch):
            body, content_type = patch.to_bytes(), content_type or MediaType.JSON_PATCH
        elif isinstance(patch, (bytes, str)):
            if content_type is None:
                raise ValueError("content_type is required for a raw patch document")
            body = patch.encode("utf-8") if isinstance(patch, str) else patch
        else:
            body, content_type = json_dumps(list(patch)), content_type or MediaType.JSON_PATCH
        extra = self._conditional(if_match, None, links, set_linkset)
        req = self.request("PATCH", url, headers=extra, content=body, content_type=content_type)
        if headers:
            req.headers.update(httpx.Headers(headers))
        response = yield from self.call(req)
        return UpdateResult(response.status_code, ResourceMetadata.from_response(response),
                            response.content)

    def delete(
        self,
        url: str,
        *,
        if_match: str | None = None,
        recursive: bool = False,
        headers: HeaderInput = None,
    ) -> Flow[None]:
        hdrs: dict[str, str] = {}
        if if_match:
            hdrs["If-Match"] = if_match
        if recursive:
            hdrs["Depth"] = "infinity"
        req = self.request("DELETE", url, headers=hdrs)
        if headers:
            req.headers.update(httpx.Headers(headers))
        yield from self.call(req)

    # -- linksets ------------------------------------------------------------------------

    def linkset_url(self, resource_url: str) -> Flow[str]:
        metadata = yield from self.head(resource_url)
        if metadata.linkset is None:
            raise ProtocolError(f"{resource_url} advertises no linkset (Link rel=linkset)")
        return metadata.linkset

    def read_linkset(self, resource_url: str) -> Flow[LinksetDocument]:
        url = yield from self.linkset_url(resource_url)
        return (yield from self.read_linkset_at(url))

    def read_linkset_at(self, linkset_url: str) -> Flow[LinksetDocument]:
        req = self.request("GET", linkset_url, accept=MediaType.LINKSET_JSON)
        response = yield from self.call(req)
        data = parse_json_body(response.content, "linkset")
        if not isinstance(data, dict):
            raise ProtocolError("linkset document must be a JSON object")
        return LinksetDocument(
            url=str(response.url),
            linkset=Linkset.from_json(data),
            metadata=ResourceMetadata.from_response(response),
        )

    def update_linkset(
        self, linkset_url: str, linkset: Linkset | Mapping[str, Any], *, if_match: str | None
    ) -> Flow[UpdateResult]:
        doc = linkset.to_json() if isinstance(linkset, Linkset) else dict(linkset)
        return (
            yield from self.update(
                linkset_url, json_dumps(doc), MediaType.LINKSET_JSON, if_match=if_match
            )
        )

    def patch_linkset(
        self,
        linkset_url: str,
        patch: JsonPatch | Sequence[Mapping[str, Any]],
        *,
        if_match: str | None,
    ) -> Flow[UpdateResult]:
        return (yield from self.patch(linkset_url, patch, if_match=if_match))

    # -- JSON documents (notifications, access) ------------------------------------------

    def post_json(self, url: str, document: Mapping[str, Any]) -> Flow[httpx.Response]:
        req = self.request(
            "POST",
            url,
            content=json_dumps(document),
            content_type=MediaType.LWS_JSON,
            accept=f"{MediaType.LWS_JSON}, {MediaType.JSON};q=0.9",
        )
        return (yield from self.call(req))

    def get_json(self, url: str) -> Flow[tuple[Any, httpx.Response]]:
        req = self.request("GET", url, accept=f"{MediaType.LWS_JSON}, {MediaType.LD_JSON};q=0.9, "
                                               f"{MediaType.JSON};q=0.8")
        response = yield from self.call(req)
        return parse_json_body(response.content, f"response from {url}"), response

    def created_location(self, response: httpx.Response) -> str:
        location = response.headers.get("location")
        if not location:
            raise ProtocolError(f"{response.status_code} response to POST has no Location header")
        return resolve(str(response.url), location)

    # -- notifications -------------------------------------------------------------------

    def subscribe(
        self, service: ServiceRef, request: WebhookSubscriptionRequest
    ) -> Flow[Subscription]:
        if isinstance(service, Service) and service.subscription_types and (
            SUBSCRIPTION_WEBHOOK not in service.subscription_types
        ):
            raise UnsupportedError(
                f"notification service {service.service_endpoint} does not offer "
                f"{SUBSCRIPTION_WEBHOOK} (offers {', '.join(service.subscription_types)})"
            )
        response = yield from self.post_json(endpoint(service), request.to_json())
        location = response.headers.get("location")
        data: Any = {}
        if response.content:
            data = parse_json_body(response.content, "subscription response")
        return Subscription.from_json(
            data if isinstance(data, dict) else {},
            str(response.url),
            resolve(str(response.url), location) if location else None,
        )

    def get_subscription(self, url: str) -> Flow[Subscription]:
        data, response = yield from self.get_json(url)
        return Subscription.from_json(data, str(response.url), str(response.url))

    # -- access requests / grants --------------------------------------------------------

    def post_access(self, service: ServiceRef, document: AccessRequest | AccessGrant) -> Flow[str]:
        response = yield from self.post_json(endpoint(service), document.to_json())
        return self.created_location(response)

    def get_access_request(self, url: str) -> Flow[AccessRequest]:
        data, _ = yield from self.get_json(url)
        return AccessRequest.from_json(data)

    def get_access_grant(self, url: str) -> Flow[AccessGrant]:
        data, _ = yield from self.get_json(url)
        return AccessGrant.from_json(data)

    # -- type index / search -------------------------------------------------------------

    def read_type_index(self, url: str) -> Flow[TypeIndexPage]:
        req = self.request("GET", url, accept=MediaType.LWS_JSON)
        response = yield from self.call(req)
        return TypeIndexPage.parse(ResourceMetadata.from_response(response), response.content)

    def search_types(self, service: ServiceRef, query: TypeQuery | Mapping[str, Any]) -> Flow[SearchPage]:
        body = query.to_json() if isinstance(query, TypeQuery) else dict(query)
        req = self.request(
            "QUERY",
            endpoint(service),
            content=json.dumps(body).encode("utf-8"),
            content_type=MediaType.LWS_QUERY_JSON,
            accept=MediaType.LWS_JSON,
        )
        response = yield from self.call(req)
        return SearchPage.parse(ResourceMetadata.from_response(response), response.content)

    def search_page(self, url: str) -> Flow[SearchPage]:
        req = self.request("GET", url, accept=MediaType.LWS_JSON)
        response = yield from self.call(req)
        return SearchPage.parse(ResourceMetadata.from_response(response), response.content)

    def accepted_query_formats(self, service: ServiceRef) -> Flow[list[str]]:
        response = yield from self.call(self.request("OPTIONS", endpoint(service)))
        return [v.strip().strip('"') for v in split_header_list(response.headers.get_list("accept-query"))]

    # -- misc ----------------------------------------------------------------------------

    def authenticate(self, url: str) -> Flow[None]:
        response = yield from self.execute(self.request("HEAD", url))
        if response.status_code == 401:
            raise error_for_response(response)
