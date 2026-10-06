# SPDX-License-Identifier: MIT
"""The public clients: :class:`LwsClient` (synchronous) and :class:`AsyncLwsClient`.

Both are thin drivers over the same sans-I/O core, so they behave identically; the async
client simply ``await``\\s each operation and returns async iterators for listings.
"""

from __future__ import annotations

from collections.abc import AsyncIterator, Iterable, Iterator, Mapping, Sequence
from contextlib import asynccontextmanager, contextmanager
from datetime import datetime
from types import TracebackType
from typing import Any

import httpx

from ._core import Body, Core, HeaderInput, ServiceRef, endpoint
from ._flow import AsyncDriver, SyncDriver
from ._util import json_dumps
from .access import AccessGrant, AccessRequest
from .auth import Authenticator
from .errors import error_for_response
from .headers import Link
from .json_patch import JsonPatch
from .linkset import Linkset, LinksetDocument
from .models import (
    ContainedResource,
    ContainerPage,
    CreateResult,
    Resource,
    ResourceMetadata,
    SearchPage,
    StorageDescription,
    TypeIndexPage,
    UpdateResult,
)
from .notifications import Subscription, WebhookSubscriptionRequest
from .type_index import TypeQuery

__all__ = ["LwsClient", "AsyncLwsClient", "ResourceStream", "AsyncResourceStream"]

RangeSpec = str | tuple[int, int | None] | None
PatchInput = JsonPatch | Sequence[Mapping[str, Any]] | bytes | str


class ResourceStream:
    """A streaming read: metadata is available immediately, the body is iterated lazily."""

    def __init__(self, metadata: ResourceMetadata, response: httpx.Response) -> None:
        self.metadata = metadata
        self._response = response

    @property
    def not_modified(self) -> bool:
        return self.metadata.status == 304

    def iter_bytes(self, chunk_size: int | None = None) -> Iterator[bytes]:
        return self._response.iter_bytes(chunk_size)

    def read(self) -> bytes:
        return self._response.read()


class AsyncResourceStream:
    """Async counterpart of :class:`ResourceStream`."""

    def __init__(self, metadata: ResourceMetadata, response: httpx.Response) -> None:
        self.metadata = metadata
        self._response = response

    @property
    def not_modified(self) -> bool:
        return self.metadata.status == 304

    def aiter_bytes(self, chunk_size: int | None = None) -> AsyncIterator[bytes]:
        return self._response.aiter_bytes(chunk_size)

    async def aread(self) -> bytes:
        return await self._response.aread()


def _subscription_request(
    topics: str | Iterable[str], inbox: str, expires: datetime | str | None
) -> WebhookSubscriptionRequest:
    return WebhookSubscriptionRequest(
        topics=[topics] if isinstance(topics, str) else list(topics), inbox=inbox, expires=expires
    )


class LwsClient:
    """Synchronous LWS client.

    :param authenticator: e.g. ``TokenExchangeAuthenticator(SelfSignedCredentials.did_key(key))``.
    :param http_client: an ``httpx.Client`` to use (redirects are handled by this library).
    :param user_agent: ``User-Agent`` header (default ``lws-client-python/<version>``).
    :param default_headers: extra headers sent with every request.
    :param timeout: request timeout in seconds when the client creates its own ``httpx.Client``.

    The client is thread-safe and should be reused; close it (or use ``with``) when done.
    """

    def __init__(
        self,
        *,
        authenticator: Authenticator | None = None,
        http_client: httpx.Client | None = None,
        user_agent: str | None = None,
        default_headers: HeaderInput = None,
        timeout: float = 30.0,
    ) -> None:
        self._owns_http = http_client is None
        self._http = http_client or httpx.Client(timeout=timeout)
        self._core = Core(authenticator, user_agent, default_headers)
        self._driver = SyncDriver(self._http)

    @property
    def authenticator(self) -> Authenticator | None:
        return self._core.authenticator

    # -- lifecycle -----------------------------------------------------------------------

    def close(self) -> None:
        if self._owns_http:
            self._http.close()

    def __enter__(self) -> LwsClient:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self.close()

    # -- discovery -----------------------------------------------------------------------

    def discover_storage(self, resource_url: str) -> StorageDescription:
        """Find the storage of any resource (``Link rel=lws#storage``) and read its
        storage description."""
        return self._driver.run(self._core.discover_storage(resource_url))

    def get_storage_description(self, storage_url: str) -> StorageDescription:
        """Read a storage description (``application/lws+cid``)."""
        return self._driver.run(self._core.get_storage_description(storage_url))

    def authenticate(self, url: str) -> None:
        """Establish credentials for ``url`` ahead of time (``HEAD`` through the
        authenticator) — useful before streaming a large upload."""
        self._driver.run(self._core.authenticate(url))

    # -- reading -------------------------------------------------------------------------

    def head(self, url: str, *, headers: HeaderInput = None) -> ResourceMetadata:
        """Read a resource's metadata (``HEAD``)."""
        return self._driver.run(self._core.head(url, headers))

    def read(
        self,
        url: str,
        *,
        accept: str | None = None,
        range: RangeSpec = None,
        if_none_match: str | None = None,
        if_modified_since: datetime | str | None = None,
        prefer: str | None = None,
        headers: HeaderInput = None,
    ) -> Resource:
        """Read a resource (``GET``). A ``304`` is returned with ``not_modified=True``."""
        req = self._core.read_request(
            url,
            accept=accept,
            range=range,
            if_none_match=if_none_match,
            if_modified_since=if_modified_since,
            prefer=prefer,
            headers=headers,
        )
        return self._driver.run(self._core.read(req))

    def read_json(self, url: str, **kwargs: Any) -> Any:
        """Read a resource and parse its body as JSON."""
        return self.read(url, accept=kwargs.pop("accept", "application/json"), **kwargs).json()

    @contextmanager
    def stream(
        self,
        url: str,
        *,
        accept: str | None = None,
        range: RangeSpec = None,
        if_none_match: str | None = None,
        headers: HeaderInput = None,
    ) -> Iterator[ResourceStream]:
        """Stream a resource body::

            with client.stream(url) as r:
                for chunk in r.iter_bytes():
                    ...
        """
        req = self._core.read_request(
            url, accept=accept, range=range, if_none_match=if_none_match, headers=headers
        )
        response = self._driver.run(self._core.execute(req, stream=True))
        try:
            if not (response.is_success or response.status_code == 304):
                raise error_for_response(response, req.method)
            yield ResourceStream(ResourceMetadata.from_response(response), response)
        finally:
            response.close()

    def read_container(self, url: str, *, headers: HeaderInput = None) -> ContainerPage:
        """Read one page of a container listing (``application/lws+json``)."""
        return self._driver.run(self._core.read_container(url, headers))

    def container_pages(self, url: str) -> Iterator[ContainerPage]:
        """Iterate over all pages of a container, following ``rel="next"`` lazily."""
        seen: set[str] = set()
        next_url: str | None = url
        while next_url and next_url not in seen:
            seen.add(next_url)
            page = self.read_container(next_url)
            yield page
            next_url = page.next

    def list_container(self, url: str) -> Iterator[ContainedResource]:
        """Iterate over every member of a container across all pages."""
        for page in self.container_pages(url):
            yield from page.items

    # -- creating ------------------------------------------------------------------------

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
    ) -> CreateResult:
        """Create a data resource in a container (``POST``). ``slug`` is the identity
        hint; ``links`` / ``types`` become user-managed ``Link`` headers."""
        return self._driver.run(
            self._core.create(
                container_url, body, content_type, slug=slug, links=links, types=types,
                headers=headers,
            )
        )

    def create_json(
        self,
        container_url: str,
        value: Any,
        *,
        content_type: str = "application/json",
        **kwargs: Any,
    ) -> CreateResult:
        """Create a JSON data resource."""
        return self.create(container_url, json_dumps(value), content_type, **kwargs)

    def create_text(
        self,
        container_url: str,
        text: str,
        *,
        content_type: str = "text/plain; charset=utf-8",
        **kwargs: Any,
    ) -> CreateResult:
        """Create a text data resource."""
        return self.create(container_url, text, content_type, **kwargs)

    def create_container(
        self,
        parent_url: str,
        *,
        slug: str | None = None,
        links: Iterable[Link] = (),
        headers: HeaderInput = None,
    ) -> CreateResult:
        """Create a sub-container (``POST`` with ``Link: <lws#Container>; rel="type"``)."""
        return self._driver.run(
            self._core.create_container(parent_url, slug=slug, links=links, headers=headers)
        )

    # -- updating ------------------------------------------------------------------------

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
    ) -> UpdateResult:
        """Replace a resource's content (``PUT``). With ``set_linkset=True`` the ``links``
        also replace its linkset (``Prefer: set-linkset``)."""
        return self._driver.run(
            self._core.update(
                url, body, content_type, if_match=if_match, if_none_match=if_none_match,
                links=links, set_linkset=set_linkset, headers=headers,
            )
        )

    def patch(
        self,
        url: str,
        patch: PatchInput,
        *,
        content_type: str | None = None,
        if_match: str | None = None,
        links: Iterable[Link] = (),
        set_linkset: bool = False,
        headers: HeaderInput = None,
    ) -> UpdateResult:
        """Partially update a resource (``PATCH``) with a :class:`JsonPatch` (or a raw patch
        document plus ``content_type``, e.g. ``application/sparql-update``)."""
        return self._driver.run(
            self._core.patch(
                url, patch, content_type=content_type, if_match=if_match, links=links,
                set_linkset=set_linkset, headers=headers,
            )
        )

    def delete(
        self,
        url: str,
        *,
        if_match: str | None = None,
        recursive: bool = False,
        headers: HeaderInput = None,
    ) -> None:
        """Delete a resource. ``recursive=True`` sends ``Depth: infinity`` for containers."""
        self._driver.run(
            self._core.delete(url, if_match=if_match, recursive=recursive, headers=headers)
        )

    # -- linksets ------------------------------------------------------------------------

    def linkset_url(self, resource_url: str) -> str:
        """Discover a resource's linkset URL (``rel="linkset"``)."""
        return self._driver.run(self._core.linkset_url(resource_url))

    def read_linkset(self, resource_url: str) -> LinksetDocument:
        """Discover and read a resource's linkset (metadata)."""
        return self._driver.run(self._core.read_linkset(resource_url))

    def read_linkset_at(self, linkset_url: str) -> LinksetDocument:
        """Read a linkset whose URL is already known."""
        return self._driver.run(self._core.read_linkset_at(linkset_url))

    def update_linkset(
        self,
        linkset_url: str,
        linkset: Linkset | Mapping[str, Any],
        *,
        if_match: str | None = None,
    ) -> UpdateResult:
        """Replace a linkset (``PUT``; only if the server allows it)."""
        return self._driver.run(self._core.update_linkset(linkset_url, linkset, if_match=if_match))

    def patch_linkset(
        self,
        linkset_url: str,
        patch: JsonPatch | Sequence[Mapping[str, Any]],
        *,
        if_match: str | None = None,
    ) -> UpdateResult:
        """Patch a linkset with JSON Patch."""
        return self._driver.run(self._core.patch_linkset(linkset_url, patch, if_match=if_match))

    # -- notifications -------------------------------------------------------------------

    def subscribe(
        self,
        service: ServiceRef,
        topics: str | Iterable[str],
        inbox: str,
        *,
        expires: datetime | str | None = None,
    ) -> Subscription:
        """Create a webhook subscription for ``topics`` delivered to ``inbox``."""
        return self._driver.run(
            self._core.subscribe(service, _subscription_request(topics, inbox, expires))
        )

    def list_subscriptions(self, service: ServiceRef) -> Iterator[ContainedResource]:
        """List the subscriber's active subscriptions."""
        return self.list_container(endpoint(service))

    def get_subscription(self, url: str) -> Subscription:
        return self._driver.run(self._core.get_subscription(url))

    def unsubscribe(self, url: str | Subscription) -> None:
        """Cancel a subscription."""
        self.delete(url.subscription if isinstance(url, Subscription) else url)

    # -- access requests / grants --------------------------------------------------------

    def request_access(self, service: ServiceRef, request: AccessRequest) -> str:
        """Submit an access request; returns its URL."""
        return self._driver.run(self._core.post_access(service, request))

    def list_access_requests(self, service: ServiceRef) -> Iterator[ContainedResource]:
        return self.list_container(endpoint(service))

    def get_access_request(self, url: str) -> AccessRequest:
        return self._driver.run(self._core.get_access_request(url))

    def cancel_access_request(self, url: str) -> None:
        self.delete(url)

    def grant_access(self, service: ServiceRef, grant: AccessGrant) -> str:
        """Create an access grant (storage controllers); returns its URL."""
        return self._driver.run(self._core.post_access(service, grant))

    def list_access_grants(self, service: ServiceRef) -> Iterator[ContainedResource]:
        return self.list_container(endpoint(service))

    def get_access_grant(self, url: str) -> AccessGrant:
        return self._driver.run(self._core.get_access_grant(url))

    def revoke_access_grant(self, url: str) -> None:
        self.delete(url)

    # -- type index / search -------------------------------------------------------------

    def read_type_index(self, url: ServiceRef) -> TypeIndexPage:
        """Read one page of the Type Index (service URL or a pagination URL)."""
        return self._driver.run(self._core.read_type_index(endpoint(url)))

    def list_types(self, service: ServiceRef) -> Iterator[str]:
        """Iterate over every type IRI in the Type Index across all pages."""
        seen: set[str] = set()
        next_url: str | None = endpoint(service)
        while next_url and next_url not in seen:
            seen.add(next_url)
            page = self.read_type_index(next_url)
            yield from page.types
            next_url = page.next

    def search_types(
        self, service: ServiceRef, query: TypeQuery | Mapping[str, Any]
    ) -> SearchPage:
        """Run a Type Search (HTTP ``QUERY``) and return the first result page."""
        return self._driver.run(self._core.search_types(service, query))

    def search_pages(
        self, service: ServiceRef, query: TypeQuery | Mapping[str, Any]
    ) -> Iterator[SearchPage]:
        page = self.search_types(service, query)
        seen: set[str] = set()
        while True:
            yield page
            if not page.next or page.next in seen:
                return
            seen.add(page.next)
            page = self._driver.run(self._core.search_page(page.next))

    def search_all(
        self, service: ServiceRef, query: TypeQuery | Mapping[str, Any]
    ) -> Iterator[ContainedResource]:
        """Iterate over every matching resource (``QUERY``, then ``GET`` of each ``next``)."""
        for page in self.search_pages(service, query):
            yield from page.items

    def accepted_query_formats(self, service: ServiceRef) -> list[str]:
        """Query formats accepted by a Type Search Service (``OPTIONS`` → ``Accept-Query``)."""
        return self._driver.run(self._core.accepted_query_formats(service))


class AsyncLwsClient:
    """Asynchronous LWS client with the same operations as :class:`LwsClient`.

    Listing operations (``list_container``, ``list_types``, ``search_all`` …) return async
    iterators: ``async for item in client.list_container(url): ...``.
    """

    def __init__(
        self,
        *,
        authenticator: Authenticator | None = None,
        http_client: httpx.AsyncClient | None = None,
        user_agent: str | None = None,
        default_headers: HeaderInput = None,
        timeout: float = 30.0,
    ) -> None:
        self._owns_http = http_client is None
        self._http = http_client or httpx.AsyncClient(timeout=timeout)
        self._core = Core(authenticator, user_agent, default_headers)
        self._driver = AsyncDriver(self._http)

    @property
    def authenticator(self) -> Authenticator | None:
        return self._core.authenticator

    async def aclose(self) -> None:
        if self._owns_http:
            await self._http.aclose()

    async def __aenter__(self) -> AsyncLwsClient:
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        await self.aclose()

    # -- discovery -----------------------------------------------------------------------

    async def discover_storage(self, resource_url: str) -> StorageDescription:
        return await self._driver.run(self._core.discover_storage(resource_url))

    async def get_storage_description(self, storage_url: str) -> StorageDescription:
        return await self._driver.run(self._core.get_storage_description(storage_url))

    async def authenticate(self, url: str) -> None:
        await self._driver.run(self._core.authenticate(url))

    # -- reading -------------------------------------------------------------------------

    async def head(self, url: str, *, headers: HeaderInput = None) -> ResourceMetadata:
        return await self._driver.run(self._core.head(url, headers))

    async def read(
        self,
        url: str,
        *,
        accept: str | None = None,
        range: RangeSpec = None,
        if_none_match: str | None = None,
        if_modified_since: datetime | str | None = None,
        prefer: str | None = None,
        headers: HeaderInput = None,
    ) -> Resource:
        req = self._core.read_request(
            url,
            accept=accept,
            range=range,
            if_none_match=if_none_match,
            if_modified_since=if_modified_since,
            prefer=prefer,
            headers=headers,
        )
        return await self._driver.run(self._core.read(req))

    async def read_json(self, url: str, **kwargs: Any) -> Any:
        resource = await self.read(url, accept=kwargs.pop("accept", "application/json"), **kwargs)
        return resource.json()

    @asynccontextmanager
    async def stream(
        self,
        url: str,
        *,
        accept: str | None = None,
        range: RangeSpec = None,
        if_none_match: str | None = None,
        headers: HeaderInput = None,
    ) -> AsyncIterator[AsyncResourceStream]:
        req = self._core.read_request(
            url, accept=accept, range=range, if_none_match=if_none_match, headers=headers
        )
        response = await self._driver.run(self._core.execute(req, stream=True))
        try:
            if not (response.is_success or response.status_code == 304):
                raise error_for_response(response, req.method)
            yield AsyncResourceStream(ResourceMetadata.from_response(response), response)
        finally:
            await response.aclose()

    async def read_container(self, url: str, *, headers: HeaderInput = None) -> ContainerPage:
        return await self._driver.run(self._core.read_container(url, headers))

    async def container_pages(self, url: str) -> AsyncIterator[ContainerPage]:
        seen: set[str] = set()
        next_url: str | None = url
        while next_url and next_url not in seen:
            seen.add(next_url)
            page = await self.read_container(next_url)
            yield page
            next_url = page.next

    async def list_container(self, url: str) -> AsyncIterator[ContainedResource]:
        async for page in self.container_pages(url):
            for item in page.items:
                yield item

    # -- creating ------------------------------------------------------------------------

    async def create(
        self,
        container_url: str,
        body: Body,
        content_type: str | None,
        *,
        slug: str | None = None,
        links: Iterable[Link] = (),
        types: Iterable[str] = (),
        headers: HeaderInput = None,
    ) -> CreateResult:
        return await self._driver.run(
            self._core.create(
                container_url, body, content_type, slug=slug, links=links, types=types,
                headers=headers,
            )
        )

    async def create_json(
        self,
        container_url: str,
        value: Any,
        *,
        content_type: str = "application/json",
        **kwargs: Any,
    ) -> CreateResult:
        return await self.create(container_url, json_dumps(value), content_type, **kwargs)

    async def create_text(
        self,
        container_url: str,
        text: str,
        *,
        content_type: str = "text/plain; charset=utf-8",
        **kwargs: Any,
    ) -> CreateResult:
        return await self.create(container_url, text, content_type, **kwargs)

    async def create_container(
        self,
        parent_url: str,
        *,
        slug: str | None = None,
        links: Iterable[Link] = (),
        headers: HeaderInput = None,
    ) -> CreateResult:
        return await self._driver.run(
            self._core.create_container(parent_url, slug=slug, links=links, headers=headers)
        )

    # -- updating ------------------------------------------------------------------------

    async def update(
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
    ) -> UpdateResult:
        return await self._driver.run(
            self._core.update(
                url, body, content_type, if_match=if_match, if_none_match=if_none_match,
                links=links, set_linkset=set_linkset, headers=headers,
            )
        )

    async def patch(
        self,
        url: str,
        patch: PatchInput,
        *,
        content_type: str | None = None,
        if_match: str | None = None,
        links: Iterable[Link] = (),
        set_linkset: bool = False,
        headers: HeaderInput = None,
    ) -> UpdateResult:
        return await self._driver.run(
            self._core.patch(
                url, patch, content_type=content_type, if_match=if_match, links=links,
                set_linkset=set_linkset, headers=headers,
            )
        )

    async def delete(
        self,
        url: str,
        *,
        if_match: str | None = None,
        recursive: bool = False,
        headers: HeaderInput = None,
    ) -> None:
        await self._driver.run(
            self._core.delete(url, if_match=if_match, recursive=recursive, headers=headers)
        )

    # -- linksets ------------------------------------------------------------------------

    async def linkset_url(self, resource_url: str) -> str:
        return await self._driver.run(self._core.linkset_url(resource_url))

    async def read_linkset(self, resource_url: str) -> LinksetDocument:
        return await self._driver.run(self._core.read_linkset(resource_url))

    async def read_linkset_at(self, linkset_url: str) -> LinksetDocument:
        return await self._driver.run(self._core.read_linkset_at(linkset_url))

    async def update_linkset(
        self,
        linkset_url: str,
        linkset: Linkset | Mapping[str, Any],
        *,
        if_match: str | None = None,
    ) -> UpdateResult:
        return await self._driver.run(
            self._core.update_linkset(linkset_url, linkset, if_match=if_match)
        )

    async def patch_linkset(
        self,
        linkset_url: str,
        patch: JsonPatch | Sequence[Mapping[str, Any]],
        *,
        if_match: str | None = None,
    ) -> UpdateResult:
        return await self._driver.run(
            self._core.patch_linkset(linkset_url, patch, if_match=if_match)
        )

    # -- notifications -------------------------------------------------------------------

    async def subscribe(
        self,
        service: ServiceRef,
        topics: str | Iterable[str],
        inbox: str,
        *,
        expires: datetime | str | None = None,
    ) -> Subscription:
        return await self._driver.run(
            self._core.subscribe(service, _subscription_request(topics, inbox, expires))
        )

    def list_subscriptions(self, service: ServiceRef) -> AsyncIterator[ContainedResource]:
        return self.list_container(endpoint(service))

    async def get_subscription(self, url: str) -> Subscription:
        return await self._driver.run(self._core.get_subscription(url))

    async def unsubscribe(self, url: str | Subscription) -> None:
        await self.delete(url.subscription if isinstance(url, Subscription) else url)

    # -- access requests / grants --------------------------------------------------------

    async def request_access(self, service: ServiceRef, request: AccessRequest) -> str:
        return await self._driver.run(self._core.post_access(service, request))

    def list_access_requests(self, service: ServiceRef) -> AsyncIterator[ContainedResource]:
        return self.list_container(endpoint(service))

    async def get_access_request(self, url: str) -> AccessRequest:
        return await self._driver.run(self._core.get_access_request(url))

    async def cancel_access_request(self, url: str) -> None:
        await self.delete(url)

    async def grant_access(self, service: ServiceRef, grant: AccessGrant) -> str:
        return await self._driver.run(self._core.post_access(service, grant))

    def list_access_grants(self, service: ServiceRef) -> AsyncIterator[ContainedResource]:
        return self.list_container(endpoint(service))

    async def get_access_grant(self, url: str) -> AccessGrant:
        return await self._driver.run(self._core.get_access_grant(url))

    async def revoke_access_grant(self, url: str) -> None:
        await self.delete(url)

    # -- type index / search -------------------------------------------------------------

    async def read_type_index(self, url: ServiceRef) -> TypeIndexPage:
        return await self._driver.run(self._core.read_type_index(endpoint(url)))

    async def list_types(self, service: ServiceRef) -> AsyncIterator[str]:
        seen: set[str] = set()
        next_url: str | None = endpoint(service)
        while next_url and next_url not in seen:
            seen.add(next_url)
            page = await self.read_type_index(next_url)
            for t in page.types:
                yield t
            next_url = page.next

    async def search_types(
        self, service: ServiceRef, query: TypeQuery | Mapping[str, Any]
    ) -> SearchPage:
        return await self._driver.run(self._core.search_types(service, query))

    async def search_pages(
        self, service: ServiceRef, query: TypeQuery | Mapping[str, Any]
    ) -> AsyncIterator[SearchPage]:
        page = await self.search_types(service, query)
        seen: set[str] = set()
        while True:
            yield page
            if not page.next or page.next in seen:
                return
            seen.add(page.next)
            page = await self._driver.run(self._core.search_page(page.next))

    async def search_all(
        self, service: ServiceRef, query: TypeQuery | Mapping[str, Any]
    ) -> AsyncIterator[ContainedResource]:
        async for page in self.search_pages(service, query):
            for item in page.items:
                yield item

    async def accepted_query_formats(self, service: ServiceRef) -> list[str]:
        return await self._driver.run(self._core.accepted_query_formats(service))
