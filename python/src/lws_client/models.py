# SPDX-License-Identifier: MIT
"""Immutable result models for discovery, reading, creating and updating resources."""

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime
from email.utils import parsedate_to_datetime
from typing import Any

import httpx

from ._util import (
    as_list,
    charset_of,
    has_type,
    media_type_essence,
    parse_datetime,
    resolve,
    split_header_list,
    string_list,
)
from .constants import MediaType, Rel, ServiceType, Types
from .errors import ProtocolError
from .headers import Link, parse_link_header

__all__ = [
    "ResourceMetadata",
    "Resource",
    "ContainedResource",
    "ContainerPage",
    "SearchPage",
    "TypeIndexPage",
    "CreateResult",
    "UpdateResult",
    "Service",
    "Capability",
    "VerificationMethod",
    "StorageDescription",
    "parse_json_body",
]

_CONTAINER_MEDIA_TYPES = {MediaType.LWS_JSON, MediaType.LD_JSON, MediaType.JSON}


def parse_json_body(body: bytes, what: str) -> Any:
    try:
        return json.loads(body)
    except ValueError as exc:
        raise ProtocolError(f"{what} is not valid JSON: {exc}") from exc


def _http_date(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return parsedate_to_datetime(value)
    except (TypeError, ValueError, IndexError):
        return None


def _int_or_none(value: Any) -> int | None:
    if isinstance(value, bool) or not isinstance(value, int):
        return None
    return value


@dataclass(frozen=True, slots=True)
class ResourceMetadata:
    """Metadata parsed from the response headers of a resource (``HEAD`` or ``GET``)."""

    url: str
    status: int
    headers: httpx.Headers
    links: tuple[Link, ...] = ()
    etag: str | None = None
    last_modified: datetime | None = None
    content_type: str | None = None
    content_length: int | None = None

    @classmethod
    def from_response(cls, response: httpx.Response) -> ResourceMetadata:
        url = str(response.url)
        headers = httpx.Headers(response.headers)
        length = headers.get("content-length")
        return cls(
            url=url,
            status=response.status_code,
            headers=headers,
            links=tuple(parse_link_header(headers.get_list("link"), url)),
            etag=headers.get("etag"),
            last_modified=_http_date(headers.get("last-modified")),
            content_type=headers.get("content-type"),
            content_length=int(length) if length and length.isdigit() else None,
        )

    # -- links ---------------------------------------------------------------------------

    def link(self, rel: str) -> Link | None:
        """The first link with relation ``rel``."""
        for candidate in self.links_for(rel):
            return candidate
        return None

    def links_for(self, rel: str) -> list[Link]:
        """All links with relation ``rel`` (registered relations compare case-insensitively)."""
        wanted = rel if ":" in rel else rel.lower()
        return [link for link in self.links if link.rel == wanted]

    def _href(self, rel: str) -> str | None:
        found = self.link(rel)
        return found.href if found else None

    @property
    def linkset(self) -> str | None:
        """URL of the linkset resource (``rel="linkset"``)."""
        return self._href(Rel.LINKSET)

    @property
    def parent(self) -> str | None:
        """URL of the parent container (``rel="up"``)."""
        return self._href(Rel.UP)

    @property
    def storage(self) -> str | None:
        """URL of the storage (``rel="https://www.w3.org/ns/lws#storage"``)."""
        return self._href(Rel.STORAGE)

    @property
    def types(self) -> tuple[str, ...]:
        """Targets of ``rel="type"`` links."""
        return tuple(link.href for link in self.links_for(Rel.TYPE))

    def has_type(self, type_: str) -> bool:
        return has_type(self.types, type_)

    @property
    def is_container(self) -> bool:
        return has_type(self.types, Types.CONTAINER)

    @property
    def is_data_resource(self) -> bool:
        return has_type(self.types, Types.DATA_RESOURCE)

    @property
    def allow(self) -> list[str]:
        return [m.upper() for m in split_header_list(self.headers.get_list("allow"))]

    @property
    def accept_patch(self) -> list[str]:
        return split_header_list(self.headers.get_list("accept-patch"))

    @property
    def media_type(self) -> str:
        """``type/subtype`` of ``Content-Type`` without parameters (lower case)."""
        return media_type_essence(self.content_type)


@dataclass(frozen=True, slots=True)
class Resource(ResourceMetadata):
    """A read resource: metadata plus the (fully read) body.

    A conditional read answered with ``304 Not Modified`` is returned with
    ``not_modified=True`` and an empty body rather than raised.
    """

    content: bytes = b""
    not_modified: bool = False

    @property
    def text(self) -> str:
        """The body decoded with the ``Content-Type`` charset (UTF-8 by default)."""
        return self.content.decode(charset_of(self.content_type), "replace")

    def json(self) -> Any:
        """The body parsed as JSON."""
        return json.loads(self.content)

    @property
    def content_range(self) -> str | None:
        """``Content-Range`` of a ``206 Partial Content`` response."""
        value: str | None = self.headers.get("content-range")
        return value

    @property
    def is_partial(self) -> bool:
        return self.status == 206


@dataclass(frozen=True, slots=True)
class ContainedResource:
    """One entry of a container listing (or of a search result page)."""

    id: str
    types: tuple[str, ...] = ()
    format: str | None = None
    size: int | None = None
    modified: datetime | None = None
    modified_raw: str | None = None
    raw: Mapping[str, Any] = field(default_factory=dict)

    @classmethod
    def from_json(cls, data: Mapping[str, Any], base: str) -> ContainedResource:
        raw_id = data.get("id", data.get("@id"))
        if not isinstance(raw_id, str):
            raise ProtocolError("contained resource description without an 'id'")
        modified_raw = data.get("modified")
        fmt = data.get("format")
        return cls(
            id=resolve(base, raw_id),
            types=string_list(data.get("type", data.get("@type"))),
            format=fmt if isinstance(fmt, str) else None,
            size=_int_or_none(data.get("size")),
            modified=parse_datetime(modified_raw),
            modified_raw=modified_raw if isinstance(modified_raw, str) else None,
            raw=dict(data),
        )

    def has_type(self, type_: str) -> bool:
        return has_type(self.types, type_)

    @property
    def is_container(self) -> bool:
        return has_type(self.types, Types.CONTAINER)

    @property
    def is_data_resource(self) -> bool:
        return has_type(self.types, Types.DATA_RESOURCE)


def _pagination(metadata: ResourceMetadata) -> dict[str, str | None]:
    return {
        "first": metadata._href(Rel.FIRST),
        "next": metadata._href(Rel.NEXT),
        "prev": metadata._href(Rel.PREV) or metadata._href("previous"),
        "last": metadata._href(Rel.LAST),
    }


def _items(body: Mapping[str, Any], base: str) -> tuple[ContainedResource, ...]:
    items = body.get("items", [])
    if not isinstance(items, list):
        raise ProtocolError("'items' must be an array")
    return tuple(ContainedResource.from_json(i, base) for i in items if isinstance(i, dict))


def _check_json_listing(metadata: ResourceMetadata, body: bytes, what: str) -> dict[str, Any]:
    essence = metadata.media_type
    if essence not in _CONTAINER_MEDIA_TYPES:
        raise ProtocolError(f"unexpected media type {metadata.content_type!r} for {what}")
    data = parse_json_body(body, what)
    if not isinstance(data, dict):
        raise ProtocolError(f"{what} must be a JSON object")
    return data


@dataclass(frozen=True, slots=True)
class ContainerPage:
    """One page of a container listing (``application/lws+json``)."""

    id: str
    types: tuple[str, ...]
    total_items: int | None
    items: tuple[ContainedResource, ...]
    metadata: ResourceMetadata
    first: str | None = None
    next: str | None = None
    prev: str | None = None
    last: str | None = None
    raw: Mapping[str, Any] = field(default_factory=dict)

    @classmethod
    def parse(cls, metadata: ResourceMetadata, body: bytes) -> ContainerPage:
        data = _check_json_listing(metadata, body, "container representation")
        body_types = string_list(data.get("type", data.get("@type")))
        if not (metadata.is_container or has_type(body_types, Types.CONTAINER)):
            raise ProtocolError(f"{metadata.url} is not a container")
        raw_id = data.get("id", data.get("@id"))
        return cls(
            id=resolve(metadata.url, raw_id) if isinstance(raw_id, str) else metadata.url,
            types=body_types,
            total_items=_int_or_none(data.get("totalItems")),
            items=_items(data, metadata.url),
            metadata=metadata,
            raw=data,
            **_pagination(metadata),
        )

    @property
    def etag(self) -> str | None:
        return self.metadata.etag

    @property
    def is_container(self) -> bool:
        return True


@dataclass(frozen=True, slots=True)
class SearchPage:
    """One page of Type Search results — a synthetic ``ContainerPage``, whose ``id`` is the page's own URL
    when the body names none."""

    total_items: int | None
    items: tuple[ContainedResource, ...]
    metadata: ResourceMetadata
    id: str = ""
    types: tuple[str, ...] = ()
    first: str | None = None
    next: str | None = None
    prev: str | None = None
    last: str | None = None
    raw: Mapping[str, Any] = field(default_factory=dict)

    @classmethod
    def parse(cls, metadata: ResourceMetadata, body: bytes) -> SearchPage:
        data = _check_json_listing(metadata, body, "search result page")
        raw_id = data.get("id", data.get("@id"))
        return cls(
            id=resolve(metadata.url, raw_id) if isinstance(raw_id, str) else metadata.url,
            total_items=_int_or_none(data.get("totalItems")),
            items=_items(data, metadata.url),
            metadata=metadata,
            types=string_list(data.get("type")),
            raw=data,
            **_pagination(metadata),
        )


@dataclass(frozen=True, slots=True)
class TypeIndexPage:
    """One page of a Type Index listing: the distinct type IRIs visible to the client."""

    total_items: int | None
    types: tuple[str, ...]
    metadata: ResourceMetadata
    first: str | None = None
    next: str | None = None
    prev: str | None = None
    last: str | None = None
    raw: Mapping[str, Any] = field(default_factory=dict)

    @classmethod
    def parse(cls, metadata: ResourceMetadata, body: bytes) -> TypeIndexPage:
        data = _check_json_listing(metadata, body, "type index page")
        types: list[str] = []
        for item in as_list(data.get("items")):
            if isinstance(item, dict) and isinstance(item.get("id"), str):
                types.append(item["id"])
            elif isinstance(item, str):
                types.append(item)
        return cls(
            total_items=_int_or_none(data.get("totalItems")),
            types=tuple(types),
            metadata=metadata,
            raw=data,
            **_pagination(metadata),
        )


@dataclass(frozen=True, slots=True)
class CreateResult:
    """Result of ``create`` / ``create_container``: the new resource's absolute URL."""

    location: str
    metadata: ResourceMetadata
    content: bytes = b""

    @property
    def linkset(self) -> str | None:
        return self.metadata.linkset

    @property
    def parent(self) -> str | None:
        return self.metadata.parent

    @property
    def etag(self) -> str | None:
        return self.metadata.etag

    @property
    def is_container(self) -> bool:
        return self.metadata.is_container


@dataclass(frozen=True, slots=True)
class UpdateResult:
    """Result of ``update`` / ``patch`` / linkset updates."""

    status: int
    metadata: ResourceMetadata
    content: bytes = b""

    @property
    def etag(self) -> str | None:
        return self.metadata.etag


# --- storage description ------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Service:
    """A ``service`` entry of a storage description."""

    types: tuple[str, ...]
    service_endpoint: str
    id: str | None = None
    raw: Mapping[str, Any] = field(default_factory=dict)

    def has_type(self, type_: str) -> bool:
        return has_type(self.types, type_)

    def get(self, name: str, default: Any = None) -> Any:
        """An extension property (e.g. ``subscriptionType``, ``conformsTo``)."""
        return self.raw.get(name, default)

    @property
    def subscription_types(self) -> tuple[str, ...]:
        return string_list(self.raw.get("subscriptionType"))

    @property
    def conforms_to(self) -> tuple[str, ...]:
        return string_list(self.raw.get("conformsTo"))


@dataclass(frozen=True, slots=True)
class Capability:
    """A ``capability`` entry of a storage description."""

    types: tuple[str, ...]
    id: str | None = None
    raw: Mapping[str, Any] = field(default_factory=dict)

    def has_type(self, type_: str) -> bool:
        return has_type(self.types, type_)

    def get(self, name: str, default: Any = None) -> Any:
        return self.raw.get(name, default)


@dataclass(frozen=True, slots=True)
class VerificationMethod:
    """A controlled-identifier verification method (``publicKeyJwk`` keys)."""

    id: str
    type: str | None = None
    controller: str | None = None
    public_key_jwk: Mapping[str, Any] | None = None
    raw: Mapping[str, Any] = field(default_factory=dict)

    @classmethod
    def from_json(cls, data: Mapping[str, Any]) -> VerificationMethod:
        jwk = data.get("publicKeyJwk")
        vm_type = data.get("type")
        controller = data.get("controller")
        return cls(
            id=str(data.get("id", "")),
            type=vm_type if isinstance(vm_type, str) else None,
            controller=controller if isinstance(controller, str) else None,
            public_key_jwk=dict(jwk) if isinstance(jwk, dict) else None,
            raw=dict(data),
        )


def id_matches(candidate: str, wanted: str, base: str) -> bool:
    """Match a verification-method id (possibly relative / bare fragment) against ``wanted``."""
    if not candidate:
        return False
    if candidate == wanted:
        return True
    resolved_candidate = resolve(base, candidate if not _is_bare_fragment(candidate) else "#" + candidate)
    resolved_wanted = resolve(base, wanted if not _is_bare_fragment(wanted) else "#" + wanted)
    return resolved_candidate == resolved_wanted


def _is_bare_fragment(value: str) -> bool:
    return ":" not in value and "/" not in value and not value.startswith("#")


@dataclass(frozen=True, slots=True)
class StorageDescription:
    """A storage description resource (``application/lws+cid``), a Controlled Identifier
    document describing the storage, its services and capabilities."""

    id: str
    types: tuple[str, ...]
    services: tuple[Service, ...] = ()
    capabilities: tuple[Capability, ...] = ()
    verification_methods: tuple[VerificationMethod, ...] = ()
    authentication: tuple[str | VerificationMethod, ...] = ()
    raw: Mapping[str, Any] = field(default_factory=dict)

    @classmethod
    def from_json(cls, data: Mapping[str, Any], base: str = "") -> StorageDescription:
        """Parse a storage description; raises :class:`ProtocolError` if it is invalid."""
        if not isinstance(data, Mapping):
            raise ProtocolError("storage description must be a JSON object")
        raw_id = data.get("id", data.get("@id"))
        if not isinstance(raw_id, str):
            raise ProtocolError("storage description has no 'id'")
        doc_id = resolve(base, raw_id)
        types = string_list(data.get("type", data.get("@type")))
        if not has_type(types, "Storage"):
            raise ProtocolError(f"document {doc_id} is not a Storage (type={list(types)})")
        services: list[Service] = []
        for entry in as_list(data.get("service")):
            if not isinstance(entry, dict):
                continue
            endpoint = entry.get("serviceEndpoint")
            if not isinstance(endpoint, str):
                continue
            sid = entry.get("id")
            services.append(
                Service(
                    types=string_list(entry.get("type")),
                    service_endpoint=resolve(doc_id, endpoint),
                    id=resolve(doc_id, sid) if isinstance(sid, str) else None,
                    raw=dict(entry),
                )
            )
        capabilities = tuple(
            Capability(
                types=string_list(c.get("type")),
                id=c.get("id") if isinstance(c.get("id"), str) else None,
                raw=dict(c),
            )
            for c in as_list(data.get("capability"))
            if isinstance(c, dict)
        )
        vms = tuple(
            VerificationMethod.from_json(v)
            for v in as_list(data.get("verificationMethod"))
            if isinstance(v, dict)
        )
        auth: list[str | VerificationMethod] = []
        for a in as_list(data.get("authentication")):
            if isinstance(a, str):
                auth.append(a)
            elif isinstance(a, dict):
                auth.append(VerificationMethod.from_json(a))
        return cls(
            id=doc_id,
            types=types,
            services=tuple(services),
            capabilities=capabilities,
            verification_methods=vms,
            authentication=tuple(auth),
            raw=dict(data),
        )

    def has_type(self, type_: str) -> bool:
        return has_type(self.types, type_)

    def service(self, type_: str) -> Service | None:
        """The first service of the given type."""
        for s in self.services:
            if s.has_type(type_):
                return s
        return None

    def find_services(self, type_: str) -> list[Service]:
        """All services of the given type."""
        return [s for s in self.services if s.has_type(type_)]

    def capability(self, type_: str) -> Capability | None:
        for c in self.capabilities:
            if c.has_type(type_):
                return c
        return None

    def storage_root(self) -> str:
        """URL of the storage root container (the required ``StorageRoot`` service)."""
        root = self.service(ServiceType.STORAGE_ROOT)
        if root is None:
            raise ProtocolError(f"storage description {self.id} has no StorageRoot service")
        return root.service_endpoint

    def _endpoint(self, type_: str) -> str | None:
        found = self.service(type_)
        return found.service_endpoint if found else None

    def notification_service(self) -> str | None:
        return self._endpoint(ServiceType.NOTIFICATION)

    def access_request_service(self) -> str | None:
        return self._endpoint(ServiceType.ACCESS_REQUEST)

    def access_grant_service(self) -> str | None:
        return self._endpoint(ServiceType.ACCESS_GRANT)

    def type_index_service(self) -> str | None:
        return self._endpoint(ServiceType.TYPE_INDEX)

    def type_search_service(self) -> str | None:
        return self._endpoint(ServiceType.TYPE_SEARCH)

    def verification_method(self, id_or_fragment: str) -> VerificationMethod | None:
        """Find a verification method by full id, relative id or fragment."""
        for vm in self.verification_methods:
            if id_matches(vm.id, id_or_fragment, self.id):
                return vm
        for a in self.authentication:
            if isinstance(a, VerificationMethod) and id_matches(a.id, id_or_fragment, self.id):
                return a
        return None

    def is_authentication_method(self, vm_id: str) -> bool:
        """True if ``vm_id`` is referenced (or embedded) in ``authentication``."""
        for a in self.authentication:
            ref = a if isinstance(a, str) else a.id
            if id_matches(ref, vm_id, self.id):
                return True
        return False


def text_of(content: bytes, content_type: str | None) -> str:
    return content.decode(charset_of(content_type), "replace")


def media_is(content_type: str | None, expected: str) -> bool:
    return media_type_essence(content_type) == expected
