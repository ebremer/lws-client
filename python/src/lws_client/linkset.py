# SPDX-License-Identifier: MIT
"""Linkset documents (RFC 9264, ``application/linkset+json``) — LWS resource metadata — and
moving resources, which is a change of the ``up`` link in a linkset."""

from __future__ import annotations

import copy
from collections.abc import Iterator, Mapping
from dataclasses import dataclass, field
from typing import Any

from ._util import normalize_url, resolve
from .constants import Rel
from .errors import ProtocolError
from .headers import Link
from .json_patch import JsonPatch, JsonPointer
from .models import ResourceMetadata, parse_json_body

__all__ = ["LinkTarget", "LinkContext", "Linkset", "LinksetDocument", "MoveResult", "move_patch"]


@dataclass(slots=True)
class LinkTarget:
    """A target object: ``href`` plus target attributes (``type``, ``title``, ``hreflang``,
    ``title*`` … — all preserved verbatim)."""

    href: str
    attributes: dict[str, Any] = field(default_factory=dict)

    def to_json(self) -> dict[str, Any]:
        out: dict[str, Any] = {"href": self.href}
        out.update(copy.deepcopy(self.attributes))
        return out

    @classmethod
    def from_json(cls, data: Mapping[str, Any]) -> LinkTarget:
        href = data.get("href")
        if not isinstance(href, str):
            raise ProtocolError("linkset target object without 'href'")
        return cls(href, {k: copy.deepcopy(v) for k, v in data.items() if k != "href"})


@dataclass(slots=True)
class LinkContext:
    """A link context object: an ``anchor`` and an ordered map relation → targets."""

    anchor: str | None
    relations: dict[str, list[LinkTarget]] = field(default_factory=dict)

    def targets(self, rel: str) -> list[LinkTarget]:
        return self.relations.get(rel, [])

    def to_json(self) -> dict[str, Any]:
        out: dict[str, Any] = {}
        if self.anchor is not None:
            out["anchor"] = self.anchor
        for rel, targets in self.relations.items():
            out[rel] = [t.to_json() for t in targets]
        return out

    @classmethod
    def from_json(cls, data: Mapping[str, Any]) -> LinkContext:
        anchor = data.get("anchor")
        relations: dict[str, list[LinkTarget]] = {}
        for key, value in data.items():
            if key == "anchor":
                continue
            if not isinstance(value, list):
                raise ProtocolError(f"linkset relation {key!r} must be an array")
            relations[key] = [LinkTarget.from_json(t) for t in value if isinstance(t, dict)]
        return cls(anchor if isinstance(anchor, str) else None, relations)


@dataclass(slots=True)
class Linkset:
    """A mutable RFC 9264 linkset that round-trips losslessly to JSON."""

    contexts: list[LinkContext] = field(default_factory=list)

    @classmethod
    def from_json(cls, data: Mapping[str, Any]) -> Linkset:
        entries = data.get("linkset") if isinstance(data, Mapping) else None
        if not isinstance(entries, list):
            raise ProtocolError("linkset document must have a 'linkset' array")
        return cls([LinkContext.from_json(c) for c in entries if isinstance(c, dict)])

    def to_json(self) -> dict[str, Any]:
        return {"linkset": [c.to_json() for c in self.contexts]}

    def context(self, anchor: str | None) -> LinkContext | None:
        """The context object for ``anchor`` (``None`` → the first context)."""
        if anchor is None:
            return self.contexts[0] if self.contexts else None
        for ctx in self.contexts:
            if ctx.anchor == anchor:
                return ctx
        return None

    def links(self, base: str = "") -> list[Link]:
        """All links flattened; targets and anchors are resolved against ``base`` if given."""
        out: list[Link] = []
        for ctx in self.contexts:
            anchor = resolve(base, ctx.anchor) if ctx.anchor is not None else None
            for rel, targets in ctx.relations.items():
                for t in targets:
                    params = {k: v for k, v in t.attributes.items() if isinstance(v, str)}
                    if anchor is not None:
                        params["anchor"] = anchor
                    out.append(Link(resolve(base, t.href), rel, params))
        return out

    def targets(self, rel: str, anchor: str | None = None) -> list[str]:
        """Target hrefs for ``rel`` (in all contexts, or only the one for ``anchor``)."""
        out: list[str] = []
        for ctx in self.contexts:
            if anchor is None or ctx.anchor == anchor:
                out.extend(t.href for t in ctx.targets(rel))
        return out

    def add(
        self,
        anchor: str | None,
        rel: str,
        href: str,
        attributes: Mapping[str, Any] | None = None,
    ) -> Linkset:
        """Append a link (creating the context if needed). Returns ``self`` for chaining."""
        ctx = self.context(anchor)
        if ctx is None:
            ctx = LinkContext(anchor)
            self.contexts.append(ctx)
        ctx.relations.setdefault(rel, []).append(LinkTarget(href, dict(attributes or {})))
        return self

    def remove(self, anchor: str | None, rel: str, href: str | None = None) -> int:
        """Remove links of ``rel`` (optionally only those to ``href``); returns the count."""
        removed = 0
        for ctx in self.contexts:
            if anchor is not None and ctx.anchor != anchor:
                continue
            targets = ctx.relations.get(rel)
            if not targets:
                continue
            keep = [t for t in targets if href is not None and t.href != href]
            removed += len(targets) - len(keep)
            if keep:
                ctx.relations[rel] = keep
            else:
                del ctx.relations[rel]
        return removed

    def copy(self) -> Linkset:
        return Linkset.from_json(self.to_json())

    def __iter__(self) -> Iterator[Link]:
        return iter(self.links())

    def __len__(self) -> int:
        return sum(len(ts) for ctx in self.contexts for ts in ctx.relations.values())


@dataclass(frozen=True, slots=True)
class LinksetDocument:
    """A linkset resource as read from the server, with its URL and ETag for updates, and the
    document as received."""

    url: str
    linkset: Linkset
    metadata: ResourceMetadata
    raw: Mapping[str, Any] = field(default_factory=dict)

    @property
    def etag(self) -> str | None:
        return self.metadata.etag

    @property
    def allow(self) -> list[str]:
        return self.metadata.allow

    @property
    def accept_patch(self) -> list[str]:
        return self.metadata.accept_patch


# --- moving resources ---------------------------------------------------------------


def _same_url(a: str, b: str) -> bool:
    return a == b or (normalize_url(a) or a) == (normalize_url(b) or b)


def move_patch(
    resource_url: str,
    linkset_url: str,
    linkset: Linkset | Mapping[str, Any],
    destination_url: str,
) -> JsonPatch:
    """The JSON Patch that moves ``resource_url`` into the container ``destination_url``
    (lws10-core "Moving Resources"): a ``test`` that the resource's ``up`` link still holds the
    ``href`` read, and a ``replace`` of it with the destination.

    The link context is the first whose ``anchor`` resolves (against ``linkset_url``) to the
    resource, or the only one when it has no anchor; the ``up`` link is its first ``up`` target
    with a string ``href``. Without either, :class:`ProtocolError`.
    """
    data = linkset.to_json() if isinstance(linkset, Linkset) else linkset
    contexts = data.get("linkset") if isinstance(data, Mapping) else None
    if not isinstance(contexts, list):
        raise ProtocolError("linkset document must have a 'linkset' array")
    index = next(
        (
            i
            for i, ctx in enumerate(contexts)
            if isinstance(ctx, dict)
            and isinstance(ctx.get("anchor"), str)
            and _same_url(resolve(linkset_url, ctx["anchor"]), resource_url)
        ),
        None,
    )
    if index is None and len(contexts) == 1 and isinstance(contexts[0], dict) and (
        "anchor" not in contexts[0]
    ):
        index = 0
    if index is not None:
        targets = contexts[index].get(Rel.UP)
        for j, target in enumerate(targets if isinstance(targets, list) else []):
            if isinstance(target, dict) and isinstance(target.get("href"), str):
                pointer = JsonPointer.from_segments("linkset", index, Rel.UP, j, "href")
                destination = resolve(resource_url, destination_url)
                return JsonPatch().test(pointer, target["href"]).replace(pointer, destination)
    raise ProtocolError(f"the linkset {linkset_url} has no up link of {resource_url} to change")


@dataclass(frozen=True, slots=True)
class MoveResult:
    """Result of ``move``: where the resource and its linkset are after the move.

    A storage that keeps identifiers answers ``204`` (or ``200`` with the linkset), and
    ``location`` is the resource's URL as before. One that does not answers ``200`` with the
    updated linkset, whose anchor is the new identifier, and ``Content-Location``, the linkset's
    new URL. Without a ``preservesIdentifier: true``, rely on this result for the identifier.
    """

    status: int
    location: str
    linkset: str
    identifier_preserved: bool
    metadata: ResourceMetadata
    document: Linkset | None = None

    @property
    def etag(self) -> str | None:
        """ETag of the linkset after the move."""
        return self.metadata.etag

    @classmethod
    def parse(cls, resource_url: str, metadata: ResourceMetadata, content: bytes) -> MoveResult:
        """Interpret the answer to the patch of a move; ``metadata.url`` is the linkset's URL."""
        content_location = metadata.headers.get("content-location")
        linkset_url = resolve(metadata.url, content_location) if content_location else metadata.url
        location = resource_url
        document = None
        if metadata.status == 200 and content:
            data = parse_json_body(content, "linkset")
            if not isinstance(data, dict):
                raise ProtocolError("linkset document must be a JSON object")
            document = Linkset.from_json(data)
            moved = next((c for c in document.contexts if c.targets(Rel.UP)), None)
            if moved is not None and moved.anchor is not None:
                location = resolve(linkset_url, moved.anchor)
        return cls(
            status=metadata.status,
            location=location,
            linkset=linkset_url,
            identifier_preserved=_same_url(location, resource_url),
            metadata=metadata,
            document=document,
        )
