# SPDX-License-Identifier: MIT
"""JSON Patch (RFC 6902) builder and JSON Pointer (RFC 6901) helpers.

JSON Patch is the LWS baseline patch format for resources and linksets.
"""

from __future__ import annotations

from collections.abc import Iterable, Iterator
from typing import Any

from ._util import json_dumps

__all__ = ["JsonPatch", "JsonPointer"]


class JsonPointer:
    """JSON Pointer helpers."""

    @staticmethod
    def escape(segment: str) -> str:
        """Escape one reference token: ``~`` → ``~0``, ``/`` → ``~1``."""
        return segment.replace("~", "~0").replace("/", "~1")

    @staticmethod
    def unescape(segment: str) -> str:
        return segment.replace("~1", "/").replace("~0", "~")

    @staticmethod
    def from_segments(*segments: str | int) -> str:
        """Build a pointer from unescaped segments, e.g.
        ``from_segments("linkset", 0, "https://example.org/rel", "-")`` →
        ``/linkset/0/https:~1~1example.org~1rel/-``."""
        return "".join("/" + JsonPointer.escape(str(s)) for s in segments)

    @staticmethod
    def segments(pointer: str) -> list[str]:
        """Split a pointer into unescaped segments."""
        if pointer == "":
            return []
        if not pointer.startswith("/"):
            raise ValueError(f"invalid JSON Pointer: {pointer!r}")
        return [JsonPointer.unescape(s) for s in pointer[1:].split("/")]


class JsonPatch:
    """Fluent JSON Patch document builder.

    >>> JsonPatch().replace("/age", 31).add("/city", "Boston").to_json()
    [{'op': 'replace', 'path': '/age', 'value': 31}, {'op': 'add', 'path': '/city', 'value': 'Boston'}]
    """

    __slots__ = ("_ops",)

    def __init__(self, operations: Iterable[dict[str, Any]] = ()) -> None:
        self._ops: list[dict[str, Any]] = [dict(op) for op in operations]

    def add(self, path: str, value: Any) -> JsonPatch:
        self._ops.append({"op": "add", "path": path, "value": value})
        return self

    def remove(self, path: str) -> JsonPatch:
        self._ops.append({"op": "remove", "path": path})
        return self

    def replace(self, path: str, value: Any) -> JsonPatch:
        self._ops.append({"op": "replace", "path": path, "value": value})
        return self

    def move(self, from_: str, path: str) -> JsonPatch:
        self._ops.append({"op": "move", "from": from_, "path": path})
        return self

    def copy(self, from_: str, path: str) -> JsonPatch:
        self._ops.append({"op": "copy", "from": from_, "path": path})
        return self

    def test(self, path: str, value: Any) -> JsonPatch:
        self._ops.append({"op": "test", "path": path, "value": value})
        return self

    @property
    def operations(self) -> list[dict[str, Any]]:
        return [dict(op) for op in self._ops]

    def to_json(self) -> list[dict[str, Any]]:
        """The patch document as a JSON-compatible list."""
        return self.operations

    def to_bytes(self) -> bytes:
        return json_dumps(self._ops)

    def __len__(self) -> int:
        return len(self._ops)

    def __iter__(self) -> Iterator[dict[str, Any]]:
        return iter(self.operations)

    def __eq__(self, other: object) -> bool:
        return isinstance(other, JsonPatch) and other._ops == self._ops

    __hash__ = None  # type: ignore[assignment]

    def __repr__(self) -> str:
        return f"JsonPatch({self._ops!r})"
