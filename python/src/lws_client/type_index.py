# SPDX-License-Identifier: MIT
"""Type Search filters (``application/lws-query+json``, lws10-index)."""

from __future__ import annotations

from typing import Any, Union

from ._util import is_absolute_iri
from .constants import Rel

__all__ = ["TypeQuery"]

_Group = Union[str, list[str]]


class TypeQuery:
    """A conjunctive-normal-form filter for the Type Search Service.

    Each call to :meth:`all_of` adds one AND group per IRI; each call to :meth:`any_of`
    adds a single OR group. Groups under the same key are combined with AND, and different
    keys (``type`` and indexed relations) are combined with AND as well.

    >>> TypeQuery().any_of("https://schema.org/Person", "http://xmlns.com/foaf/0.1/Person") \\
    ...     .all_of("https://www.w3.org/ns/lws#DataResource").to_json()
    {'type': [['https://schema.org/Person', 'http://xmlns.com/foaf/0.1/Person'], 'https://www.w3.org/ns/lws#DataResource']}
    """

    __slots__ = ("_filters",)

    def __init__(self) -> None:
        self._filters: dict[str, list[_Group]] = {}

    @staticmethod
    def _check(iris: tuple[str, ...]) -> None:
        for iri in iris:
            if not is_absolute_iri(iri):
                raise ValueError(f"not an absolute IRI: {iri!r}")

    def all_of(self, *iris: str, key: str = Rel.TYPE) -> TypeQuery:
        """Require every IRI (one AND group each) under ``key`` (default ``type``)."""
        self._check(iris)
        groups = self._filters.setdefault(key, [])
        for iri in iris:
            if iri not in groups:
                groups.append(iri)
        return self

    def any_of(self, *iris: str, key: str = Rel.TYPE) -> TypeQuery:
        """Require at least one of the IRIs (a single OR group) under ``key``."""
        if not iris:
            raise ValueError("an OR group must not be empty")
        self._check(iris)
        group: _Group = iris[0] if len(iris) == 1 else list(iris)
        groups = self._filters.setdefault(key, [])
        if group not in groups:
            groups.append(group)
        return self

    def relation(self, rel: str) -> _RelationFilter:
        """Filter on an indexed descriptive link relation (same grammar as ``type``)."""
        return _RelationFilter(self, rel)

    @classmethod
    def of_types(cls, *iris: str) -> TypeQuery:
        """Shortcut for ``TypeQuery().all_of(*iris)``."""
        return cls().all_of(*iris)

    def to_json(self) -> dict[str, Any]:
        return {k: [g if isinstance(g, str) else list(g) for g in v]
                for k, v in self._filters.items() if v}

    def __repr__(self) -> str:
        return f"TypeQuery({self.to_json()!r})"


class _RelationFilter:
    __slots__ = ("_query", "_rel")

    def __init__(self, query: TypeQuery, rel: str) -> None:
        self._query = query
        self._rel = rel

    def all_of(self, *iris: str) -> TypeQuery:
        return self._query.all_of(*iris, key=self._rel)

    def any_of(self, *iris: str) -> TypeQuery:
        return self._query.any_of(*iris, key=self._rel)
