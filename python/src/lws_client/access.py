# SPDX-License-Identifier: MIT
"""Access requests and access grants (lws10-core §Access Requests and Grants), using the
ODRL-based LWS Access Profile."""

from __future__ import annotations

import copy
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from ._util import as_list, format_datetime, string_list
from .constants import (
    LWS_CONTEXT,
    TYPE_ACCESS_GRANT,
    TYPE_ACCESS_POLICY,
    TYPE_ACCESS_REQUEST,
    Operand,
    Operator,
)
from .errors import ProtocolError

__all__ = ["Constraint", "AccessTarget", "AccessPolicy", "AccessRequest", "AccessGrant"]


@dataclass(frozen=True, slots=True)
class Constraint:
    """An ODRL constraint: ``leftOperand``, ``operator`` and ``rightOperand``."""

    left_operand: str
    operator: str
    right_operand: Any

    def to_json(self) -> dict[str, Any]:
        return {
            "leftOperand": self.left_operand,
            "operator": self.operator,
            "rightOperand": copy.deepcopy(self.right_operand),
        }

    @classmethod
    def from_json(cls, data: Mapping[str, Any]) -> Constraint:
        return cls(
            str(data.get("leftOperand", "")),
            str(data.get("operator", "")),
            copy.deepcopy(data.get("rightOperand")),
        )

    # convenience factories --------------------------------------------------------------

    @classmethod
    def purpose(cls, uri: str) -> Constraint:
        return cls(Operand.PURPOSE, Operator.EQ, uri)

    @classmethod
    def purpose_any_of(cls, *uris: str) -> Constraint:
        return cls(Operand.PURPOSE, Operator.IS_ANY_OF, list(uris))

    @classmethod
    def client(cls, uri: str) -> Constraint:
        return cls(Operand.CLIENT, Operator.EQ, uri)

    @classmethod
    def format(cls, media_type: str) -> Constraint:
        return cls(Operand.FORMAT, Operator.EQ, media_type)

    @classmethod
    def format_any_of(cls, *media_types: str) -> Constraint:
        return cls(Operand.FORMAT, Operator.IS_ANY_OF, list(media_types))

    @classmethod
    def resource_type(cls, uri: str) -> Constraint:
        """``type eq uri`` — restrict by the resource's ``rel="type"`` link targets."""
        return cls(Operand.TYPE, Operator.EQ, uri)

    @classmethod
    def resource_type_any_of(cls, *uris: str) -> Constraint:
        return cls(Operand.TYPE, Operator.IS_ANY_OF, list(uris))

    @classmethod
    def not_before(cls, when: datetime | str) -> Constraint:
        """``dateTime gteq when`` — start of a time window."""
        return cls(Operand.DATE_TIME, Operator.GTEQ, format_datetime(when))

    @classmethod
    def not_after(cls, when: datetime | str) -> Constraint:
        """``dateTime lteq when`` — end of a time window."""
        return cls(Operand.DATE_TIME, Operator.LTEQ, format_datetime(when))


@dataclass(frozen=True, slots=True)
class AccessTarget:
    """Which resources a policy applies to: a target matcher ``type`` and ``value`` list."""

    type: str
    values: Sequence[str]

    def to_json(self) -> dict[str, Any]:
        return {"type": self.type, "value": list(self.values)}

    @classmethod
    def from_json(cls, data: Mapping[str, Any]) -> AccessTarget:
        return cls(str(data.get("type", "")), string_list(data.get("value")))


@dataclass(frozen=True, slots=True)
class AccessPolicy:
    """One entry of ``access``: actions an assignee may perform on targets, with constraints."""

    actions: Sequence[str]
    assignee: str
    target: AccessTarget | None = None
    constraints: Sequence[Constraint] = ()
    types: Sequence[str] = (TYPE_ACCESS_POLICY,)
    extra: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.actions:
            raise ValueError("an access policy needs at least one action")
        if not self.assignee:
            raise ValueError("an access policy needs an assignee")

    def to_json(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "type": list(self.types),
            "action": list(self.actions),
            "assignee": self.assignee,
        }
        if self.target is not None:
            out["target"] = self.target.to_json()
        if self.constraints:
            out["constraint"] = [c.to_json() for c in self.constraints]
        out.update(copy.deepcopy(dict(self.extra)))
        return out

    @classmethod
    def from_json(cls, data: Mapping[str, Any]) -> AccessPolicy:
        target = data.get("target")
        known = {"type", "action", "assignee", "target", "constraint"}
        try:
            return cls(
                actions=string_list(data.get("action")),
                assignee=str(data.get("assignee", "")),
                target=AccessTarget.from_json(target) if isinstance(target, dict) else None,
                constraints=tuple(
                    Constraint.from_json(c) for c in as_list(data.get("constraint"))
                    if isinstance(c, dict)
                ),
                types=string_list(data.get("type")) or (TYPE_ACCESS_POLICY,),
                extra={k: v for k, v in data.items() if k not in known},
            )
        except ValueError as exc:
            raise ProtocolError(f"invalid access policy: {exc}") from exc


def _parse_common(data: Mapping[str, Any], required_type: str) -> dict[str, Any]:
    if not isinstance(data, Mapping):
        raise ProtocolError("access document must be a JSON object")
    types = string_list(data.get("type"))
    if required_type not in types:
        raise ProtocolError(f"document is not an {required_type}")
    storage = data.get("storage")
    if not isinstance(storage, str):
        raise ProtocolError(f"{required_type} has no 'storage'")
    inbox = data.get("inbox")
    known = {"@context", "type", "storage", "inbox", "access"}
    return {
        "storage": storage,
        "access": tuple(
            AccessPolicy.from_json(p) for p in as_list(data.get("access")) if isinstance(p, dict)
        ),
        "inbox": inbox if isinstance(inbox, str) else None,
        "types": types,
        "extra": {k: v for k, v in data.items() if k not in known},
    }


@dataclass(frozen=True, slots=True)
class _AccessDocument:
    storage: str
    access: Sequence[AccessPolicy]
    inbox: str | None = None
    types: Sequence[str] = ()
    extra: Mapping[str, Any] = field(default_factory=dict)

    _REQUIRED_TYPE = ""

    def __post_init__(self) -> None:
        if not self.storage:
            raise ValueError("'storage' is required")
        if not self.access:
            raise ValueError("at least one access policy is required")

    def to_json(self) -> dict[str, Any]:
        types = list(self.types) or [self._REQUIRED_TYPE]
        if self._REQUIRED_TYPE not in types:
            types.insert(0, self._REQUIRED_TYPE)
        out: dict[str, Any] = {"@context": [LWS_CONTEXT], "type": types}
        if self.inbox is not None:
            out["inbox"] = self.inbox
        out["storage"] = self.storage
        out["access"] = [p.to_json() for p in self.access]
        out.update(copy.deepcopy(dict(self.extra)))
        return out


@dataclass(frozen=True, slots=True)
class AccessRequest(_AccessDocument):
    """A request by an agent for access to resources."""

    _REQUIRED_TYPE = TYPE_ACCESS_REQUEST

    @classmethod
    def from_json(cls, data: Mapping[str, Any]) -> AccessRequest:
        try:
            return cls(**_parse_common(data, TYPE_ACCESS_REQUEST))
        except ValueError as exc:
            raise ProtocolError(f"invalid access request: {exc}") from exc


@dataclass(frozen=True, slots=True)
class AccessGrant(_AccessDocument):
    """A storage controller's record of access granted to an agent."""

    _REQUIRED_TYPE = TYPE_ACCESS_GRANT

    @classmethod
    def from_json(cls, data: Mapping[str, Any]) -> AccessGrant:
        try:
            return cls(**_parse_common(data, TYPE_ACCESS_GRANT))
        except ValueError as exc:
            raise ProtocolError(f"invalid access grant: {exc}") from exc
