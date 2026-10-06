# SPDX-License-Identifier: MIT
"""Notification data model and webhook subscriptions (lws10-core §Notifications,
lws10-notifications-webhook)."""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from ._util import format_datetime, has_type, parse_datetime, resolve, string_list
from .constants import LWS_CONTEXT, SUBSCRIPTION_WEBHOOK, ActivityType
from .errors import ProtocolError

__all__ = [
    "ActivityObject",
    "Activity",
    "Notification",
    "parse_notification",
    "WebhookSubscriptionRequest",
    "Subscription",
]


@dataclass(frozen=True, slots=True)
class ActivityObject:
    """The resource an activity is about."""

    id: str
    types: tuple[str, ...] = ()

    def has_type(self, type_: str) -> bool:
        return has_type(self.types, type_)


@dataclass(frozen=True, slots=True)
class Activity:
    """An Activity Streams 2.0 activity describing a change to a resource."""

    id: str
    types: tuple[str, ...]
    object: ActivityObject
    published: datetime | None = None
    published_raw: str | None = None
    actor: str | None = None
    target: str | None = None
    origin: str | None = None
    raw: Mapping[str, Any] = field(default_factory=dict)

    @classmethod
    def from_json(cls, data: Mapping[str, Any]) -> Activity:
        obj = data.get("object")
        if isinstance(obj, str):
            obj = {"id": obj}
        if not isinstance(obj, dict) or not isinstance(obj.get("id"), str):
            raise ProtocolError("activity has no 'object' with an 'id'")
        published = data.get("published")

        def ref(name: str) -> str | None:
            value = data.get(name)
            if isinstance(value, dict):
                value = value.get("id")
            return value if isinstance(value, str) else None

        return cls(
            id=str(data.get("id", "")),
            types=string_list(data.get("type")),
            object=ActivityObject(obj["id"], string_list(obj.get("type"))),
            published=parse_datetime(published),
            published_raw=published if isinstance(published, str) else None,
            actor=ref("actor"),
            target=ref("target"),
            origin=ref("origin"),
            raw=dict(data),
        )

    def _is(self, t: str) -> bool:
        return t in self.types or f"as:{t}" in self.types or (
            f"https://www.w3.org/ns/activitystreams#{t}" in self.types
        )

    @property
    def is_create(self) -> bool:
        return self._is(ActivityType.CREATE)

    @property
    def is_update(self) -> bool:
        return self._is(ActivityType.UPDATE)

    @property
    def is_delete(self) -> bool:
        return self._is(ActivityType.DELETE)


@dataclass(frozen=True, slots=True)
class Notification:
    """A notification envelope: the storage plus one or more activities."""

    storage: str
    activities: tuple[Activity, ...]
    raw: Mapping[str, Any] = field(default_factory=dict)

    @classmethod
    def from_json(cls, data: Mapping[str, Any]) -> Notification:
        if not isinstance(data, Mapping):
            raise ProtocolError("notification must be a JSON object")
        if "Notification" not in string_list(data.get("type")):
            raise ProtocolError("document is not a Notification")
        storage = data.get("storage")
        if not isinstance(storage, str):
            raise ProtocolError("notification has no 'storage'")
        raw_activity = data.get("activity")
        entries = raw_activity if isinstance(raw_activity, list) else [raw_activity]
        activities = tuple(Activity.from_json(a) for a in entries if isinstance(a, dict))
        return cls(storage=storage, activities=activities, raw=dict(data))


def parse_notification(data: bytes | str | Mapping[str, Any]) -> Notification:
    """Parse a notification envelope from bytes, text or an already-decoded JSON object."""
    if isinstance(data, (bytes, bytearray, str)):
        try:
            data = json.loads(data)
        except ValueError as exc:
            raise ProtocolError(f"notification is not valid JSON: {exc}") from exc
    if not isinstance(data, Mapping):
        raise ProtocolError("notification must be a JSON object")
    return Notification.from_json(data)


@dataclass(frozen=True, slots=True)
class WebhookSubscriptionRequest:
    """Body of a webhook subscription request."""

    topics: Sequence[str]
    inbox: str
    expires: datetime | str | None = None
    extra: Mapping[str, Any] = field(default_factory=dict)

    def to_json(self) -> dict[str, Any]:
        body: dict[str, Any] = {
            "@context": [LWS_CONTEXT],
            "type": SUBSCRIPTION_WEBHOOK,
            "topic": list(self.topics),
            "inbox": self.inbox,
        }
        if self.expires is not None:
            body["expires"] = format_datetime(self.expires)
        body.update(self.extra)
        return body


@dataclass(frozen=True, slots=True)
class Subscription:
    """A subscription as returned by the notification service."""

    type: str
    subscription: str
    expires: datetime | None = None
    expires_raw: str | None = None
    raw: Mapping[str, Any] = field(default_factory=dict)

    @classmethod
    def from_json(
        cls, data: Mapping[str, Any], base: str = "", location: str | None = None
    ) -> Subscription:
        if not isinstance(data, Mapping):
            raise ProtocolError("subscription must be a JSON object")
        url = data.get("subscription", data.get("id"))
        if not isinstance(url, str):
            url = location
        if not isinstance(url, str):
            raise ProtocolError("subscription response has neither 'subscription' nor Location")
        expires = data.get("expires")
        types = string_list(data.get("type"))
        return cls(
            type=types[0] if types else SUBSCRIPTION_WEBHOOK,
            subscription=resolve(base, url),
            expires=parse_datetime(expires),
            expires_raw=expires if isinstance(expires, str) else None,
            raw=dict(data),
        )

    @property
    def url(self) -> str:
        """Alias of :attr:`subscription` — the URL that manages this subscription."""
        return self.subscription
