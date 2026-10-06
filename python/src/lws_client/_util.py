# SPDX-License-Identifier: MIT
"""Small internal helpers: base64url, URL handling, dates, type matching, header lists."""

from __future__ import annotations

import base64
import json
import re
from collections.abc import Iterable, Mapping, Sequence
from datetime import datetime, timedelta, timezone
from typing import Any
from urllib.parse import urljoin, urlsplit, urlunsplit

from .constants import LWS_NS

_DEFAULT_PORTS = {"http": 80, "https": 443}


def b64url_encode(data: bytes) -> str:
    """Base64url without padding (RFC 7515)."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64url_decode(data: str) -> bytes:
    """Decode base64url, tolerating missing padding."""
    pad = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + pad)


def resolve(base: str, ref: str) -> str:
    """Resolve ``ref`` against ``base`` (RFC 3986)."""
    if not base:
        return ref
    return urljoin(base, ref)


def strip_fragment(url: str) -> str:
    return url.split("#", 1)[0]


def origin_parts(url: str) -> tuple[str, str, int | None]:
    """Return ``(scheme, host, port)`` with lower-cased scheme/host and explicit default port."""
    parts = urlsplit(url)
    scheme = parts.scheme.lower()
    host = (parts.hostname or "").lower()
    try:
        port = parts.port
    except ValueError:
        port = None
    if port is None:
        port = _DEFAULT_PORTS.get(scheme)
    return scheme, host, port


def is_loopback(url: str) -> bool:
    host = (urlsplit(url).hostname or "").lower()
    return host in {"localhost", "127.0.0.1", "::1"} or host.endswith(".localhost")


def authority(url: str) -> str:
    """The RFC 9421 ``@authority`` value: lower-case host plus ``:port`` only if non-default."""
    parts = urlsplit(url)
    scheme = parts.scheme.lower()
    host = (parts.hostname or "").lower()
    if ":" in host:
        host = f"[{host}]"
    port = parts.port
    if port is not None and port != _DEFAULT_PORTS.get(scheme):
        return f"{host}:{port}"
    return host


def with_path(url: str, path: str) -> str:
    parts = urlsplit(url)
    return urlunsplit((parts.scheme, parts.netloc, path, "", ""))


def is_absolute_iri(value: object) -> bool:
    """True if ``value`` is a string with a URI scheme and no whitespace."""
    return (
        isinstance(value, str)
        and re.match(r"^[A-Za-z][A-Za-z0-9+.\-]*:", value) is not None
        and not any(c.isspace() for c in value)
    )


# --- types -----------------------------------------------------------------------------


def as_list(value: Any) -> list[Any]:
    """Normalise a JSON value that may be a single item or an array into a list."""
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def string_list(value: Any) -> tuple[str, ...]:
    return tuple(v for v in as_list(value) if isinstance(v, str))


def expand_term(term: str) -> str:
    """Expand ``Term`` / ``lws:Term`` to ``https://www.w3.org/ns/lws#Term``; IRIs are kept."""
    if term.startswith("lws:"):
        return LWS_NS + term[4:]
    if ":" not in term:
        return LWS_NS + term
    return term


def has_type(types: Iterable[str], wanted: str) -> bool:
    """Type membership treating ``Term``, ``lws:Term`` and the full LWS IRI as equal."""
    target = expand_term(wanted)
    return any(expand_term(t) == target for t in types)


# --- dates -----------------------------------------------------------------------------

_DT_RE = re.compile(
    r"^(\d{4})-(\d{2})-(\d{2})[Tt ](\d{2}):(\d{2}):(\d{2})(\.\d+)?([Zz]|[+-]\d{2}:?\d{2})?$"
)


def parse_datetime(value: Any) -> datetime | None:
    """Parse an RFC 3339 / ISO 8601 date-time into an aware ``datetime``; ``None`` if invalid.

    A missing offset is interpreted as UTC.
    """
    if not isinstance(value, str):
        return None
    m = _DT_RE.match(value.strip())
    if not m:
        return None
    year, month, day, hour, minute, second = (int(m.group(i)) for i in range(1, 7))
    frac = m.group(7)
    micro = int((frac[1:] + "000000")[:6]) if frac else 0
    tz_text = m.group(8)
    tz = timezone.utc
    if tz_text and tz_text not in ("Z", "z"):
        sign = 1 if tz_text[0] == "+" else -1
        digits = tz_text[1:].replace(":", "")
        tz = timezone(sign * timedelta(hours=int(digits[:2]), minutes=int(digits[2:])))
    try:
        if second == 60:  # leap second: clamp
            second = 59
        return datetime(year, month, day, hour, minute, second, micro, tzinfo=tz)
    except ValueError:
        return None


def format_datetime(value: datetime | str) -> str:
    """Format as RFC 3339 in UTC with a ``Z`` suffix (strings pass through)."""
    if isinstance(value, str):
        return value
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    value = value.astimezone(timezone.utc)
    text = value.isoformat(timespec="microseconds" if value.microsecond else "seconds")
    return text.replace("+00:00", "Z")


# --- header helpers -------------------------------------------------------------------


def split_header_list(values: Iterable[str]) -> list[str]:
    """Split comma-separated header lists, honouring quoted strings."""
    out: list[str] = []
    for value in values:
        current: list[str] = []
        in_quotes = False
        escaped = False
        for ch in value:
            if escaped:
                current.append(ch)
                escaped = False
            elif ch == "\\" and in_quotes:
                current.append(ch)
                escaped = True
            elif ch == '"':
                in_quotes = not in_quotes
                current.append(ch)
            elif ch == "," and not in_quotes:
                item = "".join(current).strip()
                if item:
                    out.append(item)
                current = []
            else:
                current.append(ch)
        item = "".join(current).strip()
        if item:
            out.append(item)
    return out


def media_type_essence(content_type: str | None) -> str:
    """``type/subtype`` in lower case without parameters."""
    if not content_type:
        return ""
    return content_type.split(";", 1)[0].strip().lower()


def charset_of(content_type: str | None) -> str:
    if content_type:
        for part in content_type.split(";")[1:]:
            name, _, value = part.partition("=")
            if name.strip().lower() == "charset" and value.strip():
                return value.strip().strip('"')
    return "utf-8"


def json_loads(data: bytes | str) -> Any:
    return json.loads(data)


def json_dumps(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def frozen_mapping(value: Mapping[str, Any] | None) -> dict[str, Any]:
    return dict(value) if value else {}


def first(seq: Sequence[Any]) -> Any:
    return seq[0] if seq else None
