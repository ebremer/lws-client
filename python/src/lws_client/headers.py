# SPDX-License-Identifier: MIT
"""HTTP header helpers: RFC 8288 ``Link``, RFC 9110 ``WWW-Authenticate`` and RFC 5023 ``Slug``."""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from urllib.parse import unquote

from ._util import resolve

__all__ = [
    "Link",
    "parse_link_header",
    "serialize_links",
    "AuthChallenge",
    "parse_www_authenticate",
    "encode_slug",
    "decode_ext_value",
]

_TCHAR = set("!#$%&'*+-.^_`|~0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")
_TOKEN68_RE = re.compile(r"[A-Za-z0-9\-._~+/]+=*")
_WS = " \t\r\n"


def _is_extension_rel(rel: str) -> bool:
    return ":" in rel


@dataclass(frozen=True, slots=True)
class Link:
    """A single typed link (RFC 8288).

    ``href`` is absolute when produced by :func:`parse_link_header` (resolved against the
    request URL). ``params`` holds target attributes other than ``rel`` with lower-cased
    names; a valueless parameter has the value ``""``.
    """

    href: str
    rel: str
    params: Mapping[str, str] = field(default_factory=dict)

    @property
    def type(self) -> str | None:
        """The ``type`` target attribute (media type hint), if any."""
        return self.params.get("type")

    @property
    def anchor(self) -> str | None:
        """The ``anchor`` parameter as given (unresolved), if any."""
        return self.params.get("anchor")

    @property
    def title(self) -> str | None:
        """``title*`` (decoded) or ``title``."""
        star = self.params.get("title*")
        if star:
            decoded = decode_ext_value(star)
            if decoded is not None:
                return decoded
        return self.params.get("title")

    def serialize(self) -> str:
        """Serialise as a ``Link`` header link-value: ``<href>; rel="rel"; name="value"``."""
        parts = [f"<{self.href}>", f'rel="{_escape(self.rel)}"']
        for name, value in self.params.items():
            if name.lower() == "rel":
                continue
            if value == "":
                parts.append(name)
            elif name.endswith("*"):
                parts.append(f"{name}={value}")
            else:
                parts.append(f'{name}="{_escape(value)}"')
        return "; ".join(parts)

    def __str__(self) -> str:
        return self.serialize()


def _escape(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"')


def serialize_links(links: Iterable[Link]) -> str:
    """Serialise several links into one ``Link`` header field value."""
    return ", ".join(link.serialize() for link in links)


class _Scanner:
    __slots__ = ("pos", "text")

    def __init__(self, text: str) -> None:
        self.text = text
        self.pos = 0

    def eof(self) -> bool:
        return self.pos >= len(self.text)

    def peek(self) -> str:
        return self.text[self.pos] if self.pos < len(self.text) else ""

    def skip_ws(self) -> None:
        while self.pos < len(self.text) and self.text[self.pos] in _WS:
            self.pos += 1

    def token(self) -> str:
        start = self.pos
        while self.pos < len(self.text) and self.text[self.pos] in _TCHAR:
            self.pos += 1
        return self.text[start : self.pos]

    def quoted(self) -> str:
        """Read a quoted-string starting at the opening quote; returns the unescaped value."""
        assert self.peek() == '"'
        self.pos += 1
        out: list[str] = []
        while self.pos < len(self.text):
            ch = self.text[self.pos]
            self.pos += 1
            if ch == "\\" and self.pos < len(self.text):
                out.append(self.text[self.pos])
                self.pos += 1
            elif ch == '"':
                return "".join(out)
            else:
                out.append(ch)
        return "".join(out)  # unterminated: be lenient

    def skip_to(self, stops: str) -> None:
        """Advance to the next unquoted character in ``stops`` (or end)."""
        while self.pos < len(self.text) and self.text[self.pos] not in stops:
            if self.text[self.pos] == '"':
                self.quoted()
            else:
                self.pos += 1


def parse_link_header(values: str | Iterable[str], base: str = "") -> list[Link]:
    """Parse one or more ``Link`` header field values (RFC 8288).

    Commas inside ``<...>`` and quoted strings do not split links; a ``rel`` holding several
    space-separated relation types yields one :class:`Link` per relation type. Registered
    relation types are lower-cased; extension relation URIs are kept as-is. Targets are
    resolved against ``base``.
    """
    if isinstance(values, str):
        values = [values]
    links: list[Link] = []
    for value in values:
        s = _Scanner(value)
        while True:
            s.skip_ws()
            while s.peek() == ",":
                s.pos += 1
                s.skip_ws()
            if s.eof():
                break
            if s.peek() != "<":
                s.skip_to(",")  # malformed link-value: skip it
                continue
            end = value.find(">", s.pos)
            if end < 0:
                break
            target = value[s.pos + 1 : end].strip()
            s.pos = end + 1
            params: dict[str, str] = {}
            rels: list[str] = []
            while True:
                s.skip_ws()
                if s.peek() != ";":
                    break
                s.pos += 1
                s.skip_ws()
                name = s.token().lower()
                if not name:
                    s.skip_to(";,")
                    continue
                s.skip_ws()
                param_value = ""
                if s.peek() == "=":
                    s.pos += 1
                    s.skip_ws()
                    if s.peek() == '"':
                        param_value = s.quoted()
                    else:
                        start = s.pos
                        s.skip_to(";," + _WS)
                        param_value = value[start : s.pos]
                if name == "rel":
                    if not rels:
                        rels = param_value.split()
                elif name not in params:
                    params[name] = param_value
            s.skip_to(",")
            href = resolve(base, target)
            for rel in rels:
                links.append(
                    Link(href=href, rel=rel if _is_extension_rel(rel) else rel.lower(), params=params)
                )
    return links


@dataclass(frozen=True, slots=True)
class AuthChallenge:
    """One authentication challenge from ``WWW-Authenticate``."""

    scheme: str
    params: Mapping[str, str] = field(default_factory=dict)
    token68: str | None = None

    def is_scheme(self, scheme: str) -> bool:
        return self.scheme.lower() == scheme.lower()

    @property
    def as_uri(self) -> str | None:
        """The LWS ``as_uri`` parameter (authorization server issuer)."""
        return self.params.get("as_uri")

    @property
    def realm(self) -> str | None:
        return self.params.get("realm")

    @property
    def error(self) -> str | None:
        return self.params.get("error")

    @property
    def error_description(self) -> str | None:
        return self.params.get("error_description")


def _try_auth_param(s: _Scanner) -> tuple[str, str] | None:
    """Try to read ``token BWS "=" BWS (token / quoted-string)``; restore position on failure."""
    start = s.pos
    name = s.token()
    if not name:
        s.pos = start
        return None
    s.skip_ws()
    if s.peek() != "=":
        s.pos = start
        return None
    s.pos += 1
    s.skip_ws()
    if s.peek() == '"':
        return name.lower(), s.quoted()
    value = s.token()
    if not value:
        s.pos = start
        return None
    return name.lower(), value


def parse_www_authenticate(values: str | Iterable[str]) -> list[AuthChallenge]:
    """Parse ``WWW-Authenticate`` field values into challenges (RFC 9110 §11.6.1).

    Several challenges may appear in one field value. Parameter names are lower-cased and
    values unquoted.
    """
    if isinstance(values, str):
        values = [values]
    challenges: list[AuthChallenge] = []
    for value in values:
        s = _Scanner(value)
        while True:
            s.skip_ws()
            while s.peek() == ",":
                s.pos += 1
                s.skip_ws()
            if s.eof():
                break
            scheme = s.token()
            if not scheme:
                s.skip_to(",")
                continue
            params: dict[str, str] = {}
            token68: str | None = None
            s.skip_ws()
            first = _try_auth_param(s)
            if first is not None:
                params.setdefault(*first)
            else:
                m = _TOKEN68_RE.match(value, s.pos)
                if m:
                    after = _Scanner(value)
                    after.pos = m.end()
                    after.skip_ws()
                    if after.eof() or after.peek() == ",":
                        token68 = m.group(0)
                        s.pos = m.end()
            if first is not None:
                while True:
                    save = s.pos
                    s.skip_ws()
                    if s.peek() != ",":
                        s.pos = save
                        break
                    s.pos += 1
                    s.skip_ws()
                    while s.peek() == ",":
                        s.pos += 1
                        s.skip_ws()
                    param = _try_auth_param(s)
                    if param is None:
                        s.pos = save  # next challenge starts here
                        break
                    params.setdefault(*param)
            challenges.append(AuthChallenge(scheme=scheme, params=params, token68=token68))
            s.skip_ws()
            if s.peek() not in (",", ""):
                s.skip_to(",")
    return challenges


def encode_slug(slug: str) -> str:
    """Encode an identity hint for the ``Slug`` header (RFC 5023 §9.7).

    Printable ASCII is kept; ``%``, control characters and non-ASCII characters are
    percent-encoded as UTF-8.
    """
    out: list[str] = []
    for ch in slug:
        code = ord(ch)
        if 0x20 <= code <= 0x7E and ch != "%":
            out.append(ch)
        else:
            out.extend(f"%{b:02X}" for b in ch.encode("utf-8"))
    return "".join(out)


def decode_ext_value(value: str) -> str | None:
    """Decode an RFC 8187 ext-value such as ``UTF-8''n%C3%A4me``; ``None`` if malformed."""
    parts = value.split("'", 2)
    if len(parts) != 3:
        return None
    charset = parts[0] or "utf-8"
    try:
        return unquote(parts[2], encoding=charset, errors="strict")
    except (LookupError, UnicodeDecodeError):
        return None
