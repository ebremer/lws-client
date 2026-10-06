# SPDX-License-Identifier: MIT
"""RFC 8941 / RFC 9651 Structured Field Values — dictionaries, items and inner lists.

This is the subset needed for ``Signature-Input``, ``Signature`` and ``Content-Digest``
(RFC 9421 / RFC 9530): dictionaries whose members are items or inner lists with
parameters. Bare items: integers, decimals, strings, tokens, byte sequences, booleans, plus
RFC 9651 dates and display strings.
"""

from __future__ import annotations

import base64
import binascii
from dataclasses import dataclass, field
from typing import Union

__all__ = [
    "Token",
    "Date",
    "DisplayString",
    "BareItem",
    "Item",
    "InnerList",
    "Member",
    "StructuredFieldError",
    "parse_dictionary",
    "parse_list",
    "serialize_bare_item",
    "serialize_params",
    "serialize_item",
    "serialize_inner_list",
    "serialize_member",
    "serialize_dictionary",
]


class StructuredFieldError(ValueError):
    """Raised when a structured field value cannot be parsed."""


class Token(str):
    """An sf-token (distinct from an sf-string)."""

    __slots__ = ()

    def __repr__(self) -> str:
        return f"Token({str.__repr__(self)})"


class Date(int):
    """An RFC 9651 sf-date (seconds since the epoch)."""

    __slots__ = ()


class DisplayString(str):
    """An RFC 9651 sf-displaystring."""

    __slots__ = ()


BareItem = Union[int, float, str, bytes, bool, Token, Date, DisplayString]


@dataclass(frozen=True, slots=True)
class Item:
    value: BareItem
    params: dict[str, BareItem] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class InnerList:
    items: list[Item]
    params: dict[str, BareItem] = field(default_factory=dict)


Member = Union[Item, InnerList]

_LCALPHA = "abcdefghijklmnopqrstuvwxyz"
_DIGIT = "0123456789"
_KEY_CHARS = set(_LCALPHA + _DIGIT + "_-.*")
_TOKEN_CHARS = set(
    "!#$%&'*+-.^_`|~:/" + _DIGIT + _LCALPHA + _LCALPHA.upper()
)


class _Parser:
    __slots__ = ("pos", "s")

    def __init__(self, text: str) -> None:
        self.s = text
        self.pos = 0

    def error(self, message: str) -> StructuredFieldError:
        return StructuredFieldError(f"{message} at position {self.pos}: {self.s!r}")

    def peek(self) -> str:
        return self.s[self.pos] if self.pos < len(self.s) else ""

    def skip_sp(self) -> None:
        while self.peek() == " ":
            self.pos += 1

    def skip_ows(self) -> None:
        while self.peek() in (" ", "\t") and self.peek() != "":
            self.pos += 1

    def key(self) -> str:
        ch = self.peek()
        if not ch or not (ch in _LCALPHA or ch == "*"):
            raise self.error("invalid key")
        start = self.pos
        while self.peek() and self.peek() in _KEY_CHARS:
            self.pos += 1
        return self.s[start : self.pos]

    def params(self) -> dict[str, BareItem]:
        params: dict[str, BareItem] = {}
        while self.peek() == ";":
            self.pos += 1
            self.skip_sp()
            name = self.key()
            value: BareItem = True
            if self.peek() == "=":
                self.pos += 1
                value = self.bare_item()
            params[name] = value
        return params

    def item(self) -> Item:
        value = self.bare_item()
        return Item(value, self.params())

    def item_or_inner_list(self) -> Member:
        if self.peek() == "(":
            return self.inner_list()
        return self.item()

    def inner_list(self) -> InnerList:
        self.pos += 1  # "("
        items: list[Item] = []
        while self.pos < len(self.s):
            self.skip_sp()
            if self.peek() == ")":
                self.pos += 1
                return InnerList(items, self.params())
            items.append(self.item())
            if self.peek() not in (" ", ")"):
                raise self.error("expected space or ')' in inner list")
        raise self.error("unterminated inner list")

    def bare_item(self) -> BareItem:
        ch = self.peek()
        if ch == "-" or (ch and ch in _DIGIT):
            return self.number()
        if ch == '"':
            return self.string()
        if ch == ":":
            return self.byte_sequence()
        if ch == "?":
            return self.boolean()
        if ch == "@":
            self.pos += 1
            value = self.number()
            if not isinstance(value, int):
                raise self.error("date must be an integer")
            return Date(value)
        if ch == "%":
            return self.display_string()
        if ch and ((ch.isalpha() and ch.isascii()) or ch == "*"):
            return self.token()
        raise self.error("invalid bare item")

    def number(self) -> int | float:
        sign = 1
        if self.peek() == "-":
            sign = -1
            self.pos += 1
        digits_start = self.pos
        if not (self.peek() and self.peek() in _DIGIT):
            raise self.error("expected digit")
        is_decimal = False
        while self.peek() and (self.peek() in _DIGIT or (self.peek() == "." and not is_decimal)):
            if self.peek() == ".":
                if self.pos - digits_start > 12:
                    raise self.error("decimal integer part too long")
                is_decimal = True
            self.pos += 1
        text = self.s[digits_start : self.pos]
        if is_decimal:
            if text.endswith("."):
                raise self.error("decimal must have fractional digits")
            frac = text.split(".", 1)[1]
            if len(frac) > 3:
                raise self.error("too many fractional digits")
            return sign * float(text)
        if len(text) > 15:
            raise self.error("integer too long")
        return sign * int(text)

    def string(self) -> str:
        self.pos += 1
        out: list[str] = []
        while self.pos < len(self.s):
            ch = self.s[self.pos]
            self.pos += 1
            if ch == "\\":
                if self.pos >= len(self.s):
                    break
                nxt = self.s[self.pos]
                self.pos += 1
                if nxt not in ('"', "\\"):
                    raise self.error("invalid escape in string")
                out.append(nxt)
            elif ch == '"':
                return "".join(out)
            elif ord(ch) < 0x20 or ord(ch) > 0x7E:
                raise self.error("invalid character in string")
            else:
                out.append(ch)
        raise self.error("unterminated string")

    def token(self) -> Token:
        start = self.pos
        self.pos += 1
        while self.peek() and self.peek() in _TOKEN_CHARS:
            self.pos += 1
        return Token(self.s[start : self.pos])

    def byte_sequence(self) -> bytes:
        self.pos += 1
        end = self.s.find(":", self.pos)
        if end < 0:
            raise self.error("unterminated byte sequence")
        text = self.s[self.pos : end]
        self.pos = end + 1
        try:
            return base64.b64decode(text + "=" * (-len(text) % 4), validate=True)
        except (binascii.Error, ValueError) as exc:
            raise self.error("invalid base64 in byte sequence") from exc

    def boolean(self) -> bool:
        self.pos += 1
        ch = self.peek()
        if ch == "1":
            self.pos += 1
            return True
        if ch == "0":
            self.pos += 1
            return False
        raise self.error("invalid boolean")

    def display_string(self) -> DisplayString:
        self.pos += 1
        if self.peek() != '"':
            raise self.error("expected '\"' after '%'")
        self.pos += 1
        raw = bytearray()
        while self.pos < len(self.s):
            ch = self.s[self.pos]
            self.pos += 1
            if ch == "%":
                hexpart = self.s[self.pos : self.pos + 2]
                if len(hexpart) != 2 or any(c not in "0123456789abcdef" for c in hexpart):
                    raise self.error("invalid percent-encoding in display string")
                raw.append(int(hexpart, 16))
                self.pos += 2
            elif ch == '"':
                try:
                    return DisplayString(raw.decode("utf-8"))
                except UnicodeDecodeError as exc:
                    raise self.error("invalid UTF-8 in display string") from exc
            else:
                raw.extend(ch.encode("ascii", "strict"))
        raise self.error("unterminated display string")


def parse_dictionary(text: str) -> dict[str, Member]:
    """Parse an sf-dictionary. Duplicate keys: the last occurrence wins (order of first)."""
    p = _Parser(text.strip(" \t"))
    result: dict[str, Member] = {}
    if not p.s:
        return result
    while True:
        name = p.key()
        member: Member
        if p.peek() == "=":
            p.pos += 1
            member = p.item_or_inner_list()
        else:
            member = Item(True, p.params())
        result[name] = member
        p.skip_ows()
        if p.pos >= len(p.s):
            return result
        if p.peek() != ",":
            raise p.error("expected ','")
        p.pos += 1
        p.skip_ows()
        if p.pos >= len(p.s):
            raise p.error("trailing comma")


def parse_list(text: str) -> list[Member]:
    """Parse an sf-list."""
    p = _Parser(text.strip(" \t"))
    result: list[Member] = []
    if not p.s:
        return result
    while True:
        result.append(p.item_or_inner_list())
        p.skip_ows()
        if p.pos >= len(p.s):
            return result
        if p.peek() != ",":
            raise p.error("expected ','")
        p.pos += 1
        p.skip_ows()
        if p.pos >= len(p.s):
            raise p.error("trailing comma")


def serialize_bare_item(value: BareItem) -> str:
    """Canonical serialisation of a bare item (RFC 8941 §4.1.3)."""
    if isinstance(value, bool):
        return "?1" if value else "?0"
    if isinstance(value, Date):
        return f"@{int(value)}"
    if isinstance(value, int):
        return str(value)
    if isinstance(value, float):
        text = f"{round(value, 3):.3f}".rstrip("0")
        return text + "0" if text.endswith(".") else text
    if isinstance(value, Token):
        return str(value)
    if isinstance(value, DisplayString):
        out = []
        for b in value.encode("utf-8"):
            if b == 0x25 or b == 0x22 or b < 0x20 or b > 0x7E:
                out.append(f"%{b:02x}")
            else:
                out.append(chr(b))
        return '%"' + "".join(out) + '"'
    if isinstance(value, str):
        return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'
    if isinstance(value, (bytes, bytearray)):
        return ":" + base64.b64encode(bytes(value)).decode("ascii") + ":"
    raise TypeError(f"cannot serialise {type(value).__name__} as a structured field item")


def serialize_params(params: dict[str, BareItem]) -> str:
    out = []
    for name, value in params.items():
        if value is True:
            out.append(f";{name}")
        else:
            out.append(f";{name}={serialize_bare_item(value)}")
    return "".join(out)


def serialize_item(item: Item) -> str:
    return serialize_bare_item(item.value) + serialize_params(item.params)


def serialize_inner_list(inner: InnerList) -> str:
    """Canonical serialisation, e.g. ``("@method" "@path");created=1;keyid="k"``."""
    return "(" + " ".join(serialize_item(i) for i in inner.items) + ")" + serialize_params(
        inner.params
    )


def serialize_member(member: Member) -> str:
    if isinstance(member, InnerList):
        return serialize_inner_list(member)
    return serialize_item(member)


def serialize_dictionary(dictionary: dict[str, Member]) -> str:
    out = []
    for name, member in dictionary.items():
        if isinstance(member, Item) and member.value is True:
            out.append(name + serialize_params(member.params))
        else:
            out.append(f"{name}={serialize_member(member)}")
    return ", ".join(out)
