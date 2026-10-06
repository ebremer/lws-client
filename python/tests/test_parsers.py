# SPDX-License-Identifier: MIT
"""Shared-fixture tests for Link, WWW-Authenticate, structured fields, JSON Patch and TypeQuery."""

from __future__ import annotations

import base64
from typing import Any

import pytest
from conftest import load

from lws_client import (
    JsonPatch,
    JsonPointer,
    Link,
    TypeQuery,
    encode_slug,
    parse_link_header,
    parse_www_authenticate,
    serialize_links,
)
from lws_client.headers import decode_ext_value
from lws_client.structured_fields import (
    Date,
    InnerList,
    Item,
    StructuredFieldError,
    Token,
    parse_dictionary,
    parse_list,
    serialize_bare_item,
    serialize_dictionary,
    serialize_inner_list,
    serialize_member,
)

LINK_CASES = load("link-headers.json")["cases"]
AUTH_CASES = load("www-authenticate.json")["cases"]
SF_CASES = load("structured-fields.json")["cases"]
PATCH = load("json-patch.json")
QUERY_CASES = load("type-queries.json")["cases"]


@pytest.mark.parametrize("case", LINK_CASES, ids=[c["name"] for c in LINK_CASES])
def test_link_header_fixture(case: dict[str, Any]) -> None:
    links = parse_link_header(case["headers"], case["base"])
    assert [{"href": lk.href, "rel": lk.rel, "params": dict(lk.params)} for lk in links] == case[
        "expected"
    ]


def test_link_serialization_roundtrip() -> None:
    links = [
        Link("https://example.org/a", "describedby", {"type": "text/turtle", "title": 'say "hi"'}),
        Link("https://www.w3.org/ns/lws#Container", "type"),
        Link("https://example.org/e", "alternate", {"crossorigin": ""}),
    ]
    header = serialize_links(links)
    assert header.startswith('<https://example.org/a>; rel="describedby"; type="text/turtle"')
    parsed = parse_link_header(header, "https://example.org/")
    assert [(p.href, p.rel, dict(p.params)) for p in parsed] == [
        (lk.href, lk.rel, dict(lk.params)) for lk in links
    ]
    assert parsed[0].type == "text/turtle"


def test_link_title_star_decoding() -> None:
    (link,) = parse_link_header("<https://example.org/h>; rel=related; title*=UTF-8''n%C3%A4me")
    assert link.params["title*"] == "UTF-8''n%C3%A4me"
    assert link.title == "näme"
    assert decode_ext_value("bogus") is None


@pytest.mark.parametrize("case", AUTH_CASES, ids=[c["name"] for c in AUTH_CASES])
def test_www_authenticate_fixture(case: dict[str, Any]) -> None:
    challenges = parse_www_authenticate(case["headers"])
    assert len(challenges) == len(case["expected"])
    for got, exp in zip(challenges, case["expected"], strict=True):
        assert got.scheme.lower() == exp["scheme"].lower()
        assert dict(got.params) == exp["params"]
        assert got.token68 == exp.get("token68")


def test_challenge_accessors() -> None:
    (ch,) = parse_www_authenticate(
        'Bearer as_uri="https://as.example", realm="https://s.example/", error="invalid_token", '
        'error_description="expired"'
    )
    assert ch.is_scheme("bearer")
    assert (ch.as_uri, ch.realm, ch.error, ch.error_description) == (
        "https://as.example", "https://s.example/", "invalid_token", "expired"
    )


def _bare(value: Any) -> Any:
    if isinstance(value, bool):
        return {"boolean": value}
    if isinstance(value, Date):
        return {"date": int(value)}
    if isinstance(value, int):
        return {"integer": value}
    if isinstance(value, float):
        return {"decimal": value}
    if isinstance(value, Token):
        return {"token": str(value)}
    if isinstance(value, str):
        return {"string": value}
    if isinstance(value, bytes):
        return {"bytes": base64.b64encode(value).decode()}
    raise AssertionError(value)


def _member(member: Item | InnerList) -> Any:
    params = {k: _bare(v) for k, v in member.params.items()}
    if isinstance(member, InnerList):
        return {"innerList": [_member(i) for i in member.items], "params": params}
    return {"item": _bare(member.value), "params": params}


@pytest.mark.parametrize("case", SF_CASES, ids=[c["name"] for c in SF_CASES])
def test_structured_fields_fixture(case: dict[str, Any]) -> None:
    if case.get("error"):
        with pytest.raises(StructuredFieldError):
            parse_dictionary(case["input"])
        return
    parsed = parse_dictionary(case["input"])
    assert {k: _member(v) for k, v in parsed.items()} == case["expected"]
    assert list(parsed) == list(case["expected"])
    for key, text in case.get("serialized", {}).items():
        assert serialize_member(parsed[key]) == text
    # canonical re-serialisation parses back to the same structure
    assert parse_dictionary(serialize_dictionary(parsed)) == parsed


def test_structured_field_lists_and_items() -> None:
    assert parse_list('"a", tok, (1 2);p') == [
        Item("a"), Item(Token("tok")), InnerList([Item(1), Item(2)], {"p": True})
    ]
    assert serialize_bare_item(2.5) == "2.5"
    assert serialize_bare_item(Date(1659578233)) == "@1659578233"
    assert serialize_inner_list(InnerList([Item("@method")], {"created": 1})) == '("@method");created=1'
    assert parse_dictionary("d=@1659578233") == {"d": Item(Date(1659578233))}
    assert parse_dictionary('s=%"f%c3%bc%c3%bc"')["s"].value == "füü"


def test_json_pointer_fixture() -> None:
    for case in PATCH["pointerEscapes"]:
        assert JsonPointer.escape(case["segment"]) == case["escaped"]
        assert JsonPointer.unescape(case["escaped"]) == case["segment"]
    for case in PATCH["pointers"]:
        assert JsonPointer.from_segments(*case["segments"]) == case["pointer"]
        assert JsonPointer.segments(case["pointer"]) == case["segments"]


def test_json_patch_fixture() -> None:
    ops = PATCH["patch"]["operations"]
    patch = (
        JsonPatch()
        .add(ops[0]["path"], ops[0]["value"])
        .remove(ops[1]["path"])
        .replace(ops[2]["path"], ops[2]["value"])
        .move(ops[3]["from"], ops[3]["path"])
        .copy(ops[4]["from"], ops[4]["path"])
        .test(ops[5]["path"], ops[5]["value"])
    )
    assert patch.to_json() == ops
    assert len(patch) == 6
    assert JsonPatch(ops) == patch


@pytest.mark.parametrize("case", QUERY_CASES, ids=[c["name"] for c in QUERY_CASES])
def test_type_query_fixture(case: dict[str, Any]) -> None:
    def build() -> TypeQuery:
        query = TypeQuery()
        for step in case["steps"]:
            if "allOf" in step:
                query.all_of(*step["allOf"], key=step["key"])
            else:
                query.any_of(*step["anyOf"], key=step["key"])
        return query

    if case.get("error"):
        with pytest.raises(ValueError):
            build()
    else:
        assert build().to_json() == case["json"]


def test_type_query_relation_builder() -> None:
    q = TypeQuery.of_types("https://schema.org/Person").relation("describedby").any_of(
        "https://example.org/shapes/person", "https://example.org/shapes/agent"
    )
    assert q.to_json() == {
        "type": ["https://schema.org/Person"],
        "describedby": [["https://example.org/shapes/person", "https://example.org/shapes/agent"]],
    }


def test_slug_encoding() -> None:
    assert encode_slug("hello.txt") == "hello.txt"
    assert encode_slug("naïve 100%") == "na%C3%AFve 100%25"
