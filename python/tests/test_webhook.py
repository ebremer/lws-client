# SPDX-License-Identifier: MIT
"""RFC 9421 webhook vectors (shared fixtures), sync and async."""

from __future__ import annotations

from typing import Any

import pytest
from conftest import load

from lws_client import (
    AsyncWebhookVerifier,
    SignatureVerificationError,
    StorageDescription,
    WebhookVerifier,
    signature_base,
    verify_content_digest,
)
from lws_client.structured_fields import InnerList, parse_dictionary

INDEX = load("webhook/index.json")
DESCRIPTION = load("webhook/storage-description.json")
VECTORS = [load(f"webhook/{name}") for name in INDEX["vectors"]]


def _verifier(now: float, fetched: list[str]) -> WebhookVerifier:
    def fetch(storage_id: str) -> dict[str, Any]:
        fetched.append(storage_id)
        return DESCRIPTION

    return WebhookVerifier(fetch=fetch, clock=lambda: now)


def _check(result_or_error: Any, v: dict[str, Any]) -> None:
    exp = v["expected"]
    if not exp["valid"]:
        assert isinstance(result_or_error, SignatureVerificationError), result_or_error
        return
    assert not isinstance(result_or_error, Exception), result_or_error
    assert result_or_error.keyid == exp["keyid"]
    n = result_or_error.notification
    assert n.storage == exp["notification"]["storage"]
    assert len(n.activities) == len(exp["notification"]["activities"])
    for act, e in zip(n.activities, exp["notification"]["activities"], strict=True):
        assert list(act.types) == e["types"]
        assert act.object.id == e["objectId"]
        if "target" in e:
            assert act.target == e["target"]


def test_vector_count() -> None:
    assert len(VECTORS) == 13
    assert sum(v["expected"]["valid"] for v in VECTORS) == 3


@pytest.mark.parametrize("v", VECTORS, ids=[v["name"] for v in VECTORS])
def test_webhook_vector_sync(v: dict[str, Any]) -> None:
    fetched: list[str] = []
    verifier = _verifier(v["now"], fetched)
    try:
        result: Any = verifier.verify(v["method"], v["url"], v["headers"], v["body"])
    except SignatureVerificationError as exc:
        result = exc
    _check(result, v)


@pytest.mark.anyio
@pytest.mark.parametrize("v", VECTORS, ids=[v["name"] for v in VECTORS])
async def test_webhook_vector_async(v: dict[str, Any]) -> None:
    async def fetch(storage_id: str) -> StorageDescription:
        return StorageDescription.from_json(DESCRIPTION, storage_id)

    verifier = AsyncWebhookVerifier(fetch=fetch, clock=lambda: v["now"])
    try:
        result: Any = await verifier.verify(v["method"], v["url"], v["headers"], v["body"].encode())
    except SignatureVerificationError as exc:
        result = exc
    _check(result, v)


@pytest.mark.parametrize("v", [v for v in VECTORS if v["expected"]["valid"]],
                         ids=[v["name"] for v in VECTORS if v["expected"]["valid"]])
def test_signature_base_matches_fixture(v: dict[str, Any]) -> None:
    _label, member = next(iter(parse_dictionary(v["headers"]["signature-input"]).items()))
    assert isinstance(member, InnerList)
    assert signature_base(v["method"], v["url"], v["headers"], member) == v["signatureBase"]


def test_trusted_storages_and_cache() -> None:
    v = VECTORS[[x["name"] for x in VECTORS].index("p256-valid")]
    fetched: list[str] = []
    verifier = _verifier(v["now"], fetched)
    verifier.verify(v["method"], v["url"], v["headers"], v["body"])
    verifier.verify(v["method"], v["url"], v["headers"], v["body"])
    assert fetched == ["https://storage.example/"]  # cached
    strict = WebhookVerifier(fetch=lambda _: DESCRIPTION, clock=lambda: v["now"],
                             trusted_storages=["https://other.example/"])
    with pytest.raises(SignatureVerificationError, match="not trusted"):
        strict.verify(v["method"], v["url"], v["headers"], v["body"])
    # An empty allow-list trusts no storage; spellings of the same URL are the same storage.
    nobody = WebhookVerifier(fetch=lambda _: DESCRIPTION, clock=lambda: v["now"], trusted_storages=[])
    with pytest.raises(SignatureVerificationError, match="not trusted"):
        nobody.verify(v["method"], v["url"], v["headers"], v["body"])
    spelled = WebhookVerifier(fetch=lambda _: DESCRIPTION, clock=lambda: v["now"],
                              trusted_storages=["HTTPS://Storage.Example:443/"])
    assert spelled.verify(v["method"], v["url"], v["headers"], v["body"]).storage == "https://storage.example/"


def test_content_digest_rules() -> None:
    with pytest.raises(SignatureVerificationError):
        verify_content_digest(None, b"x")
    with pytest.raises(SignatureVerificationError):
        verify_content_digest("md5=:AAAA:", b"x")
    verify_content_digest(
        "sha-256=:X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=:, unknown=:AAAA:",
        b'{"hello": "world"}',
    )


@pytest.mark.anyio
async def test_asgi_helper() -> None:
    v = VECTORS[0]
    scope = {"type": "http", "method": "POST",
             "headers": [(k.encode(), val.encode()) for k, val in v["headers"].items()]}
    chunks = [{"body": v["body"].encode()[:10], "more_body": True},
              {"body": v["body"].encode()[10:], "more_body": False}]

    async def receive() -> dict[str, Any]:
        return chunks.pop(0)

    verifier = AsyncWebhookVerifier(fetch=lambda _: DESCRIPTION, clock=lambda: v["now"])
    result = await verifier.verify_asgi(scope, receive, v["url"])
    assert result.storage == "https://storage.example/"
