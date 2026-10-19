# SPDX-License-Identifier: MIT
"""conformance/fixtures/move.json: the patch a move sends and what the client makes of the
answer, without a server and through both clients (httpx.MockTransport)."""

from __future__ import annotations

import json
from typing import Any

import httpx
import pytest
from conftest import load, make_response

from lws_client import (
    AsyncLwsClient,
    LwsClient,
    MoveResult,
    ProtocolError,
    ResourceMetadata,
    move_patch,
)

FX = load("move.json")
PATCHES = FX["patches"]
RESPONSES = FX["responses"]
LINKSET_ETAG = '"ls-1"'


@pytest.mark.parametrize("case", PATCHES, ids=[c["name"] for c in PATCHES])
def test_move_patch_fixture(case: dict[str, Any]) -> None:
    def build() -> list[dict[str, Any]]:
        patch = move_patch(case["resource"], case["linksetUrl"], case["linkset"], case["destination"])
        return patch.to_json()

    if case["expected"] is None:
        with pytest.raises(ProtocolError):
            build()
    else:
        assert build() == case["expected"]


@pytest.mark.parametrize("case", RESPONSES, ids=[c["name"] for c in RESPONSES])
def test_move_response_fixture(case: dict[str, Any]) -> None:
    response = make_response(case["linksetUrl"], case["status"], case["headers"], case["body"],
                             method="PATCH")
    result = MoveResult.parse(case["resource"], ResourceMetadata.from_response(response),
                              response.content)
    check_result(result, case)


def check_result(result: MoveResult, case: dict[str, Any]) -> None:
    exp = case["expected"]
    assert result.status == case["status"]
    assert result.location == exp["location"]
    assert result.linkset == exp["linkset"]
    assert result.identifier_preserved is exp["identifierPreserved"]
    assert result.etag == exp["etag"]
    assert (result.document is not None) is (case["body"] is not None)


class Storage:
    """A resource, its linkset and the answer to a patch of it; records the patches."""

    def __init__(self, resource: str, linkset_url: str, linkset: dict[str, Any],
                 answer: httpx.Response | None = None) -> None:
        self.resource = resource
        self.linkset_url = linkset_url
        self.linkset = linkset
        self.answer = answer or httpx.Response(204, headers={"ETag": '"ls-2"'})
        self.patches: list[httpx.Request] = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        if url == self.resource and request.method == "HEAD":
            return httpx.Response(200, headers={"Link": f'<{self.linkset_url}>; rel="linkset"'})
        if url == self.linkset_url and request.method == "GET":
            return httpx.Response(200, headers={"Content-Type": "application/linkset+json",
                                                "ETag": LINKSET_ETAG},
                                  content=json.dumps(self.linkset).encode())
        if url == self.linkset_url and request.method == "PATCH":
            self.patches.append(request)
            return self.answer
        return httpx.Response(404)

    def check_patch(self, expected: list[dict[str, Any]], if_match: str = LINKSET_ETAG) -> None:
        (patch,) = self.patches
        assert patch.headers["content-type"] == "application/json-patch+json"
        assert patch.headers["if-match"] == if_match
        assert json.loads(patch.content) == expected


def answer(case: dict[str, Any]) -> httpx.Response:
    body = case["body"]
    return httpx.Response(case["status"], headers=case["headers"],
                          content=b"" if body is None else json.dumps(body).encode())


def up_linkset(resource: str) -> dict[str, Any]:
    return {"linkset": [{"anchor": resource, "up": [{"href": "https://storage.example/from/"}]}]}


def sync_client(storage: Storage) -> LwsClient:
    return LwsClient(http_client=httpx.Client(transport=httpx.MockTransport(storage)))


def async_client(storage: Storage) -> AsyncLwsClient:
    return AsyncLwsClient(http_client=httpx.AsyncClient(transport=httpx.MockTransport(storage)))


@pytest.mark.parametrize("case", PATCHES, ids=[c["name"] for c in PATCHES])
def test_move_sends_the_patch(case: dict[str, Any]) -> None:
    storage = Storage(case["resource"], case["linksetUrl"], case["linkset"])
    with sync_client(storage) as client:
        if case["expected"] is None:
            with pytest.raises(ProtocolError):
                client.move(case["resource"], case["destination"])
            assert storage.patches == []  # nothing is sent
            return
        result = client.move(case["resource"], case["destination"])
    storage.check_patch(case["expected"])
    assert (result.status, result.location, result.identifier_preserved) == (204, case["resource"], True)
    assert (result.linkset, result.etag) == (case["linksetUrl"], '"ls-2"')


@pytest.mark.parametrize("case", RESPONSES, ids=[c["name"] for c in RESPONSES])
def test_move_interprets_the_answer(case: dict[str, Any]) -> None:
    storage = Storage(case["resource"], case["linksetUrl"], up_linkset(case["resource"]), answer(case))
    with sync_client(storage) as client:
        check_result(client.move(case["resource"], "https://storage.example/to/"), case)


def test_move_if_match_overrides_the_linkset_etag() -> None:
    case = PATCHES[0]
    storage = Storage(case["resource"], case["linksetUrl"], case["linkset"])
    with sync_client(storage) as client:
        client.move(case["resource"], case["destination"], if_match='"mine"')
    storage.check_patch(case["expected"], if_match='"mine"')


@pytest.mark.anyio
@pytest.mark.parametrize("case", PATCHES, ids=[c["name"] for c in PATCHES])
async def test_move_sends_the_patch_async(case: dict[str, Any]) -> None:
    storage = Storage(case["resource"], case["linksetUrl"], case["linkset"])
    async with async_client(storage) as client:
        if case["expected"] is None:
            with pytest.raises(ProtocolError):
                await client.move(case["resource"], case["destination"])
            assert storage.patches == []
            return
        await client.move(case["resource"], case["destination"])
    storage.check_patch(case["expected"])


@pytest.mark.anyio
@pytest.mark.parametrize("case", RESPONSES, ids=[c["name"] for c in RESPONSES])
async def test_move_interprets_the_answer_async(case: dict[str, Any]) -> None:
    storage = Storage(case["resource"], case["linksetUrl"], up_linkset(case["resource"]), answer(case))
    async with async_client(storage) as client:
        check_result(await client.move(case["resource"], "https://storage.example/to/"), case)
