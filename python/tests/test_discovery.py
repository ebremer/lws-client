# SPDX-License-Identifier: MIT
"""conformance/fixtures/discovery.json through the TokenExchangeAuthenticator of both clients,
against a server answering as the fixture describes (httpx.MockTransport)."""

from __future__ import annotations

import json
from typing import Any
from urllib.parse import parse_qs

import httpx
import pytest
from conftest import load

from lws_client import (
    AsyncLwsClient,
    AuthenticationError,
    LwsClient,
    SelfSignedCredentials,
    SigningKey,
    TokenExchangeAuthenticator,
    UnauthorizedError,
)

FX = load("discovery.json")
CASES = FX["cases"]
# Two origins: the server under test and another one (loopback, so http is allowed).
A = "http://127.0.0.1:8787"
B = "http://localhost:8787"
ERRORS: dict[str, type[Exception]] = {
    "AuthenticationError": AuthenticationError,
    "UnauthorizedError": UnauthorizedError,
}


def place(value: Any) -> Any:
    """``value`` with ``{A}`` and ``{B}`` replaced by the two origins."""
    if isinstance(value, str):
        return value.replace("{A}", A).replace("{B}", B)
    if isinstance(value, list):
        return [place(v) for v in value]
    if isinstance(value, dict):
        return {place(k): place(v) for k, v in value.items()}
    return value


class Server:
    """Answers as discovery.json's description says, and records what the client asked for."""

    def __init__(self, case: dict[str, Any]) -> None:
        self.case = place(case)
        self.expected = self.case["expected"]
        self.later = {t["request"] for t in self.expected.get("then", [])}
        self.fetched: list[str] = []
        self.token_requests: list[tuple[str, dict[str, list[str]]]] = []
        self.carried: dict[str, bool] = {}
        self.then = False

    def __call__(self, request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        self.fetched.append(url)
        has_token = request.headers.get("authorization") == "Bearer token-1"
        if self.then and url in self.later:
            self.carried[url] = has_token
            return httpx.Response(200, text="ok")
        if request.method == "POST" and url == f"{A}/as/token":
            self.token_requests.append((url, parse_qs(request.content.decode())))
            return httpx.Response(200, json=FX["tokenResponse"])
        if url == self.case["request"]:
            return httpx.Response(200, text="ok") if has_token else httpx.Response(
                401, headers=self.case["challenge"])
        document = self.case["documents"].get(url)
        if document is None or request.method != "GET":
            return httpx.Response(404)
        body = document["body"]
        return httpx.Response(document["status"], headers=document["headers"],
                              content=b"" if body is None else json.dumps(body).encode())

    def check(self) -> None:
        expected = self.expected["tokenRequest"]
        if expected is None:
            assert self.token_requests == []
        else:
            assert [(url, form.get("resource")) for url, form in self.token_requests] == [
                (expected["endpoint"], [expected["resource"]])
            ]
        assert not set(self.expected["notFetched"]) & set(self.fetched)

    def check_then(self) -> None:
        assert self.carried == {t["request"]: t["sendsToken"] for t in self.expected["then"]}
        assert len(self.token_requests) == 1  # no second token request


def authenticator() -> TokenExchangeAuthenticator:
    return TokenExchangeAuthenticator(SelfSignedCredentials.did_key(SigningKey.generate()))


@pytest.mark.parametrize("case", CASES, ids=[c["name"] for c in CASES])
def test_discovery_sync(case: dict[str, Any]) -> None:
    server = Server(case)
    transport = httpx.MockTransport(server)
    with LwsClient(authenticator=authenticator(), http_client=httpx.Client(transport=transport)) as client:
        outcome = server.expected["outcome"]
        if outcome == "ok":
            assert client.read(server.case["request"]).text == "ok"
        else:
            with pytest.raises(ERRORS[outcome]):
                client.read(server.case["request"])
        server.check()
        if "then" in server.expected:
            server.then = True
            for later in server.expected["then"]:
                assert client.read(later["request"]).text == "ok"
            server.check_then()


@pytest.mark.anyio
@pytest.mark.parametrize("case", CASES, ids=[c["name"] for c in CASES])
async def test_discovery_async(case: dict[str, Any]) -> None:
    server = Server(case)
    transport = httpx.MockTransport(server)
    async with AsyncLwsClient(authenticator=authenticator(),
                              http_client=httpx.AsyncClient(transport=transport)) as client:
        outcome = server.expected["outcome"]
        if outcome == "ok":
            assert (await client.read(server.case["request"])).text == "ok"
        else:
            with pytest.raises(ERRORS[outcome]):
                await client.read(server.case["request"])
        server.check()
        if "then" in server.expected:
            server.then = True
            for later in server.expected["then"]:
                assert (await client.read(later["request"])).text == "ok"
            server.check_then()
