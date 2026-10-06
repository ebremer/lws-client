# SPDX-License-Identifier: MIT
from __future__ import annotations

import json
from collections.abc import Mapping
from pathlib import Path
from typing import Any

import httpx
import pytest

FIXTURES = Path(__file__).resolve().parents[2] / "conformance" / "fixtures"


def load(rel: str) -> Any:
    return json.loads((FIXTURES / rel).read_text(encoding="utf-8"))


def header_list(headers: Mapping[str, Any]) -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    for name, value in headers.items():
        if isinstance(value, list):
            out.extend((name, v) for v in value)
        else:
            out.append((name, str(value)))
    return out


def make_response(
    url: str,
    status: int = 200,
    headers: Mapping[str, Any] | None = None,
    body: Any = None,
    method: str = "GET",
) -> httpx.Response:
    content = b""
    if isinstance(body, (bytes, str)):
        content = body.encode() if isinstance(body, str) else body
    elif body is not None:
        content = json.dumps(body).encode()
    return httpx.Response(
        status,
        headers=header_list(headers or {}),
        content=content,
        request=httpx.Request(method, url),
    )


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"
