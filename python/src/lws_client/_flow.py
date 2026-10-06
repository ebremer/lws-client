# SPDX-License-Identifier: MIT
"""Sans-I/O effects.

Every operation (and the authentication state machine) is written once as a generator
("flow") that *yields effects* — "send this HTTP request", "call this (maybe async)
function", "run this sub-flow exclusively" — and receives their results. The sync and async
clients are thin drivers that perform the effects with ``httpx.Client`` or
``httpx.AsyncClient``. This keeps both clients behaviourally identical.
"""

from __future__ import annotations

import asyncio
import inspect
import threading
from collections.abc import Callable, Generator, Hashable
from dataclasses import dataclass, field
from typing import Any, TypeVar

import httpx

from .errors import TransportError

T = TypeVar("T")

#: A flow yields effects, receives their results and finally returns a ``T``.
Flow = Generator[Any, Any, T]


@dataclass(slots=True)
class Send:
    """Send an HTTP request; the result is an ``httpx.Response``.

    Non-streamed responses are fully read. For ``stream=True`` only unsuccessful
    (non-2xx) responses are read; successful ones are returned open.
    """

    request: httpx.Request
    stream: bool = False


@dataclass(slots=True)
class Invoke:
    """Call ``fn(*args)``; awaitable results are awaited by the async driver."""

    fn: Callable[..., Any]
    args: tuple[Any, ...] = field(default_factory=tuple)


@dataclass(slots=True)
class Exclusive:
    """Run ``flow`` while holding the driver's lock for ``key`` (single-flight)."""

    key: Hashable
    flow: Flow[Any]


def immediate(value: T) -> Flow[T]:
    """A flow that yields nothing and returns ``value``."""
    return value
    yield  # pragma: no cover


class SyncDriver:
    """Performs effects synchronously with an ``httpx.Client``."""

    def __init__(self, http: httpx.Client) -> None:
        self.http = http
        self._locks: dict[Hashable, threading.Lock] = {}
        self._locks_guard = threading.Lock()

    def run(self, flow: Flow[T]) -> T:
        value: Any = None
        error: BaseException | None = None
        while True:
            try:
                effect = flow.throw(error) if error is not None else flow.send(value)
            except StopIteration as stop:
                result: T = stop.value
                return result
            value, error = None, None
            try:
                value = self._perform(effect)
            except Exception as exc:  # delivered into the flow
                error = exc

    def _lock(self, key: Hashable) -> threading.Lock:
        with self._locks_guard:
            lock = self._locks.get(key)
            if lock is None:
                lock = self._locks[key] = threading.Lock()
            return lock

    def _perform(self, effect: Any) -> Any:
        if isinstance(effect, Send):
            try:
                response = self.http.send(
                    effect.request, stream=effect.stream, follow_redirects=False
                )
            except httpx.TransportError as exc:
                raise TransportError(f"{effect.request.method} {effect.request.url}: {exc}") from exc
            if effect.stream and not response.is_success:
                try:
                    response.read()
                finally:
                    response.close()
            return response
        if isinstance(effect, Invoke):
            result = effect.fn(*effect.args)
            if inspect.isawaitable(result):
                close = getattr(result, "close", None)
                if callable(close):
                    close()
                raise TypeError(
                    f"{getattr(effect.fn, '__qualname__', effect.fn)!r} returned an awaitable; "
                    "use AsyncLwsClient with asynchronous callbacks"
                )
            return result
        if isinstance(effect, Exclusive):
            with self._lock(effect.key):
                return self.run(effect.flow)
        raise TypeError(f"unknown effect {effect!r}")


class AsyncDriver:
    """Performs effects asynchronously with an ``httpx.AsyncClient``."""

    def __init__(self, http: httpx.AsyncClient) -> None:
        self.http = http
        self._locks: dict[tuple[int, Hashable], asyncio.Lock] = {}

    async def run(self, flow: Flow[T]) -> T:
        value: Any = None
        error: BaseException | None = None
        while True:
            try:
                effect = flow.throw(error) if error is not None else flow.send(value)
            except StopIteration as stop:
                result: T = stop.value
                return result
            value, error = None, None
            try:
                value = await self._perform(effect)
            except Exception as exc:
                error = exc

    def _lock(self, key: Hashable) -> asyncio.Lock:
        loop_key = (id(asyncio.get_running_loop()), key)
        lock = self._locks.get(loop_key)
        if lock is None:
            lock = self._locks[loop_key] = asyncio.Lock()
        return lock

    async def _perform(self, effect: Any) -> Any:
        if isinstance(effect, Send):
            try:
                response = await self.http.send(
                    effect.request, stream=effect.stream, follow_redirects=False
                )
            except httpx.TransportError as exc:
                raise TransportError(f"{effect.request.method} {effect.request.url}: {exc}") from exc
            if effect.stream and not response.is_success:
                try:
                    await response.aread()
                finally:
                    await response.aclose()
            return response
        if isinstance(effect, Invoke):
            result = effect.fn(*effect.args)
            if inspect.isawaitable(result):
                result = await result
            return result
        if isinstance(effect, Exclusive):
            async with self._lock(effect.key):
                return await self.run(effect.flow)
        raise TypeError(f"unknown effect {effect!r}")
