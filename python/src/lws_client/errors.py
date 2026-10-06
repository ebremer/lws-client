# SPDX-License-Identifier: MIT
"""Error hierarchy (design contract §10) and RFC 9457 problem details."""

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

import httpx

from ._util import media_type_essence, split_header_list
from .headers import AuthChallenge, parse_www_authenticate

__all__ = [
    "ProblemDetails",
    "LwsError",
    "TransportError",
    "HttpError",
    "BadRequestError",
    "UnauthorizedError",
    "ForbiddenError",
    "NotFoundError",
    "MethodNotAllowedError",
    "NotAcceptableError",
    "ConflictError",
    "GoneError",
    "PreconditionFailedError",
    "UnsupportedMediaTypeError",
    "UnprocessableContentError",
    "NotImplementedByServerError",
    "InsufficientStorageError",
    "AuthenticationError",
    "ProtocolError",
    "UnsupportedError",
    "SignatureVerificationError",
    "error_for_response",
]

_PROBLEM_MEMBERS = ("type", "title", "status", "detail", "instance")


@dataclass(frozen=True, slots=True)
class ProblemDetails:
    """RFC 9457 problem details; unknown members are kept in ``extensions``."""

    type: str | None = None
    title: str | None = None
    status: int | None = None
    detail: str | None = None
    instance: str | None = None
    extensions: Mapping[str, Any] = field(default_factory=dict)

    @classmethod
    def from_json(cls, data: Mapping[str, Any]) -> ProblemDetails:
        def text(name: str) -> str | None:
            value = data.get(name)
            return value if isinstance(value, str) else None

        status = data.get("status")
        return cls(
            type=text("type"),
            title=text("title"),
            status=status if isinstance(status, int) and not isinstance(status, bool) else None,
            detail=text("detail"),
            instance=text("instance"),
            extensions={k: v for k, v in data.items() if k not in _PROBLEM_MEMBERS},
        )

    @classmethod
    def from_response(cls, content_type: str | None, body: bytes) -> ProblemDetails | None:
        """Parse problem details from a ``+json``/``json`` body, if it looks like one."""
        essence = media_type_essence(content_type)
        if not body or not (essence.endswith("+json") or essence == "application/json"):
            return None
        try:
            data = json.loads(body)
        except ValueError:
            return None
        if not isinstance(data, dict):
            return None
        if essence != "application/problem+json" and not any(k in data for k in _PROBLEM_MEMBERS):
            return None
        return cls.from_json(data)


class LwsError(Exception):
    """Base class of every error raised by this library."""


class TransportError(LwsError):
    """The HTTP request could not be completed (connection, TLS, timeout …)."""


class HttpError(LwsError):
    """A request completed with an unsuccessful HTTP status."""

    status: int

    def __init__(
        self,
        status: int,
        method: str,
        url: str,
        headers: httpx.Headers | None = None,
        body: bytes = b"",
        problem: ProblemDetails | None = None,
        message: str | None = None,
    ) -> None:
        self.status = status
        self.method = method
        self.url = url
        self.headers = headers if headers is not None else httpx.Headers()
        self.body_text = body[:4096].decode("utf-8", "replace")
        self.problem = problem
        if message is None:
            reason = httpx.codes.get_reason_phrase(status) or "HTTP error"
            message = f"{method} {url} failed: {status} {reason}"
            if problem is not None and (problem.detail or problem.title):
                message += f" — {problem.detail or problem.title}"
        super().__init__(message)


class BadRequestError(HttpError):
    """400 Bad Request."""


class UnauthorizedError(HttpError):
    """401 Unauthorized — the LWS *unknown requester* response (after auth handling)."""

    @property
    def challenges(self) -> list[AuthChallenge]:
        return parse_www_authenticate(self.headers.get_list("www-authenticate"))


class ForbiddenError(HttpError):
    """403 Forbidden — the LWS *not permitted* response."""


class NotFoundError(HttpError):
    """404 Not Found — *target not found*."""


class MethodNotAllowedError(HttpError):
    """405 Method Not Allowed."""

    @property
    def allow(self) -> list[str]:
        return split_header_list(self.headers.get_list("allow"))


class NotAcceptableError(HttpError):
    """406 Not Acceptable."""


class ConflictError(HttpError):
    """409 Conflict (e.g. deleting a non-empty container without recursion)."""


class GoneError(NotFoundError):
    """410 Gone (a subclass of :class:`NotFoundError`)."""


class PreconditionFailedError(HttpError):
    """412 Precondition Failed (``If-Match`` / ``If-None-Match`` did not hold)."""


class UnsupportedMediaTypeError(HttpError):
    """415 Unsupported Media Type."""

    @property
    def accept_patch(self) -> list[str]:
        return split_header_list(self.headers.get_list("accept-patch"))

    @property
    def accept_query(self) -> list[str]:
        return [v.strip('"') for v in split_header_list(self.headers.get_list("accept-query"))]


class UnprocessableContentError(HttpError):
    """422 Unprocessable Content."""


class NotImplementedByServerError(HttpError):
    """501 Not Implemented."""


class InsufficientStorageError(HttpError):
    """507 Insufficient Storage — quota exceeded."""


class AuthenticationError(LwsError):
    """Obtaining an access token failed (realm check, metadata, token exchange …)."""

    def __init__(
        self,
        message: str,
        *,
        error: str | None = None,
        error_description: str | None = None,
        status: int | None = None,
    ) -> None:
        self.error = error
        self.error_description = error_description
        self.status = status
        super().__init__(message)


class ProtocolError(LwsError):
    """The server's response violates the LWS specification."""


class UnsupportedError(LwsError):
    """The server does not support the requested feature (e.g. a subscription type)."""


class SignatureVerificationError(LwsError):
    """A webhook delivery failed RFC 9421 / RFC 9530 verification."""


_BY_STATUS: dict[int, type[HttpError]] = {
    400: BadRequestError,
    401: UnauthorizedError,
    403: ForbiddenError,
    404: NotFoundError,
    405: MethodNotAllowedError,
    406: NotAcceptableError,
    409: ConflictError,
    410: GoneError,
    412: PreconditionFailedError,
    415: UnsupportedMediaTypeError,
    422: UnprocessableContentError,
    501: NotImplementedByServerError,
    507: InsufficientStorageError,
}


def error_for_response(response: httpx.Response, method: str | None = None) -> HttpError:
    """Build the matching :class:`HttpError` subclass for an unsuccessful response."""
    try:
        body = response.content
    except httpx.ResponseNotRead:
        body = b""
    problem = ProblemDetails.from_response(response.headers.get("content-type"), body)
    cls = _BY_STATUS.get(response.status_code, HttpError)
    return cls(
        response.status_code,
        method or response.request.method,
        str(response.request.url),
        response.headers,
        body,
        problem,
    )
