// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Erich Bremer and the lws-client contributors
//
// Error hierarchy (design/client-api.md §10). Every exception thrown by the library derives
// from lws::Error, which derives from std::runtime_error.
#pragma once

#include <optional>
#include <stdexcept>
#include <string>
#include <vector>

#include <nlohmann/json.hpp>

#include "lws/http.hpp"
#include "lws/link.hpp"

namespace lws {

/// RFC 9457 problem details attached to an error response.
struct ProblemDetails {
    std::optional<std::string> type;
    std::optional<std::string> title;
    std::optional<int> status;
    std::optional<std::string> detail;
    std::optional<std::string> instance;
    nlohmann::json extensions = nlohmann::json::object();  ///< members other than the five above
    nlohmann::json raw;

    /// Parses a problem document if `response` carries a JSON body with at least one of
    /// type/title/status/detail/instance; returns std::nullopt otherwise.
    static std::optional<ProblemDetails> from_response(const HttpResponse& response);
};

/// Base class of all lws-client errors.
class Error : public std::runtime_error {
public:
    using std::runtime_error::runtime_error;
};

/// Network / transport failure (DNS, TLS, connection reset, timeout, ...).
class TransportError : public Error {
public:
    using Error::Error;
};

/// A server response violates the LWS specification (missing Location, wrong media type,
/// malformed JSON, ...).
class ProtocolError : public Error {
public:
    using Error::Error;
};

/// A header or document could not be parsed.
class ParseError : public ProtocolError {
public:
    using ProtocolError::ProtocolError;
};

/// Token exchange, realm validation or authorization server metadata failure.
class AuthenticationError : public Error {
public:
    explicit AuthenticationError(const std::string& message, std::optional<std::string> oauth_error = {},
                                 std::optional<std::string> error_description = {})
        : Error(message), oauth_error_(std::move(oauth_error)), error_description_(std::move(error_description)) {}

    /// The OAuth `error` code returned by the token endpoint, if any.
    const std::optional<std::string>& oauth_error() const noexcept { return oauth_error_; }
    /// The OAuth `error_description`, if any.
    const std::optional<std::string>& error_description() const noexcept { return error_description_; }

private:
    std::optional<std::string> oauth_error_;
    std::optional<std::string> error_description_;
};

/// Webhook (RFC 9421 / RFC 9530) verification failure.
class SignatureVerificationError : public Error {
public:
    using Error::Error;
};

/// A non-success HTTP status.
class HttpError : public Error {
public:
    HttpError(std::string message, int status, std::string method, std::string url, HttpHeaders headers,
              std::optional<ProblemDetails> problem, std::string body);

    int status() const noexcept { return status_; }
    const std::string& method() const noexcept { return method_; }
    const std::string& url() const noexcept { return url_; }
    const HttpHeaders& headers() const noexcept { return headers_; }
    const std::optional<ProblemDetails>& problem() const noexcept { return problem_; }
    /// Response body as text (truncated to 2048 bytes).
    const std::string& body() const noexcept { return body_; }

private:
    int status_;
    std::string method_;
    std::string url_;
    HttpHeaders headers_;
    std::optional<ProblemDetails> problem_;
    std::string body_;
};

#define LWS_DECLARE_HTTP_ERROR(Name) \
    class Name : public HttpError {  \
    public:                          \
        using HttpError::HttpError;  \
    }

LWS_DECLARE_HTTP_ERROR(BadRequestError);           // 400
LWS_DECLARE_HTTP_ERROR(ForbiddenError);            // 403 — "not permitted"
LWS_DECLARE_HTTP_ERROR(NotFoundError);             // 404 — "target not found"
LWS_DECLARE_HTTP_ERROR(NotAcceptableError);        // 406
LWS_DECLARE_HTTP_ERROR(ConflictError);             // 409 — "conflict"
LWS_DECLARE_HTTP_ERROR(GoneError);                 // 410
LWS_DECLARE_HTTP_ERROR(PreconditionFailedError);   // 412
LWS_DECLARE_HTTP_ERROR(UnprocessableContentError); // 422
LWS_DECLARE_HTTP_ERROR(NotImplementedError);       // 501
LWS_DECLARE_HTTP_ERROR(InsufficientStorageError);  // 507 — quota exceeded
#undef LWS_DECLARE_HTTP_ERROR

/// 401 after authentication handling — "unknown requester".
class UnauthorizedError : public HttpError {
public:
    using HttpError::HttpError;
    /// The parsed WWW-Authenticate challenges.
    std::vector<AuthChallenge> challenges() const;
};

/// 405 Method Not Allowed.
class MethodNotAllowedError : public HttpError {
public:
    using HttpError::HttpError;
    /// Methods listed in the Allow header.
    std::vector<std::string> allow() const;
};

/// 415 Unsupported Media Type.
class UnsupportedMediaTypeError : public HttpError {
public:
    using HttpError::HttpError;
    /// Media types listed in Accept-Patch.
    std::vector<std::string> accept_patch() const;
    /// Media types listed in Accept-Query (RFC 10008).
    std::vector<std::string> accept_query() const;
};

/// Throws the HttpError subclass that corresponds to `response.status`.
[[noreturn]] void throw_http_error(const HttpRequest& request, const HttpResponse& response);

/// Throws (via throw_http_error) unless `response.status` is 2xx (or 304 when `allow_not_modified`).
void raise_for_status(const HttpRequest& request, const HttpResponse& response, bool allow_not_modified = false);

}  // namespace lws
