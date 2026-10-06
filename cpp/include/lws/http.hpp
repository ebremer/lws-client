// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Erich Bremer and the lws-client contributors
//
// HTTP abstraction: header multimap, request/response values and the pluggable transport.
#pragma once

#include <chrono>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "lws/config.hpp"

namespace lws {

/// Ordered, case-insensitive header multimap. Header field lines are kept in insertion order;
/// lookups compare names case-insensitively.
class HttpHeaders {
public:
    using value_type = std::pair<std::string, std::string>;
    using const_iterator = std::vector<value_type>::const_iterator;

    HttpHeaders() = default;
    HttpHeaders(std::initializer_list<value_type> init);

    /// Appends a header field line.
    HttpHeaders& add(std::string name, std::string value);
    /// Replaces all lines named `name` by a single line.
    HttpHeaders& set(std::string name, std::string value);
    /// Removes all lines named `name`.
    HttpHeaders& remove(std::string_view name);

    bool contains(std::string_view name) const noexcept;
    /// First value of `name`, if present.
    std::optional<std::string> get(std::string_view name) const;
    /// All values of `name`, in order.
    std::vector<std::string> get_all(std::string_view name) const;
    /// All values combined with ", " (RFC 9110 §5.3).
    std::optional<std::string> get_combined(std::string_view name) const;
    /// All values split on commas (for list-based fields such as Allow, Accept-Patch), trimmed.
    std::vector<std::string> get_list(std::string_view name) const;

    const_iterator begin() const noexcept { return fields_.begin(); }
    const_iterator end() const noexcept { return fields_.end(); }
    std::size_t size() const noexcept { return fields_.size(); }
    bool empty() const noexcept { return fields_.empty(); }

private:
    std::vector<value_type> fields_;
};

/// Case-insensitive ASCII comparison.
bool iequals(std::string_view a, std::string_view b) noexcept;

/// An HTTP request as handed to an HttpTransport.
struct HttpRequest {
    std::string method = "GET";
    std::string url{};
    HttpHeaders headers{};
    std::string body{};  ///< raw bytes
    /// Per-request timeout; zero means "transport default".
    std::chrono::milliseconds timeout{0};
};

/// An HTTP response returned by an HttpTransport. Transports must NOT follow redirects; the
/// client follows them itself so that credentials are never forwarded outside their realm.
struct HttpResponse {
    int status = 0;
    std::string url{};  ///< URL the response was obtained from
    HttpHeaders headers{};
    std::string body{};  ///< raw bytes

    bool ok() const noexcept { return status >= 200 && status < 300; }
};

/// Pluggable HTTP engine. Implementations must be safe to call from several threads at once
/// and must throw lws::TransportError for network failures (not for HTTP error statuses).
class HttpTransport {
public:
    virtual ~HttpTransport() = default;
    virtual HttpResponse send(const HttpRequest& request) = 0;
};

#if LWS_WITH_CURL
/// Options of the libcurl-based transport.
struct CurlTransportOptions {
    std::chrono::milliseconds connect_timeout{10000};
    std::chrono::milliseconds default_timeout{30000};
    bool verify_tls = true;
    /// Optional CA bundle path (CURLOPT_CAINFO).
    std::optional<std::string> ca_bundle{};
    /// Ask for compressed responses and decode them transparently.
    bool accept_compression = true;
};

/// Default transport built on libcurl. Thread-safe; keeps a pool of easy handles so that
/// connections are reused.
class CurlTransport final : public HttpTransport {
public:
    explicit CurlTransport(CurlTransportOptions options = {});
    ~CurlTransport() override;
    CurlTransport(const CurlTransport&) = delete;
    CurlTransport& operator=(const CurlTransport&) = delete;

    HttpResponse send(const HttpRequest& request) override;

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};
#endif

/// The default transport (CurlTransport) — throws lws::Error when the library was built
/// without LWS_WITH_CURL.
std::shared_ptr<HttpTransport> make_default_transport();

}  // namespace lws
