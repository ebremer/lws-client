// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Erich Bremer and the lws-client contributors
//
// Minimal RFC 3986 URI handling: parsing, reference resolution and origin comparison.
#pragma once

#include <optional>
#include <string>
#include <string_view>

namespace lws {

/// A parsed URI reference (RFC 3986 §3). Components keep their original (encoded) text.
struct Url {
    std::string scheme;               ///< lower-cased; empty for relative references
    std::optional<std::string> authority;  ///< userinfo@host:port, as written
    std::string host;                 ///< lower-cased (brackets kept for IPv6)
    std::string port;                 ///< digits as written, empty when absent
    std::string path;
    std::optional<std::string> query;     ///< without '?'
    std::optional<std::string> fragment;  ///< without '#'

    /// Parses any URI reference. Returns std::nullopt for malformed input.
    static std::optional<Url> parse(std::string_view text);

    /// Recomposes the reference (RFC 3986 §5.3).
    std::string str() const;
    bool is_absolute() const noexcept { return !scheme.empty(); }
    /// Port number, using the scheme default (80/443) when absent; -1 if unknown.
    int effective_port() const noexcept;
    /// "scheme://host[:port]" with the default port omitted.
    std::string origin() const;
    /// host[:port] lower-cased with default port omitted (RFC 9421 @authority).
    std::string authority_for_signature() const;
};

/// Resolves `reference` against the absolute `base` (RFC 3986 §5.2). If `reference` is
/// already absolute it is normalised (dot segments removed). If either cannot be parsed the
/// reference is returned unchanged.
std::string resolve_url(std::string_view base, std::string_view reference);

/// True when `text` starts with a valid URI scheme followed by ':' (an absolute IRI).
bool is_absolute_iri(std::string_view text) noexcept;

/// `url` without its fragment component.
std::string strip_fragment(std::string_view url);

/// True when the URL is a loopback address (localhost, 127.0.0.0/8, [::1]).
bool is_loopback(std::string_view url);

/// Returns true if `url` is logically contained within `realm` (design/client-api.md §6.2):
/// same scheme, host and port, and the path equals the realm path or lies below it.
bool url_within_realm(std::string_view url, std::string_view realm);

/// The RFC 8414 §3.1 metadata URL for an authorization server issuer, using the
/// `/.well-known/lws-configuration` suffix.
std::string authorization_server_metadata_url(std::string_view issuer);

}  // namespace lws
