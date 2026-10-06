// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Erich Bremer and the lws-client contributors
//
// Web Linking (RFC 8288) and WWW-Authenticate (RFC 9110 §11.6.1) header parsing.
#pragma once

#include <map>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace lws {

/// One typed link. A link-value with several space-separated relation types is split into
/// one Link per relation type.
struct Link {
    std::string href{};  ///< absolute target URI (resolved against the request URL)
    std::string rel{};   ///< registered relations lower-cased; extension URIs verbatim
    std::map<std::string, std::string> params{};  ///< target attributes (lower-cased names, without "rel")

    /// The `type` target attribute (media type hint), if present.
    std::optional<std::string> type() const;
    /// The `anchor` parameter resolved against `base`, if present.
    std::optional<std::string> anchor(std::string_view base) const;
    /// Serialises as a Link header field value: `<href>; rel="rel"; name="value"`.
    std::string to_header() const;

    friend bool operator==(const Link&, const Link&) = default;
};

/// Parses one Link header field value. Relative targets are resolved against `base`.
/// Malformed link-values are skipped.
std::vector<Link> parse_link_header(std::string_view value, std::string_view base);
/// Parses several Link header field lines.
std::vector<Link> parse_link_headers(const std::vector<std::string>& values, std::string_view base);

/// One authentication challenge from a WWW-Authenticate header.
struct AuthChallenge {
    std::string scheme{};                        ///< as written; compare case-insensitively
    std::map<std::string, std::string> params{}; ///< lower-cased names, unquoted values
    std::optional<std::string> token68{};

    bool is_scheme(std::string_view name) const noexcept;
    std::optional<std::string> param(std::string_view name) const;
    std::optional<std::string> as_uri() const { return param("as_uri"); }
    std::optional<std::string> realm() const { return param("realm"); }
    std::optional<std::string> error() const { return param("error"); }
    std::optional<std::string> error_description() const { return param("error_description"); }
};

/// Parses all challenges contained in one or more WWW-Authenticate header field lines.
std::vector<AuthChallenge> parse_www_authenticate(const std::vector<std::string>& values);
/// Convenience overload for a single header field line.
std::vector<AuthChallenge> parse_www_authenticate(std::string_view value);

}  // namespace lws
