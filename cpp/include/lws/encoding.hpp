// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Erich Bremer and the lws-client contributors
//
// Byte encodings and date-time helpers used throughout the library.
#pragma once

#include <chrono>
#include <optional>
#include <string>
#include <string_view>

namespace lws {

/// Standard base64 (RFC 4648 §4) with padding.
std::string base64_encode(std::string_view bytes);
/// Decodes standard base64; padding optional. Throws lws::ParseError on invalid input.
std::string base64_decode(std::string_view text);
/// base64url (RFC 4648 §5) without padding.
std::string base64url_encode(std::string_view bytes);
/// Decodes base64url (padding optional). Throws lws::ParseError on invalid input.
std::string base64url_decode(std::string_view text);
/// Bitcoin base58 alphabet (as used by multibase 'z').
std::string base58btc_encode(std::string_view bytes);
/// Decodes base58btc. Throws lws::ParseError on invalid input.
std::string base58btc_decode(std::string_view text);

/// application/x-www-form-urlencoded component encoding (space → '+').
std::string form_url_encode(std::string_view text);
/// Percent-encodes everything outside printable ASCII plus '%' (RFC 5023 Slug header).
std::string slug_encode(std::string_view text);

/// Parses an RFC 3339 / ISO 8601 date-time ("2026-03-26T10:30:00Z", fractional seconds and
/// numeric offsets allowed). Returns std::nullopt if the text is not a valid date-time.
std::optional<std::chrono::system_clock::time_point> parse_rfc3339(std::string_view text) noexcept;
/// Formats a time point as RFC 3339 UTC with second precision ("2026-03-26T10:30:00Z").
std::string format_rfc3339(std::chrono::system_clock::time_point time);

}  // namespace lws
