// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Erich Bremer and the lws-client contributors
//
// Structured Field Values (RFC 8941 / RFC 9651) — the dictionary subset needed for
// Signature-Input, Signature and Content-Digest.
#pragma once

#include <cstdint>
#include <string>
#include <string_view>
#include <utility>
#include <variant>
#include <vector>

namespace lws::sf {

struct Token {
    std::string value;
    friend bool operator==(const Token&, const Token&) = default;
};
struct ByteSequence {
    std::string bytes;  ///< decoded raw bytes
    friend bool operator==(const ByteSequence&, const ByteSequence&) = default;
};
struct Date {
    std::int64_t seconds = 0;
    friend bool operator==(const Date&, const Date&) = default;
};
struct DisplayString {
    std::string value;  ///< UTF-8
    friend bool operator==(const DisplayString&, const DisplayString&) = default;
};

/// Integer, Decimal, String, Token, Byte Sequence, Boolean, Date, Display String.
using BareItem = std::variant<std::int64_t, double, std::string, Token, ByteSequence, bool, Date, DisplayString>;
using Parameters = std::vector<std::pair<std::string, BareItem>>;

struct Item {
    BareItem value;
    Parameters params;
};

struct InnerList {
    std::vector<Item> items;
    Parameters params;
};

using Member = std::variant<Item, InnerList>;
/// Dictionary members in order (duplicate keys: last value wins, first position kept).
using Dictionary = std::vector<std::pair<std::string, Member>>;

/// Parses a dictionary field value. Throws lws::ParseError on malformed input.
Dictionary parse_dictionary(std::string_view input);

/// Finds a member by key; nullptr if absent.
const Member* find(const Dictionary& dictionary, std::string_view key) noexcept;
/// Finds a parameter by key; nullptr if absent.
const BareItem* find(const Parameters& params, std::string_view key) noexcept;

/// Canonical serialisations (RFC 8941 §4.1).
std::string serialize(const BareItem& item);
std::string serialize(const Parameters& params);
std::string serialize(const Item& item);
std::string serialize(const InnerList& list);
std::string serialize(const Member& member);

}  // namespace lws::sf
