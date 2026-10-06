// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Erich Bremer and the lws-client contributors
//
// JSON Patch (RFC 6902) builder and JSON Pointer (RFC 6901) helpers. JSON Patch is the
// baseline PATCH format of LWS (application/json-patch+json).
#pragma once

#include <initializer_list>
#include <string>
#include <string_view>
#include <vector>

#include <nlohmann/json.hpp>

namespace lws {

/// JSON Pointer helpers.
struct JsonPointer {
    /// Escapes one reference token: '~' → "~0", '/' → "~1".
    static std::string escape(std::string_view segment);
    /// Builds a pointer from unescaped segments ("" for no segments).
    static std::string from_segments(const std::vector<std::string>& segments);
    static std::string from_segments(std::initializer_list<std::string_view> segments);
};

/// Fluent builder for a JSON Patch document.
///
///     auto patch = lws::JsonPatch{}.replace("/age", 31).add("/city", "Boston");
class JsonPatch {
public:
    JsonPatch& add(std::string path, nlohmann::json value);
    JsonPatch& remove(std::string path);
    JsonPatch& replace(std::string path, nlohmann::json value);
    JsonPatch& move(std::string from, std::string path);
    JsonPatch& copy(std::string from, std::string path);
    JsonPatch& test(std::string path, nlohmann::json value);

    /// The patch document (a JSON array of operation objects).
    const nlohmann::json& to_json() const noexcept { return operations_; }
    std::string dump() const { return operations_.dump(); }
    bool empty() const noexcept { return operations_.empty(); }
    std::size_t size() const noexcept { return operations_.size(); }

private:
    nlohmann::json operations_ = nlohmann::json::array();
};

}  // namespace lws
