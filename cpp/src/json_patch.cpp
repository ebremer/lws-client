// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Erich Bremer and the lws-client contributors

#include "lws/json_patch.hpp"

namespace lws {

std::string JsonPointer::escape(std::string_view segment) {
    std::string out;
    out.reserve(segment.size());
    for (char c : segment) {
        if (c == '~')
            out += "~0";
        else if (c == '/')
            out += "~1";
        else
            out += c;
    }
    return out;
}

std::string JsonPointer::from_segments(const std::vector<std::string>& segments) {
    std::string out;
    for (const auto& s : segments) out += "/" + escape(s);
    return out;
}

std::string JsonPointer::from_segments(std::initializer_list<std::string_view> segments) {
    std::string out;
    for (auto s : segments) out += "/" + escape(s);
    return out;
}

JsonPatch& JsonPatch::add(std::string path, nlohmann::json value) {
    operations_.push_back({{"op", "add"}, {"path", std::move(path)}, {"value", std::move(value)}});
    return *this;
}

JsonPatch& JsonPatch::remove(std::string path) {
    operations_.push_back({{"op", "remove"}, {"path", std::move(path)}});
    return *this;
}

JsonPatch& JsonPatch::replace(std::string path, nlohmann::json value) {
    operations_.push_back({{"op", "replace"}, {"path", std::move(path)}, {"value", std::move(value)}});
    return *this;
}

JsonPatch& JsonPatch::move(std::string from, std::string path) {
    operations_.push_back({{"op", "move"}, {"from", std::move(from)}, {"path", std::move(path)}});
    return *this;
}

JsonPatch& JsonPatch::copy(std::string from, std::string path) {
    operations_.push_back({{"op", "copy"}, {"from", std::move(from)}, {"path", std::move(path)}});
    return *this;
}

JsonPatch& JsonPatch::test(std::string path, nlohmann::json value) {
    operations_.push_back({{"op", "test"}, {"path", std::move(path)}, {"value", std::move(value)}});
    return *this;
}

}  // namespace lws
