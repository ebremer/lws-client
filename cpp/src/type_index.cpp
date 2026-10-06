// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Erich Bremer and the lws-client contributors

#include "lws/type_index.hpp"

#include <stdexcept>

#include "lws/constants.hpp"
#include "lws/errors.hpp"
#include "lws/url.hpp"

namespace lws {

nlohmann::json& TypeQuery::groups(std::string_view key) {
    for (auto& [k, v] : keys_)
        if (k == key) return v;
    keys_.emplace_back(std::string(key), nlohmann::json::array());
    return keys_.back().second;
}

namespace {
void validate_iris(const std::vector<std::string>& iris) {
    for (const auto& iri : iris)
        if (!is_absolute_iri(iri)) throw std::invalid_argument("type query values must be absolute IRIs: " + iri);
}
void validate_rel(std::string_view rel) {
    if (rel.empty() || rel.starts_with('@')) throw std::invalid_argument("invalid relation key in type query");
}
}  // namespace

TypeQuery& TypeQuery::all_of(const std::vector<std::string>& iris) { return relation_all_of("type", iris); }

TypeQuery& TypeQuery::any_of(const std::vector<std::string>& iris) { return relation_any_of("type", iris); }

TypeQuery& TypeQuery::relation_all_of(std::string_view rel, const std::vector<std::string>& iris) {
    validate_rel(rel);
    validate_iris(iris);
    if (iris.empty()) return *this;
    auto& g = groups(rel);
    for (const auto& iri : iris) g.push_back(iri);
    return *this;
}

TypeQuery& TypeQuery::relation_any_of(std::string_view rel, const std::vector<std::string>& iris) {
    validate_rel(rel);
    if (iris.empty()) throw std::invalid_argument("an OR group in a type query must not be empty");
    validate_iris(iris);
    auto& g = groups(rel);
    if (iris.size() == 1)
        g.push_back(iris.front());
    else
        g.push_back(iris);
    return *this;
}

nlohmann::json TypeQuery::to_json() const {
    nlohmann::json out = nlohmann::json::object();
    for (const auto& [k, v] : keys_) out[k] = v;
    return out;
}

TypeIndexPage TypeIndexPage::from_response(const HttpResponse& response) {
    TypeIndexPage page;
    page.metadata = ResourceMetadata::from_response(response);
    page.raw = nlohmann::json::parse(response.body, nullptr, false);
    if (page.raw.is_discarded() || !page.raw.is_object())
        throw ParseError("type index response is not a JSON object: " + response.url);
    if (auto it = page.raw.find("totalItems"); it != page.raw.end() && it->is_number_integer())
        page.total_items = it->get<std::int64_t>();
    if (auto it = page.raw.find("items"); it != page.raw.end() && it->is_array()) {
        for (const auto& item : *it) {
            if (item.is_string())
                page.types.push_back(item.get<std::string>());
            else if (item.is_object() && item.contains("id") && item["id"].is_string())
                page.types.push_back(item["id"].get<std::string>());
        }
    }
    auto link = [&](std::string_view rel) -> std::optional<std::string> {
        if (auto l = page.metadata.link(rel)) return l->href;
        return std::nullopt;
    };
    page.first = link(rel::first);
    page.next = link(rel::next);
    page.prev = link(rel::prev);
    page.last = link(rel::last);
    return page;
}

}  // namespace lws
