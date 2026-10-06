// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Erich Bremer and the lws-client contributors
//
// Type Index and Type Search services (lws10-index).
#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <nlohmann/json.hpp>

#include "lws/models.hpp"

namespace lws {

/// application/lws-query+json filter in conjunctive normal form.
///
///     auto q = lws::TypeQuery{}
///                  .any_of({"https://schema.org/Person", "http://xmlns.com/foaf/0.1/Person"})
///                  .all_of({"https://www.w3.org/ns/lws#DataResource"});
///
/// Builder calls validate eagerly and throw std::invalid_argument for a relative IRI or an
/// empty OR group.
class TypeQuery {
public:
    /// Adds each IRI as its own AND group on the `type` key.
    TypeQuery& all_of(const std::vector<std::string>& iris);
    /// Adds one OR group on the `type` key.
    TypeQuery& any_of(const std::vector<std::string>& iris);
    /// Same as all_of / any_of for an indexed descriptive relation (e.g. "describedby").
    TypeQuery& relation_all_of(std::string_view rel, const std::vector<std::string>& iris);
    TypeQuery& relation_any_of(std::string_view rel, const std::vector<std::string>& iris);

    /// Convenience: a query for resources bearing all the given types.
    static TypeQuery of_types(const std::vector<std::string>& iris) { return TypeQuery{}.all_of(iris); }

    nlohmann::json to_json() const;
    std::string dump() const { return to_json().dump(); }
    bool empty() const noexcept { return keys_.empty(); }

private:
    std::vector<std::pair<std::string, nlohmann::json>> keys_;  ///< key → array of groups
    nlohmann::json& groups(std::string_view key);
};

/// One page of a Type Index listing.
struct TypeIndexPage {
    std::optional<std::int64_t> total_items;
    std::vector<std::string> types;
    std::optional<std::string> first;
    std::optional<std::string> next;
    std::optional<std::string> prev;
    std::optional<std::string> last;
    ResourceMetadata metadata;
    nlohmann::json raw;

    static TypeIndexPage from_response(const HttpResponse& response);
};

}  // namespace lws
