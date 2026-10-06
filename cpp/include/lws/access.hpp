// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Erich Bremer and the lws-client contributors
//
// Access requests and access grants (lws10-core §Access Requests and Grants, ODRL-based
// Access Profile). Models are aggregates, so C++20 designated initializers work:
//
//     lws::AccessRequest request{
//         .storage = "https://storage.example/",
//         .access = {lws::AccessPolicy{.actions = {"read"}, .assignee = "https://id.example/me"}}};
#pragma once

#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include <nlohmann/json.hpp>

#include "lws/constants.hpp"

namespace lws {

/// An ODRL constraint (leftOperand / operator / rightOperand).
struct Constraint {
    std::string left_operand{};
    std::string op{};  ///< "operator" is a C++ keyword
    nlohmann::json right_operand{};

    static Constraint purpose(std::string uri);
    static Constraint purpose_any_of(std::vector<std::string> uris);
    static Constraint client(std::string uri);
    static Constraint format(std::string media_type);
    static Constraint format_any_of(std::vector<std::string> media_types);
    static Constraint type(std::string uri);
    static Constraint type_any_of(std::vector<std::string> uris);
    /// dateTime gteq — start of the access window (XML Schema dateTime).
    static Constraint not_before(std::string date_time);
    /// dateTime lteq — end of the access window.
    static Constraint not_after(std::string date_time);

    nlohmann::json to_json() const;
    static Constraint from_json(const nlohmann::json& json);
};

/// The resources a policy applies to.
struct AccessTarget {
    std::string type = "StorageResource";  ///< "DataResource", "Container", "StorageResource" or an IRI
    std::vector<std::string> values{};
};

/// One access policy (an entry of the "access" array).
struct AccessPolicy {
    std::vector<std::string> types = {"AccessPolicy"};
    std::vector<std::string> actions{};  ///< read / modify / create / delete
    std::string assignee{};              ///< agent URI, or access::public_agent
    std::optional<AccessTarget> target{};
    std::vector<Constraint> constraints{};
    nlohmann::json extra = nlohmann::json::object();  ///< additional members, preserved

    nlohmann::json to_json() const;  ///< validates; throws std::invalid_argument
    static AccessPolicy from_json(const nlohmann::json& json);
};

/// A request by an agent for access to resources.
struct AccessRequest {
    std::vector<std::string> types = {std::string(lws::access::type_access_request)};
    std::string storage{};
    std::optional<std::string> inbox{};
    std::vector<AccessPolicy> access{};
    nlohmann::json extra = nlohmann::json::object();  ///< additional members, preserved

    bool has_type(std::string_view type) const noexcept;
    /// JSON-LD serialisation. Validates required members; throws std::invalid_argument.
    nlohmann::json to_json() const;
    static AccessRequest from_json(const nlohmann::json& json);
};

/// An authorization by a storage controller granting access to resources.
struct AccessGrant {
    std::vector<std::string> types = {std::string(lws::access::type_access_grant)};
    std::string storage{};
    std::optional<std::string> inbox{};
    std::vector<AccessPolicy> access{};
    nlohmann::json extra = nlohmann::json::object();  ///< additional members, preserved

    bool has_type(std::string_view type) const noexcept;
    /// JSON-LD serialisation. Validates required members; throws std::invalid_argument.
    nlohmann::json to_json() const;
    static AccessGrant from_json(const nlohmann::json& json);
};

}  // namespace lws
