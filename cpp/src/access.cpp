// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Erich Bremer and the lws-client contributors

#include "lws/access.hpp"

#include <algorithm>
#include <stdexcept>

#include "lws/errors.hpp"
#include "lws/models.hpp"

namespace lws {
namespace {

std::optional<std::string> string_member(const nlohmann::json& j, const char* key) {
    if (!j.is_object()) return std::nullopt;
    auto it = j.find(key);
    if (it == j.end() || !it->is_string()) return std::nullopt;
    return it->get<std::string>();
}

bool contains_type(const std::vector<std::string>& types, std::string_view type) {
    return std::any_of(types.begin(), types.end(), [&](const std::string& t) { return type_matches(t, type); });
}

template <typename Doc>
nlohmann::json document_to_json(const Doc& doc, std::string_view required_type) {
    if (!contains_type(doc.types, required_type))
        throw std::invalid_argument("access document type must include " + std::string(required_type));
    if (doc.storage.empty()) throw std::invalid_argument("access document needs a storage");
    if (doc.access.empty()) throw std::invalid_argument("access document needs at least one access policy");
    nlohmann::json j = doc.extra.is_object() ? doc.extra : nlohmann::json::object();
    // Keep a caller-supplied @context only if it includes the LWS context (it MUST).
    const auto ctx = j.find("@context");
    const bool keep_ctx = ctx != j.end() && ctx->is_array() &&
                          std::find(ctx->begin(), ctx->end(), nlohmann::json(std::string(ns::lws_context))) != ctx->end();
    if (!keep_ctx) j["@context"] = nlohmann::json::array({std::string(ns::lws_context)});
    j["type"] = doc.types;
    if (doc.inbox) j["inbox"] = *doc.inbox;
    j["storage"] = doc.storage;
    nlohmann::json access = nlohmann::json::array();
    for (const auto& p : doc.access) access.push_back(p.to_json());
    j["access"] = std::move(access);
    return j;
}

template <typename Doc>
Doc document_from_json(const nlohmann::json& json, std::string_view required_type) {
    if (!json.is_object()) throw ProtocolError("access document is not a JSON object");
    Doc doc;
    doc.types = json_types(json.value("type", nlohmann::json()));
    if (!contains_type(doc.types, required_type))
        throw ProtocolError("document type does not include " + std::string(required_type));
    doc.storage = string_member(json, "storage").value_or("");
    doc.inbox = string_member(json, "inbox");
    if (auto it = json.find("access"); it != json.end()) {
        if (it->is_array()) {
            for (const auto& p : *it) doc.access.push_back(AccessPolicy::from_json(p));
        } else if (it->is_object()) {
            doc.access.push_back(AccessPolicy::from_json(*it));
        }
    }
    doc.extra = nlohmann::json::object();
    for (auto m = json.begin(); m != json.end(); ++m) {
        const auto& k = m.key();
        if (k != "@context" && k != "type" && k != "storage" && k != "inbox" && k != "access")
            doc.extra[k] = m.value();
    }
    if (json.contains("@context")) doc.extra["@context"] = json["@context"];
    return doc;
}

}  // namespace

Constraint Constraint::purpose(std::string uri) {
    return {std::string(access::operand_purpose), std::string(access::operator_eq), std::move(uri)};
}
Constraint Constraint::purpose_any_of(std::vector<std::string> uris) {
    return {std::string(access::operand_purpose), std::string(access::operator_is_any_of), std::move(uris)};
}
Constraint Constraint::client(std::string uri) {
    return {std::string(access::operand_client), std::string(access::operator_eq), std::move(uri)};
}
Constraint Constraint::format(std::string media_type) {
    return {std::string(access::operand_format), std::string(access::operator_eq), std::move(media_type)};
}
Constraint Constraint::format_any_of(std::vector<std::string> media_types) {
    return {std::string(access::operand_format), std::string(access::operator_is_any_of), std::move(media_types)};
}
Constraint Constraint::type(std::string uri) {
    return {std::string(access::operand_type), std::string(access::operator_eq), std::move(uri)};
}
Constraint Constraint::type_any_of(std::vector<std::string> uris) {
    return {std::string(access::operand_type), std::string(access::operator_is_any_of), std::move(uris)};
}
Constraint Constraint::not_before(std::string date_time) {
    return {std::string(access::operand_date_time), std::string(access::operator_gteq), std::move(date_time)};
}
Constraint Constraint::not_after(std::string date_time) {
    return {std::string(access::operand_date_time), std::string(access::operator_lteq), std::move(date_time)};
}

nlohmann::json Constraint::to_json() const {
    if (left_operand.empty() || op.empty()) throw std::invalid_argument("constraint needs leftOperand and operator");
    return {{"leftOperand", left_operand}, {"operator", op}, {"rightOperand", right_operand}};
}

Constraint Constraint::from_json(const nlohmann::json& json) {
    Constraint c;
    c.left_operand = string_member(json, "leftOperand").value_or("");
    c.op = string_member(json, "operator").value_or("");
    if (json.is_object() && json.contains("rightOperand")) c.right_operand = json["rightOperand"];
    return c;
}

nlohmann::json AccessPolicy::to_json() const {
    if (actions.empty()) throw std::invalid_argument("access policy needs at least one action");
    if (assignee.empty()) throw std::invalid_argument("access policy needs an assignee");
    nlohmann::json j = extra.is_object() ? extra : nlohmann::json::object();
    j["type"] = types.empty() ? std::vector<std::string>{std::string(access::type_access_policy)} : types;
    j["action"] = actions;
    j["assignee"] = assignee;
    if (target) j["target"] = {{"type", target->type}, {"value", target->values}};
    if (!constraints.empty()) {
        nlohmann::json cs = nlohmann::json::array();
        for (const auto& c : constraints) cs.push_back(c.to_json());
        j["constraint"] = std::move(cs);
    }
    return j;
}

AccessPolicy AccessPolicy::from_json(const nlohmann::json& json) {
    if (!json.is_object()) throw ProtocolError("access policy is not a JSON object");
    AccessPolicy p;
    p.types = json_types(json.value("type", nlohmann::json()));
    p.actions = json_types(json.value("action", nlohmann::json()));
    p.assignee = string_member(json, "assignee").value_or("");
    if (auto it = json.find("target"); it != json.end() && it->is_object()) {
        AccessTarget t;
        t.type = string_member(*it, "type").value_or("");
        t.values = json_types(it->value("value", nlohmann::json()));
        p.target = std::move(t);
    }
    if (auto it = json.find("constraint"); it != json.end() && it->is_array())
        for (const auto& c : *it) p.constraints.push_back(Constraint::from_json(c));
    p.extra = nlohmann::json::object();
    for (auto m = json.begin(); m != json.end(); ++m) {
        const auto& k = m.key();
        if (k != "type" && k != "action" && k != "assignee" && k != "target" && k != "constraint")
            p.extra[k] = m.value();
    }
    return p;
}

bool AccessRequest::has_type(std::string_view type) const noexcept { return contains_type(types, type); }
bool AccessGrant::has_type(std::string_view type) const noexcept { return contains_type(types, type); }

nlohmann::json AccessRequest::to_json() const { return document_to_json(*this, access::type_access_request); }
nlohmann::json AccessGrant::to_json() const { return document_to_json(*this, access::type_access_grant); }

AccessRequest AccessRequest::from_json(const nlohmann::json& json) {
    return document_from_json<AccessRequest>(json, access::type_access_request);
}
AccessGrant AccessGrant::from_json(const nlohmann::json& json) {
    return document_from_json<AccessGrant>(json, access::type_access_grant);
}

}  // namespace lws
