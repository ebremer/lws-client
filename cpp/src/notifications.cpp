// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Erich Bremer and the lws-client contributors

#include "lws/notifications.hpp"

#include <algorithm>

#include "lws/constants.hpp"
#include "lws/encoding.hpp"
#include "lws/errors.hpp"
#include "lws/url.hpp"

namespace lws {
namespace {

std::optional<std::string> string_member(const nlohmann::json& j, const char* key) {
    if (!j.is_object()) return std::nullopt;
    auto it = j.find(key);
    if (it == j.end() || !it->is_string()) return std::nullopt;
    return it->get<std::string>();
}

// An "id"-bearing member may be a string or an object with an id.
std::optional<std::string> ref_member(const nlohmann::json& j, const char* key) {
    if (!j.is_object()) return std::nullopt;
    auto it = j.find(key);
    if (it == j.end()) return std::nullopt;
    if (it->is_string()) return it->get<std::string>();
    if (it->is_object()) return string_member(*it, "id");
    return std::nullopt;
}

Activity parse_activity(const nlohmann::json& j) {
    if (!j.is_object()) throw ProtocolError("notification activity is not an object");
    Activity a;
    a.raw = j;
    a.id = string_member(j, "id").value_or("");
    a.types = json_types(j.value("type", nlohmann::json()));
    if (auto it = j.find("object"); it != j.end()) {
        if (it->is_object()) {
            a.object.raw = *it;
            a.object.id = string_member(*it, "id").value_or("");
            a.object.types = json_types(it->value("type", nlohmann::json()));
        } else if (it->is_string()) {
            a.object.id = it->get<std::string>();
            a.object.raw = *it;
        }
    }
    a.actor = ref_member(j, "actor");
    a.target = ref_member(j, "target");
    a.origin = ref_member(j, "origin");
    a.published_raw = string_member(j, "published").value_or("");
    if (!a.published_raw.empty()) a.published = parse_rfc3339(a.published_raw);
    return a;
}

}  // namespace

bool Activity::has_type(std::string_view type) const noexcept {
    return std::any_of(types.begin(), types.end(), [&](const std::string& t) {
        return t == type || t == "as:" + std::string(type) ||
               t == std::string("https://www.w3.org/ns/activitystreams#") + std::string(type);
    });
}

Notification Notification::from_json(const nlohmann::json& json) {
    if (!json.is_object()) throw ProtocolError("notification is not a JSON object");
    const auto types = json_types(json.value("type", nlohmann::json()));
    if (std::none_of(types.begin(), types.end(), [](const std::string& t) { return type_matches(t, "Notification"); }))
        throw ProtocolError("document is not a Notification");
    Notification n;
    n.raw = json;
    n.storage = string_member(json, "storage").value_or("");
    if (auto it = json.find("activity"); it != json.end()) {
        if (it->is_array()) {
            for (const auto& a : *it) n.activities.push_back(parse_activity(a));
        } else if (it->is_object()) {
            n.activities.push_back(parse_activity(*it));
        }
    }
    return n;
}

Notification parse_notification(std::string_view body) {
    auto json = nlohmann::json::parse(body, nullptr, false);
    if (json.is_discarded()) throw ParseError("notification body is not valid JSON");
    return Notification::from_json(json);
}

nlohmann::json WebhookSubscriptionRequest::to_json() const {
    if (topics.empty()) throw std::invalid_argument("a webhook subscription needs at least one topic");
    if (inbox.empty()) throw std::invalid_argument("a webhook subscription needs an inbox");
    nlohmann::json j = {
        {"@context", nlohmann::json::array({std::string(ns::lws_context)})},
        {"type", std::string(subscription::webhook)},
        {"topic", topics},
        {"inbox", inbox},
    };
    if (expires) j["expires"] = *expires;
    return j;
}

Subscription Subscription::from_json(const nlohmann::json& json, std::string_view base,
                                     std::optional<std::string> location) {
    Subscription s;
    s.raw = json;
    s.type = string_member(json, "type").value_or(std::string(subscription::webhook));
    if (auto sub = string_member(json, "subscription")) {
        s.subscription = resolve_url(base, *sub);
    } else if (auto id = string_member(json, "id")) {
        s.subscription = resolve_url(base, *id);
    } else if (location) {
        s.subscription = resolve_url(base, *location);
    }
    s.expires = string_member(json, "expires");
    return s;
}

}  // namespace lws
