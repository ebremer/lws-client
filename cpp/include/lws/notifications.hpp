// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Erich Bremer and the lws-client contributors
//
// Notification data model and webhook subscriptions (lws10-core §Notifications,
// lws10-notifications-webhook). The WebhookVerifier lives in lws/webhook.hpp.
#pragma once

#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include <nlohmann/json.hpp>

#include "lws/models.hpp"

namespace lws {

/// The resource an activity is about.
struct ActivityObject {
    std::string id{};
    std::vector<std::string> types{};
    nlohmann::json raw{};
};

/// An Activity Streams 2.0 activity inside a notification.
struct Activity {
    std::string id{};
    std::vector<std::string> types{};
    ActivityObject object{};
    std::optional<std::string> actor{};
    std::optional<std::string> target{};  ///< container a resource was added to (Create)
    std::optional<std::string> origin{};  ///< container a resource was removed from (Delete)
    std::string published_raw{};
    std::optional<TimePoint> published{};
    nlohmann::json raw{};

    bool has_type(std::string_view type) const noexcept;
    bool is_create() const noexcept { return has_type("Create"); }
    bool is_update() const noexcept { return has_type("Update"); }
    bool is_delete() const noexcept { return has_type("Delete"); }
};

/// A notification envelope.
struct Notification {
    std::string storage{};
    std::vector<Activity> activities{};  ///< "activity" may be an object or an array
    nlohmann::json raw{};

    /// Parses and validates (type must be Notification). Throws lws::ProtocolError.
    static Notification from_json(const nlohmann::json& json);
};

/// Parses a notification body. Throws lws::ProtocolError / lws::ParseError.
Notification parse_notification(std::string_view body);

/// Input of Client::subscribe().
struct WebhookSubscriptionRequest {
    std::vector<std::string> topics{};
    std::string inbox{};
    std::optional<std::string> expires{};  ///< RFC 3339 date-time

    nlohmann::json to_json() const;
};

/// A webhook subscription as returned by the notification service.
struct Subscription {
    std::string type{};
    std::string subscription{};  ///< absolute URL used to manage the subscription
    std::optional<std::string> expires{};
    nlohmann::json raw{};

    static Subscription from_json(const nlohmann::json& json, std::string_view base,
                                  std::optional<std::string> location = {});
};

}  // namespace lws
