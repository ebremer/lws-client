// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Erich Bremer and the lws-client contributors
//
// Shared constants of the W3C Linked Web Storage protocol (lws10-core and companion specs,
// as of 2026-10-05). See design/client-api.md §2.
#pragma once

#include <string_view>

namespace lws {

/// Namespaces and JSON-LD contexts.
namespace ns {
inline constexpr std::string_view lws = "https://www.w3.org/ns/lws#";
inline constexpr std::string_view lws_context = "https://www.w3.org/ns/lws/v1";
inline constexpr std::string_view cid_context = "https://www.w3.org/ns/cid/v1";
inline constexpr std::string_view activitystreams_context = "https://www.w3.org/ns/activitystreams";
}  // namespace ns

/// Link relation types used by LWS.
namespace rel {
inline constexpr std::string_view storage = "https://www.w3.org/ns/lws#storage";
inline constexpr std::string_view linkset = "linkset";
inline constexpr std::string_view up = "up";
inline constexpr std::string_view type = "type";
inline constexpr std::string_view first = "first";
inline constexpr std::string_view next = "next";
inline constexpr std::string_view prev = "prev";
inline constexpr std::string_view last = "last";
inline constexpr std::string_view describedby = "describedby";
}  // namespace rel

/// Resource type IRIs (the short terms "Container", "DataResource", "StorageResource" are equivalent).
namespace types {
inline constexpr std::string_view container = "https://www.w3.org/ns/lws#Container";
inline constexpr std::string_view data_resource = "https://www.w3.org/ns/lws#DataResource";
inline constexpr std::string_view storage_resource = "https://www.w3.org/ns/lws#StorageResource";
inline constexpr std::string_view storage = "https://www.w3.org/ns/lws#Storage";
}  // namespace types

/// Media types.
namespace media {
inline constexpr std::string_view lws_json = "application/lws+json";
inline constexpr std::string_view lws_cid = "application/lws+cid";
inline constexpr std::string_view linkset_json = "application/linkset+json";
inline constexpr std::string_view json_patch = "application/json-patch+json";
inline constexpr std::string_view lws_query_json = "application/lws-query+json";
inline constexpr std::string_view ld_json = "application/ld+json";
inline constexpr std::string_view json = "application/json";
inline constexpr std::string_view problem_json = "application/problem+json";
inline constexpr std::string_view form = "application/x-www-form-urlencoded";
inline constexpr std::string_view text_plain = "text/plain";
inline constexpr std::string_view octet_stream = "application/octet-stream";
}  // namespace media

/// Service types found in a storage description's "service" array.
namespace service {
inline constexpr std::string_view storage_root = "StorageRoot";
inline constexpr std::string_view notification = "NotificationService";
inline constexpr std::string_view access_request = "AccessRequestService";
inline constexpr std::string_view access_grant = "AccessGrantService";
inline constexpr std::string_view type_index = "TypeIndexService";
inline constexpr std::string_view type_search = "TypeSearchService";
}  // namespace service

/// Notification subscription types.
namespace subscription {
inline constexpr std::string_view webhook = "WebhookSubscription";
}  // namespace subscription

/// OAuth 2.0 token exchange and authentication suite identifiers.
namespace oauth {
inline constexpr std::string_view grant_type_token_exchange = "urn:ietf:params:oauth:grant-type:token-exchange";
inline constexpr std::string_view token_type_id_token = "urn:ietf:params:oauth:token-type:id_token";
inline constexpr std::string_view token_type_saml2 = "urn:ietf:params:oauth:token-type:saml2";
inline constexpr std::string_view token_type_jwt = "urn:ietf:params:oauth:token-type:jwt";
inline constexpr std::string_view token_type_access_token = "urn:ietf:params:oauth:token-type:access_token";
inline constexpr std::string_view well_known_lws_configuration = "/.well-known/lws-configuration";
inline constexpr std::string_view openid_provider_service = "https://www.w3.org/ns/lws#OpenIdProvider";
}  // namespace oauth

/// Access requests and grants (ODRL-based Access Profile).
namespace access {
inline constexpr std::string_view profile = "https://www.w3.org/ns/lws#AccessProfile";
inline constexpr std::string_view type_access_request = "AccessRequest";
inline constexpr std::string_view type_access_grant = "AccessGrant";
inline constexpr std::string_view type_access_policy = "AccessPolicy";
inline constexpr std::string_view action_read = "read";
inline constexpr std::string_view action_modify = "modify";
inline constexpr std::string_view action_create = "create";
inline constexpr std::string_view action_delete = "delete";
inline constexpr std::string_view operand_client = "client";
inline constexpr std::string_view operand_format = "format";
inline constexpr std::string_view operand_type = "type";
inline constexpr std::string_view operand_purpose = "purpose";
inline constexpr std::string_view operand_date_time = "dateTime";
inline constexpr std::string_view operator_eq = "eq";
inline constexpr std::string_view operator_is_any_of = "isAnyOf";
inline constexpr std::string_view operator_gteq = "gteq";
inline constexpr std::string_view operator_lteq = "lteq";
inline constexpr std::string_view public_agent = "http://xmlns.com/foaf/0.1/Agent";
}  // namespace access

/// Prefer header tokens.
namespace prefer {
inline constexpr std::string_view set_linkset = "set-linkset";
inline constexpr std::string_view link_relations = "https://www.w3.org/ns/lws#PreferLinkRelations";
}  // namespace prefer

/// Activity Streams 2.0 activity types used in notifications.
namespace activity {
inline constexpr std::string_view create = "Create";
inline constexpr std::string_view update = "Update";
inline constexpr std::string_view remove = "Delete";
}  // namespace activity

/// Returns true if two type values denote the same type, treating `Term`, `lws:Term` and
/// `https://www.w3.org/ns/lws#Term` as equal (design/client-api.md §2 "Type matching").
bool type_matches(std::string_view actual, std::string_view expected) noexcept;

}  // namespace lws
