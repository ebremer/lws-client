// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Erich Bremer and the lws-client contributors
//
// Value-semantic models of LWS resources (design/client-api.md §5).
#pragma once

#include <chrono>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <nlohmann/json.hpp>

#include "lws/http.hpp"
#include "lws/link.hpp"

namespace lws {

using TimePoint = std::chrono::system_clock::time_point;

/// Metadata parsed from the headers of a response (GET/HEAD/POST/PUT/PATCH).
struct ResourceMetadata {
    std::string url{};  ///< final URL of the response
    int status = 0;
    std::optional<std::string> etag{};  ///< raw (quotes / W/ kept) — echo verbatim in If-Match
    std::optional<std::string> last_modified{};
    std::optional<std::string> content_type{};
    std::optional<std::uint64_t> content_length{};
    std::vector<Link> links{};
    std::optional<std::string> linkset{};  ///< rel="linkset"
    std::optional<std::string> parent{};   ///< rel="up"
    std::optional<std::string> storage{};  ///< rel="https://www.w3.org/ns/lws#storage"
    std::vector<std::string> types{};      ///< targets of rel="type"
    std::vector<std::string> allow{};
    std::vector<std::string> accept_patch{};
    HttpHeaders headers{};

    static ResourceMetadata from_response(const HttpResponse& response);

    bool is_container() const noexcept;
    bool is_data_resource() const noexcept;
    bool has_type(std::string_view type) const noexcept;
    /// First link with relation `rel` (registered relations compared case-insensitively).
    std::optional<Link> link(std::string_view rel) const;
    std::vector<Link> links_with(std::string_view rel) const;
    /// Media type without parameters, lower-cased.
    std::optional<std::string> media_type() const;
};

/// Result of read(): metadata plus body.
struct Resource : ResourceMetadata {
    std::string body{};           ///< raw bytes
    bool not_modified = false;  ///< true for a 304 answer to a conditional read (body empty)
    std::optional<std::string> content_range{};  ///< for 206 Partial Content

    /// Body interpreted as text (bytes are returned as-is; LWS text is UTF-8 by default).
    const std::string& text() const noexcept { return body; }
    /// Body parsed as JSON. Throws lws::ParseError for invalid JSON.
    nlohmann::json json() const;
};

/// One member listed in a container representation.
struct ContainedResource {
    std::string id{};  ///< absolute
    std::vector<std::string> types{};
    std::optional<std::string> format{};
    std::optional<std::int64_t> size{};
    std::optional<std::string> modified_raw{};  ///< as received
    std::optional<TimePoint> modified{};        ///< parsed; nullopt if absent or unparseable
    nlohmann::json raw{};

    bool is_container() const noexcept;
    bool is_data_resource() const noexcept;
    bool has_type(std::string_view type) const noexcept;

    static ContainedResource from_json(const nlohmann::json& json, std::string_view base);
};

/// One page of a container listing (or of a Type Search result set).
struct ContainerPage {
    std::string id{};  ///< absolute (empty for synthetic search pages without id)
    std::vector<std::string> types{};
    std::optional<std::int64_t> total_items{};
    std::vector<ContainedResource> items{};
    std::optional<std::string> first{};
    std::optional<std::string> next{};
    std::optional<std::string> prev{};
    std::optional<std::string> last{};
    ResourceMetadata metadata{};
    nlohmann::json raw{};

    bool is_container() const noexcept;
    bool has_type(std::string_view type) const noexcept;

    /// Parses a container representation. With `require_container`, throws ProtocolError if the
    /// rel=type links or the body `type` show the resource is not a Container, and rejects
    /// content types other than application/lws+json, application/ld+json, application/json.
    static ContainerPage from_response(const HttpResponse& response, bool require_container = true);
};

/// A Type Search result page has the ContainerPage shape (lws10-index).
using SearchPage = ContainerPage;

/// A service entry of a storage description.
struct Service {
    std::optional<std::string> id{};
    std::vector<std::string> types{};
    std::string service_endpoint{};  ///< absolute
    nlohmann::json raw{};            ///< all members, e.g. subscriptionType, conformsTo

    bool has_type(std::string_view type) const noexcept;
    /// String values of a member that is a string or an array of strings.
    std::vector<std::string> strings(std::string_view member) const;
};

/// A capability entry of a storage description.
struct Capability {
    std::optional<std::string> id{};
    std::vector<std::string> types{};
    nlohmann::json raw{};

    bool has_type(std::string_view type) const noexcept;
};

/// A verification method of a controlled identifier document.
struct VerificationMethod {
    std::string id{};  ///< as written (may be relative, e.g. "#key-1")
    std::string type{};
    std::optional<std::string> controller{};
    nlohmann::json public_key_jwk{};  ///< null if absent
    nlohmann::json raw{};
};

/// A storage description resource (a W3C Controlled Identifier document specialisation).
struct StorageDescription {
    std::string id{};
    std::vector<std::string> types{};
    std::vector<Service> services{};
    std::vector<Capability> capabilities{};
    std::vector<VerificationMethod> verification_methods{};
    nlohmann::json authentication = nlohmann::json::array();  ///< references (strings) or embedded methods
    nlohmann::json raw{};

    /// Parses and validates (type must include "Storage"). Relative URIs are resolved against
    /// `base`. Throws lws::ProtocolError when invalid.
    static StorageDescription from_json(const nlohmann::json& json, std::string_view base);

    /// URI of the storage root container. Throws ProtocolError if no StorageRoot service.
    std::string storage_root() const;
    const Service* service(std::string_view type) const noexcept;
    std::vector<const Service*> services_of(std::string_view type) const;
    const Capability* capability(std::string_view type) const noexcept;
    const Service* notification_service() const noexcept;
    const Service* access_request_service() const noexcept;
    const Service* access_grant_service() const noexcept;
    const Service* type_index_service() const noexcept;
    const Service* type_search_service() const noexcept;
    /// Finds a verification method by full id, fragment ("#frag" / "frag") or relative id.
    const VerificationMethod* verification_method(std::string_view id_or_fragment) const;
    /// True when `method_id` (any of the forms above) is referenced from `authentication`.
    bool is_authentication_method(std::string_view method_id) const;
};

/// Result of create() / create_container().
struct CreateResult {
    std::string location{};  ///< absolute URI of the new resource
    ResourceMetadata metadata{};
    std::string body{};
};

/// Result of update() / patch() / update_linkset() / patch_linkset().
struct UpdateResult {
    int status = 0;
    std::optional<std::string> etag{};
    ResourceMetadata metadata{};
    std::string body{};
};

/// One link target object inside a linkset context.
struct LinkTarget {
    std::string href{};
    nlohmann::json attributes = nlohmann::json::object();  ///< every member except href

    friend bool operator==(const LinkTarget&, const LinkTarget&) = default;
};

/// One link context object (anchor + relations) of a linkset.
struct LinkContext {
    std::optional<std::string> anchor{};
    std::vector<std::pair<std::string, std::vector<LinkTarget>>> relations{};  ///< insertion order

    std::vector<LinkTarget>* relation(std::string_view rel) noexcept;
    const std::vector<LinkTarget>* relation(std::string_view rel) const noexcept;
};

/// application/linkset+json document (RFC 9264).
class Linkset {
public:
    std::vector<LinkContext> contexts{};

    static Linkset from_json(const nlohmann::json& json);
    nlohmann::json to_json() const;

    /// All links flattened (string attributes become Link params; `anchor` param set).
    std::vector<Link> links() const;
    /// hrefs of every target with relation `rel` (any anchor).
    std::vector<std::string> targets(std::string_view rel) const;
    /// hrefs of targets with relation `rel` under `anchor`.
    std::vector<std::string> targets(std::string_view anchor, std::string_view rel) const;
    /// Adds a target (creating the context / relation when needed).
    Linkset& add(std::string_view anchor, std::string_view rel, std::string href,
                 nlohmann::json attributes = nlohmann::json::object());
    /// Removes targets of `rel` under `anchor` (only those with `href` when given).
    Linkset& remove(std::string_view anchor, std::string_view rel, std::optional<std::string_view> href = {});

private:
    nlohmann::json extra_ = nlohmann::json::object();  ///< unknown top-level members, preserved
};

/// A linkset resource as read from the server.
struct LinksetDocument {
    std::string url{};  ///< URL of the linkset resource
    std::optional<std::string> etag{};
    Linkset linkset{};
    std::vector<std::string> allow{};
    std::vector<std::string> accept_patch{};
    ResourceMetadata metadata{};
};

/// Normalises a JSON `type` member (string or array) to a list of strings.
std::vector<std::string> json_types(const nlohmann::json& value);

}  // namespace lws
