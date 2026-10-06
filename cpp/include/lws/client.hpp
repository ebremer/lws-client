// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Erich Bremer and the lws-client contributors
//
// lws::Client — the entry point of the library (design/client-api.md §4–§9).
#pragma once

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <iterator>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <nlohmann/json.hpp>

#include "lws/access.hpp"
#include "lws/auth.hpp"
#include "lws/http.hpp"
#include "lws/json_patch.hpp"
#include "lws/link.hpp"
#include "lws/models.hpp"
#include "lws/notifications.hpp"
#include "lws/type_index.hpp"

namespace lws {

/// Client configuration.
struct ClientOptions {
    /// HTTP engine; defaults to make_default_transport() (libcurl).
    std::shared_ptr<HttpTransport> transport{};
    /// Request authentication; none (anonymous) by default.
    std::shared_ptr<Authenticator> authenticator{};
    std::string user_agent = "lws-client-cpp/0.1.0";
    /// Extra headers sent with every request.
    HttpHeaders default_headers{};
    /// Per-request timeout.
    std::chrono::milliseconds timeout{30000};
    /// Maximum redirects followed for safe methods (credentials are re-evaluated per hop).
    int max_redirects = 5;
};

/// Options common to every operation.
struct RequestOptions {
    HttpHeaders headers{};  ///< extra request headers
};

/// Options of read().
struct ReadOptions {
    HttpHeaders headers{};
    std::optional<std::string> accept{};
    std::optional<std::string> range{};  ///< e.g. "bytes=0-99" — see byte_range()
    std::optional<std::string> if_none_match{};
    std::optional<std::string> if_modified_since{};
    std::optional<std::string> prefer{};
};

/// "bytes=first-last" (last omitted → to the end).
std::string byte_range(std::uint64_t first, std::optional<std::uint64_t> last = {});

/// Options of create() / create_container().
struct CreateOptions {
    HttpHeaders headers{};
    std::optional<std::string> slug{};     ///< identity hint, sent as the Slug header
    std::vector<Link> links{};             ///< user-managed metadata sent as Link headers
    std::vector<std::string> types{};      ///< extra rel="type" links
};

/// Options of update() / patch() / update_linkset() / patch_linkset().
struct UpdateOptions {
    HttpHeaders headers{};
    std::optional<std::string> if_match{};
    std::optional<std::string> if_none_match{};
    std::vector<Link> links{};  ///< with set_linkset: replacement (PUT) / partial update (PATCH) of the linkset
    bool set_linkset = false; ///< adds "Prefer: set-linkset"
};

/// Options of remove().
struct DeleteOptions {
    HttpHeaders headers{};
    std::optional<std::string> if_match{};
    bool recursive = false;  ///< sends "Depth: infinity"
};

/// A lazy, single-pass range over items spread across pages. Pages are fetched on demand
/// while iterating, so it works in range-for and with std::ranges algorithms:
///
///     for (const lws::ContainedResource& item : client.list_container(url)) { ... }
template <typename T>
class PagedRange {
public:
    struct Page {
        std::vector<T> items{};
        std::optional<std::string> next{};
    };
    /// Fetches the page at `url` (nullopt = the first page).
    using PageFetcher = std::function<Page(const std::optional<std::string>& url)>;

    explicit PagedRange(PageFetcher fetcher) : fetcher_(std::move(fetcher)) {}

    class iterator {
    public:
        using iterator_concept = std::input_iterator_tag;
        using iterator_category = std::input_iterator_tag;
        using value_type = T;
        using difference_type = std::ptrdiff_t;
        using reference = const T&;
        using pointer = const T*;

        iterator() = default;
        reference operator*() const { return state_->page.items[state_->index]; }
        pointer operator->() const { return &state_->page.items[state_->index]; }
        iterator& operator++() {
            ++state_->index;
            settle();
            return *this;
        }
        void operator++(int) { ++*this; }
        friend bool operator==(const iterator& it, std::default_sentinel_t) noexcept {
            return !it.state_ || it.state_->index >= it.state_->page.items.size();
        }

    private:
        friend class PagedRange;
        struct State {
            PageFetcher fetcher;
            Page page;
            std::size_t index = 0;
        };
        explicit iterator(PageFetcher fetcher) : state_(std::make_shared<State>()) {
            state_->fetcher = std::move(fetcher);
            state_->page = state_->fetcher(std::nullopt);
            settle();
        }
        // Skips exhausted (or empty) pages until an item is available or no next page remains.
        void settle() {
            while (state_->index >= state_->page.items.size() && state_->page.next) {
                auto next = std::move(*state_->page.next);
                state_->page = state_->fetcher(next);
                state_->index = 0;
            }
        }
        std::shared_ptr<State> state_;
    };

    /// Starts a new traversal (fetches the first page).
    iterator begin() const { return iterator(fetcher_); }
    std::default_sentinel_t end() const noexcept { return {}; }

    /// Collects every item (fetches all pages).
    std::vector<T> to_vector() const {
        std::vector<T> out;
        for (auto it = begin(); it != end(); ++it) out.push_back(*it);
        return out;
    }

private:
    PageFetcher fetcher_;
};

using ContainerRange = PagedRange<ContainedResource>;
using TypeRange = PagedRange<std::string>;

/// The LWS client. Immutable after construction, cheap to copy (copies share state) and safe to
/// use from several threads at once.
class Client {
public:
    explicit Client(ClientOptions options = {});

    // ---- Discovery (§5.1) -------------------------------------------------------------
    /// HEAD (falling back to GET) `resource_url`, follow rel="…lws#storage" and fetch the
    /// storage description.
    StorageDescription discover_storage(std::string_view resource_url, const RequestOptions& options = {}) const;
    StorageDescription get_storage_description(std::string_view storage_url, const RequestOptions& options = {}) const;

    // ---- Reading (§5.2) ---------------------------------------------------------------
    ResourceMetadata head(std::string_view url, const RequestOptions& options = {}) const;
    /// GET a resource. A 304 answer to a conditional read is returned with not_modified = true.
    Resource read(std::string_view url, const ReadOptions& options = {}) const;
    ContainerPage read_container(std::string_view url, const RequestOptions& options = {}) const;
    /// Lazily iterates every member of a container, following rel="next".
    ContainerRange list_container(std::string_view url, const RequestOptions& options = {}) const;

    // ---- Creating (§5.3) --------------------------------------------------------------
    CreateResult create(std::string_view container_url, std::string_view body, std::string_view content_type,
                        const CreateOptions& options = {}) const;
    CreateResult create_json(std::string_view container_url, const nlohmann::json& value,
                             const CreateOptions& options = {}) const;
    CreateResult create_container(std::string_view parent_url, const CreateOptions& options = {}) const;

    // ---- Updating (§5.4) --------------------------------------------------------------
    /// PUT — full replacement.
    UpdateResult update(std::string_view url, std::string_view body, std::string_view content_type,
                        const UpdateOptions& options = {}) const;
    /// PATCH with JSON Patch (application/json-patch+json).
    UpdateResult patch(std::string_view url, const JsonPatch& patch, const UpdateOptions& options = {}) const;
    /// PATCH with any patch format advertised in Accept-Patch.
    UpdateResult patch(std::string_view url, std::string_view body, std::string_view content_type,
                       const UpdateOptions& options = {}) const;

    // ---- Deleting (§5.5) — `delete` is a C++ keyword ----------------------------------
    void remove(std::string_view url, const DeleteOptions& options = {}) const;

    // ---- Metadata / linksets (§5.6) ----------------------------------------------------
    std::string linkset_url(std::string_view resource_url, const RequestOptions& options = {}) const;
    LinksetDocument read_linkset(std::string_view resource_url, const RequestOptions& options = {}) const;
    UpdateResult update_linkset(std::string_view linkset_url, const Linkset& linkset,
                                const UpdateOptions& options = {}) const;
    UpdateResult patch_linkset(std::string_view linkset_url, const JsonPatch& patch,
                               const UpdateOptions& options = {}) const;

    // ---- Notifications (§7) -----------------------------------------------------------
    Subscription subscribe(std::string_view service_url, const WebhookSubscriptionRequest& request,
                           const RequestOptions& options = {}) const;
    /// Uses the storage's NotificationService after checking it supports WebhookSubscription.
    Subscription subscribe(const StorageDescription& storage, const WebhookSubscriptionRequest& request,
                           const RequestOptions& options = {}) const;
    ContainerRange list_subscriptions(std::string_view service_url, const RequestOptions& options = {}) const;
    Subscription get_subscription(std::string_view subscription_url, const RequestOptions& options = {}) const;
    void unsubscribe(std::string_view subscription_url, const RequestOptions& options = {}) const;

    // ---- Access requests / grants (§8) -------------------------------------------------
    std::string request_access(std::string_view service_url, const AccessRequest& request,
                               const RequestOptions& options = {}) const;
    ContainerRange list_access_requests(std::string_view service_url, const RequestOptions& options = {}) const;
    AccessRequest get_access_request(std::string_view url, const RequestOptions& options = {}) const;
    void cancel_access_request(std::string_view url, const RequestOptions& options = {}) const;
    std::string grant_access(std::string_view service_url, const AccessGrant& grant,
                             const RequestOptions& options = {}) const;
    ContainerRange list_access_grants(std::string_view service_url, const RequestOptions& options = {}) const;
    AccessGrant get_access_grant(std::string_view url, const RequestOptions& options = {}) const;
    void revoke_access_grant(std::string_view url, const RequestOptions& options = {}) const;

    // ---- Type index / search (§9) ------------------------------------------------------
    TypeIndexPage read_type_index(std::string_view url, const RequestOptions& options = {}) const;
    TypeRange list_types(std::string_view service_url, const RequestOptions& options = {}) const;
    /// HTTP QUERY with an application/lws-query+json filter.
    SearchPage search_types(std::string_view service_url, const TypeQuery& query,
                            const RequestOptions& options = {}) const;
    /// QUERY the first page, then GET each opaque rel="next" page.
    ContainerRange search_all(std::string_view service_url, const TypeQuery& query,
                              const RequestOptions& options = {}) const;
    /// OPTIONS → media types from Accept-Query.
    std::vector<std::string> accepted_query_formats(std::string_view service_url,
                                                    const RequestOptions& options = {}) const;

    // ---- Low level ---------------------------------------------------------------------
    /// Sends a request with default headers, authentication (incl. the 401 retry) and redirect
    /// handling. Does not throw for HTTP error statuses.
    HttpResponse execute(HttpRequest request) const;
    /// Like execute() but throws the matching lws::HttpError unless the status is 2xx.
    HttpResponse execute_checked(HttpRequest request) const;

    const ClientOptions& options() const noexcept;

private:
    struct Impl;
    std::shared_ptr<const Impl> impl_;
};

}  // namespace lws
