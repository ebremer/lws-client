// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Erich Bremer and the lws-client contributors

#include "lws/client.hpp"

#include <algorithm>

#include "lws/constants.hpp"
#include "lws/encoding.hpp"
#include "lws/errors.hpp"
#include "lws/url.hpp"

namespace lws {

struct Client::Impl {
    ClientOptions options;
};

namespace {

// Request headers given per call override same-named headers set earlier.
void merge_headers(HttpHeaders& target, const HttpHeaders& extra) {
    for (const auto& [name, value] : extra) target.remove(name);
    for (const auto& [name, value] : extra) target.add(name, value);
}

bool is_redirect(int status) noexcept {
    return status == 301 || status == 302 || status == 303 || status == 307 || status == 308;
}

HttpRequest make_request(std::string method, std::string_view url, const HttpHeaders& extra = {}) {
    HttpRequest r;
    r.method = std::move(method);
    r.url = std::string(url);
    merge_headers(r.headers, extra);
    return r;
}

void set_if(HttpHeaders& headers, const char* name, const std::optional<std::string>& value) {
    if (value) headers.set(name, *value);
}

nlohmann::json parse_json(const HttpResponse& response, std::string_view what) {
    auto json = nlohmann::json::parse(response.body, nullptr, false);
    if (json.is_discarded()) throw ParseError(std::string(what) + " is not valid JSON: " + response.url);
    return json;
}

std::string required_location(const HttpRequest& request, const HttpResponse& response) {
    auto location = response.headers.get("location");
    if (!location || location->empty())
        throw ProtocolError(request.method + " " + request.url + " succeeded without a Location header");
    return resolve_url(response.url.empty() ? request.url : response.url, *location);
}

UpdateResult to_update_result(HttpResponse&& response) {
    UpdateResult result;
    result.status = response.status;
    result.etag = response.headers.get("etag");
    result.metadata = ResourceMetadata::from_response(response);
    result.body = std::move(response.body);
    return result;
}

void apply_update_options(HttpRequest& req, const UpdateOptions& options) {
    set_if(req.headers, "If-Match", options.if_match);
    set_if(req.headers, "If-None-Match", options.if_none_match);
    for (const auto& link : options.links) req.headers.add("Link", link.to_header());
    if (options.set_linkset) req.headers.add("Prefer", std::string(prefer::set_linkset));
    merge_headers(req.headers, options.headers);
}

}  // namespace

std::string byte_range(std::uint64_t first, std::optional<std::uint64_t> last) {
    return "bytes=" + std::to_string(first) + "-" + (last ? std::to_string(*last) : std::string());
}

Client::Client(ClientOptions options) {
    auto impl = std::make_shared<Impl>();
    impl->options = std::move(options);
    if (!impl->options.transport) impl->options.transport = make_default_transport();
    impl_ = std::move(impl);
}

const ClientOptions& Client::options() const noexcept { return impl_->options; }

HttpResponse Client::execute(HttpRequest request) const {
    const auto& opts = impl_->options;
    if (request.timeout.count() == 0) request.timeout = opts.timeout;
    if (!request.headers.contains("user-agent") && !opts.user_agent.empty())
        request.headers.set("User-Agent", opts.user_agent);
    for (const auto& [name, value] : opts.default_headers)
        if (!request.headers.contains(name)) request.headers.add(name, value);

    auto& transport = *opts.transport;
    for (int hop = 0;; ++hop) {
        HttpRequest attempt = request;
        if (opts.authenticator) opts.authenticator->authorize(attempt);
        HttpResponse response = transport.send(attempt);
        if (response.url.empty()) response.url = attempt.url;
        if (response.status == 401 && opts.authenticator &&
            opts.authenticator->handle_challenge(attempt, response, transport)) {
            attempt = request;
            opts.authenticator->authorize(attempt);
            response = transport.send(attempt);
            if (response.url.empty()) response.url = attempt.url;
        }
        if (!is_redirect(response.status) || hop >= opts.max_redirects) return response;
        const auto location = response.headers.get("location");
        if (!location) return response;
        const bool get_like = request.method == "GET" || request.method == "HEAD";
        const bool preserving = response.status == 307 || response.status == 308;
        if (!get_like && !((request.method == "OPTIONS" || request.method == "QUERY") && preserving)) return response;
        request.url = resolve_url(response.url, *location);
        // Credentials are re-evaluated by the authenticator for the new URL; never forward them.
        request.headers.remove("authorization");
    }
}

HttpResponse Client::execute_checked(HttpRequest request) const {
    const HttpRequest copy = request;
    auto response = execute(std::move(request));
    raise_for_status(copy, response);
    return response;
}

// ---- Discovery ----------------------------------------------------------------------------

StorageDescription Client::discover_storage(std::string_view resource_url, const RequestOptions& options) const {
    auto req = make_request("HEAD", resource_url, options.headers);
    auto resp = execute(req);
    if (resp.status == 405 || resp.status == 501) {
        req.method = "GET";
        resp = execute(req);
    }
    const auto meta = ResourceMetadata::from_response(resp);
    if (!meta.storage) {
        if (!resp.ok()) throw_http_error(req, resp);
        throw ProtocolError("response has no rel=\"" + std::string(rel::storage) + "\" link: " + resp.url);
    }
    return get_storage_description(*meta.storage, options);
}

StorageDescription Client::get_storage_description(std::string_view storage_url, const RequestOptions& options) const {
    auto req = make_request("GET", storage_url);
    req.headers.set("Accept", "application/lws+cid, application/ld+json;q=0.9, application/json;q=0.8");
    merge_headers(req.headers, options.headers);
    auto resp = execute_checked(req);
    return StorageDescription::from_json(parse_json(resp, "storage description"), resp.url);
}

// ---- Reading --------------------------------------------------------------------------------

ResourceMetadata Client::head(std::string_view url, const RequestOptions& options) const {
    auto resp = execute_checked(make_request("HEAD", url, options.headers));
    return ResourceMetadata::from_response(resp);
}

Resource Client::read(std::string_view url, const ReadOptions& options) const {
    auto req = make_request("GET", url);
    set_if(req.headers, "Accept", options.accept);
    set_if(req.headers, "Range", options.range);
    set_if(req.headers, "If-None-Match", options.if_none_match);
    set_if(req.headers, "If-Modified-Since", options.if_modified_since);
    set_if(req.headers, "Prefer", options.prefer);
    merge_headers(req.headers, options.headers);
    auto resp = execute(req);
    raise_for_status(req, resp, /*allow_not_modified=*/true);
    Resource r;
    static_cast<ResourceMetadata&>(r) = ResourceMetadata::from_response(resp);
    r.not_modified = resp.status == 304;
    r.content_range = resp.headers.get("content-range");
    if (!r.not_modified) r.body = std::move(resp.body);
    return r;
}

ContainerPage Client::read_container(std::string_view url, const RequestOptions& options) const {
    auto req = make_request("GET", url);
    req.headers.set("Accept", std::string(media::lws_json));
    merge_headers(req.headers, options.headers);
    return ContainerPage::from_response(execute_checked(req), /*require_container=*/true);
}

ContainerRange Client::list_container(std::string_view url, const RequestOptions& options) const {
    return ContainerRange([client = *this, start = std::string(url), options](const std::optional<std::string>& page) {
        auto p = client.read_container(page.value_or(start), options);
        return ContainerRange::Page{std::move(p.items), std::move(p.next)};
    });
}

// ---- Creating -------------------------------------------------------------------------------

CreateResult Client::create(std::string_view container_url, std::string_view body, std::string_view content_type,
                            const CreateOptions& options) const {
    auto req = make_request("POST", container_url);
    req.body = std::string(body);
    if (!content_type.empty()) req.headers.set("Content-Type", std::string(content_type));
    if (options.slug) req.headers.set("Slug", slug_encode(*options.slug));
    for (const auto& type : options.types) req.headers.add("Link", Link{type, std::string(rel::type), {}}.to_header());
    for (const auto& link : options.links) req.headers.add("Link", link.to_header());
    merge_headers(req.headers, options.headers);
    auto resp = execute_checked(req);
    CreateResult result;
    result.location = required_location(req, resp);
    result.metadata = ResourceMetadata::from_response(resp);
    result.body = std::move(resp.body);
    return result;
}

CreateResult Client::create_json(std::string_view container_url, const nlohmann::json& value,
                                 const CreateOptions& options) const {
    return create(container_url, value.dump(), media::json, options);
}

CreateResult Client::create_container(std::string_view parent_url, const CreateOptions& options) const {
    CreateOptions opts = options;
    opts.links.insert(opts.links.begin(), Link{std::string(types::container), std::string(rel::type), {}});
    return create(parent_url, {}, {}, opts);
}

// ---- Updating / deleting --------------------------------------------------------------------

UpdateResult Client::update(std::string_view url, std::string_view body, std::string_view content_type,
                            const UpdateOptions& options) const {
    auto req = make_request("PUT", url);
    req.body = std::string(body);
    if (!content_type.empty()) req.headers.set("Content-Type", std::string(content_type));
    apply_update_options(req, options);
    return to_update_result(execute_checked(req));
}

UpdateResult Client::patch(std::string_view url, const JsonPatch& patch, const UpdateOptions& options) const {
    return this->patch(url, patch.dump(), media::json_patch, options);
}

UpdateResult Client::patch(std::string_view url, std::string_view body, std::string_view content_type,
                           const UpdateOptions& options) const {
    auto req = make_request("PATCH", url);
    req.body = std::string(body);
    req.headers.set("Content-Type", std::string(content_type));
    apply_update_options(req, options);
    return to_update_result(execute_checked(req));
}

void Client::remove(std::string_view url, const DeleteOptions& options) const {
    auto req = make_request("DELETE", url);
    set_if(req.headers, "If-Match", options.if_match);
    if (options.recursive) req.headers.set("Depth", "infinity");
    merge_headers(req.headers, options.headers);
    execute_checked(req);
}

// ---- Linksets -------------------------------------------------------------------------------

std::string Client::linkset_url(std::string_view resource_url, const RequestOptions& options) const {
    auto meta = head(resource_url, options);
    if (!meta.linkset) throw ProtocolError("resource advertises no rel=\"linkset\": " + std::string(resource_url));
    return *meta.linkset;
}

LinksetDocument Client::read_linkset(std::string_view resource_url, const RequestOptions& options) const {
    const auto url = linkset_url(resource_url, options);
    auto req = make_request("GET", url);
    req.headers.set("Accept", std::string(media::linkset_json));
    merge_headers(req.headers, options.headers);
    auto resp = execute_checked(req);
    LinksetDocument doc;
    doc.linkset = Linkset::from_json(parse_json(resp, "linkset"));
    doc.metadata = ResourceMetadata::from_response(resp);
    doc.url = resp.url;
    doc.etag = doc.metadata.etag;
    doc.allow = doc.metadata.allow;
    doc.accept_patch = doc.metadata.accept_patch;
    return doc;
}

UpdateResult Client::update_linkset(std::string_view linkset_url, const Linkset& linkset,
                                    const UpdateOptions& options) const {
    return update(linkset_url, linkset.to_json().dump(), media::linkset_json, options);
}

UpdateResult Client::patch_linkset(std::string_view linkset_url, const JsonPatch& patch,
                                   const UpdateOptions& options) const {
    return this->patch(linkset_url, patch, options);
}

// ---- Notifications --------------------------------------------------------------------------

Subscription Client::subscribe(std::string_view service_url, const WebhookSubscriptionRequest& request,
                               const RequestOptions& options) const {
    auto req = make_request("POST", service_url);
    req.headers.set("Content-Type", std::string(media::lws_json));
    req.headers.set("Accept", std::string(media::lws_json));
    req.body = request.to_json().dump();
    merge_headers(req.headers, options.headers);
    auto resp = execute_checked(req);
    nlohmann::json body = nlohmann::json::object();
    if (!resp.body.empty()) body = parse_json(resp, "subscription response");
    auto sub = Subscription::from_json(body, resp.url, resp.headers.get("location"));
    if (sub.subscription.empty()) throw ProtocolError("subscription response has no subscription URL");
    return sub;
}

Subscription Client::subscribe(const StorageDescription& storage, const WebhookSubscriptionRequest& request,
                               const RequestOptions& options) const {
    const auto* svc = storage.notification_service();
    if (!svc) throw ProtocolError("storage " + storage.id + " advertises no NotificationService");
    const auto supported = svc->strings("subscriptionType");
    if (std::none_of(supported.begin(), supported.end(),
                     [](const std::string& t) { return type_matches(t, subscription::webhook); }))
        throw ProtocolError("NotificationService of " + storage.id + " does not support WebhookSubscription");
    return subscribe(svc->service_endpoint, request, options);
}

ContainerRange Client::list_subscriptions(std::string_view service_url, const RequestOptions& options) const {
    return list_container(service_url, options);
}

Subscription Client::get_subscription(std::string_view subscription_url, const RequestOptions& options) const {
    auto req = make_request("GET", subscription_url);
    req.headers.set("Accept", std::string(media::lws_json));
    merge_headers(req.headers, options.headers);
    auto resp = execute_checked(req);
    return Subscription::from_json(parse_json(resp, "subscription"), resp.url, std::string(subscription_url));
}

void Client::unsubscribe(std::string_view subscription_url, const RequestOptions& options) const {
    execute_checked(make_request("DELETE", subscription_url, options.headers));
}

// ---- Access requests / grants ---------------------------------------------------------------

namespace {
template <typename Doc>
std::string post_access(const Client& client, std::string_view service_url, const Doc& doc,
                        const RequestOptions& options) {
    auto req = make_request("POST", service_url);
    req.headers.set("Content-Type", std::string(media::lws_json));
    req.headers.set("Accept", std::string(media::lws_json));
    req.body = doc.to_json().dump();
    merge_headers(req.headers, options.headers);
    auto resp = client.execute_checked(req);
    return required_location(req, resp);
}

template <typename Doc>
Doc get_access(const Client& client, std::string_view url, const RequestOptions& options) {
    auto req = make_request("GET", url);
    req.headers.set("Accept", std::string(media::lws_json));
    merge_headers(req.headers, options.headers);
    auto resp = client.execute_checked(req);
    return Doc::from_json(parse_json(resp, "access document"));
}
}  // namespace

std::string Client::request_access(std::string_view service_url, const AccessRequest& request,
                                   const RequestOptions& options) const {
    return post_access(*this, service_url, request, options);
}
ContainerRange Client::list_access_requests(std::string_view service_url, const RequestOptions& options) const {
    return list_container(service_url, options);
}
AccessRequest Client::get_access_request(std::string_view url, const RequestOptions& options) const {
    return get_access<AccessRequest>(*this, url, options);
}
void Client::cancel_access_request(std::string_view url, const RequestOptions& options) const {
    execute_checked(make_request("DELETE", url, options.headers));
}
std::string Client::grant_access(std::string_view service_url, const AccessGrant& grant,
                                 const RequestOptions& options) const {
    return post_access(*this, service_url, grant, options);
}
ContainerRange Client::list_access_grants(std::string_view service_url, const RequestOptions& options) const {
    return list_container(service_url, options);
}
AccessGrant Client::get_access_grant(std::string_view url, const RequestOptions& options) const {
    return get_access<AccessGrant>(*this, url, options);
}
void Client::revoke_access_grant(std::string_view url, const RequestOptions& options) const {
    execute_checked(make_request("DELETE", url, options.headers));
}

// ---- Type index / search --------------------------------------------------------------------

TypeIndexPage Client::read_type_index(std::string_view url, const RequestOptions& options) const {
    auto req = make_request("GET", url);
    req.headers.set("Accept", std::string(media::lws_json));
    merge_headers(req.headers, options.headers);
    return TypeIndexPage::from_response(execute_checked(req));
}

TypeRange Client::list_types(std::string_view service_url, const RequestOptions& options) const {
    return TypeRange([client = *this, start = std::string(service_url), options](const std::optional<std::string>& page) {
        auto p = client.read_type_index(page.value_or(start), options);
        return TypeRange::Page{std::move(p.types), std::move(p.next)};
    });
}

SearchPage Client::search_types(std::string_view service_url, const TypeQuery& query,
                                const RequestOptions& options) const {
    auto req = make_request("QUERY", service_url);
    req.headers.set("Content-Type", std::string(media::lws_query_json));
    req.headers.set("Accept", std::string(media::lws_json));
    req.body = query.dump();
    merge_headers(req.headers, options.headers);
    return ContainerPage::from_response(execute_checked(req), /*require_container=*/false);
}

ContainerRange Client::search_all(std::string_view service_url, const TypeQuery& query,
                                  const RequestOptions& options) const {
    return ContainerRange(
        [client = *this, start = std::string(service_url), query, options](const std::optional<std::string>& page) {
            ContainerPage p;
            if (!page) {
                p = client.search_types(start, query, options);
            } else {
                auto req = make_request("GET", *page);
                req.headers.set("Accept", std::string(media::lws_json));
                merge_headers(req.headers, options.headers);
                p = ContainerPage::from_response(client.execute_checked(req), /*require_container=*/false);
            }
            return ContainerRange::Page{std::move(p.items), std::move(p.next)};
        });
}

std::vector<std::string> Client::accepted_query_formats(std::string_view service_url,
                                                        const RequestOptions& options) const {
    auto resp = execute_checked(make_request("OPTIONS", service_url, options.headers));
    return resp.headers.get_list("accept-query");
}

}  // namespace lws
