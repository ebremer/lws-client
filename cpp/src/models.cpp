// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Erich Bremer and the lws-client contributors

#include "lws/models.hpp"

#include <algorithm>
#include <cctype>

#include "lws/constants.hpp"
#include "lws/encoding.hpp"
#include "lws/errors.hpp"
#include "lws/url.hpp"

namespace lws {
namespace {

bool rel_equals(std::string_view a, std::string_view b) {
    // Extension relation types (URIs) compare exactly; registered ones case-insensitively.
    if (a.find(':') != std::string_view::npos || b.find(':') != std::string_view::npos) return a == b;
    return iequals(a, b);
}

std::optional<std::string> string_member(const nlohmann::json& j, const char* key) {
    if (!j.is_object()) return std::nullopt;
    auto it = j.find(key);
    if (it == j.end() || !it->is_string()) return std::nullopt;
    return it->get<std::string>();
}

bool any_type(const std::vector<std::string>& types, std::string_view type) noexcept {
    return std::any_of(types.begin(), types.end(), [&](const std::string& t) { return type_matches(t, type); });
}

std::optional<std::string> first_link(const std::vector<Link>& links, std::string_view rel) {
    for (const auto& l : links)
        if (rel_equals(l.rel, rel)) return l.href;
    return std::nullopt;
}

std::string lower_media_type(std::string_view content_type) {
    std::string m(content_type.substr(0, content_type.find(';')));
    const auto b = m.find_first_not_of(" \t");
    const auto e = m.find_last_not_of(" \t");
    m = b == std::string::npos ? std::string() : m.substr(b, e - b + 1);
    std::transform(m.begin(), m.end(), m.begin(), [](unsigned char c) { return char(std::tolower(c)); });
    return m;
}

nlohmann::json parse_json_body(const HttpResponse& response, std::string_view what) {
    auto json = nlohmann::json::parse(response.body, nullptr, false);
    if (json.is_discarded()) throw ParseError(std::string(what) + ": response body is not valid JSON");
    return json;
}

}  // namespace

std::vector<std::string> json_types(const nlohmann::json& value) {
    std::vector<std::string> out;
    if (value.is_string()) {
        out.push_back(value.get<std::string>());
    } else if (value.is_array()) {
        for (const auto& v : value)
            if (v.is_string()) out.push_back(v.get<std::string>());
    }
    return out;
}

// ---------------------------------------------------------------------------------------------
// ResourceMetadata / Resource
// ---------------------------------------------------------------------------------------------

ResourceMetadata ResourceMetadata::from_response(const HttpResponse& response) {
    ResourceMetadata m;
    m.url = response.url;
    m.status = response.status;
    m.headers = response.headers;
    m.etag = response.headers.get("etag");
    m.last_modified = response.headers.get("last-modified");
    m.content_type = response.headers.get("content-type");
    if (auto cl = response.headers.get("content-length")) {
        try {
            m.content_length = std::stoull(*cl);
        } catch (...) {
        }
    }
    m.links = parse_link_headers(response.headers.get_all("link"), response.url);
    m.linkset = first_link(m.links, lws::rel::linkset);
    m.parent = first_link(m.links, lws::rel::up);
    m.storage = first_link(m.links, lws::rel::storage);
    for (const auto& l : m.links)
        if (l.rel == lws::rel::type) m.types.push_back(l.href);
    m.allow = response.headers.get_list("allow");
    m.accept_patch = response.headers.get_list("accept-patch");
    return m;
}

bool ResourceMetadata::is_container() const noexcept { return any_type(types, lws::types::container); }
bool ResourceMetadata::is_data_resource() const noexcept { return any_type(types, lws::types::data_resource); }
bool ResourceMetadata::has_type(std::string_view type) const noexcept { return any_type(types, type); }

std::optional<Link> ResourceMetadata::link(std::string_view rel) const {
    for (const auto& l : links)
        if (rel_equals(l.rel, rel)) return l;
    return std::nullopt;
}

std::vector<Link> ResourceMetadata::links_with(std::string_view rel) const {
    std::vector<Link> out;
    for (const auto& l : links)
        if (rel_equals(l.rel, rel)) out.push_back(l);
    return out;
}

std::optional<std::string> ResourceMetadata::media_type() const {
    if (!content_type) return std::nullopt;
    return lower_media_type(*content_type);
}

nlohmann::json Resource::json() const {
    auto j = nlohmann::json::parse(body, nullptr, false);
    if (j.is_discarded()) throw ParseError("resource body is not valid JSON: " + url);
    return j;
}

// ---------------------------------------------------------------------------------------------
// Containers
// ---------------------------------------------------------------------------------------------

bool ContainedResource::is_container() const noexcept { return any_type(types, lws::types::container); }
bool ContainedResource::is_data_resource() const noexcept { return any_type(types, lws::types::data_resource); }
bool ContainedResource::has_type(std::string_view type) const noexcept { return any_type(types, type); }

ContainedResource ContainedResource::from_json(const nlohmann::json& json, std::string_view base) {
    ContainedResource r;
    r.raw = json;
    if (auto id = string_member(json, "id")) r.id = resolve_url(base, *id);
    if (json.is_object() && json.contains("type")) r.types = json_types(json["type"]);
    r.format = string_member(json, "format");
    if (json.is_object()) {
        if (auto it = json.find("size"); it != json.end() && it->is_number_integer()) r.size = it->get<std::int64_t>();
    }
    r.modified_raw = string_member(json, "modified");
    if (r.modified_raw) r.modified = parse_rfc3339(*r.modified_raw);
    return r;
}

bool ContainerPage::is_container() const noexcept { return any_type(types, lws::types::container); }
bool ContainerPage::has_type(std::string_view type) const noexcept { return any_type(types, type); }

ContainerPage ContainerPage::from_response(const HttpResponse& response, bool require_container) {
    ContainerPage page;
    page.metadata = ResourceMetadata::from_response(response);
    if (require_container) {
        const auto media = page.metadata.media_type().value_or("");
        if (media != media::lws_json && media != media::ld_json && media != media::json)
            throw ProtocolError("container listing has unexpected media type '" + media + "': " + response.url);
        if (!page.metadata.types.empty() && !page.metadata.is_container())
            throw ProtocolError("resource is not a container: " + response.url);
    }
    page.raw = parse_json_body(response, "container listing");
    if (!page.raw.is_object()) throw ProtocolError("container listing is not a JSON object: " + response.url);
    if (auto id = string_member(page.raw, "id")) page.id = resolve_url(response.url, *id);
    else if (require_container) page.id = response.url;
    if (page.raw.contains("type")) page.types = json_types(page.raw["type"]);
    if (require_container && !page.types.empty() && !page.is_container())
        throw ProtocolError("resource is not a container: " + response.url);
    if (auto it = page.raw.find("totalItems"); it != page.raw.end() && it->is_number_integer())
        page.total_items = it->get<std::int64_t>();
    if (auto it = page.raw.find("items"); it != page.raw.end()) {
        if (!it->is_array()) throw ProtocolError("container 'items' is not an array: " + response.url);
        page.items.reserve(it->size());
        for (const auto& item : *it) page.items.push_back(ContainedResource::from_json(item, response.url));
    }
    page.first = first_link(page.metadata.links, lws::rel::first);
    page.next = first_link(page.metadata.links, lws::rel::next);
    page.prev = first_link(page.metadata.links, lws::rel::prev);
    page.last = first_link(page.metadata.links, lws::rel::last);
    return page;
}

// ---------------------------------------------------------------------------------------------
// Storage description
// ---------------------------------------------------------------------------------------------

bool Service::has_type(std::string_view type) const noexcept { return any_type(types, type); }

std::vector<std::string> Service::strings(std::string_view member) const {
    if (!raw.is_object()) return {};
    auto it = raw.find(std::string(member));
    if (it == raw.end()) return {};
    return json_types(*it);
}

bool Capability::has_type(std::string_view type) const noexcept { return any_type(types, type); }

StorageDescription StorageDescription::from_json(const nlohmann::json& json, std::string_view base) {
    if (!json.is_object()) throw ProtocolError("storage description is not a JSON object");
    StorageDescription d;
    d.raw = json;
    auto id = string_member(json, "id");
    if (!id) throw ProtocolError("storage description has no 'id'");
    d.id = resolve_url(base, *id);
    d.types = json_types(json.value("type", nlohmann::json()));
    if (!any_type(d.types, "Storage")) throw ProtocolError("document is not a storage description (type != Storage)");
    if (auto it = json.find("service"); it != json.end() && it->is_array()) {
        for (const auto& s : *it) {
            if (!s.is_object()) continue;
            Service svc;
            svc.raw = s;
            if (auto sid = string_member(s, "id")) svc.id = resolve_url(d.id, *sid);
            svc.types = json_types(s.value("type", nlohmann::json()));
            if (auto ep = string_member(s, "serviceEndpoint")) svc.service_endpoint = resolve_url(d.id, *ep);
            d.services.push_back(std::move(svc));
        }
    }
    if (auto it = json.find("capability"); it != json.end() && it->is_array()) {
        for (const auto& c : *it) {
            if (!c.is_object()) continue;
            Capability cap;
            cap.raw = c;
            if (auto cid = string_member(c, "id")) cap.id = *cid;
            cap.types = json_types(c.value("type", nlohmann::json()));
            d.capabilities.push_back(std::move(cap));
        }
    }
    if (auto it = json.find("verificationMethod"); it != json.end() && it->is_array()) {
        for (const auto& v : *it) {
            if (!v.is_object()) continue;
            VerificationMethod vm;
            vm.raw = v;
            vm.id = string_member(v, "id").value_or("");
            vm.type = string_member(v, "type").value_or("");
            vm.controller = string_member(v, "controller");
            if (auto jwk = v.find("publicKeyJwk"); jwk != v.end()) vm.public_key_jwk = *jwk;
            d.verification_methods.push_back(std::move(vm));
        }
    }
    if (auto it = json.find("authentication"); it != json.end()) {
        d.authentication = it->is_array() ? *it : nlohmann::json::array({*it});
    }
    return d;
}

std::string StorageDescription::storage_root() const {
    if (const auto* s = service(lws::service::storage_root); s && !s->service_endpoint.empty()) return s->service_endpoint;
    throw ProtocolError("storage description has no StorageRoot service: " + id);
}

const Service* StorageDescription::service(std::string_view type) const noexcept {
    for (const auto& s : services)
        if (s.has_type(type)) return &s;
    return nullptr;
}

std::vector<const Service*> StorageDescription::services_of(std::string_view type) const {
    std::vector<const Service*> out;
    for (const auto& s : services)
        if (s.has_type(type)) out.push_back(&s);
    return out;
}

const Capability* StorageDescription::capability(std::string_view type) const noexcept {
    for (const auto& c : capabilities)
        if (c.has_type(type)) return &c;
    return nullptr;
}

const Service* StorageDescription::notification_service() const noexcept { return service(lws::service::notification); }
const Service* StorageDescription::access_request_service() const noexcept { return service(lws::service::access_request); }
const Service* StorageDescription::access_grant_service() const noexcept { return service(lws::service::access_grant); }
const Service* StorageDescription::type_index_service() const noexcept { return service(lws::service::type_index); }
const Service* StorageDescription::type_search_service() const noexcept { return service(lws::service::type_search); }

namespace {
// Does the (possibly relative / fragment-only) identifier `candidate` denote `target`?
bool same_method(std::string_view candidate, std::string_view target, std::string_view base) {
    if (candidate.empty() || target.empty()) return false;
    if (candidate == target) return true;
    const std::string resolved_target = resolve_url(base, target);
    const auto hash = resolved_target.find('#');
    const std::string fragment = hash == std::string::npos ? std::string() : resolved_target.substr(hash + 1);
    if (!fragment.empty() && (candidate == "#" + fragment || candidate == fragment)) return true;
    return resolve_url(base, candidate) == resolved_target;
}
}  // namespace

const VerificationMethod* StorageDescription::verification_method(std::string_view id_or_fragment) const {
    for (const auto& vm : verification_methods)
        if (same_method(vm.id, id_or_fragment, id)) return &vm;
    return nullptr;
}

bool StorageDescription::is_authentication_method(std::string_view method_id) const {
    for (const auto& ref : authentication) {
        std::optional<std::string> ref_id;
        if (ref.is_string()) ref_id = ref.get<std::string>();
        else if (ref.is_object()) ref_id = string_member(ref, "id");
        if (ref_id && same_method(*ref_id, method_id, id)) return true;
    }
    return false;
}

// ---------------------------------------------------------------------------------------------
// Linksets
// ---------------------------------------------------------------------------------------------

std::vector<LinkTarget>* LinkContext::relation(std::string_view rel) noexcept {
    for (auto& [name, targets] : relations)
        if (name == rel) return &targets;
    return nullptr;
}

const std::vector<LinkTarget>* LinkContext::relation(std::string_view rel) const noexcept {
    for (const auto& [name, targets] : relations)
        if (name == rel) return &targets;
    return nullptr;
}

Linkset Linkset::from_json(const nlohmann::json& json) {
    if (!json.is_object()) throw ProtocolError("linkset document is not a JSON object");
    auto it = json.find("linkset");
    if (it == json.end() || !it->is_array()) throw ProtocolError("linkset document has no 'linkset' array");
    Linkset ls;
    for (auto m = json.begin(); m != json.end(); ++m)
        if (m.key() != "linkset") ls.extra_[m.key()] = m.value();
    for (const auto& ctx : *it) {
        if (!ctx.is_object()) continue;
        LinkContext lc;
        for (auto m = ctx.begin(); m != ctx.end(); ++m) {
            if (m.key() == "anchor") {
                if (m.value().is_string()) lc.anchor = m.value().get<std::string>();
                continue;
            }
            if (!m.value().is_array()) continue;
            std::vector<LinkTarget> targets;
            for (const auto& t : m.value()) {
                if (!t.is_object()) continue;
                LinkTarget target;
                target.href = t.value("href", "");
                for (auto a = t.begin(); a != t.end(); ++a)
                    if (a.key() != "href") target.attributes[a.key()] = a.value();
                targets.push_back(std::move(target));
            }
            lc.relations.emplace_back(m.key(), std::move(targets));
        }
        ls.contexts.push_back(std::move(lc));
    }
    return ls;
}

nlohmann::json Linkset::to_json() const {
    nlohmann::json out = extra_.is_object() ? extra_ : nlohmann::json::object();
    nlohmann::json arr = nlohmann::json::array();
    for (const auto& ctx : contexts) {
        nlohmann::json c = nlohmann::json::object();
        if (ctx.anchor) c["anchor"] = *ctx.anchor;
        for (const auto& [rel, targets] : ctx.relations) {
            nlohmann::json ts = nlohmann::json::array();
            for (const auto& t : targets) {
                nlohmann::json o = t.attributes.is_object() ? t.attributes : nlohmann::json::object();
                o["href"] = t.href;
                ts.push_back(std::move(o));
            }
            c[rel] = std::move(ts);
        }
        arr.push_back(std::move(c));
    }
    out["linkset"] = std::move(arr);
    return out;
}

std::vector<Link> Linkset::links() const {
    std::vector<Link> out;
    for (const auto& ctx : contexts) {
        for (const auto& [rel, targets] : ctx.relations) {
            for (const auto& t : targets) {
                Link l{t.href, rel, {}};
                if (ctx.anchor) l.params["anchor"] = *ctx.anchor;
                for (auto a = t.attributes.begin(); a != t.attributes.end(); ++a)
                    if (a.value().is_string()) l.params[a.key()] = a.value().get<std::string>();
                out.push_back(std::move(l));
            }
        }
    }
    return out;
}

std::vector<std::string> Linkset::targets(std::string_view rel) const {
    std::vector<std::string> out;
    for (const auto& ctx : contexts)
        if (const auto* ts = ctx.relation(rel))
            for (const auto& t : *ts) out.push_back(t.href);
    return out;
}

std::vector<std::string> Linkset::targets(std::string_view anchor, std::string_view rel) const {
    std::vector<std::string> out;
    for (const auto& ctx : contexts) {
        if (!ctx.anchor || *ctx.anchor != anchor) continue;
        if (const auto* ts = ctx.relation(rel))
            for (const auto& t : *ts) out.push_back(t.href);
    }
    return out;
}

Linkset& Linkset::add(std::string_view anchor, std::string_view rel, std::string href, nlohmann::json attributes) {
    LinkContext* ctx = nullptr;
    for (auto& c : contexts)
        if (c.anchor && *c.anchor == anchor) ctx = &c;
    if (!ctx) {
        contexts.push_back(LinkContext{std::string(anchor), {}});
        ctx = &contexts.back();
    }
    auto* targets = ctx->relation(rel);
    if (!targets) {
        ctx->relations.emplace_back(std::string(rel), std::vector<LinkTarget>{});
        targets = &ctx->relations.back().second;
    }
    if (attributes.is_object()) attributes.erase("href");
    targets->push_back(LinkTarget{std::move(href), attributes.is_object() ? std::move(attributes) : nlohmann::json::object()});
    return *this;
}

Linkset& Linkset::remove(std::string_view anchor, std::string_view rel, std::optional<std::string_view> href) {
    for (auto& ctx : contexts) {
        if (!ctx.anchor || *ctx.anchor != anchor) continue;
        for (auto it = ctx.relations.begin(); it != ctx.relations.end();) {
            if (it->first != rel) {
                ++it;
                continue;
            }
            if (href) std::erase_if(it->second, [&](const LinkTarget& t) { return t.href == *href; });
            if (!href || it->second.empty())
                it = ctx.relations.erase(it);
            else
                ++it;
        }
    }
    return *this;
}

}  // namespace lws
