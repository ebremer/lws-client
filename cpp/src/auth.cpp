// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Erich Bremer and the lws-client contributors

#include "lws/auth.hpp"

#include <algorithm>

#include "lws/constants.hpp"
#include "lws/encoding.hpp"
#include "lws/errors.hpp"
#include "lws/link.hpp"
#include "lws/url.hpp"

namespace lws {
namespace {

std::vector<std::string> string_list(const nlohmann::json& j, const char* key) {
    std::vector<std::string> out;
    if (!j.is_object()) return out;
    auto it = j.find(key);
    if (it == j.end() || !it->is_array()) return out;
    for (const auto& v : *it)
        if (v.is_string()) out.push_back(v.get<std::string>());
    return out;
}

std::string trim_slash(std::string s) {
    if (s.size() > 1 && s.back() == '/') s.pop_back();
    return s;
}

// Credentials go over https only, except to loopback hosts or when the options allow plain http.
bool secure(std::string_view url, bool allow_insecure) {
    auto u = Url::parse(url);
    if (!u || !u->is_absolute()) return false;
    return u->scheme == "https" || (u->scheme == "http" && (allow_insecure || is_loopback(url)));
}

void require_secure(std::string_view url, bool allow_insecure, const char* what) {
    if (secure(url, allow_insecure)) return;
    throw AuthenticationError(std::string(what) + " must be an https URL: " + std::string(url));
}

// The length of the path of `scope`, as a directory, when it contains `url`: the longest wins.
std::optional<std::size_t> scope_match(std::string_view url, std::string_view scope) {
    if (!url_within_realm(url, scope)) return std::nullopt;
    std::string path = Url::parse(scope)->path;
    if (!path.ends_with('/')) path += '/';
    return path.size();
}

// The bearer token a request carried, if any.
std::optional<std::string> bearer_token(const HttpRequest& request) {
    auto auth = request.headers.get("authorization");
    if (!auth || auth->size() < 7 || !iequals(std::string_view(*auth).substr(0, 7), "Bearer ")) return std::nullopt;
    return auth->substr(7);
}

// A GET for discovery: no credentials, and (like every transport) no redirect followed.
HttpResponse discovery_get(HttpTransport& transport, const std::string& url, std::string accept, const char* what) {
    HttpRequest req;
    req.method = "GET";
    req.url = url;
    req.headers.set("Accept", std::move(accept));
    try {
        return transport.send(req);
    } catch (const TransportError& e) {
        throw AuthenticationError(std::string("cannot fetch ") + what + ": " + e.what());
    }
}

}  // namespace

std::optional<nlohmann::json> decode_jwt_payload(std::string_view jwt) {
    const auto first = jwt.find('.');
    if (first == std::string_view::npos) return std::nullopt;
    const auto second = jwt.find('.', first + 1);
    if (second == std::string_view::npos) return std::nullopt;
    try {
        auto json = nlohmann::json::parse(base64url_decode(jwt.substr(first + 1, second - first - 1)), nullptr, false);
        if (json.is_discarded() || !json.is_object()) return std::nullopt;
        return json;
    } catch (const Error&) {
        return std::nullopt;
    }
}

// ---------------------------------------------------------------------------------------------
// BearerTokenAuthenticator
// ---------------------------------------------------------------------------------------------

BearerTokenAuthenticator::BearerTokenAuthenticator(std::string token, std::optional<std::string> realm)
    : supplier_([t = std::move(token)] { return t; }), realm_(std::move(realm)) {}

BearerTokenAuthenticator::BearerTokenAuthenticator(TokenSupplier supplier, std::optional<std::string> realm)
    : supplier_(std::move(supplier)), realm_(std::move(realm)) {}

void BearerTokenAuthenticator::authorize(HttpRequest& request) {
    if (realm_ && !url_within_realm(request.url, *realm_)) return;
    request.headers.set("Authorization", "Bearer " + supplier_());
}

bool BearerTokenAuthenticator::handle_challenge(const HttpRequest& request, const HttpResponse&, HttpTransport&) {
    if (realm_ && !url_within_realm(request.url, *realm_)) return false;
    const auto sent = request.headers.get("authorization");
    return !sent || *sent != "Bearer " + supplier_();
}

// ---------------------------------------------------------------------------------------------
// Metadata and credential providers
// ---------------------------------------------------------------------------------------------

ProtectedResourceMetadata ProtectedResourceMetadata::from_json(const nlohmann::json& json) {
    if (!json.is_object()) throw AuthenticationError("protected resource metadata is not a JSON object");
    ProtectedResourceMetadata m;
    m.raw = json;
    auto resource = json.find("resource");
    if (resource == json.end() || !resource->is_string())
        throw AuthenticationError("protected resource metadata has no resource");
    m.resource = resource->get<std::string>();
    // lws10-core makes authorization_servers REQUIRED, with at least one issuer.
    auto servers = json.find("authorization_servers");
    if (servers == json.end() || !servers->is_array() || servers->empty())
        throw AuthenticationError("protected resource metadata names no authorization_servers");
    for (const auto& as : *servers) {
        if (!as.is_string()) throw AuthenticationError("protected resource metadata has a non-string authorization server");
        m.authorization_servers.push_back(as.get<std::string>());
    }
    return m;
}

AuthorizationServerMetadata AuthorizationServerMetadata::from_json(const nlohmann::json& json) {
    if (!json.is_object()) throw AuthenticationError("authorization server metadata is not a JSON object");
    AuthorizationServerMetadata m;
    m.raw = json;
    m.issuer = json.value("issuer", "");
    m.token_endpoint = json.value("token_endpoint", "");
    if (auto it = json.find("jwks_uri"); it != json.end() && it->is_string()) m.jwks_uri = it->get<std::string>();
    m.grant_types_supported = string_list(json, "grant_types_supported");
    m.subject_token_types_supported = string_list(json, "subject_token_types_supported");
    m.subject_identifier_types_supported = string_list(json, "subject_identifier_types_supported");
    return m;
}

OpenIdCredentials::OpenIdCredentials(std::string id_token)
    : supplier_([t = std::move(id_token)](const CredentialContext&) { return t; }) {}
OpenIdCredentials::OpenIdCredentials(Supplier supplier) : supplier_(std::move(supplier)) {}
std::string OpenIdCredentials::token_type() const { return std::string(oauth::token_type_id_token); }
std::string OpenIdCredentials::subject_token(const CredentialContext& context) { return supplier_(context); }

SamlCredentials::SamlCredentials(std::string encoded_assertion)
    : supplier_([t = std::move(encoded_assertion)](const CredentialContext&) { return t; }) {}
SamlCredentials::SamlCredentials(Supplier supplier) : supplier_(std::move(supplier)) {}
SamlCredentials SamlCredentials::from_xml(std::string_view assertion_xml) {
    return SamlCredentials(encode_assertion(assertion_xml));
}
std::string SamlCredentials::encode_assertion(std::string_view assertion_xml) { return base64url_encode(assertion_xml); }
std::string SamlCredentials::token_type() const { return std::string(oauth::token_type_saml2); }
std::string SamlCredentials::subject_token(const CredentialContext& context) { return supplier_(context); }

// ---------------------------------------------------------------------------------------------
// TokenExchangeAuthenticator
// ---------------------------------------------------------------------------------------------

TokenExchangeAuthenticator::TokenExchangeAuthenticator(std::shared_ptr<CredentialProvider> credentials,
                                                       TokenExchangeOptions options)
    : credentials_(std::move(credentials)), options_(std::move(options)) {
    if (!credentials_) throw std::invalid_argument("TokenExchangeAuthenticator requires a CredentialProvider");
}

std::chrono::system_clock::time_point TokenExchangeAuthenticator::now() const {
    return options_.clock ? options_.clock() : std::chrono::system_clock::now();
}

std::optional<AccessToken> TokenExchangeAuthenticator::find_token(std::string_view url) const {
    const auto limit = now() + options_.refresh_skew;
    std::lock_guard lock(mutex_);
    // Where several tokens' scopes contain the URL, the longest scope path wins.
    const AccessToken* best = nullptr;
    std::size_t best_length = 0;
    for (const auto& t : tokens_) {
        if (t.expires_at <= limit) continue;
        for (const auto& scope : t.scopes) {
            const auto length = scope_match(url, scope);
            if (length && (!best || *length > best_length)) {
                best = &t;
                best_length = *length;
            }
        }
    }
    if (best) return *best;
    return std::nullopt;
}

void TokenExchangeAuthenticator::authorize(HttpRequest& request) {
    if (auto token = find_token(request.url)) request.headers.set("Authorization", "Bearer " + token->value);
}

void TokenExchangeAuthenticator::authorize_retry(HttpRequest& request) {
    {
        std::lock_guard lock(mutex_);
        const auto it = std::find_if(retries_.begin(), retries_.end(),
                                     [&](const auto& retry) { return retry.first == request.url; });
        if (it != retries_.end()) {
            request.headers.set("Authorization", "Bearer " + it->second);
            retries_.erase(it);
            return;
        }
    }
    authorize(request);
}

void TokenExchangeAuthenticator::clear() {
    std::lock_guard lock(mutex_);
    tokens_.clear();
    metadata_.clear();
    descriptions_.clear();
    retries_.clear();
}

std::vector<AccessToken> TokenExchangeAuthenticator::cached_tokens() const {
    std::lock_guard lock(mutex_);
    return tokens_;
}

AuthorizationServerMetadata TokenExchangeAuthenticator::metadata(std::string_view issuer, HttpTransport& transport) {
    {
        std::lock_guard lock(mutex_);
        if (auto it = metadata_.find(issuer); it != metadata_.end()) return it->second;
    }
    const std::string url = authorization_server_metadata_url(issuer);
    const HttpResponse resp = discovery_get(transport, url, "application/json", "authorization server metadata");
    if (!resp.ok())
        throw AuthenticationError("authorization server metadata request failed with HTTP " +
                                  std::to_string(resp.status) + ": " + url);
    auto json = nlohmann::json::parse(resp.body, nullptr, false);
    if (json.is_discarded()) throw AuthenticationError("authorization server metadata is not valid JSON: " + url);
    auto md = AuthorizationServerMetadata::from_json(json);
    if (trim_slash(md.issuer) != trim_slash(std::string(issuer)))
        throw AuthenticationError("authorization server metadata issuer '" + md.issuer + "' does not match '" +
                                  std::string(issuer) + "'");
    if (md.token_endpoint.empty()) throw AuthenticationError("authorization server metadata has no token_endpoint");
    md.token_endpoint = resolve_url(url, md.token_endpoint);
    require_secure(md.token_endpoint, options_.allow_insecure_http, "token endpoint");
    std::lock_guard lock(mutex_);
    metadata_.insert_or_assign(std::string(issuer), md);
    return md;
}

StorageDescription TokenExchangeAuthenticator::storage_description(const std::string& storage_url,
                                                                   HttpTransport& transport) {
    {
        std::lock_guard lock(mutex_);
        if (auto it = descriptions_.find(storage_url); it != descriptions_.end()) return it->second;
    }
    const HttpResponse resp = discovery_get(transport, storage_url,
                                            "application/lws+cid, application/ld+json;q=0.9, application/json;q=0.8",
                                            "storage description");
    if (!resp.ok())
        throw AuthenticationError("storage description request failed with HTTP " + std::to_string(resp.status) +
                                  ": " + storage_url);
    auto json = nlohmann::json::parse(resp.body, nullptr, false);
    if (json.is_discarded()) throw AuthenticationError("storage description is not valid JSON: " + storage_url);
    StorageDescription description;
    try {
        description = StorageDescription::from_json(json, storage_url);
    } catch (const ProtocolError& e) {
        throw AuthenticationError("storage description of " + storage_url + " is invalid: " + e.what());
    }
    std::lock_guard lock(mutex_);
    descriptions_.insert_or_assign(storage_url, description);
    return description;
}

bool TokenExchangeAuthenticator::acceptable_issuer(std::string_view issuer, std::string_view storage) const {
    if (!secure(issuer, options_.allow_insecure_http)) return false;
    return !options_.authorization_server_filter || options_.authorization_server_filter(issuer, storage);
}

TokenExchangeAuthenticator::Discovery TokenExchangeAuthenticator::discover(const HttpRequest& request,
                                                                         const HttpResponse& response,
                                                                         const AuthChallenge& challenge,
                                                                         HttpTransport& transport) {
    // 2. The metadata is on the requested origin.
    const std::string metadata_url = resolve_url(request.url, *challenge.resource_metadata());
    if (!same_origin(metadata_url, request.url))
        throw AuthenticationError("protected resource metadata " + metadata_url + " is not on the origin of " +
                                  request.url);
    // 3. The storage the 401 links to is what the token is for.
    std::optional<std::string> storage;
    for (const auto& link : parse_link_headers(response.headers.get_all("link"), request.url)) {
        if (link.rel == rel::storage) {
            storage = link.href;
            break;
        }
    }
    if (!storage) throw AuthenticationError("the 401 for " + request.url + " links to no storage");
    // 4. The protected resource metadata names the authorization servers.
    const HttpResponse resp = discovery_get(transport, metadata_url, "application/json", "protected resource metadata");
    if (resp.status != 200)
        throw AuthenticationError("protected resource metadata request failed with HTTP " + std::to_string(resp.status) +
                                  ": " + metadata_url);
    const auto json = nlohmann::json::parse(resp.body, nullptr, false);
    if (json.is_discarded()) throw AuthenticationError("protected resource metadata is not valid JSON: " + metadata_url);
    const auto prm = ProtectedResourceMetadata::from_json(json);
    // 5. It describes the resource requested, and no other.
    if (!same_resource(request.url, prm.resource))
        throw AuthenticationError("protected resource metadata " + metadata_url + " describes " + prm.resource +
                                  ", not " + request.url);
    // 6. The storage's root is on the requested origin, so a token for it cannot be replayed elsewhere.
    const auto description = storage_description(*storage, transport);
    std::string root;
    try {
        root = description.storage_root();
    } catch (const ProtocolError& e) {
        throw AuthenticationError("storage " + *storage + " has no storage root: " + e.what());
    }
    if (!same_origin(root, request.url))
        throw AuthenticationError("the root " + root + " of storage " + *storage + " is not on the origin of " +
                                  request.url);
    // 7.–9. The first authorization server that is secure and that the policy accepts.
    for (const auto& issuer : prm.authorization_servers)
        if (acceptable_issuer(issuer, *storage)) return Discovery{issuer, *storage, {*storage, root}};
    throw AuthenticationError("none of the authorization servers named for " + request.url +
                              " uses https and passes the authorization server filter");
}

TokenExchangeAuthenticator::Discovery TokenExchangeAuthenticator::discover_legacy(const HttpRequest& request,
                                                                                const AuthChallenge& challenge) const {
    // The challenge of the drafts before 19 October 2026: the realm must contain the URL, and is the
    // token's resource and its scope.
    const std::string as_uri = *challenge.as_uri();
    const std::string realm = *challenge.realm();
    if (!url_within_realm(request.url, realm))
        throw AuthenticationError("request URL " + request.url + " is not within the challenge realm " + realm);
    require_secure(as_uri, options_.allow_insecure_http, "authorization server");
    if (options_.authorization_server_filter && !options_.authorization_server_filter(as_uri, realm))
        throw AuthenticationError("authorization server rejected by policy: " + as_uri);
    return Discovery{as_uri, realm, {realm}};
}

bool TokenExchangeAuthenticator::handle_challenge(const HttpRequest& request, const HttpResponse& response,
                                                  HttpTransport& transport) {
    // 1. The first Bearer challenge with resource_metadata; else one with as_uri and realm (earlier drafts).
    const auto challenges = parse_www_authenticate(response.headers.get_all("www-authenticate"));
    const AuthChallenge* challenge = nullptr;
    const AuthChallenge* legacy = nullptr;
    for (const auto& c : challenges) {
        if (!c.is_scheme("Bearer")) continue;
        if (c.resource_metadata()) {
            challenge = &c;
            break;
        }
        if (!legacy && c.as_uri() && c.realm()) legacy = &c;
    }
    if (!challenge && !legacy) return false;

    // The challenge is acted on only once it checks out (steps 2–10): one that names another storage (a
    // decoy) must not cost the client its token.
    const Discovery found =
        challenge ? discover(request, response, *challenge, transport) : discover_legacy(request, *legacy);
    const auto md = metadata(found.issuer, transport);
    const std::string token_type = credentials_->token_type();
    if (!md.subject_token_types_supported.empty() &&
        std::find(md.subject_token_types_supported.begin(), md.subject_token_types_supported.end(), token_type) ==
            md.subject_token_types_supported.end())
        throw AuthenticationError("authorization server " + found.issuer + " does not accept subject tokens of type " +
                                  token_type);
    const auto same_target = [&](const AccessToken& t) {
        return t.storage == found.storage && trim_slash(t.issuer) == trim_slash(found.issuer);
    };

    // A token for this issuer and storage that the request carried was rejected: drop it.
    const auto rejected = bearer_token(request);
    if (rejected) {
        std::lock_guard lock(mutex_);
        std::erase_if(tokens_, [&](const AccessToken& t) { return same_target(t) && t.value == *rejected; });
    }

    std::lock_guard exchange(exchange_mutex_);
    // A fresh token for this issuer and storage is reused: one obtained by another thread meanwhile, or
    // one held already for a request outside its scope. The retry carries it either way.
    {
        const auto limit = now() + options_.refresh_skew;
        std::lock_guard lock(mutex_);
        for (const auto& t : tokens_) {
            if (same_target(t) && t.expires_at > limit && (!rejected || t.value != *rejected)) {
                retries_.emplace_back(request.url, t.value);
                return true;
            }
        }
    }

    CredentialContext ctx{found.issuer, found.storage, md};
    const std::string subject_token = credentials_->subject_token(ctx);

    HttpRequest token_req;
    token_req.method = "POST";
    token_req.url = md.token_endpoint;
    token_req.headers.set("Content-Type", std::string(media::form));
    token_req.headers.set("Accept", "application/json");
    token_req.body = "grant_type=" + form_url_encode(oauth::grant_type_token_exchange) +
                     "&resource=" + form_url_encode(found.storage) + "&subject_token=" + form_url_encode(subject_token) +
                     "&subject_token_type=" + form_url_encode(token_type);
    HttpResponse token_resp;
    try {
        token_resp = transport.send(token_req);
    } catch (const TransportError& e) {
        throw AuthenticationError(std::string("token exchange failed: ") + e.what());
    }
    auto body = nlohmann::json::parse(token_resp.body, nullptr, false);
    if (!token_resp.ok()) {
        std::optional<std::string> error, description;
        if (!body.is_discarded() && body.is_object()) {
            if (body.contains("error") && body["error"].is_string()) error = body["error"].get<std::string>();
            if (body.contains("error_description") && body["error_description"].is_string())
                description = body["error_description"].get<std::string>();
        }
        throw AuthenticationError("token exchange failed with HTTP " + std::to_string(token_resp.status) +
                                      (error ? ": " + *error : std::string()) +
                                      (description ? " (" + *description + ")" : std::string()),
                                  error, description);
    }
    if (body.is_discarded() || !body.is_object() || !body.contains("access_token") ||
        !body["access_token"].is_string())
        throw AuthenticationError("token endpoint returned no access_token");
    const std::string token_type_resp = body.value("token_type", "");
    if (!iequals(token_type_resp, "Bearer"))
        throw AuthenticationError("unsupported token_type '" + token_type_resp + "' (expected Bearer)");

    AccessToken token;
    token.value = body["access_token"].get<std::string>();
    token.token_type = "Bearer";
    token.issuer = found.issuer;
    token.storage = found.storage;
    token.scopes = found.scopes;
    const auto issued = now();
    if (auto it = body.find("expires_in"); it != body.end() && it->is_number()) {
        token.expires_at = issued + std::chrono::seconds(it->get<std::int64_t>());
    } else if (auto payload = decode_jwt_payload(token.value);
               payload && payload->contains("exp") && (*payload)["exp"].is_number()) {
        token.expires_at = std::chrono::system_clock::time_point(std::chrono::seconds((*payload)["exp"].get<std::int64_t>()));
    } else {
        token.expires_at = issued + options_.default_token_lifetime;
    }
    std::lock_guard lock(mutex_);
    std::erase_if(tokens_, same_target);
    retries_.emplace_back(request.url, token.value);
    tokens_.push_back(std::move(token));
    return true;
}

}  // namespace lws
