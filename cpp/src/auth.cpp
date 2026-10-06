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

void require_secure(std::string_view url, bool allow_insecure, const char* what) {
    auto u = Url::parse(url);
    if (!u || !u->is_absolute()) throw AuthenticationError(std::string(what) + " is not an absolute URL: " + std::string(url));
    if (u->scheme == "https") return;
    if (u->scheme == "http" && (allow_insecure || is_loopback(url))) return;
    throw AuthenticationError(std::string(what) + " must use https: " + std::string(url));
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
    // Prefer the most specific (longest) realm.
    const AccessToken* best = nullptr;
    for (const auto& t : tokens_) {
        if (t.expires_at <= limit || !url_within_realm(url, t.realm)) continue;
        if (!best || t.realm.size() > best->realm.size()) best = &t;
    }
    if (best) return *best;
    return std::nullopt;
}

void TokenExchangeAuthenticator::authorize(HttpRequest& request) {
    if (auto token = find_token(request.url)) request.headers.set("Authorization", "Bearer " + token->value);
}

void TokenExchangeAuthenticator::clear() {
    std::lock_guard lock(mutex_);
    tokens_.clear();
    metadata_.clear();
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
    HttpRequest req;
    req.method = "GET";
    req.url = authorization_server_metadata_url(issuer);
    req.headers.set("Accept", "application/json");
    HttpResponse resp;
    try {
        resp = transport.send(req);
    } catch (const TransportError& e) {
        throw AuthenticationError(std::string("cannot fetch authorization server metadata: ") + e.what());
    }
    if (!resp.ok())
        throw AuthenticationError("authorization server metadata request failed with HTTP " +
                                  std::to_string(resp.status) + ": " + req.url);
    auto json = nlohmann::json::parse(resp.body, nullptr, false);
    if (json.is_discarded()) throw AuthenticationError("authorization server metadata is not valid JSON: " + req.url);
    auto md = AuthorizationServerMetadata::from_json(json);
    if (trim_slash(md.issuer) != trim_slash(std::string(issuer)))
        throw AuthenticationError("authorization server metadata issuer '" + md.issuer + "' does not match '" +
                                  std::string(issuer) + "'");
    if (md.token_endpoint.empty()) throw AuthenticationError("authorization server metadata has no token_endpoint");
    md.token_endpoint = resolve_url(req.url, md.token_endpoint);
    require_secure(md.token_endpoint, options_.allow_insecure_http, "token endpoint");
    std::lock_guard lock(mutex_);
    metadata_.insert_or_assign(std::string(issuer), md);
    return md;
}

bool TokenExchangeAuthenticator::handle_challenge(const HttpRequest& request, const HttpResponse& response,
                                                  HttpTransport& transport) {
    const auto challenges = parse_www_authenticate(response.headers.get_all("www-authenticate"));
    const AuthChallenge* challenge = nullptr;
    for (const auto& c : challenges) {
        if (c.is_scheme("Bearer") && c.as_uri() && c.realm()) {
            challenge = &c;
            break;
        }
    }
    if (!challenge) return false;
    const std::string as_uri = *challenge->as_uri();
    const std::string realm = *challenge->realm();

    // A token we sent was rejected: drop it.
    std::optional<std::string> rejected;
    if (auto auth = request.headers.get("authorization"); auth && auth->starts_with("Bearer ")) {
        rejected = auth->substr(7);
        std::lock_guard lock(mutex_);
        std::erase_if(tokens_, [&](const AccessToken& t) { return t.value == *rejected; });
    }

    if (!url_within_realm(request.url, realm))
        throw AuthenticationError("request URL " + request.url + " is not within the challenge realm " + realm);
    require_secure(as_uri, options_.allow_insecure_http, "authorization server");
    if (options_.authorization_server_filter && !options_.authorization_server_filter(as_uri, realm))
        throw AuthenticationError("authorization server rejected by policy: " + as_uri);

    std::lock_guard exchange(exchange_mutex_);
    // Another thread may have obtained a fresh token for this realm meanwhile.
    {
        const auto limit = now() + options_.refresh_skew;
        std::lock_guard lock(mutex_);
        for (const auto& t : tokens_) {
            if (t.realm == realm && trim_slash(t.issuer) == trim_slash(as_uri) && t.expires_at > limit &&
                (!rejected || t.value != *rejected))
                return true;
        }
    }

    const auto md = metadata(as_uri, transport);
    const std::string token_type = credentials_->token_type();
    if (!md.subject_token_types_supported.empty() &&
        std::find(md.subject_token_types_supported.begin(), md.subject_token_types_supported.end(), token_type) ==
            md.subject_token_types_supported.end())
        throw AuthenticationError("authorization server " + as_uri + " does not accept subject tokens of type " +
                                  token_type);

    CredentialContext ctx{as_uri, realm, md};
    const std::string subject_token = credentials_->subject_token(ctx);

    HttpRequest token_req;
    token_req.method = "POST";
    token_req.url = md.token_endpoint;
    token_req.headers.set("Content-Type", std::string(media::form));
    token_req.headers.set("Accept", "application/json");
    token_req.body = "grant_type=" + form_url_encode(oauth::grant_type_token_exchange) +
                     "&resource=" + form_url_encode(realm) + "&subject_token=" + form_url_encode(subject_token) +
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
    token.issuer = as_uri;
    token.realm = realm;
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
    std::erase_if(tokens_, [&](const AccessToken& t) { return t.realm == realm && t.issuer == as_uri; });
    tokens_.push_back(std::move(token));
    return true;
}

}  // namespace lws
