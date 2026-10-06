// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Erich Bremer and the lws-client contributors
//
// Authentication and authorization (lws10-core §Authentication, §Authorization; the OpenID
// Connect and SAML 2.0 authentication suites). Self-signed credentials are in lws/crypto.hpp.
#pragma once

#include <chrono>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <nlohmann/json.hpp>

#include "lws/http.hpp"

namespace lws {

/// Pluggable request authentication. Implementations must be thread-safe.
class Authenticator {
public:
    virtual ~Authenticator() = default;
    /// Called before each request is sent; may add an Authorization header.
    virtual void authorize(HttpRequest& request) = 0;
    /// Called when a request returned 401. May obtain credentials (using `transport` for any
    /// HTTP it needs). Returns true when the request should be retried once.
    virtual bool handle_challenge(const HttpRequest& request, const HttpResponse& response,
                                  HttpTransport& transport) = 0;
};

/// Sends a known access token. With a `realm`, the token is only attached to URLs inside it.
class BearerTokenAuthenticator final : public Authenticator {
public:
    using TokenSupplier = std::function<std::string()>;

    explicit BearerTokenAuthenticator(std::string token, std::optional<std::string> realm = {});
    /// The supplier is called for every request; after a 401 it is called again and the request
    /// is retried once if it returns a different token.
    explicit BearerTokenAuthenticator(TokenSupplier supplier, std::optional<std::string> realm = {});

    void authorize(HttpRequest& request) override;
    bool handle_challenge(const HttpRequest& request, const HttpResponse& response, HttpTransport& transport) override;

private:
    TokenSupplier supplier_;
    std::optional<std::string> realm_;
};

/// Authorization server metadata (RFC 8414 + LWS extensions), from /.well-known/lws-configuration.
struct AuthorizationServerMetadata {
    std::string issuer{};
    std::string token_endpoint{};
    std::optional<std::string> jwks_uri{};
    std::vector<std::string> grant_types_supported{};
    std::vector<std::string> subject_token_types_supported{};
    std::vector<std::string> subject_identifier_types_supported{};
    nlohmann::json raw{};

    static AuthorizationServerMetadata from_json(const nlohmann::json& json);
};

/// Context handed to a CredentialProvider when a subject token is needed.
struct CredentialContext {
    std::string issuer{};  ///< the authorization server (as_uri) — the audience of the credential
    std::string realm{};
    AuthorizationServerMetadata metadata{};
};

/// Supplies authentication credentials (subject tokens) — one implementation per
/// authentication suite.
class CredentialProvider {
public:
    virtual ~CredentialProvider() = default;
    /// The RFC 8693 token type URI of the tokens this provider returns.
    virtual std::string token_type() const = 0;
    /// Returns a subject token for the given authorization server.
    virtual std::string subject_token(const CredentialContext& context) = 0;
};

/// OpenID Connect authentication suite (lws10-authn-openid): presents an ID token.
/// Interactive login is out of scope — obtain the ID token with your OIDC library.
class OpenIdCredentials final : public CredentialProvider {
public:
    using Supplier = std::function<std::string(const CredentialContext&)>;
    explicit OpenIdCredentials(std::string id_token);
    explicit OpenIdCredentials(Supplier supplier);

    std::string token_type() const override;
    std::string subject_token(const CredentialContext& context) override;

private:
    Supplier supplier_;
};

/// SAML 2.0 authentication suite (lws10-authn-saml): presents a base64url-encoded assertion.
class SamlCredentials final : public CredentialProvider {
public:
    using Supplier = std::function<std::string(const CredentialContext&)>;
    /// `encoded_assertion` must already be base64url-encoded (see encode_assertion).
    explicit SamlCredentials(std::string encoded_assertion);
    /// The supplier returns base64url-encoded assertions.
    explicit SamlCredentials(Supplier supplier);
    /// Wraps raw assertion XML (it is base64url-encoded for you).
    static SamlCredentials from_xml(std::string_view assertion_xml);
    /// base64url encoding of a raw SAML assertion (RFC 8693 §3).
    static std::string encode_assertion(std::string_view assertion_xml);

    std::string token_type() const override;
    std::string subject_token(const CredentialContext& context) override;

private:
    Supplier supplier_;
};

/// Options of the LWS token exchange flow.
struct TokenExchangeOptions {
    /// Allow plain-http authorization servers on non-loopback hosts (testing only).
    bool allow_insecure_http = false;
    /// Optional policy deciding whether credentials may be sent to an authorization server.
    std::function<bool(std::string_view as_uri, std::string_view realm)> authorization_server_filter;
    /// Lifetime assumed when neither expires_in nor a JWT exp is available.
    std::chrono::seconds default_token_lifetime{300};
    /// Tokens are refreshed this long before they expire.
    std::chrono::seconds refresh_skew{30};
    /// Clock (injectable for tests).
    std::function<std::chrono::system_clock::time_point()> clock;
};

/// An access token issued by an authorization server.
struct AccessToken {
    std::string value{};
    std::string token_type{};
    std::chrono::system_clock::time_point expires_at{};
    std::string issuer{};
    std::string realm{};
};

/// The LWS authorization flow (design/client-api.md §6.2): on a 401 Bearer challenge with
/// as_uri/realm it validates the realm, discovers the authorization server metadata, exchanges a
/// subject token from the CredentialProvider for an access token (RFC 8693) and retries.
/// Tokens are cached per (issuer, realm) and sent proactively to URLs inside the realm.
class TokenExchangeAuthenticator final : public Authenticator {
public:
    explicit TokenExchangeAuthenticator(std::shared_ptr<CredentialProvider> credentials,
                                        TokenExchangeOptions options = {});

    void authorize(HttpRequest& request) override;
    bool handle_challenge(const HttpRequest& request, const HttpResponse& response, HttpTransport& transport) override;

    /// Drops all cached access tokens and metadata.
    void clear();
    /// A snapshot of the cached access tokens.
    std::vector<AccessToken> cached_tokens() const;
    /// Fetches (and caches) authorization server metadata for `issuer`.
    AuthorizationServerMetadata metadata(std::string_view issuer, HttpTransport& transport);

private:
    std::chrono::system_clock::time_point now() const;
    std::optional<AccessToken> find_token(std::string_view url) const;

    std::shared_ptr<CredentialProvider> credentials_;
    TokenExchangeOptions options_;
    mutable std::mutex mutex_;          // guards tokens_ and metadata_
    std::mutex exchange_mutex_;         // serialises token exchanges
    std::vector<AccessToken> tokens_;
    std::map<std::string, AuthorizationServerMetadata, std::less<>> metadata_;
};

/// Decodes the payload of a JWT without verifying it. Returns std::nullopt if malformed.
std::optional<nlohmann::json> decode_jwt_payload(std::string_view jwt);

}  // namespace lws
