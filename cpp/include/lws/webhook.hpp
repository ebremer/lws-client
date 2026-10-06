// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Erich Bremer and the lws-client contributors
//
// Verification of signed webhook deliveries (lws10-notifications-webhook; RFC 9421 HTTP
// Message Signatures and RFC 9530 Content-Digest). Requires LWS_WITH_OPENSSL.
#pragma once

#include "lws/config.hpp"

#if LWS_WITH_OPENSSL

#include <chrono>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "lws/http.hpp"
#include "lws/models.hpp"
#include "lws/notifications.hpp"

namespace lws {

class Client;

/// Options of a WebhookVerifier.
struct WebhookVerifierOptions {
    /// Maximum age of the `created` signature parameter.
    std::chrono::seconds max_age{300};
    /// Tolerated clock skew for `created` values in the future.
    std::chrono::seconds clock_skew{300};
    /// When non-empty, only these storage identifiers are accepted.
    std::vector<std::string> trusted_storages{};
    /// How long fetched storage descriptions are cached.
    std::chrono::seconds key_cache_ttl{600};
    /// Clock (injectable for tests).
    std::function<std::chrono::system_clock::time_point()> clock;
};

/// A successfully verified notification delivery.
struct VerifiedNotification {
    Notification notification{};
    std::string keyid{};
    std::string storage{};  ///< storage identifier (keyid without fragment)
    std::string label{};    ///< signature label used (e.g. "sig1")
};

/// Verifies webhook deliveries. Thread-safe.
class WebhookVerifier {
public:
    /// Retrieves the storage description for a storage identifier.
    using DescriptionFetcher = std::function<StorageDescription(const std::string& storage_id)>;

    /// Uses `client` (normally unauthenticated) to dereference storage identifiers.
    explicit WebhookVerifier(Client client, WebhookVerifierOptions options = {});
    explicit WebhookVerifier(DescriptionFetcher fetcher, WebhookVerifierOptions options = {});

    /// Verifies one delivery. `url` is the registered inbox URL (use the public URL when behind
    /// a proxy), `body` the raw request body. Throws SignatureVerificationError on failure.
    VerifiedNotification verify(std::string_view method, std::string_view url, const HttpHeaders& headers,
                                std::string_view body);
    /// Convenience overload for an HttpRequest value.
    VerifiedNotification verify(const HttpRequest& request) {
        return verify(request.method, request.url, request.headers, request.body);
    }

private:
    struct CachedDescription {
        StorageDescription description;
        std::chrono::system_clock::time_point fetched_at;
    };
    std::chrono::system_clock::time_point now() const;
    CachedDescription describe(const std::string& storage_id, bool force_refresh);

    DescriptionFetcher fetcher_;
    WebhookVerifierOptions options_;
    std::mutex mutex_;
    std::map<std::string, CachedDescription, std::less<>> cache_;
};

/// Builds the RFC 9421 signature base for the covered `components` of a request, ending with
/// the "@signature-params" line (`signature_params` is the serialised inner list).
/// Throws SignatureVerificationError for unsupported or missing components.
std::string build_signature_base(const std::vector<std::string>& components, std::string_view signature_params,
                                 std::string_view method, std::string_view url, const HttpHeaders& headers);

}  // namespace lws

#endif  // LWS_WITH_OPENSSL
