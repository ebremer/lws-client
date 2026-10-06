// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Erich Bremer and the lws-client contributors

#include "lws/webhook.hpp"

#include <algorithm>

#include "lws/client.hpp"
#include "lws/crypto.hpp"
#include "lws/encoding.hpp"
#include "lws/errors.hpp"
#include "lws/structured_fields.hpp"
#include "lws/url.hpp"

namespace lws {
namespace {

[[noreturn]] void reject(const std::string& why) { throw SignatureVerificationError("webhook verification failed: " + why); }

constexpr std::string_view kRequired[] = {"@method", "@scheme", "@authority", "@path", "content-type", "content-digest"};

void verify_content_digest(const HttpHeaders& headers, std::string_view body) {
    const auto field = headers.get_combined("content-digest");
    if (!field) reject("missing Content-Digest");
    sf::Dictionary dict;
    try {
        dict = sf::parse_dictionary(*field);
    } catch (const Error&) {
        reject("malformed Content-Digest");
    }
    bool recognised = false;
    for (const auto& [alg, member] : dict) {
        std::string (*fn)(std::string_view) = nullptr;
        if (alg == "sha-256") fn = &sha256;
        else if (alg == "sha-512") fn = &sha512;
        else continue;
        recognised = true;
        const auto* item = std::get_if<sf::Item>(&member);
        const auto* bytes = item ? std::get_if<sf::ByteSequence>(&item->value) : nullptr;
        if (!bytes) reject("malformed Content-Digest value");
        if (bytes->bytes != fn(body)) reject("content-digest mismatch (" + alg + ")");
    }
    if (!recognised) reject("Content-Digest has no supported algorithm (sha-256, sha-512)");
}

std::string_view algorithm_for(KeyAlgorithm a) {
    switch (a) {
        case KeyAlgorithm::ES256: return "ecdsa-p256-sha256";
        case KeyAlgorithm::ES384: return "ecdsa-p384-sha384";
        case KeyAlgorithm::EdDSA: return "ed25519";
    }
    return "";
}

}  // namespace

std::string build_signature_base(const std::vector<std::string>& components, std::string_view signature_params,
                                 std::string_view method, std::string_view url, const HttpHeaders& headers) {
    const auto u = Url::parse(url);
    if (!u || !u->is_absolute()) reject("target URL is not absolute");
    std::string base;
    for (const auto& name : components) {
        std::string value;
        if (name == "@method") {
            value = std::string(method);
            std::transform(value.begin(), value.end(), value.begin(), [](unsigned char c) { return char(std::toupper(c)); });
        } else if (name == "@scheme") {
            value = u->scheme;
        } else if (name == "@authority") {
            value = u->authority_for_signature();
        } else if (name == "@path") {
            value = u->path.empty() ? "/" : u->path;
        } else if (name == "@query") {
            value = "?" + u->query.value_or("");
        } else if (name == "@target-uri") {
            Url t = *u;
            t.fragment.reset();
            value = t.str();
        } else if (name == "@request-target") {
            value = (u->path.empty() ? "/" : u->path) + (u->query ? "?" + *u->query : "");
        } else if (name.starts_with('@')) {
            reject("unsupported derived component " + name);
        } else {
            for (char c : name)
                if (c >= 'A' && c <= 'Z') reject("component names must be lower-case: " + name);
            const auto values = headers.get_all(name);
            if (values.empty()) reject("covered header field missing: " + name);
            for (std::size_t i = 0; i < values.size(); ++i) {
                std::string_view v = values[i];
                while (!v.empty() && (v.front() == ' ' || v.front() == '\t')) v.remove_prefix(1);
                while (!v.empty() && (v.back() == ' ' || v.back() == '\t')) v.remove_suffix(1);
                if (i) value += ", ";
                value += v;
            }
        }
        base += "\"" + name + "\": " + value + "\n";
    }
    base += "\"@signature-params\": ";
    base += signature_params;
    return base;
}

WebhookVerifier::WebhookVerifier(Client client, WebhookVerifierOptions options)
    : WebhookVerifier(DescriptionFetcher([client = std::move(client)](const std::string& storage_id) {
                          return client.get_storage_description(storage_id);
                      }),
                      std::move(options)) {}

WebhookVerifier::WebhookVerifier(DescriptionFetcher fetcher, WebhookVerifierOptions options)
    : fetcher_(std::move(fetcher)), options_(std::move(options)) {
    if (!fetcher_) throw std::invalid_argument("WebhookVerifier requires a storage description fetcher");
}

std::chrono::system_clock::time_point WebhookVerifier::now() const {
    return options_.clock ? options_.clock() : std::chrono::system_clock::now();
}

WebhookVerifier::CachedDescription WebhookVerifier::describe(const std::string& storage_id, bool force_refresh) {
    const auto t = now();
    {
        std::lock_guard lock(mutex_);
        if (auto it = cache_.find(storage_id);
            !force_refresh && it != cache_.end() && t - it->second.fetched_at < options_.key_cache_ttl)
            return it->second;
    }
    StorageDescription description;
    try {
        description = fetcher_(storage_id);
    } catch (const SignatureVerificationError&) {
        throw;
    } catch (const std::exception& e) {
        reject(std::string("cannot retrieve storage description: ") + e.what());
    }
    CachedDescription entry{std::move(description), t};
    std::lock_guard lock(mutex_);
    cache_.insert_or_assign(storage_id, entry);
    return entry;
}

VerifiedNotification WebhookVerifier::verify(std::string_view method, std::string_view url, const HttpHeaders& headers,
                                             std::string_view body) {
    // 1. Content-Digest
    verify_content_digest(headers, body);

    // 2. Signature-Input / Signature
    const auto input_field = headers.get_combined("signature-input");
    const auto signature_field = headers.get_combined("signature");
    if (!input_field || !signature_field) reject("missing Signature-Input or Signature");
    sf::Dictionary inputs, signatures;
    try {
        inputs = sf::parse_dictionary(*input_field);
        signatures = sf::parse_dictionary(*signature_field);
    } catch (const Error&) {
        reject("malformed Signature-Input or Signature");
    }
    const sf::InnerList* params_list = nullptr;
    std::string label;
    std::string signature;
    for (const auto& [name, member] : inputs) {
        const auto* list = std::get_if<sf::InnerList>(&member);
        const auto* sig_member = sf::find(signatures, name);
        if (!list || !sig_member || !sf::find(list->params, "keyid")) continue;
        const auto* sig_item = std::get_if<sf::Item>(sig_member);
        const auto* bytes = sig_item ? std::get_if<sf::ByteSequence>(&sig_item->value) : nullptr;
        if (!bytes) continue;
        params_list = list;
        label = name;
        signature = bytes->bytes;
        break;
    }
    if (!params_list) reject("no signature with a keyid");

    // 3. Covered components and parameters
    std::vector<std::string> components;
    for (const auto& item : params_list->items) {
        const auto* name = std::get_if<std::string>(&item.value);
        if (!name) reject("component identifiers must be strings");
        if (!item.params.empty()) reject("component parameters are not supported: " + *name);
        components.push_back(*name);
    }
    for (auto required : kRequired)
        if (std::find(components.begin(), components.end(), required) == components.end())
            reject("required component not covered: " + std::string(required));
    const auto* created_item = sf::find(params_list->params, "created");
    const auto* created = created_item ? std::get_if<std::int64_t>(created_item) : nullptr;
    if (!created) reject("signature has no integer 'created' parameter");
    const auto* keyid_item = sf::find(params_list->params, "keyid");
    const auto* keyid_ptr = keyid_item ? std::get_if<std::string>(keyid_item) : nullptr;
    if (!keyid_ptr) reject("signature 'keyid' must be a string");
    const std::string keyid = *keyid_ptr;
    const auto now_s = std::chrono::duration_cast<std::chrono::seconds>(now().time_since_epoch()).count();
    if (*created < now_s - options_.max_age.count()) reject("signature too old");
    if (*created > now_s + options_.clock_skew.count()) reject("signature created in the future");
    if (const auto* exp_item = sf::find(params_list->params, "expires")) {
        const auto* exp = std::get_if<std::int64_t>(exp_item);
        if (!exp || *exp < now_s) reject("signature expired");
    }
    std::optional<std::string> alg_param;
    if (const auto* a = sf::find(params_list->params, "alg")) {
        const auto* s = std::get_if<std::string>(a);
        if (!s) reject("'alg' parameter must be a string");
        alg_param = *s;
    }

    // 4. keyid → storage identifier
    const auto hash = keyid.find('#');
    if (hash == std::string::npos || hash + 1 >= keyid.size()) reject("keyid is not a URL with a fragment");
    if (!is_absolute_iri(keyid)) reject("keyid is not an absolute URL");
    const std::string storage_id = keyid.substr(0, hash);
    if (!options_.trusted_storages.empty() &&
        std::find(options_.trusted_storages.begin(), options_.trusted_storages.end(), storage_id) ==
            options_.trusted_storages.end())
        reject("storage is not trusted: " + storage_id);

    const std::string base = build_signature_base(components, sf::serialize(*params_list), method, url, headers);

    // 5–8. Resolve the key and verify; refetch once on failure (key rotation).
    for (int attempt = 0; attempt < 2; ++attempt) {
        const bool fresh = attempt > 0;
        const auto entry = describe(storage_id, fresh);
        const auto& sd = entry.description;
        if (sd.id != storage_id) reject("storage description id '" + sd.id + "' does not match " + storage_id);
        const auto* vm = sd.verification_method(keyid);
        if (!vm) {
            if (!fresh) continue;
            reject("verification method not found: " + keyid);
        }
        if (!sd.is_authentication_method(keyid)) {
            if (!fresh) continue;
            reject("key not authorized for authentication: " + keyid);
        }
        std::optional<PublicKey> key;
        try {
            key = PublicKey::from_jwk(vm->public_key_jwk);
        } catch (const std::exception& e) {
            reject(std::string("unusable verification key: ") + e.what());
        }
        if (alg_param && *alg_param != algorithm_for(key->algorithm()))
            reject("alg does not match key (" + *alg_param + ")");
        if (!key->verify(base, signature)) {
            if (!fresh) continue;
            reject("signature mismatch");
        }
        // 9. Notification
        Notification notification;
        try {
            notification = parse_notification(body);
        } catch (const Error& e) {
            reject(std::string("invalid notification body: ") + e.what());
        }
        if (notification.storage != storage_id)
            reject("notification storage does not match keyid storage (" + notification.storage + ")");
        return VerifiedNotification{std::move(notification), keyid, storage_id, label};
    }
    reject("signature mismatch");
}

}  // namespace lws
