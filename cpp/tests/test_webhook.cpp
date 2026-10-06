// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Erich Bremer and the lws-client contributors
//
// RFC 9421 webhook verification against the shared vectors.

#include <gtest/gtest.h>

#include <atomic>

#include "test_support.hpp"

#if LWS_WITH_OPENSSL

using namespace lws;
using lws::test::fixture;

namespace {

StorageDescription fixture_description() {
    return StorageDescription::from_json(fixture("webhook/storage-description.json"), "https://storage.example/");
}

HttpHeaders headers_of(const nlohmann::json& v) {
    HttpHeaders h;
    for (auto it = v["headers"].begin(); it != v["headers"].end(); ++it) h.add(it.key(), it.value().get<std::string>());
    return h;
}

WebhookVerifier verifier_at(std::int64_t now, std::atomic<int>* fetches = nullptr,
                            std::vector<std::string> trusted = {}) {
    WebhookVerifierOptions options;
    options.clock = [now] { return std::chrono::system_clock::time_point(std::chrono::seconds(now)); };
    options.trusted_storages = std::move(trusted);
    return WebhookVerifier(
        [fetches](const std::string& id) {
            EXPECT_EQ(id, "https://storage.example/");
            if (fetches) ++*fetches;
            return fixture_description();
        },
        options);
}

}  // namespace

TEST(Webhook, ConformanceVectors) {
    const auto index = fixture("webhook/index.json");
    int valid = 0, invalid = 0;
    for (const auto& name : index["vectors"]) {
        const auto v = fixture("webhook/" + name.get<std::string>());
        SCOPED_TRACE(v["name"].get<std::string>());
        auto verifier = verifier_at(v["now"].get<std::int64_t>());
        const auto headers = headers_of(v);
        const auto body = v["body"].get<std::string>();
        if (v["expected"]["valid"].get<bool>()) {
            ++valid;
            const auto result = verifier.verify(v["method"].get<std::string>(), v["url"].get<std::string>(), headers, body);
            EXPECT_EQ(result.keyid, v["expected"]["keyid"].get<std::string>());
            EXPECT_EQ(result.storage, "https://storage.example/");
            const auto& en = v["expected"]["notification"];
            EXPECT_EQ(result.notification.storage, en["storage"].get<std::string>());
            ASSERT_EQ(result.notification.activities.size(), en["activities"].size());
            for (std::size_t i = 0; i < en["activities"].size(); ++i) {
                EXPECT_EQ(result.notification.activities[i].types, en["activities"][i]["types"].get<std::vector<std::string>>());
                EXPECT_EQ(result.notification.activities[i].object.id, en["activities"][i]["objectId"].get<std::string>());
            }
            // The signature base we build must equal the generator's.
            const auto inputs = sf::parse_dictionary(*headers.get("signature-input"));
            const auto& list = std::get<sf::InnerList>(inputs.at(0).second);
            std::vector<std::string> components;
            for (const auto& item : list.items) components.push_back(std::get<std::string>(item.value));
            EXPECT_EQ(build_signature_base(components, sf::serialize(list), "POST", v["url"].get<std::string>(), headers),
                      v["signatureBase"].get<std::string>());
        } else {
            ++invalid;
            EXPECT_THROW(verifier.verify(v["method"].get<std::string>(), v["url"].get<std::string>(), headers, body),
                         SignatureVerificationError)
                << v["expected"]["reason"];
        }
    }
    EXPECT_EQ(valid, 3);
    EXPECT_EQ(invalid, 10);
}

TEST(Webhook, TrustedStoragesAndCaching) {
    const auto v = fixture("webhook/p256-valid.json");
    std::atomic<int> fetches{0};
    auto verifier = verifier_at(v["now"].get<std::int64_t>(), &fetches);
    HttpRequest req{.method = "POST", .url = v["url"].get<std::string>(), .headers = headers_of(v), .body = v["body"].get<std::string>()};
    verifier.verify(req);
    verifier.verify(req);
    EXPECT_EQ(fetches, 1);  // cached

    auto untrusted = verifier_at(v["now"].get<std::int64_t>(), nullptr, {"https://other.example/"});
    EXPECT_THROW(untrusted.verify(req), SignatureVerificationError);
    auto trusted = verifier_at(v["now"].get<std::int64_t>(), nullptr, {"https://storage.example/"});
    EXPECT_NO_THROW(trusted.verify(req));
}

TEST(Webhook, KeyRotationRefetchesOnce) {
    const auto v = fixture("webhook/p256-valid.json");
    std::atomic<int> fetches{0};
    WebhookVerifierOptions options;
    const auto now = v["now"].get<std::int64_t>();
    options.clock = [now] { return std::chrono::system_clock::time_point(std::chrono::seconds(now)); };
    WebhookVerifier verifier(
        [&](const std::string&) {
            auto doc = fixture("webhook/storage-description.json");
            if (fetches++ == 0) doc["verificationMethod"][0]["publicKeyJwk"] = fixture("keys/p256-unlisted.json")["publicJwk"];
            return StorageDescription::from_json(doc, "https://storage.example/");
        },
        options);
    const auto result = verifier.verify("POST", v["url"].get<std::string>(), headers_of(v), v["body"].get<std::string>());
    EXPECT_EQ(fetches, 2);
    EXPECT_EQ(result.label, "sig1");
}

TEST(Webhook, MissingHeaders) {
    const auto v = fixture("webhook/p256-valid.json");
    auto verifier = verifier_at(v["now"].get<std::int64_t>());
    for (const char* drop : {"content-digest", "signature", "signature-input"}) {
        auto headers = headers_of(v);
        headers.remove(drop);
        EXPECT_THROW(verifier.verify("POST", v["url"].get<std::string>(), headers, v["body"].get<std::string>()),
                     SignatureVerificationError)
            << drop;
    }
}

#else
TEST(Webhook, Disabled) { GTEST_SKIP() << "built without LWS_WITH_OPENSSL"; }
#endif
