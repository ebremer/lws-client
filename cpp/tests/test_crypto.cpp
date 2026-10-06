// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Erich Bremer and the lws-client contributors
//
// Keys, JWS/JWT and the self-signed authentication suite (requires OpenSSL).

#include <gtest/gtest.h>

#include "test_support.hpp"

#if LWS_WITH_OPENSSL

using namespace lws;
using lws::test::fixture;

TEST(Crypto, Digests) {
    // RFC 9530 example body: {"hello": "world"}
    const std::string body = "{\"hello\": \"world\"}";
    EXPECT_EQ(base64_encode(sha256(body)), "X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=");
    EXPECT_EQ(base64_encode(sha512(body)),
              "WZDPaVn/7XgHaAy8pmojAkGWoRx2UFChF41A2svX+TaPm+AbwAgBWnrIiYllu7BNNyealdVLvRwEmTHWXvJwew==");
    EXPECT_EQ(random_bytes(16).size(), 16u);
    const auto uuid = random_uuid();
    EXPECT_EQ(uuid.size(), 36u);
    EXPECT_EQ(uuid[14], '4');
}

TEST(Crypto, GenerateSignVerifyRoundTrip) {
    for (auto alg : {KeyAlgorithm::ES256, KeyAlgorithm::ES384, KeyAlgorithm::EdDSA}) {
        SCOPED_TRACE(std::string(jws_algorithm_name(alg)));
        const auto key = PrivateKey::generate(alg);
        EXPECT_EQ(key.algorithm(), alg);
        const auto sig = key.sign("payload");
        EXPECT_EQ(sig.size(), alg == KeyAlgorithm::ES384 ? 96u : 64u);
        EXPECT_TRUE(key.public_key().verify("payload", sig));
        EXPECT_FALSE(key.public_key().verify("payload!", sig));
        // JWK and PEM round trips
        const auto again = PrivateKey::from_jwk(key.private_jwk());
        EXPECT_EQ(again.public_jwk(), key.public_jwk());
        EXPECT_TRUE(PublicKey::from_jwk(key.public_jwk()).verify("payload", again.sign("payload")));
        const auto pem = PrivateKey::from_pem(key.to_pem());
        EXPECT_EQ(pem.public_jwk(), key.public_jwk());
        EXPECT_FALSE(key.public_jwk().contains("d"));
    }
    EXPECT_THROW(PublicKey::from_jwk({{"kty", "RSA"}}), std::invalid_argument);
    EXPECT_THROW(PublicKey::from_jwk({{"kty", "EC"}, {"crv", "P-256"}, {"x", base64url_encode(std::string(32, 'A'))},
                                      {"y", base64url_encode(std::string(32, 'B'))}}),
                 std::invalid_argument);  // not on the curve
}

TEST(Crypto, FixtureKeysMatchDidKeyVectors) {
    const auto vectors = fixture("did-key.json")["vectors"];
    for (const auto& [name, file] : {std::pair{"fixture-p256", "keys/p256.json"}, std::pair{"fixture-ed25519", "keys/ed25519.json"}}) {
        const auto key = PrivateKey::from_jwk(fixture(file)["privateJwk"]);
        for (const auto& v : vectors) {
            if (v["name"] != name) continue;
            EXPECT_EQ(key.did_key().did, v["did"].get<std::string>());
            EXPECT_EQ(key.did_key().kid, v["kid"].get<std::string>());
        }
    }
}

TEST(Crypto, JwtVectorsVerify) {
    for (const auto& v : fixture("jwt.json")["vectors"]) {
        SCOPED_TRACE(v["name"].get<std::string>());
        const auto key = PublicKey::from_jwk(v["publicJwk"]);
        const auto jwt = v["jwt"].get<std::string>();
        EXPECT_TRUE(verify_jwt(jwt, key));
        EXPECT_EQ(*decode_jwt_payload(jwt), v["claims"]);
        std::string tampered = jwt;
        tampered[tampered.find('.') + 5] ^= 1;
        EXPECT_FALSE(verify_jwt(tampered, key));
    }
    // alg "none" is always rejected.
    const auto key = PrivateKey::generate();
    const std::string none = base64url_encode(R"({"alg":"none"})") + "." + base64url_encode("{}") + ".";
    EXPECT_FALSE(verify_jwt(none, key.public_key()));
}

TEST(SelfSigned, DidKeyCredentialClaims) {
    for (auto alg : {KeyAlgorithm::ES256, KeyAlgorithm::EdDSA}) {
        const auto key = PrivateKey::generate(alg);
        auto creds = SelfSignedCredentials::did_key(key);
        creds->clock = [] { return std::chrono::system_clock::time_point(std::chrono::seconds(1790000000)); };
        EXPECT_TRUE(creds->agent_id().starts_with(alg == KeyAlgorithm::ES256 ? "did:key:zDn" : "did:key:z6Mk"));
        EXPECT_EQ(creds->token_type(), "urn:ietf:params:oauth:token-type:jwt");
        CredentialContext ctx{"https://as.example", "https://s.example/", {}};
        const auto jwt = creds->subject_token(ctx);
        EXPECT_TRUE(verify_jwt(jwt, key.public_key()));
        const auto header = nlohmann::json::parse(base64url_decode(jwt.substr(0, jwt.find('.'))));
        EXPECT_EQ(header["alg"], alg == KeyAlgorithm::ES256 ? "ES256" : "EdDSA");
        EXPECT_EQ(header["typ"], "JWT");
        EXPECT_EQ(header["kid"], creds->kid());
        const auto claims = *decode_jwt_payload(jwt);
        EXPECT_EQ(claims["sub"], creds->agent_id());
        EXPECT_EQ(claims["iss"], creds->agent_id());
        EXPECT_EQ(claims["client_id"], creds->agent_id());
        EXPECT_EQ(claims["aud"], nlohmann::json::array({"https://as.example"}));
        EXPECT_EQ(claims["iat"], 1790000000);
        EXPECT_EQ(claims["exp"], 1790000300);
        EXPECT_EQ(claims["jti"].get<std::string>().size(), 36u);
        // Cached per audience; a different audience mints a new token.
        EXPECT_EQ(creds->subject_token(ctx), jwt);
        CredentialContext other{"https://as2.example", "https://s.example/", {}};
        const auto other_jwt = creds->subject_token(other);
        EXPECT_NE(other_jwt, jwt);
        EXPECT_EQ((*decode_jwt_payload(other_jwt))["aud"][0], "https://as2.example");
    }
}

TEST(SelfSigned, ForAgentWithCidDocument) {
    const auto key = PrivateKey::generate();
    auto creds = SelfSignedCredentials::for_agent("https://id.example/bot", key, "key-1", std::chrono::seconds(120));
    const auto claims = *decode_jwt_payload(creds->mint("https://as.example"));
    EXPECT_EQ(claims["sub"], "https://id.example/bot");
    EXPECT_EQ(claims["exp"].get<std::int64_t>() - claims["iat"].get<std::int64_t>(), 120);
    const auto doc = controlled_identifier_document("https://id.example/bot", key.public_jwk(), "key-1");
    EXPECT_EQ(PublicKey::from_jwk(doc["authentication"][0]["publicKeyJwk"]).to_jwk(), key.public_jwk());
}

#else
TEST(Crypto, Disabled) { GTEST_SKIP() << "built without LWS_WITH_OPENSSL"; }
#endif
