// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Erich Bremer and the lws-client contributors
//
// OpenSSL-backed cryptography: keys, JWS signing/verification, digests and the self-signed
// identity authentication suite (lws10-authn-ssi-cid, incl. did:key subjects).
// Available when the library is built with LWS_WITH_OPENSSL.
#pragma once

#include "lws/config.hpp"

#if LWS_WITH_OPENSSL

#include <chrono>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>

#include <nlohmann/json.hpp>

#include "lws/auth.hpp"
#include "lws/keys.hpp"

namespace lws {

/// Supported signature algorithms.
enum class KeyAlgorithm {
    ES256,  ///< ECDSA P-256 / SHA-256 (JOSE raw r||s signatures)
    ES384,  ///< ECDSA P-384 / SHA-384 (verification of webhook signatures)
    EdDSA,  ///< Ed25519
};

/// JOSE "alg" name of an algorithm ("ES256", "ES384", "EdDSA").
std::string_view jws_algorithm_name(KeyAlgorithm algorithm) noexcept;

/// A public key (EC P-256 / P-384 or Ed25519). Cheap to copy (shared, immutable).
class PublicKey {
public:
    /// Imports a public JWK. Throws std::invalid_argument for unsupported/malformed keys.
    static PublicKey from_jwk(const nlohmann::json& jwk);

    KeyAlgorithm algorithm() const noexcept { return algorithm_; }
    nlohmann::json to_jwk() const;
    /// Verifies a JOSE-format signature (raw r||s for ECDSA) over `data`.
    bool verify(std::string_view data, std::string_view signature) const;

private:
    friend class PrivateKey;
    PublicKey(std::shared_ptr<void> key, KeyAlgorithm algorithm) : key_(std::move(key)), algorithm_(algorithm) {}
    std::shared_ptr<void> key_;  // EVP_PKEY
    KeyAlgorithm algorithm_;
};

/// A private signing key (EC P-256 / P-384 or Ed25519). Cheap to copy (shared, immutable).
class PrivateKey {
public:
    /// Generates a new key pair.
    static PrivateKey generate(KeyAlgorithm algorithm = KeyAlgorithm::ES256);
    /// Imports a private JWK (must contain "d").
    static PrivateKey from_jwk(const nlohmann::json& jwk);
    /// Imports a PEM private key (PKCS#8 or traditional).
    static PrivateKey from_pem(std::string_view pem);

    KeyAlgorithm algorithm() const noexcept { return algorithm_; }
    PublicKey public_key() const;
    nlohmann::json public_jwk() const;
    nlohmann::json private_jwk() const;
    /// PKCS#8 PEM encoding.
    std::string to_pem() const;
    /// JOSE-format signature (raw r||s for ECDSA, 64 bytes for Ed25519).
    std::string sign(std::string_view data) const;
    /// did:key identifier of this key (ES256 / EdDSA only).
    DidKey did_key() const { return did_key_from_public_jwk(public_jwk()); }

private:
    PrivateKey(std::shared_ptr<void> key, KeyAlgorithm algorithm) : key_(std::move(key)), algorithm_(algorithm) {}
    std::shared_ptr<void> key_;  // EVP_PKEY
    KeyAlgorithm algorithm_;
};

/// SHA-256 / SHA-512 digests (raw bytes).
std::string sha256(std::string_view data);
std::string sha512(std::string_view data);
/// Cryptographically random bytes.
std::string random_bytes(std::size_t count);
/// A random (version 4) UUID string.
std::string random_uuid();

/// Signs a compact JWS/JWT. `header` must not contain "alg"; it is set from the key.
std::string sign_jwt(const nlohmann::json& header, const nlohmann::json& claims, const PrivateKey& key);
/// Verifies a compact JWS signature (does not validate claims). Rejects alg "none" and an
/// "alg" that does not match the key.
bool verify_jwt(std::string_view jwt, const PublicKey& key);

/// Self-signed identity authentication suite (lws10-authn-ssi-cid). Mints a JWT per
/// authorization server with sub = iss = client_id = the agent, aud = [issuer], iat, exp, jti.
class SelfSignedCredentials final : public CredentialProvider {
public:
    /// An agent (HTTPS URI or DID) whose controlled identifier document lists the key under `kid`.
    static std::shared_ptr<SelfSignedCredentials> for_agent(std::string agent_uri, PrivateKey key, std::string kid,
                                                            std::chrono::seconds lifetime = std::chrono::seconds(300));
    /// A did:key agent derived from the key itself (kid = did:key:z…#z…).
    static std::shared_ptr<SelfSignedCredentials> did_key(PrivateKey key,
                                                          std::chrono::seconds lifetime = std::chrono::seconds(300));

    SelfSignedCredentials(std::string agent_uri, PrivateKey key, std::string kid, std::chrono::seconds lifetime);

    const std::string& agent_id() const noexcept { return agent_; }
    const std::string& kid() const noexcept { return kid_; }
    const PrivateKey& key() const noexcept { return key_; }

    std::string token_type() const override;
    std::string subject_token(const CredentialContext& context) override;
    /// Mints a fresh credential for `audience` (no caching).
    std::string mint(std::string_view audience) const;

    /// Clock (injectable for tests).
    std::function<std::chrono::system_clock::time_point()> clock;

private:
    std::string agent_;
    PrivateKey key_;
    std::string kid_;
    std::chrono::seconds lifetime_;
    std::mutex mutex_;
    std::map<std::string, std::pair<std::string, std::chrono::system_clock::time_point>, std::less<>> cache_;
};

}  // namespace lws

#endif  // LWS_WITH_OPENSSL
