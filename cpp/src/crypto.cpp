// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Erich Bremer and the lws-client contributors

#include "lws/crypto.hpp"

#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/param_build.h>
#include <openssl/pem.h>
#include <openssl/rand.h>

#include <cstring>
#include <stdexcept>

#include "lws/constants.hpp"
#include "lws/encoding.hpp"
#include "lws/errors.hpp"

namespace lws {
namespace {

// ---- RAII helpers -------------------------------------------------------------------------
struct PkeyDeleter {
    void operator()(EVP_PKEY* p) const noexcept { EVP_PKEY_free(p); }
};
struct CtxDeleter {
    void operator()(EVP_PKEY_CTX* p) const noexcept { EVP_PKEY_CTX_free(p); }
};
struct MdCtxDeleter {
    void operator()(EVP_MD_CTX* p) const noexcept { EVP_MD_CTX_free(p); }
};
struct BnDeleter {
    void operator()(BIGNUM* p) const noexcept { BN_free(p); }
};
struct BioDeleter {
    void operator()(BIO* p) const noexcept { BIO_free(p); }
};
struct ParamBldDeleter {
    void operator()(OSSL_PARAM_BLD* p) const noexcept { OSSL_PARAM_BLD_free(p); }
};
struct ParamDeleter {
    void operator()(OSSL_PARAM* p) const noexcept { OSSL_PARAM_free(p); }
};
struct SigDeleter {
    void operator()(ECDSA_SIG* p) const noexcept { ECDSA_SIG_free(p); }
};
using Bn = std::unique_ptr<BIGNUM, BnDeleter>;

std::shared_ptr<void> share(EVP_PKEY* p) {
    return std::shared_ptr<void>(p, [](void* k) { EVP_PKEY_free(static_cast<EVP_PKEY*>(k)); });
}
EVP_PKEY* raw(const std::shared_ptr<void>& p) { return static_cast<EVP_PKEY*>(p.get()); }

[[noreturn]] void crypto_fail(const std::string& what) { throw Error("crypto: " + what); }

struct CurveInfo {
    const char* group;
    const char* crv;
    std::size_t size;
    const EVP_MD* (*md)();
};
const CurveInfo* curve_for(KeyAlgorithm a) {
    static const CurveInfo p256{"P-256", "P-256", 32, &EVP_sha256};
    static const CurveInfo p384{"P-384", "P-384", 48, &EVP_sha384};
    if (a == KeyAlgorithm::ES256) return &p256;
    if (a == KeyAlgorithm::ES384) return &p384;
    return nullptr;
}

KeyAlgorithm algorithm_of(EVP_PKEY* key) {
    if (EVP_PKEY_is_a(key, "ED25519")) return KeyAlgorithm::EdDSA;
    if (EVP_PKEY_is_a(key, "EC")) {
        char group[64] = {0};
        size_t len = 0;
        if (EVP_PKEY_get_utf8_string_param(key, OSSL_PKEY_PARAM_GROUP_NAME, group, sizeof group, &len) != 1)
            crypto_fail("cannot read EC group");
        if (std::strcmp(group, "prime256v1") == 0 || std::strcmp(group, "P-256") == 0) return KeyAlgorithm::ES256;
        if (std::strcmp(group, "secp384r1") == 0 || std::strcmp(group, "P-384") == 0) return KeyAlgorithm::ES384;
        throw std::invalid_argument(std::string("unsupported EC curve ") + group);
    }
    throw std::invalid_argument("unsupported key type (expected EC P-256/P-384 or Ed25519)");
}

std::string bn_bytes(const BIGNUM* bn, std::size_t size) {
    std::string out(size, '\0');
    if (BN_bn2binpad(bn, reinterpret_cast<unsigned char*>(out.data()), static_cast<int>(size)) < 0)
        crypto_fail("BN_bn2binpad");
    return out;
}

Bn get_bn(EVP_PKEY* key, const char* name) {
    BIGNUM* bn = nullptr;
    if (EVP_PKEY_get_bn_param(key, name, &bn) != 1) crypto_fail(std::string("cannot read key parameter ") + name);
    return Bn(bn);
}

nlohmann::json public_jwk_of(EVP_PKEY* key, KeyAlgorithm alg) {
    if (alg == KeyAlgorithm::EdDSA) {
        unsigned char buf[32];
        size_t len = sizeof buf;
        if (EVP_PKEY_get_raw_public_key(key, buf, &len) != 1) crypto_fail("cannot export Ed25519 public key");
        return {{"kty", "OKP"}, {"crv", "Ed25519"}, {"x", base64url_encode(std::string(reinterpret_cast<char*>(buf), len))}};
    }
    const auto* c = curve_for(alg);
    auto x = get_bn(key, OSSL_PKEY_PARAM_EC_PUB_X);
    auto y = get_bn(key, OSSL_PKEY_PARAM_EC_PUB_Y);
    return {{"kty", "EC"},
            {"crv", c->crv},
            {"x", base64url_encode(bn_bytes(x.get(), c->size))},
            {"y", base64url_encode(bn_bytes(y.get(), c->size))}};
}

KeyAlgorithm jwk_algorithm(const nlohmann::json& jwk) {
    if (!jwk.is_object()) throw std::invalid_argument("JWK must be a JSON object");
    const std::string kty = jwk.value("kty", "");
    const std::string crv = jwk.value("crv", "");
    if (kty == "OKP" && crv == "Ed25519") return KeyAlgorithm::EdDSA;
    if (kty == "EC" && crv == "P-256") return KeyAlgorithm::ES256;
    if (kty == "EC" && crv == "P-384") return KeyAlgorithm::ES384;
    throw std::invalid_argument("unsupported JWK (kty=" + kty + ", crv=" + crv + ")");
}

std::string jwk_bytes(const nlohmann::json& jwk, const char* member) {
    auto it = jwk.find(member);
    if (it == jwk.end() || !it->is_string()) throw std::invalid_argument(std::string("JWK is missing '") + member + "'");
    try {
        return base64url_decode(it->get<std::string>());
    } catch (const ParseError&) {
        throw std::invalid_argument(std::string("JWK member '") + member + "' is not base64url");
    }
}

EVP_PKEY* import_jwk(const nlohmann::json& jwk, bool with_private, KeyAlgorithm alg) {
    if (alg == KeyAlgorithm::EdDSA) {
        if (with_private) {
            const auto d = jwk_bytes(jwk, "d");
            EVP_PKEY* k = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, nullptr,
                                                       reinterpret_cast<const unsigned char*>(d.data()), d.size());
            if (!k) throw std::invalid_argument("invalid Ed25519 private key");
            return k;
        }
        const auto x = jwk_bytes(jwk, "x");
        EVP_PKEY* k = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, nullptr,
                                                  reinterpret_cast<const unsigned char*>(x.data()), x.size());
        if (!k) throw std::invalid_argument("invalid Ed25519 public key");
        return k;
    }
    const auto* c = curve_for(alg);
    const auto x = jwk_bytes(jwk, "x");
    const auto y = jwk_bytes(jwk, "y");
    if (x.size() != c->size || y.size() != c->size) throw std::invalid_argument("invalid EC JWK coordinates");
    std::string point = "\x04" + x + y;
    std::unique_ptr<OSSL_PARAM_BLD, ParamBldDeleter> bld(OSSL_PARAM_BLD_new());
    OSSL_PARAM_BLD_push_utf8_string(bld.get(), OSSL_PKEY_PARAM_GROUP_NAME, c->group, 0);
    OSSL_PARAM_BLD_push_octet_string(bld.get(), OSSL_PKEY_PARAM_PUB_KEY, point.data(), point.size());
    Bn priv;
    if (with_private) {
        const auto d = jwk_bytes(jwk, "d");
        priv.reset(BN_bin2bn(reinterpret_cast<const unsigned char*>(d.data()), static_cast<int>(d.size()), nullptr));
        OSSL_PARAM_BLD_push_BN(bld.get(), OSSL_PKEY_PARAM_PRIV_KEY, priv.get());
    }
    std::unique_ptr<OSSL_PARAM, ParamDeleter> params(OSSL_PARAM_BLD_to_param(bld.get()));
    std::unique_ptr<EVP_PKEY_CTX, CtxDeleter> ctx(EVP_PKEY_CTX_new_from_name(nullptr, "EC", nullptr));
    EVP_PKEY* key = nullptr;
    if (!ctx || EVP_PKEY_fromdata_init(ctx.get()) != 1 ||
        EVP_PKEY_fromdata(ctx.get(), &key, with_private ? EVP_PKEY_KEYPAIR : EVP_PKEY_PUBLIC_KEY, params.get()) != 1)
        throw std::invalid_argument("invalid EC JWK");
    // Validate the point lies on the curve.
    std::unique_ptr<EVP_PKEY_CTX, CtxDeleter> check(EVP_PKEY_CTX_new_from_pkey(nullptr, key, nullptr));
    if (!check || EVP_PKEY_public_check(check.get()) != 1) {
        EVP_PKEY_free(key);
        throw std::invalid_argument("EC JWK public key is not on the curve");
    }
    return key;
}

std::string der_to_raw(const std::string& der, std::size_t size) {
    const unsigned char* p = reinterpret_cast<const unsigned char*>(der.data());
    std::unique_ptr<ECDSA_SIG, SigDeleter> sig(d2i_ECDSA_SIG(nullptr, &p, static_cast<long>(der.size())));
    if (!sig) crypto_fail("invalid DER signature");
    const BIGNUM* r = nullptr;
    const BIGNUM* s = nullptr;
    ECDSA_SIG_get0(sig.get(), &r, &s);
    return bn_bytes(r, size) + bn_bytes(s, size);
}

std::optional<std::string> raw_to_der(std::string_view raw_sig, std::size_t size) {
    if (raw_sig.size() != size * 2) return std::nullopt;
    std::unique_ptr<ECDSA_SIG, SigDeleter> sig(ECDSA_SIG_new());
    BIGNUM* r = BN_bin2bn(reinterpret_cast<const unsigned char*>(raw_sig.data()), static_cast<int>(size), nullptr);
    BIGNUM* s = BN_bin2bn(reinterpret_cast<const unsigned char*>(raw_sig.data()) + size, static_cast<int>(size), nullptr);
    if (!r || !s || ECDSA_SIG_set0(sig.get(), r, s) != 1) {
        BN_free(r);
        BN_free(s);
        return std::nullopt;
    }
    unsigned char* der = nullptr;
    const int len = i2d_ECDSA_SIG(sig.get(), &der);
    if (len <= 0) return std::nullopt;
    std::string out(reinterpret_cast<char*>(der), static_cast<std::size_t>(len));
    OPENSSL_free(der);
    return out;
}

std::string digest(const EVP_MD* md, std::string_view data) {
    unsigned char out[EVP_MAX_MD_SIZE];
    unsigned int len = 0;
    if (EVP_Digest(data.data(), data.size(), out, &len, md, nullptr) != 1) crypto_fail("digest failed");
    return std::string(reinterpret_cast<char*>(out), len);
}

}  // namespace

std::string_view jws_algorithm_name(KeyAlgorithm algorithm) noexcept {
    switch (algorithm) {
        case KeyAlgorithm::ES256: return "ES256";
        case KeyAlgorithm::ES384: return "ES384";
        case KeyAlgorithm::EdDSA: return "EdDSA";
    }
    return "";
}

// ---- PublicKey -----------------------------------------------------------------------------

PublicKey PublicKey::from_jwk(const nlohmann::json& jwk) {
    const auto alg = jwk_algorithm(jwk);
    return PublicKey(share(import_jwk(jwk, false, alg)), alg);
}

nlohmann::json PublicKey::to_jwk() const { return public_jwk_of(raw(key_), algorithm_); }

bool PublicKey::verify(std::string_view data, std::string_view signature) const {
    std::unique_ptr<EVP_MD_CTX, MdCtxDeleter> ctx(EVP_MD_CTX_new());
    if (!ctx) crypto_fail("EVP_MD_CTX_new");
    std::string sig;
    const EVP_MD* md = nullptr;
    if (algorithm_ == KeyAlgorithm::EdDSA) {
        if (signature.size() != 64) return false;
        sig = std::string(signature);
    } else {
        const auto* c = curve_for(algorithm_);
        auto der = raw_to_der(signature, c->size);
        if (!der) return false;
        sig = std::move(*der);
        md = c->md();
    }
    if (EVP_DigestVerifyInit(ctx.get(), nullptr, md, nullptr, raw(key_)) != 1) crypto_fail("EVP_DigestVerifyInit");
    return EVP_DigestVerify(ctx.get(), reinterpret_cast<const unsigned char*>(sig.data()), sig.size(),
                            reinterpret_cast<const unsigned char*>(data.data()), data.size()) == 1;
}

// ---- PrivateKey ----------------------------------------------------------------------------

PrivateKey PrivateKey::generate(KeyAlgorithm algorithm) {
    EVP_PKEY* key = nullptr;
    if (algorithm == KeyAlgorithm::EdDSA) {
        key = EVP_PKEY_Q_keygen(nullptr, nullptr, "ED25519");
    } else {
        key = EVP_PKEY_Q_keygen(nullptr, nullptr, "EC", curve_for(algorithm)->group);
    }
    if (!key) crypto_fail("key generation failed");
    return PrivateKey(share(key), algorithm);
}

PrivateKey PrivateKey::from_jwk(const nlohmann::json& jwk) {
    const auto alg = jwk_algorithm(jwk);
    return PrivateKey(share(import_jwk(jwk, true, alg)), alg);
}

PrivateKey PrivateKey::from_pem(std::string_view pem) {
    std::unique_ptr<BIO, BioDeleter> bio(BIO_new_mem_buf(pem.data(), static_cast<int>(pem.size())));
    EVP_PKEY* key = PEM_read_bio_PrivateKey(bio.get(), nullptr, nullptr, nullptr);
    if (!key) throw std::invalid_argument("invalid PEM private key");
    auto shared = share(key);
    return PrivateKey(shared, algorithm_of(key));
}

PublicKey PrivateKey::public_key() const { return PublicKey::from_jwk(public_jwk()); }

nlohmann::json PrivateKey::public_jwk() const { return public_jwk_of(raw(key_), algorithm_); }

nlohmann::json PrivateKey::private_jwk() const {
    auto jwk = public_jwk();
    if (algorithm_ == KeyAlgorithm::EdDSA) {
        unsigned char buf[32];
        size_t len = sizeof buf;
        if (EVP_PKEY_get_raw_private_key(raw(key_), buf, &len) != 1) crypto_fail("cannot export Ed25519 private key");
        jwk["d"] = base64url_encode(std::string(reinterpret_cast<char*>(buf), len));
    } else {
        auto d = get_bn(raw(key_), OSSL_PKEY_PARAM_PRIV_KEY);
        jwk["d"] = base64url_encode(bn_bytes(d.get(), curve_for(algorithm_)->size));
    }
    return jwk;
}

std::string PrivateKey::to_pem() const {
    std::unique_ptr<BIO, BioDeleter> bio(BIO_new(BIO_s_mem()));
    if (PEM_write_bio_PrivateKey(bio.get(), raw(key_), nullptr, nullptr, 0, nullptr, nullptr) != 1)
        crypto_fail("PEM export failed");
    char* data = nullptr;
    const long len = BIO_get_mem_data(bio.get(), &data);
    return std::string(data, static_cast<std::size_t>(len));
}

std::string PrivateKey::sign(std::string_view data) const {
    std::unique_ptr<EVP_MD_CTX, MdCtxDeleter> ctx(EVP_MD_CTX_new());
    if (!ctx) crypto_fail("EVP_MD_CTX_new");
    const auto* c = curve_for(algorithm_);
    const EVP_MD* md = c ? c->md() : nullptr;
    if (EVP_DigestSignInit(ctx.get(), nullptr, md, nullptr, raw(key_)) != 1) crypto_fail("EVP_DigestSignInit");
    size_t len = 0;
    const auto* in = reinterpret_cast<const unsigned char*>(data.data());
    if (EVP_DigestSign(ctx.get(), nullptr, &len, in, data.size()) != 1) crypto_fail("EVP_DigestSign (size)");
    std::string sig(len, '\0');
    if (EVP_DigestSign(ctx.get(), reinterpret_cast<unsigned char*>(sig.data()), &len, in, data.size()) != 1)
        crypto_fail("EVP_DigestSign");
    sig.resize(len);
    return c ? der_to_raw(sig, c->size) : sig;
}

// ---- Digests / randomness ----------------------------------------------------------------

std::string sha256(std::string_view data) { return digest(EVP_sha256(), data); }
std::string sha512(std::string_view data) { return digest(EVP_sha512(), data); }

std::string random_bytes(std::size_t count) {
    std::string out(count, '\0');
    if (RAND_bytes(reinterpret_cast<unsigned char*>(out.data()), static_cast<int>(count)) != 1)
        crypto_fail("RAND_bytes failed");
    return out;
}

std::string random_uuid() {
    auto b = random_bytes(16);
    b[6] = static_cast<char>((static_cast<unsigned char>(b[6]) & 0x0F) | 0x40);
    b[8] = static_cast<char>((static_cast<unsigned char>(b[8]) & 0x3F) | 0x80);
    static constexpr char hex[] = "0123456789abcdef";
    std::string out;
    for (int i = 0; i < 16; ++i) {
        if (i == 4 || i == 6 || i == 8 || i == 10) out += '-';
        out += hex[static_cast<unsigned char>(b[i]) >> 4];
        out += hex[static_cast<unsigned char>(b[i]) & 15];
    }
    return out;
}

// ---- JWT -----------------------------------------------------------------------------------

std::string sign_jwt(const nlohmann::json& header, const nlohmann::json& claims, const PrivateKey& key) {
    nlohmann::json h = header.is_object() ? header : nlohmann::json::object();
    h["alg"] = std::string(jws_algorithm_name(key.algorithm()));
    const std::string input = base64url_encode(h.dump()) + "." + base64url_encode(claims.dump());
    return input + "." + base64url_encode(key.sign(input));
}

bool verify_jwt(std::string_view jwt, const PublicKey& key) {
    const auto first = jwt.find('.');
    const auto last = jwt.rfind('.');
    if (first == std::string_view::npos || last == first) return false;
    try {
        auto header = nlohmann::json::parse(base64url_decode(jwt.substr(0, first)), nullptr, false);
        if (header.is_discarded() || !header.is_object()) return false;
        const std::string alg = header.value("alg", "");
        if (alg.empty() || alg == "none" || alg != jws_algorithm_name(key.algorithm())) return false;
        return key.verify(jwt.substr(0, last), base64url_decode(jwt.substr(last + 1)));
    } catch (const ParseError&) {
        return false;
    }
}

// ---- SelfSignedCredentials ---------------------------------------------------------------

SelfSignedCredentials::SelfSignedCredentials(std::string agent_uri, PrivateKey key, std::string kid,
                                             std::chrono::seconds lifetime)
    : agent_(std::move(agent_uri)), key_(std::move(key)), kid_(std::move(kid)), lifetime_(lifetime) {
    if (key_.algorithm() == KeyAlgorithm::ES384)
        throw std::invalid_argument("self-signed credentials support ES256 and EdDSA keys");
}

std::shared_ptr<SelfSignedCredentials> SelfSignedCredentials::for_agent(std::string agent_uri, PrivateKey key,
                                                                        std::string kid, std::chrono::seconds lifetime) {
    return std::make_shared<SelfSignedCredentials>(std::move(agent_uri), std::move(key), std::move(kid), lifetime);
}

std::shared_ptr<SelfSignedCredentials> SelfSignedCredentials::did_key(PrivateKey key, std::chrono::seconds lifetime) {
    const auto id = key.did_key();
    return std::make_shared<SelfSignedCredentials>(id.did, std::move(key), id.kid, lifetime);
}

std::string SelfSignedCredentials::token_type() const { return std::string(oauth::token_type_jwt); }

std::string SelfSignedCredentials::mint(std::string_view audience) const {
    const auto now = clock ? clock() : std::chrono::system_clock::now();
    const auto iat = std::chrono::duration_cast<std::chrono::seconds>(now.time_since_epoch()).count();
    nlohmann::json header = {{"typ", "JWT"}};
    if (!kid_.empty()) header["kid"] = kid_;
    const nlohmann::json claims = {
        {"sub", agent_},
        {"iss", agent_},
        {"client_id", agent_},
        {"aud", nlohmann::json::array({std::string(audience)})},
        {"iat", iat},
        {"exp", iat + lifetime_.count()},
        {"jti", random_uuid()},
    };
    return sign_jwt(header, claims, key_);
}

std::string SelfSignedCredentials::subject_token(const CredentialContext& context) {
    const auto now = clock ? clock() : std::chrono::system_clock::now();
    std::lock_guard lock(mutex_);
    if (auto it = cache_.find(context.issuer); it != cache_.end() && it->second.second - std::chrono::seconds(60) > now)
        return it->second.first;
    auto token = mint(context.issuer);
    cache_.insert_or_assign(context.issuer, std::make_pair(token, now + lifetime_));
    return token;
}

}  // namespace lws
