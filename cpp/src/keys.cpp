// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Erich Bremer and the lws-client contributors

#include "lws/keys.hpp"

#include <stdexcept>

#include "lws/constants.hpp"
#include "lws/encoding.hpp"

namespace lws {

DidKey did_key_from_public_jwk(const nlohmann::json& jwk) {
    if (!jwk.is_object()) throw std::invalid_argument("public JWK must be a JSON object");
    const std::string kty = jwk.value("kty", "");
    const std::string crv = jwk.value("crv", "");
    std::string bytes;
    if (kty == "EC" && crv == "P-256") {
        const std::string x = base64url_decode(jwk.value("x", ""));
        const std::string y = base64url_decode(jwk.value("y", ""));
        if (x.size() != 32 || y.size() != 32) throw std::invalid_argument("invalid P-256 JWK coordinates");
        bytes.push_back(static_cast<char>(0x80));  // multicodec p256-pub (0x1200), unsigned varint
        bytes.push_back(static_cast<char>(0x24));
        bytes.push_back((static_cast<unsigned char>(y.back()) & 1) ? '\x03' : '\x02');
        bytes += x;
    } else if (kty == "OKP" && crv == "Ed25519") {
        const std::string x = base64url_decode(jwk.value("x", ""));
        if (x.size() != 32) throw std::invalid_argument("invalid Ed25519 JWK");
        bytes.push_back(static_cast<char>(0xed));  // multicodec ed25519-pub (0xed), unsigned varint
        bytes.push_back(static_cast<char>(0x01));
        bytes += x;
    } else {
        throw std::invalid_argument("did:key supports P-256 (EC) and Ed25519 (OKP) keys only");
    }
    const std::string multibase = "z" + base58btc_encode(bytes);
    return DidKey{"did:key:" + multibase, "did:key:" + multibase + "#" + multibase};
}

nlohmann::json controlled_identifier_document(std::string_view agent_uri, const nlohmann::json& public_jwk,
                                              std::string_view kid) {
    std::string method_id;
    std::string bare_kid(kid);
    if (kid.find(':') != std::string_view::npos) {
        method_id = std::string(kid);
        auto hash = kid.find('#');
        bare_kid = hash == std::string_view::npos ? std::string(kid) : std::string(kid.substr(hash + 1));
    } else if (kid.starts_with('#')) {
        method_id = std::string(agent_uri) + std::string(kid);
        bare_kid = std::string(kid.substr(1));
    } else {
        method_id = std::string(agent_uri) + "#" + std::string(kid);
    }
    nlohmann::json jwk = public_jwk;
    jwk.erase("d");
    if (!jwk.contains("kid")) jwk["kid"] = bare_kid;
    return {
        {"@context", nlohmann::json::array({std::string(ns::cid_context)})},
        {"id", std::string(agent_uri)},
        {"authentication",
         nlohmann::json::array({{{"id", method_id},
                                 {"type", "JsonWebKey"},
                                 {"controller", std::string(agent_uri)},
                                 {"publicKeyJwk", jwk}}})},
    };
}

}  // namespace lws
