// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Erich Bremer and the lws-client contributors
//
// Identifier helpers that need no cryptography library: did:key encoding of public JWKs and
// controlled identifier (CID) documents.
#pragma once

#include <string>
#include <string_view>

#include <nlohmann/json.hpp>

namespace lws {

/// A did:key identifier and the matching verification method id (kid).
struct DidKey {
    std::string did{};  ///< did:key:z…
    std::string kid{};  ///< did:key:z…#z…
};

/// Derives the did:key for a P-256 (EC) or Ed25519 (OKP) public JWK:
/// multibase base58btc of the multicodec varint prefix (p256-pub 0x1200 / ed25519-pub 0xed)
/// plus the public key (33-byte compressed point for P-256). Throws std::invalid_argument
/// for other keys.
DidKey did_key_from_public_jwk(const nlohmann::json& public_jwk);

/// Builds the controlled identifier document an agent publishes at `agent_uri` so that
/// verifiers can find its key (lws10-authn-ssi-cid). `kid` may be a bare key id ("key-1"),
/// a fragment ("#key-1") or a full URL.
nlohmann::json controlled_identifier_document(std::string_view agent_uri, const nlohmann::json& public_jwk,
                                              std::string_view kid);

}  // namespace lws
