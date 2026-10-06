# SPDX-License-Identifier: MIT
"""did:key, JWK, JWT and key handling tests (shared fixtures)."""

from __future__ import annotations

from typing import Any

import pytest
from conftest import load

from lws_client import (
    SelfSignedCredentials,
    SigningKey,
    VerifyingKey,
    controlled_identifier_document,
    decode_jwt_unverified,
    did_key_from_jwk,
    did_key_kid,
    did_key_to_jwk,
    encode_jwt,
    verify_jwt,
)
from lws_client.crypto import base58btc_decode, base58btc_encode

DID_VECTORS = load("did-key.json")["vectors"]
JWT_VECTORS = load("jwt.json")["vectors"]


@pytest.mark.parametrize("v", DID_VECTORS, ids=[v["name"] for v in DID_VECTORS])
def test_did_key_vectors(v: dict[str, Any]) -> None:
    assert did_key_from_jwk(v["publicJwk"]) == v["did"]
    assert did_key_kid(v["did"]) == v["kid"]
    decoded = did_key_to_jwk(v["did"])
    for name in ("kty", "crv", "x", "y"):
        assert decoded.get(name) == v["publicJwk"].get(name)


@pytest.mark.parametrize("v", JWT_VECTORS, ids=[v["name"] for v in JWT_VECTORS])
def test_jwt_vectors_verify(v: dict[str, Any]) -> None:
    claims = verify_jwt(v["jwt"], v["publicJwk"])
    assert claims == v["claims"]
    header, _ = decode_jwt_unverified(v["jwt"])
    assert header == v["header"]
    # the did:key subject itself yields the verification key
    assert verify_jwt(v["jwt"], did_key_to_jwk(v["claims"]["sub"])) == v["claims"]
    tampered = v["jwt"][:-4] + ("AAAA" if not v["jwt"].endswith("AAAA") else "BBBB")
    with pytest.raises(ValueError):
        verify_jwt(tampered, v["publicJwk"])


def test_base58_roundtrip() -> None:
    for data in (b"", b"\x00\x00abc", bytes(range(40))):
        assert base58btc_decode(base58btc_encode(data)) == data


@pytest.mark.parametrize("alg", ["ES256", "ES384", "EdDSA"])
def test_generate_sign_verify(alg: str) -> None:
    key = SigningKey.generate(alg)
    assert key.alg == alg
    sig = key.sign(b"payload")
    assert len(sig) == {"ES256": 64, "ES384": 96, "EdDSA": 64}[alg]
    assert key.public_key.verify(sig, b"payload")
    assert not key.public_key.verify(sig, b"other")
    # JWK export/import round trip
    again = SigningKey.from_jwk(key.private_jwk())
    assert again.public_jwk() == key.public_jwk()
    assert SigningKey.from_pem(key.to_pem()).public_jwk() == key.public_jwk()
    # did:key round trip
    did = key.did_key()
    assert did_key_to_jwk(did) == key.public_jwk()
    assert VerifyingKey.from_did_key(did).verify(sig, b"payload")


def test_fixture_private_keys_match() -> None:
    for name in ("p256", "ed25519"):
        doc = load(f"keys/{name}.json")
        key = SigningKey.from_jwk(doc["privateJwk"])
        pub = key.public_jwk()
        for field in ("kty", "crv", "x", "y"):
            assert pub.get(field) == doc["publicJwk"].get(field)


@pytest.mark.parametrize("alg", ["ES256", "EdDSA"])
def test_self_signed_credentials(alg: str) -> None:
    key = SigningKey.generate(alg)
    creds = SelfSignedCredentials.did_key(key)
    assert creds.agent.startswith("did:key:z")
    assert creds.kid == f"{creds.agent}#{creds.agent[8:]}"
    token = creds.create_token("https://as.example", now=1790000000)
    header, claims = decode_jwt_unverified(token)
    assert header == {"alg": alg, "typ": "JWT", "kid": creds.kid}
    assert claims["sub"] == claims["iss"] == claims["client_id"] == creds.agent
    assert claims["aud"] == ["https://as.example"]
    assert claims["exp"] - claims["iat"] == 300
    assert claims["jti"]
    assert verify_jwt(token, did_key_to_jwk(creds.agent))["sub"] == creds.agent


def test_cid_document_and_encode_jwt() -> None:
    key = SigningKey.generate()
    doc = controlled_identifier_document("https://id.example/agent", key.public_jwk(), "k1")
    vm = doc["authentication"][0]
    assert doc["id"] == "https://id.example/agent"
    assert vm["id"] == "https://id.example/agent#k1"
    assert vm["type"] == "JsonWebKey"
    assert "d" not in vm["publicKeyJwk"]
    token = encode_jwt({"typ": "JWT", "kid": vm["id"]}, {"sub": "x"}, key)
    assert verify_jwt(token, vm["publicKeyJwk"]) == {"sub": "x"}
    with pytest.raises(ValueError):
        encode_jwt({"alg": "EdDSA"}, {}, key)
    with pytest.raises(ValueError):
        verify_jwt(token.split(".")[0] + ".e30.", vm["publicKeyJwk"])
