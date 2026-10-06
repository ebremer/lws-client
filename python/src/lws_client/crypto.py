# SPDX-License-Identifier: MIT
"""Keys, JWKs, did:key identifiers and compact JWS/JWT helpers.

Signing and verification need the optional ``cryptography`` package
(``pip install "lws-client[crypto]"``). did:key encoding/decoding and the controlled
identifier document builder are pure Python.

Supported algorithms: ``ES256`` (P-256), ``ES384`` (P-384) and ``EdDSA`` (Ed25519).
ECDSA signatures use the JOSE / RFC 9421 raw ``r‖s`` encoding, never DER.
"""

from __future__ import annotations

import json
import time
import uuid
from collections.abc import Mapping, Sequence
from typing import Any

from ._util import b64url_decode, b64url_encode
from .constants import CID_CONTEXT

__all__ = [
    "SigningKey",
    "VerifyingKey",
    "generate_key",
    "did_key_from_jwk",
    "did_key_from_public_key",
    "did_key_to_jwk",
    "did_key_kid",
    "controlled_identifier_document",
    "encode_jwt",
    "decode_jwt_unverified",
    "verify_jwt",
    "self_signed_claims",
    "base58btc_encode",
    "base58btc_decode",
]

_B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_B58_INDEX = {c: i for i, c in enumerate(_B58)}

# multicodec varint prefixes
_P256_PREFIX = bytes([0x80, 0x24])  # p256-pub 0x1200
_P384_PREFIX = bytes([0x81, 0x24])  # p384-pub 0x1201
_ED25519_PREFIX = bytes([0xED, 0x01])  # ed25519-pub 0xed

_CURVES: dict[str, dict[str, Any]] = {
    "P-256": {
        "alg": "ES256",
        "size": 32,
        "p": 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF,
        "b": 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B,
        "prefix": _P256_PREFIX,
    },
    "P-384": {
        "alg": "ES384",
        "size": 48,
        "p": int(
            "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFE"
            "FFFFFFFF0000000000000000FFFFFFFF",
            16,
        ),
        "b": int(
            "B3312FA7E23EE7E4988E056BE3F82D19181D9C6EFE8141120314088F5013875A"
            "C656398D8A2ED19D2A85C8EDD3EC2AEF",
            16,
        ),
        "prefix": _P384_PREFIX,
    },
}


def _require_cryptography() -> Any:
    try:
        import cryptography
    except ImportError as exc:  # pragma: no cover - exercised only without the extra
        raise ImportError(
            "this feature needs the 'cryptography' package: pip install \"lws-client[crypto]\""
        ) from exc
    return cryptography


# --- base58btc ----------------------------------------------------------------------


def base58btc_encode(data: bytes) -> str:
    n = int.from_bytes(data, "big")
    out = ""
    while n > 0:
        n, rem = divmod(n, 58)
        out = _B58[rem] + out
    pad = len(data) - len(data.lstrip(b"\x00"))
    return "1" * pad + out


def base58btc_decode(text: str) -> bytes:
    n = 0
    for ch in text:
        try:
            n = n * 58 + _B58_INDEX[ch]
        except KeyError:
            raise ValueError(f"invalid base58 character {ch!r}") from None
    body = n.to_bytes((n.bit_length() + 7) // 8, "big") if n else b""
    pad = len(text) - len(text.lstrip("1"))
    return b"\x00" * pad + body


# --- did:key ------------------------------------------------------------------------


def did_key_from_jwk(jwk: Mapping[str, Any]) -> str:
    """Derive the ``did:key`` identifier of a public JWK (P-256, P-384 or Ed25519)."""
    kty, crv = jwk.get("kty"), jwk.get("crv")
    if kty == "EC" and crv in _CURVES:
        x = b64url_decode(str(jwk["x"]))
        y = b64url_decode(str(jwk["y"]))
        raw = bytes([0x03 if y[-1] & 1 else 0x02]) + x
        prefix: bytes = _CURVES[str(crv)]["prefix"]
    elif kty == "OKP" and crv == "Ed25519":
        raw = b64url_decode(str(jwk["x"]))
        prefix = _ED25519_PREFIX
    else:
        raise ValueError(f"unsupported key for did:key: kty={kty!r} crv={crv!r}")
    return "did:key:z" + base58btc_encode(prefix + raw)


def did_key_kid(did: str) -> str:
    """The verification method id (JWT ``kid``) of a did:key: ``did:key:z…#z…``."""
    return f"{did}#{did.removeprefix('did:key:')}"


def did_key_to_jwk(did: str) -> dict[str, Any]:
    """Decode a ``did:key`` (P-256, P-384 or Ed25519) into a public JWK (pure Python)."""
    did = did.split("#", 1)[0]
    if not did.startswith("did:key:z"):
        raise ValueError(f"not a base58btc did:key: {did!r}")
    data = base58btc_decode(did[len("did:key:z") :])
    if data.startswith(_ED25519_PREFIX):
        key = data[2:]
        if len(key) != 32:
            raise ValueError("invalid Ed25519 did:key length")
        return {"kty": "OKP", "crv": "Ed25519", "x": b64url_encode(key)}
    for crv, params in _CURVES.items():
        if data.startswith(params["prefix"]):
            point = data[2:]
            size: int = params["size"]
            if len(point) != size + 1 or point[0] not in (2, 3):
                raise ValueError(f"invalid compressed {crv} point in did:key")
            p: int = params["p"]
            x = int.from_bytes(point[1:], "big")
            alpha = (pow(x, 3, p) - 3 * x + params["b"]) % p
            y = pow(alpha, (p + 1) // 4, p)  # p ≡ 3 (mod 4)
            if (y * y) % p != alpha:
                raise ValueError("did:key point is not on the curve")
            if (y & 1) != (point[0] & 1):
                y = p - y
            return {
                "kty": "EC",
                "crv": crv,
                "x": b64url_encode(point[1:]),
                "y": b64url_encode(y.to_bytes(size, "big")),
            }
    raise ValueError("unsupported did:key multicodec")


def did_key_from_public_key(key: VerifyingKey | SigningKey | Mapping[str, Any]) -> str:
    """Derive a ``did:key`` from a key object or a public JWK."""
    if isinstance(key, SigningKey):
        return did_key_from_jwk(key.public_jwk())
    if isinstance(key, VerifyingKey):
        return did_key_from_jwk(key.jwk())
    return did_key_from_jwk(key)


def controlled_identifier_document(
    agent: str, public_jwk: Mapping[str, Any], kid: str
) -> dict[str, Any]:
    """Build the controlled identifier document an agent publishes at ``agent`` so that
    self-signed credentials (``kid``) can be verified (lws10-authn-ssi-cid)."""
    vm_id = kid if ("#" in kid or ":" in kid) else f"{agent}#{kid}"
    jwk = {k: v for k, v in public_jwk.items() if k != "d"}
    jwk.setdefault("kid", vm_id.rsplit("#", 1)[-1])
    return {
        "@context": [CID_CONTEXT],
        "id": agent,
        "authentication": [
            {"id": vm_id, "type": "JsonWebKey", "controller": agent, "publicKeyJwk": jwk}
        ],
    }


# --- keys ---------------------------------------------------------------------------


def _int_bytes(value: int, size: int) -> bytes:
    return value.to_bytes(size, "big")


def _alg_for_jwk(jwk: Mapping[str, Any]) -> str:
    kty, crv = jwk.get("kty"), jwk.get("crv")
    if kty == "EC" and crv in _CURVES:
        return str(_CURVES[str(crv)]["alg"])
    if kty == "OKP" and crv == "Ed25519":
        return "EdDSA"
    raise ValueError(f"unsupported JWK: kty={kty!r} crv={crv!r}")


class VerifyingKey:
    """A public key able to verify JOSE / RFC 9421 signatures."""

    __slots__ = ("_jwk", "_key", "alg")

    def __init__(self, key: Any, jwk: Mapping[str, Any], alg: str) -> None:
        self._key = key
        self._jwk = dict(jwk)
        self.alg = alg

    @classmethod
    def from_jwk(cls, jwk: Mapping[str, Any]) -> VerifyingKey:
        _require_cryptography()
        from cryptography.hazmat.primitives.asymmetric import ec, ed25519

        alg = _alg_for_jwk(jwk)
        public = {k: v for k, v in jwk.items() if k != "d"}
        key: Any
        if alg == "EdDSA":
            key = ed25519.Ed25519PublicKey.from_public_bytes(b64url_decode(str(jwk["x"])))
        else:
            curve = ec.SECP256R1() if jwk["crv"] == "P-256" else ec.SECP384R1()
            numbers = ec.EllipticCurvePublicNumbers(
                int.from_bytes(b64url_decode(str(jwk["x"])), "big"),
                int.from_bytes(b64url_decode(str(jwk["y"])), "big"),
                curve,
            )
            key = numbers.public_key()
        return cls(key, public, alg)

    @classmethod
    def from_did_key(cls, did: str) -> VerifyingKey:
        return cls.from_jwk(did_key_to_jwk(did))

    def jwk(self) -> dict[str, Any]:
        return dict(self._jwk)

    @property
    def crypto_key(self) -> Any:
        """The underlying ``cryptography`` public key object."""
        return self._key

    def verify(self, signature: bytes, data: bytes) -> bool:
        """Verify a raw (``r‖s`` for ECDSA) signature; returns ``False`` on mismatch."""
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

        try:
            if self.alg == "EdDSA":
                self._key.verify(signature, data)
                return True
            size = 32 if self.alg == "ES256" else 48
            if len(signature) != 2 * size:
                return False
            der = encode_dss_signature(
                int.from_bytes(signature[:size], "big"), int.from_bytes(signature[size:], "big")
            )
            digest = hashes.SHA256() if self.alg == "ES256" else hashes.SHA384()
            self._key.verify(der, data, ec.ECDSA(digest))
            return True
        except InvalidSignature:
            return False


class SigningKey:
    """A private key for signing JWTs (``ES256``, ``ES384`` or ``EdDSA``)."""

    __slots__ = ("_key", "alg")

    def __init__(self, key: Any, alg: str) -> None:
        self._key = key
        self.alg = alg

    @classmethod
    def generate(cls, alg: str = "ES256") -> SigningKey:
        """Generate a new key pair: ``ES256`` (P-256, default), ``ES384`` or ``EdDSA``."""
        _require_cryptography()
        from cryptography.hazmat.primitives.asymmetric import ec, ed25519

        if alg == "EdDSA":
            return cls(ed25519.Ed25519PrivateKey.generate(), alg)
        if alg == "ES256":
            return cls(ec.generate_private_key(ec.SECP256R1()), alg)
        if alg == "ES384":
            return cls(ec.generate_private_key(ec.SECP384R1()), alg)
        raise ValueError(f"unsupported algorithm {alg!r}")

    @classmethod
    def from_jwk(cls, jwk: Mapping[str, Any]) -> SigningKey:
        """Import a private JWK (must contain ``d``)."""
        _require_cryptography()
        from cryptography.hazmat.primitives.asymmetric import ec, ed25519

        if "d" not in jwk:
            raise ValueError("private JWK must contain 'd'")
        alg = _alg_for_jwk(jwk)
        d = b64url_decode(str(jwk["d"]))
        if alg == "EdDSA":
            return cls(ed25519.Ed25519PrivateKey.from_private_bytes(d), alg)
        curve = ec.SECP256R1() if jwk["crv"] == "P-256" else ec.SECP384R1()
        return cls(ec.derive_private_key(int.from_bytes(d, "big"), curve), alg)

    @classmethod
    def from_pem(cls, data: bytes | str, password: bytes | None = None) -> SigningKey:
        """Import a PEM (PKCS#8 / SEC1) private key."""
        _require_cryptography()
        from cryptography.hazmat.primitives.serialization import load_pem_private_key

        key = load_pem_private_key(data.encode() if isinstance(data, str) else data, password)
        return cls.from_crypto_key(key)

    @classmethod
    def from_crypto_key(cls, key: Any) -> SigningKey:
        """Wrap an existing ``cryptography`` private key object."""
        _require_cryptography()
        from cryptography.hazmat.primitives.asymmetric import ec, ed25519

        if isinstance(key, ed25519.Ed25519PrivateKey):
            return cls(key, "EdDSA")
        if isinstance(key, ec.EllipticCurvePrivateKey):
            if isinstance(key.curve, ec.SECP256R1):
                return cls(key, "ES256")
            if isinstance(key.curve, ec.SECP384R1):
                return cls(key, "ES384")
        raise ValueError("unsupported private key type")

    @property
    def crypto_key(self) -> Any:
        """The underlying ``cryptography`` private key object."""
        return self._key

    def public_jwk(self) -> dict[str, Any]:
        from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

        if self.alg == "EdDSA":
            raw = self._key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
            return {"kty": "OKP", "crv": "Ed25519", "x": b64url_encode(raw)}
        numbers = self._key.public_key().public_numbers()
        size = 32 if self.alg == "ES256" else 48
        return {
            "kty": "EC",
            "crv": "P-256" if self.alg == "ES256" else "P-384",
            "x": b64url_encode(_int_bytes(numbers.x, size)),
            "y": b64url_encode(_int_bytes(numbers.y, size)),
        }

    def private_jwk(self) -> dict[str, Any]:
        from cryptography.hazmat.primitives.serialization import (
            Encoding,
            NoEncryption,
            PrivateFormat,
        )

        jwk = self.public_jwk()
        if self.alg == "EdDSA":
            raw = self._key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
            jwk["d"] = b64url_encode(raw)
        else:
            size = 32 if self.alg == "ES256" else 48
            jwk["d"] = b64url_encode(_int_bytes(self._key.private_numbers().private_value, size))
        return jwk

    def to_pem(self, password: bytes | None = None) -> bytes:
        """Export as PKCS#8 PEM (encrypted if ``password`` is given)."""
        from cryptography.hazmat.primitives.serialization import (
            BestAvailableEncryption,
            Encoding,
            NoEncryption,
            PrivateFormat,
        )

        encryption = BestAvailableEncryption(password) if password else NoEncryption()
        pem: bytes = self._key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, encryption)
        return pem

    @property
    def public_key(self) -> VerifyingKey:
        return VerifyingKey.from_jwk(self.public_jwk())

    def did_key(self) -> str:
        """The ``did:key`` identifier of this key's public half."""
        return did_key_from_jwk(self.public_jwk())

    def sign(self, data: bytes) -> bytes:
        """Sign ``data``; ECDSA signatures are returned as raw ``r‖s``."""
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

        if self.alg == "EdDSA":
            sig: bytes = self._key.sign(data)
            return sig
        digest = hashes.SHA256() if self.alg == "ES256" else hashes.SHA384()
        r, s = decode_dss_signature(self._key.sign(data, ec.ECDSA(digest)))
        size = 32 if self.alg == "ES256" else 48
        return _int_bytes(r, size) + _int_bytes(s, size)


def generate_key(alg: str = "ES256") -> SigningKey:
    """Generate a signing key (``ES256`` default, ``ES384`` or ``EdDSA``)."""
    return SigningKey.generate(alg)


# --- JWT ----------------------------------------------------------------------------


def _b64json(value: Mapping[str, Any]) -> str:
    return b64url_encode(json.dumps(value, separators=(",", ":")).encode("utf-8"))


def encode_jwt(header: Mapping[str, Any], claims: Mapping[str, Any], key: SigningKey) -> str:
    """Create a compact JWS. ``header['alg']`` defaults to the key's algorithm."""
    hdr = {"alg": key.alg, **header}
    if hdr["alg"] != key.alg:
        raise ValueError(f"header alg {hdr['alg']!r} does not match key alg {key.alg!r}")
    signing_input = f"{_b64json(hdr)}.{_b64json(claims)}"
    return f"{signing_input}.{b64url_encode(key.sign(signing_input.encode('ascii')))}"


def decode_jwt_unverified(token: str) -> tuple[dict[str, Any], dict[str, Any]]:
    """Decode a compact JWS header and payload **without** verifying the signature."""
    parts = token.split(".")
    if len(parts) != 3:
        raise ValueError("not a compact JWS")
    header = json.loads(b64url_decode(parts[0]))
    claims = json.loads(b64url_decode(parts[1]))
    if not isinstance(header, dict) or not isinstance(claims, dict):
        raise ValueError("JWS header and payload must be JSON objects")
    return header, claims


def verify_jwt(token: str, key: VerifyingKey | Mapping[str, Any]) -> dict[str, Any]:
    """Verify a compact JWS signature and return its claims (no claim validation).

    Rejects ``alg: none`` and algorithm/key mismatches. Raises ``ValueError`` on failure.
    """
    header, claims = decode_jwt_unverified(token)
    verifier = key if isinstance(key, VerifyingKey) else VerifyingKey.from_jwk(key)
    alg = header.get("alg")
    if alg in (None, "none") or alg != verifier.alg:
        raise ValueError(f"unacceptable JWS alg {alg!r} for key alg {verifier.alg!r}")
    signing_input, _, sig = token.rpartition(".")
    if not verifier.verify(b64url_decode(sig), signing_input.encode("ascii")):
        raise ValueError("invalid JWS signature")
    return claims


def self_signed_claims(
    agent: str,
    audience: str | Sequence[str],
    lifetime: int = 300,
    now: float | None = None,
) -> dict[str, Any]:
    """Claims of an lws10-authn-ssi-cid credential: ``sub = iss = client_id = agent``."""
    issued = int(time.time() if now is None else now)
    aud = [audience] if isinstance(audience, str) else list(audience)
    return {
        "sub": agent,
        "iss": agent,
        "client_id": agent,
        "aud": aud,
        "iat": issued,
        "exp": issued + lifetime,
        "jti": str(uuid.uuid4()),
    }
