// SPDX-License-Identifier: MIT
//! Keys, JWKs, did:key identifiers, controlled identifier documents and compact JWTs
//! (ES256 / EdDSA) for the self-signed LWS authentication suites and webhook verification.
//!
//! Requires the `crypto` feature (enabled by default).

use std::fmt;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD_INDIFFERENT as B64URL;
use ed25519_dalek::{Signer as _, Verifier as _};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};

use crate::constants::CID_CONTEXT;
use crate::error::{Error, Result};

fn b64url(data: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(data)
}

fn b64url_decode(s: &str) -> Result<Vec<u8>> {
    B64URL
        .decode(s)
        .map_err(|e| Error::Crypto(format!("invalid base64url: {e}")))
}

/// Fills `buf` with cryptographically secure random bytes.
pub fn fill_random(buf: &mut [u8]) -> Result<()> {
    getrandom::fill(buf).map_err(|e| Error::Crypto(format!("random number generator failed: {e}")))
}

/// A random (version 4) UUID string.
pub fn uuid_v4() -> Result<String> {
    let mut b = [0u8; 16];
    fill_random(&mut b)?;
    b[6] = (b[6] & 0x0f) | 0x40;
    b[8] = (b[8] & 0x3f) | 0x80;
    let h: String = b.iter().map(|x| format!("{x:02x}")).collect();
    Ok(format!(
        "{}-{}-{}-{}-{}",
        &h[0..8],
        &h[8..12],
        &h[12..16],
        &h[16..20],
        &h[20..32]
    ))
}

/// Supported key algorithms.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum KeyAlgorithm {
    /// ECDSA over P-256 with SHA-256 (JWS `ES256`, RFC 9421 `ecdsa-p256-sha256`).
    P256,
    /// Ed25519 (JWS `EdDSA`, RFC 9421 `ed25519`).
    Ed25519,
}

impl KeyAlgorithm {
    /// The JWS `alg` value.
    pub fn jws_alg(self) -> &'static str {
        match self {
            KeyAlgorithm::P256 => "ES256",
            KeyAlgorithm::Ed25519 => "EdDSA",
        }
    }
    /// The RFC 9421 HTTP Message Signatures algorithm name.
    pub fn http_signature_alg(self) -> &'static str {
        match self {
            KeyAlgorithm::P256 => "ecdsa-p256-sha256",
            KeyAlgorithm::Ed25519 => "ed25519",
        }
    }
}

/// A JSON Web Key (EC P-256 or OKP Ed25519), public or private.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Jwk {
    /// Key type (`EC` or `OKP`).
    pub kty: String,
    /// Curve (`P-256` or `Ed25519`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub crv: Option<String>,
    /// Public x coordinate / Ed25519 public key (base64url).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub x: Option<String>,
    /// Public y coordinate (EC only, base64url).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub y: Option<String>,
    /// Private key (base64url); absent for public keys.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub d: Option<String>,
    /// Key id.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kid: Option<String>,
    /// Intended algorithm.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub alg: Option<String>,
    /// Other members.
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

impl Jwk {
    /// Parses a JWK from a JSON value.
    pub fn from_json(value: &Value) -> Result<Self> {
        serde_json::from_value(value.clone())
            .map_err(|e| Error::Crypto(format!("invalid JWK: {e}")))
    }
    /// The JWK as JSON.
    pub fn to_json(&self) -> Value {
        serde_json::to_value(self).unwrap_or(Value::Null)
    }
    /// A copy without the private member `d`.
    pub fn to_public(&self) -> Jwk {
        Jwk {
            d: None,
            ..self.clone()
        }
    }
    /// Sets `kid` (builder style).
    #[must_use]
    pub fn with_kid(mut self, kid: impl Into<String>) -> Self {
        self.kid = Some(kid.into());
        self
    }
    fn algorithm(&self) -> Result<KeyAlgorithm> {
        match (self.kty.as_str(), self.crv.as_deref()) {
            ("EC", Some("P-256")) => Ok(KeyAlgorithm::P256),
            ("OKP", Some("Ed25519")) => Ok(KeyAlgorithm::Ed25519),
            (kty, crv) => Err(Error::Crypto(format!(
                "unsupported JWK kty={kty} crv={crv:?}"
            ))),
        }
    }
    fn coordinate(&self, v: &Option<String>, name: &str, len: usize) -> Result<Vec<u8>> {
        let bytes = b64url_decode(
            v.as_deref()
                .ok_or_else(|| Error::Crypto(format!("JWK is missing {name}")))?,
        )?;
        if bytes.len() != len {
            return Err(Error::Crypto(format!(
                "JWK {name} has {} bytes, expected {len}",
                bytes.len()
            )));
        }
        Ok(bytes)
    }
}

/// A private signing key (P-256 or Ed25519).
#[derive(Clone)]
pub enum SigningKey {
    /// ECDSA P-256.
    P256(p256::ecdsa::SigningKey),
    /// Ed25519.
    Ed25519(ed25519_dalek::SigningKey),
}

impl fmt::Debug for SigningKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "SigningKey({:?}, public={:?})",
            self.algorithm(),
            self.verifying_key().did_key().did
        )
    }
}

impl SigningKey {
    /// Generates a new key.
    pub fn generate(algorithm: KeyAlgorithm) -> Result<Self> {
        match algorithm {
            KeyAlgorithm::P256 => Self::generate_p256(),
            KeyAlgorithm::Ed25519 => Self::generate_ed25519(),
        }
    }
    /// Generates a new P-256 key.
    pub fn generate_p256() -> Result<Self> {
        loop {
            let mut b = [0u8; 32];
            fill_random(&mut b)?;
            if let Ok(k) = p256::ecdsa::SigningKey::from_slice(&b) {
                return Ok(SigningKey::P256(k));
            }
        }
    }
    /// Generates a new Ed25519 key.
    pub fn generate_ed25519() -> Result<Self> {
        let mut b = [0u8; 32];
        fill_random(&mut b)?;
        Ok(SigningKey::Ed25519(ed25519_dalek::SigningKey::from_bytes(
            &b,
        )))
    }
    /// Imports a private JWK (must contain `d`).
    pub fn from_jwk(jwk: &Jwk) -> Result<Self> {
        let key = match jwk.algorithm()? {
            KeyAlgorithm::P256 => {
                let d = jwk.coordinate(&jwk.d, "d", 32)?;
                SigningKey::P256(
                    p256::ecdsa::SigningKey::from_slice(&d)
                        .map_err(|e| Error::Crypto(format!("invalid P-256 key: {e}")))?,
                )
            }
            KeyAlgorithm::Ed25519 => {
                let d = jwk.coordinate(&jwk.d, "d", 32)?;
                let mut seed = [0u8; 32];
                seed.copy_from_slice(&d);
                SigningKey::Ed25519(ed25519_dalek::SigningKey::from_bytes(&seed))
            }
        };
        if jwk.x.is_some() && key.verifying_key().to_jwk().x != jwk.x {
            return Err(Error::Crypto(
                "JWK public and private parts do not match".into(),
            ));
        }
        Ok(key)
    }
    /// Exports the private key as a JWK (includes `d`; keep it secret).
    pub fn to_jwk(&self) -> Jwk {
        let mut jwk = self.verifying_key().to_jwk();
        jwk.d = Some(match self {
            SigningKey::P256(k) => b64url(&k.to_bytes()),
            SigningKey::Ed25519(k) => b64url(&k.to_bytes()),
        });
        jwk
    }
    /// The public JWK.
    pub fn public_jwk(&self) -> Jwk {
        self.verifying_key().to_jwk()
    }
    /// The public key.
    pub fn verifying_key(&self) -> VerifyingKey {
        match self {
            SigningKey::P256(k) => VerifyingKey::P256(*k.verifying_key()),
            SigningKey::Ed25519(k) => VerifyingKey::Ed25519(k.verifying_key()),
        }
    }
    /// The key algorithm.
    pub fn algorithm(&self) -> KeyAlgorithm {
        match self {
            SigningKey::P256(_) => KeyAlgorithm::P256,
            SigningKey::Ed25519(_) => KeyAlgorithm::Ed25519,
        }
    }
    /// Signs a message (ECDSA signatures are raw `r‖s`, 64 bytes).
    pub fn sign(&self, message: &[u8]) -> Vec<u8> {
        match self {
            SigningKey::P256(k) => {
                let sig: p256::ecdsa::Signature = k.sign(message);
                sig.to_vec()
            }
            SigningKey::Ed25519(k) => k.sign(message).to_bytes().to_vec(),
        }
    }
    /// The `did:key` identifier for this key's public half.
    pub fn did_key(&self) -> DidKey {
        self.verifying_key().did_key()
    }
}

/// A public verification key (P-256 or Ed25519).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerifyingKey {
    /// ECDSA P-256.
    P256(p256::ecdsa::VerifyingKey),
    /// Ed25519.
    Ed25519(ed25519_dalek::VerifyingKey),
}

impl VerifyingKey {
    /// Imports a public JWK.
    pub fn from_jwk(jwk: &Jwk) -> Result<Self> {
        match jwk.algorithm()? {
            KeyAlgorithm::P256 => {
                let x = jwk.coordinate(&jwk.x, "x", 32)?;
                let y = jwk.coordinate(&jwk.y, "y", 32)?;
                let mut sec1 = Vec::with_capacity(65);
                sec1.push(0x04);
                sec1.extend_from_slice(&x);
                sec1.extend_from_slice(&y);
                Self::p256_from_sec1(&sec1)
            }
            KeyAlgorithm::Ed25519 => {
                let x = jwk.coordinate(&jwk.x, "x", 32)?;
                Self::ed25519_from_bytes(&x)
            }
        }
    }
    /// Imports a public JWK given as JSON.
    pub fn from_jwk_json(value: &Value) -> Result<Self> {
        Self::from_jwk(&Jwk::from_json(value)?)
    }
    fn p256_from_sec1(bytes: &[u8]) -> Result<Self> {
        p256::ecdsa::VerifyingKey::from_sec1_bytes(bytes)
            .map(VerifyingKey::P256)
            .map_err(|e| Error::Crypto(format!("invalid P-256 public key: {e}")))
    }
    fn ed25519_from_bytes(bytes: &[u8]) -> Result<Self> {
        let arr: [u8; 32] = bytes
            .try_into()
            .map_err(|_| Error::Crypto("Ed25519 key must be 32 bytes".into()))?;
        ed25519_dalek::VerifyingKey::from_bytes(&arr)
            .map(VerifyingKey::Ed25519)
            .map_err(|e| Error::Crypto(format!("invalid Ed25519 public key: {e}")))
    }
    /// Exports the key as a public JWK.
    pub fn to_jwk(&self) -> Jwk {
        match self {
            VerifyingKey::P256(k) => {
                let point = k.to_sec1_point(false);
                let b = point.as_bytes();
                Jwk {
                    kty: "EC".into(),
                    crv: Some("P-256".into()),
                    x: Some(b64url(&b[1..33])),
                    y: Some(b64url(&b[33..65])),
                    ..Default::default()
                }
            }
            VerifyingKey::Ed25519(k) => Jwk {
                kty: "OKP".into(),
                crv: Some("Ed25519".into()),
                x: Some(b64url(k.as_bytes())),
                ..Default::default()
            },
        }
    }
    /// The key algorithm.
    pub fn algorithm(&self) -> KeyAlgorithm {
        match self {
            VerifyingKey::P256(_) => KeyAlgorithm::P256,
            VerifyingKey::Ed25519(_) => KeyAlgorithm::Ed25519,
        }
    }
    /// Verifies a signature (ECDSA: raw `r‖s`).
    pub fn verify(&self, message: &[u8], signature: &[u8]) -> bool {
        match self {
            VerifyingKey::P256(k) => p256::ecdsa::Signature::from_slice(signature)
                .is_ok_and(|s| k.verify(message, &s).is_ok()),
            VerifyingKey::Ed25519(k) => ed25519_dalek::Signature::from_slice(signature)
                .is_ok_and(|s| k.verify(message, &s).is_ok()),
        }
    }
    /// The `did:key` identifier for this key.
    pub fn did_key(&self) -> DidKey {
        let mut bytes = Vec::with_capacity(35);
        match self {
            VerifyingKey::P256(k) => {
                bytes.extend_from_slice(&[0x80, 0x24]);
                bytes.extend_from_slice(k.to_sec1_point(true).as_bytes());
            }
            VerifyingKey::Ed25519(k) => {
                bytes.extend_from_slice(&[0xed, 0x01]);
                bytes.extend_from_slice(k.as_bytes());
            }
        }
        let multibase = format!("z{}", base58btc_encode(&bytes));
        DidKey {
            did: format!("did:key:{multibase}"),
            kid: format!("did:key:{multibase}#{multibase}"),
        }
    }
    /// Extracts the public key from a `did:key` identifier or DID URL.
    pub fn from_did_key(did: &str) -> Result<Self> {
        let rest = did
            .strip_prefix("did:key:")
            .ok_or_else(|| Error::Crypto(format!("{did:?} is not a did:key")))?;
        let multibase = rest.split('#').next().unwrap_or_default();
        let encoded = multibase
            .strip_prefix('z')
            .ok_or_else(|| Error::Crypto("did:key must use base58btc (z)".into()))?;
        let bytes = base58btc_decode(encoded)
            .ok_or_else(|| Error::Crypto("invalid base58btc in did:key".into()))?;
        match bytes.as_slice() {
            [0x80, 0x24, key @ ..] if key.len() == 33 => Self::p256_from_sec1(key),
            [0xed, 0x01, key @ ..] if key.len() == 32 => Self::ed25519_from_bytes(key),
            _ => Err(Error::Crypto("unsupported did:key multicodec".into())),
        }
    }
}

/// A `did:key` identifier and the key id of its single verification method.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DidKey {
    /// `did:key:z…`.
    pub did: String,
    /// `did:key:z…#z…`.
    pub kid: String,
}

/// Derives the `did:key` for a public key.
pub fn did_key_from_public_key(key: &VerifyingKey) -> DidKey {
    key.did_key()
}

/// Builds the controlled identifier document an agent publishes at `agent` so verifiers can
/// validate its self-signed credentials.
///
/// The verification method id is `agent#kid` (or `kid` itself when it is already absolute).
pub fn controlled_identifier_document(agent: &str, public_jwk: &Jwk, kid: &str) -> Value {
    let vm_id = if kid.contains(':') {
        kid.to_owned()
    } else {
        format!("{agent}#{}", kid.trim_start_matches('#'))
    };
    let jwk_kid = vm_id.rsplit('#').next().unwrap_or(kid).to_owned();
    let jwk = public_jwk.to_public().with_kid(jwk_kid);
    json!({
        "@context": [CID_CONTEXT],
        "id": agent,
        "authentication": [{
            "id": vm_id,
            "type": "JsonWebKey",
            "controller": agent,
            "publicKeyJwk": jwk.to_json(),
        }]
    })
}

const B58: &[u8; 58] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

/// Base58 (Bitcoin alphabet) encoding.
pub fn base58btc_encode(data: &[u8]) -> String {
    let zeros = data.iter().take_while(|b| **b == 0).count();
    let mut digits: Vec<u8> = Vec::with_capacity(data.len() * 138 / 100 + 1);
    for &byte in &data[zeros..] {
        let mut carry = byte as u32;
        for d in digits.iter_mut() {
            carry += (*d as u32) << 8;
            *d = (carry % 58) as u8;
            carry /= 58;
        }
        while carry > 0 {
            digits.push((carry % 58) as u8);
            carry /= 58;
        }
    }
    let mut out = String::with_capacity(zeros + digits.len());
    out.extend(std::iter::repeat_n('1', zeros));
    out.extend(digits.iter().rev().map(|d| B58[*d as usize] as char));
    out
}

/// Base58 (Bitcoin alphabet) decoding.
pub fn base58btc_decode(s: &str) -> Option<Vec<u8>> {
    let zeros = s.bytes().take_while(|b| *b == b'1').count();
    let mut bytes: Vec<u8> = Vec::new();
    for c in s.bytes().skip(zeros) {
        let mut carry = B58.iter().position(|x| *x == c)? as u32;
        for b in bytes.iter_mut() {
            carry += (*b as u32) * 58;
            *b = (carry & 0xff) as u8;
            carry >>= 8;
        }
        while carry > 0 {
            bytes.push((carry & 0xff) as u8);
            carry >>= 8;
        }
    }
    let mut out = vec![0u8; zeros];
    out.extend(bytes.iter().rev());
    Some(out)
}

/// Compact JWS / JWT helpers.
pub mod jwt {
    use super::*;

    /// Signs `claims` with `key`; `header` members are merged over the defaults
    /// (`alg` from the key, `typ: "JWT"`).
    pub fn sign(header: &Map<String, Value>, claims: &Value, key: &SigningKey) -> Result<String> {
        let mut h = Map::new();
        h.insert(
            "alg".into(),
            Value::String(key.algorithm().jws_alg().into()),
        );
        h.insert("typ".into(), Value::String("JWT".into()));
        for (k, v) in header {
            if k != "alg" {
                h.insert(k.clone(), v.clone());
            }
        }
        let input = format!(
            "{}.{}",
            b64url(&serde_json::to_vec(&Value::Object(h))?),
            b64url(&serde_json::to_vec(claims)?)
        );
        let sig = key.sign(input.as_bytes());
        Ok(format!("{input}.{}", b64url(&sig)))
    }

    /// Decodes header and claims without verifying the signature.
    pub fn decode_unverified(token: &str) -> Result<(Value, Value)> {
        let mut parts = token.split('.');
        let (Some(h), Some(c), Some(_), None) =
            (parts.next(), parts.next(), parts.next(), parts.next())
        else {
            return Err(Error::Crypto("not a compact JWS".into()));
        };
        let header = serde_json::from_slice(&b64url_decode(h)?)
            .map_err(|e| Error::Crypto(format!("invalid JWT header: {e}")))?;
        let claims = serde_json::from_slice(&b64url_decode(c)?)
            .map_err(|e| Error::Crypto(format!("invalid JWT claims: {e}")))?;
        Ok((header, claims))
    }

    /// Verifies the signature (rejecting `alg: none` and algorithm/key mismatches) and returns
    /// header and claims. Claims (exp, aud, …) are not validated.
    pub fn verify(token: &str, key: &VerifyingKey) -> Result<(Value, Value)> {
        let (header, claims) = decode_unverified(token)?;
        let alg = header.get("alg").and_then(Value::as_str).unwrap_or("none");
        if alg != key.algorithm().jws_alg() {
            return Err(Error::Crypto(format!(
                "JWT alg {alg} does not match the key"
            )));
        }
        let (input, sig) = token
            .rsplit_once('.')
            .ok_or_else(|| Error::Crypto("not a compact JWS".into()))?;
        if !key.verify(input.as_bytes(), &b64url_decode(sig)?) {
            return Err(Error::Crypto("JWT signature is invalid".into()));
        }
        Ok((header, claims))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base58_round_trip() {
        for data in [&b""[..], b"\0\0abc", b"hello world", &[0xff; 40]] {
            assert_eq!(base58btc_decode(&base58btc_encode(data)).unwrap(), data);
        }
        assert_eq!(base58btc_encode(b"hello world"), "StV1DL6CwTryKyV");
    }

    #[test]
    fn generated_keys_sign_and_verify() {
        for alg in [KeyAlgorithm::P256, KeyAlgorithm::Ed25519] {
            let key = SigningKey::generate(alg).unwrap();
            let sig = key.sign(b"msg");
            assert_eq!(sig.len(), 64);
            assert!(key.verifying_key().verify(b"msg", &sig));
            assert!(!key.verifying_key().verify(b"other", &sig));
            let jwk = key.to_jwk();
            let again = SigningKey::from_jwk(&jwk).unwrap();
            assert_eq!(again.verifying_key(), key.verifying_key());
            let did = key.did_key();
            assert_eq!(
                VerifyingKey::from_did_key(&did.kid).unwrap(),
                key.verifying_key()
            );
            let token = jwt::sign(&Map::new(), &json!({"sub": did.did}), &key).unwrap();
            jwt::verify(&token, &key.verifying_key()).unwrap();
        }
    }
}
