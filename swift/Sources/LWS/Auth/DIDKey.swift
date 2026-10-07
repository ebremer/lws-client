// SPDX-License-Identifier: MIT
import Crypto
import Foundation

/// `did:key` identifiers for P-256 and Ed25519 public keys: `did:key:` + multibase base58btc (`z`) of the
/// multicodec varint prefix and the public key (P-256 as a 33-byte compressed point). P-256 identifiers start
/// with `zDn`, Ed25519 identifiers with `z6Mk`.
public enum DIDKey {
    private static let prefix = "did:key:"
    private static let p256Prefix: [UInt8] = [0x80, 0x24]
    private static let ed25519Prefix: [UInt8] = [0xED, 0x01]

    /// The `did:key` identifier of a P-256 or Ed25519 public key.
    /// - Throws: ``LWSError/invalidArgument(_:)`` for another key type.
    public static func did(for key: VerificationKey) throws -> String {
        prefix + (try multibase(key))
    }

    /// The `did:key` identifier of a public JWK.
    public static func did(forJWK jwk: JSONObject) throws -> String {
        try did(for: VerificationKey(jwk: jwk))
    }

    /// The verification method id (`did:key:z…#z…`) of a key, used as the JWT `kid`.
    public static func keyID(for key: VerificationKey) throws -> String {
        let mb = try multibase(key)
        return prefix + mb + "#" + mb
    }

    /// The verification method id of an existing `did:key` identifier (a fragment is ignored).
    public static func keyID(forDID did: String) throws -> String {
        let mb = try multibase(of: did)
        return prefix + mb + "#" + mb
    }

    /// Decodes a `did:key` (or its key id) into the public key.
    /// - Throws: ``LWSError/invalidArgument(_:)`` when it is not a supported did:key.
    public static func publicKey(_ did: String) throws -> VerificationKey {
        let mb = try multibase(of: did)
        guard mb.hasPrefix("z"), let bytes = Base58.decode(String(mb.dropFirst())) else {
            throw LWSError.invalidArgument("Not a base58btc did:key: \(did)")
        }
        if bytes.starts(with: ed25519Prefix), bytes.count == 34,
           let k = try? Curve25519.Signing.PublicKey(rawRepresentation: bytes.dropFirst(2))
        {
            return VerificationKey(.ed25519(k))
        }
        if bytes.starts(with: p256Prefix), bytes.count == 35, bytes[2] == 2 || bytes[2] == 3 {
            guard let k = try? P256.Signing.PublicKey(compressedRepresentation: bytes.dropFirst(2)) else {
                throw LWSError.invalidArgument("Invalid P-256 point in did:key")
            }
            return VerificationKey(.p256(k))
        }
        throw LWSError.invalidArgument("Unsupported did:key key type: \(did)")
    }

    private static func multibase(of did: String) throws -> String {
        guard did.hasPrefix(prefix) else { throw LWSError.invalidArgument("Not a did:key: \(did)") }
        return String(did.dropFirst(prefix.count).prefix { $0 != "#" })
    }

    private static func multibase(_ key: VerificationKey) throws -> String {
        let data: [UInt8]
        switch key.key {
        case .p256(let k): data = p256Prefix + Array(k.compressedRepresentation)
        case .ed25519(let k): data = ed25519Prefix + Array(k.rawRepresentation)
        case .p384: throw LWSError.invalidArgument("did:key supports P-256 and Ed25519 keys, not P-384")
        }
        return "z" + Base58.encode(data)
    }
}

/// Base58 with the Bitcoin alphabet (multibase `z`) (internal).
enum Base58 {
    private static let alphabet = Array("123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz".utf8)

    static func encode(_ data: [UInt8]) -> String {
        let zeros = data.prefix { $0 == 0 }.count
        var digits: [UInt8] = []  // base-58 digits, least significant first
        for byte in data.dropFirst(zeros) {
            var carry = Int(byte)
            for i in digits.indices {
                carry += Int(digits[i]) << 8
                digits[i] = UInt8(carry % 58)
                carry /= 58
            }
            while carry > 0 {
                digits.append(UInt8(carry % 58))
                carry /= 58
            }
        }
        return String(repeating: "1", count: zeros) + String(decoding: digits.reversed().map { alphabet[Int($0)] }, as: UTF8.self)
    }

    static func decode(_ s: String) -> [UInt8]? {
        let chars = Array(s.utf8)
        let zeros = chars.prefix { $0 == UInt8(ascii: "1") }.count
        var bytes: [UInt8] = []  // least significant first
        for c in chars.dropFirst(zeros) {
            guard let d = alphabet.firstIndex(of: c) else { return nil }
            var carry = d
            for i in bytes.indices {
                carry += Int(bytes[i]) * 58
                bytes[i] = UInt8(carry & 0xFF)
                carry >>= 8
            }
            while carry > 0 {
                bytes.append(UInt8(carry & 0xFF))
                carry >>= 8
            }
        }
        return [UInt8](repeating: 0, count: zeros) + bytes.reversed()
    }
}

/// Builds the W3C Controlled Identifier (CID) document an agent publishes at its identifier URL, so that
/// authorization servers can validate its self-signed credentials (`lws10-authn-ssi-cid`).
public enum ControlledIdentifierDocument {
    /// A CID document with one `JsonWebKey` verification method in the `authentication` relationship. The method
    /// id is `agent#kid`, or `kid` itself when it already is a URI.
    public static func create(agent: String, key: VerificationKey, kid: String) -> JSONObject {
        create(agent: agent, publicJWK: key.jwk, kid: kid)
    }

    /// Like ``create(agent:key:kid:)`` for a public JWK (a `d` member is dropped).
    public static func create(agent: String, publicJWK: JSONObject, kid: String) -> JSONObject {
        var jwk = publicJWK
        jwk["d"] = nil
        jwk["kid"] = .string(kid)
        if !jwk.contains("alg") {
            let kty = publicJWK.string("kty") ?? ""
            let crv = publicJWK.string("crv") ?? ""
            jwk["alg"] = .string(kty == "OKP" ? "EdDSA" : crv == "P-384" ? "ES384" : "ES256")
        }
        let methodID = kid.contains(":") ? kid : agent + "#" + kid
        return [
            "@context": .array([.string(Vocabulary.cidContext)]),
            "id": .string(agent),
            "authentication": .array([.object([
                "id": .string(methodID),
                "type": "JsonWebKey",
                "controller": .string(agent),
                "publicKeyJwk": .object(jwk),
            ])]),
        ]
    }

    /// Like ``create(agent:key:kid:)`` for a URL agent.
    public static func create(agent: URL, key: VerificationKey, kid: String) -> JSONObject {
        create(agent: agent.absoluteString, key: key, kid: kid)
    }
}
