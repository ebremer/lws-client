// SPDX-License-Identifier: MIT
import Crypto
import Foundation

/// A public key that verifies signatures: ECDSA on P-256 (`ES256`) or P-384 (`ES384`), or Ed25519 (`EdDSA`).
/// ECDSA signatures are the raw `r‖s` concatenation (JOSE and RFC 9421), never DER.
public struct VerificationKey: Sendable, Hashable, CustomStringConvertible {
    enum Key: @unchecked Sendable {
        case p256(P256.Signing.PublicKey)
        case p384(P384.Signing.PublicKey)
        case ed25519(Curve25519.Signing.PublicKey)
    }

    let key: Key

    init(_ key: Key) {
        self.key = key
    }

    /// The JOSE algorithm: `ES256`, `ES384` or `EdDSA`.
    public var algorithm: String {
        switch key {
        case .p256: return "ES256"
        case .p384: return "ES384"
        case .ed25519: return "EdDSA"
        }
    }

    /// The JWK key type: `EC` or `OKP`.
    public var keyType: String {
        if case .ed25519 = key { return "OKP" }
        return "EC"
    }

    /// The JWK curve: `P-256`, `P-384` or `Ed25519`.
    public var curve: String {
        switch key {
        case .p256: return "P-256"
        case .p384: return "P-384"
        case .ed25519: return "Ed25519"
        }
    }

    /// The raw public key: the 32-byte Ed25519 key, or the uncompressed EC point (`04‖x‖y`).
    public var rawRepresentation: Data {
        switch key {
        case .p256(let k): return k.x963Representation
        case .p384(let k): return k.x963Representation
        case .ed25519(let k): return k.rawRepresentation
        }
    }

    /// Verifies a signature over `data` (raw `r‖s` for ECDSA).
    public func verify(_ signature: Data, for data: Data) -> Bool {
        switch key {
        case .p256(let k):
            guard let s = try? P256.Signing.ECDSASignature(rawRepresentation: signature) else { return false }
            return k.isValidSignature(s, for: data)
        case .p384(let k):
            guard let s = try? P384.Signing.ECDSASignature(rawRepresentation: signature) else { return false }
            return k.isValidSignature(s, for: data)
        case .ed25519(let k):
            return signature.count == 64 && k.isValidSignature(signature, for: data)
        }
    }

    /// The public JWK.
    public var jwk: JSONObject {
        switch key {
        case .p256(let k): return Self.ecJWK("P-256", k.x963Representation)
        case .p384(let k): return Self.ecJWK("P-384", k.x963Representation)
        case .ed25519(let k): return ["kty": "OKP", "crv": "Ed25519", "x": .string(Base64URL.encode(k.rawRepresentation))]
        }
    }

    private static func ecJWK(_ crv: String, _ x963: Data) -> JSONObject {
        let size = (x963.count - 1) / 2
        let point = x963.dropFirst()
        return ["kty": "EC", "crv": .string(crv), "x": .string(Base64URL.encode(Data(point.prefix(size)))),
                "y": .string(Base64URL.encode(Data(point.suffix(size))))]
    }

    /// Imports a public JWK (`EC` P-256 / P-384, `OKP` Ed25519); private members are ignored.
    /// - Throws: ``LWSError/invalidArgument(_:)`` when the JWK is malformed or of an unsupported type.
    public init(jwk: JSONObject) throws {
        guard let kty = jwk.string("kty") else { throw LWSError.invalidArgument("JWK member 'kty' is missing") }
        guard let crv = jwk.string("crv") else { throw LWSError.invalidArgument("JWK member 'crv' is missing") }
        switch (kty, crv) {
        case ("EC", "P-256"):
            let x963 = Data([4]) + (try JWKs.member(jwk, "x", 32)) + (try JWKs.member(jwk, "y", 32))
            do { key = .p256(try P256.Signing.PublicKey(x963Representation: x963)) } catch {
                throw LWSError.invalidArgument("Invalid P-256 public key: \(error)")
            }
        case ("EC", "P-384"):
            let x963 = Data([4]) + (try JWKs.member(jwk, "x", 48)) + (try JWKs.member(jwk, "y", 48))
            do { key = .p384(try P384.Signing.PublicKey(x963Representation: x963)) } catch {
                throw LWSError.invalidArgument("Invalid P-384 public key: \(error)")
            }
        case ("EC", _):
            throw LWSError.invalidArgument("Unsupported EC curve: \(crv)")
        case ("OKP", "Ed25519"):
            do { key = .ed25519(try Curve25519.Signing.PublicKey(rawRepresentation: try JWKs.member(jwk, "x", 32))) } catch let e as LWSError {
                throw e
            } catch {
                throw LWSError.invalidArgument("Invalid Ed25519 public key: \(error)")
            }
        case ("OKP", _):
            throw LWSError.invalidArgument("Unsupported OKP curve: \(crv)")
        default:
            throw LWSError.invalidArgument("Unsupported JWK kty: \(kty)")
        }
    }

    public static func == (lhs: VerificationKey, rhs: VerificationKey) -> Bool {
        lhs.curve == rhs.curve && lhs.rawRepresentation == rhs.rawRepresentation
    }

    public func hash(into hasher: inout Hasher) {
        hasher.combine(curve)
        hasher.combine(rawRepresentation)
    }

    public var description: String { "\(algorithm) public key" }
}

/// A private key that signs JWT credentials: ECDSA P-256 (`ES256`) or P-384 (`ES384`), or Ed25519 (`EdDSA`).
/// Generate one with ``generateP256()`` / ``generateEd25519()``, or import a JWK.
public struct SigningKey: Sendable, CustomStringConvertible {
    enum Key: @unchecked Sendable {
        case p256(P256.Signing.PrivateKey)
        case p384(P384.Signing.PrivateKey)
        case ed25519(Curve25519.Signing.PrivateKey)
    }

    let key: Key

    private init(_ key: Key) {
        self.key = key
    }

    /// Generates a P-256 key (`ES256`).
    public static func generateP256() -> SigningKey { SigningKey(.p256(P256.Signing.PrivateKey())) }

    /// Generates an Ed25519 key (`EdDSA`).
    public static func generateEd25519() -> SigningKey { SigningKey(.ed25519(Curve25519.Signing.PrivateKey())) }

    /// Generates a key for a JOSE algorithm: `ES256`, `ES384` or `EdDSA`.
    /// - Throws: ``LWSError/invalidArgument(_:)`` for another algorithm.
    public static func generate(algorithm: String) throws -> SigningKey {
        switch algorithm {
        case "ES256": return generateP256()
        case "ES384": return SigningKey(.p384(P384.Signing.PrivateKey()))
        case "EdDSA", "Ed25519": return generateEd25519()
        default: throw LWSError.invalidArgument("Unsupported algorithm: \(algorithm)")
        }
    }

    /// Wraps a swift-crypto (CryptoKit) P-256 key.
    public init(_ key: P256.Signing.PrivateKey) { self.init(.p256(key)) }

    /// Wraps a swift-crypto (CryptoKit) P-384 key.
    public init(_ key: P384.Signing.PrivateKey) { self.init(.p384(key)) }

    /// Wraps a swift-crypto (CryptoKit) Ed25519 key.
    public init(_ key: Curve25519.Signing.PrivateKey) { self.init(.ed25519(key)) }

    /// The JOSE algorithm: `ES256`, `ES384` or `EdDSA`.
    public var algorithm: String { publicKey.algorithm }

    /// The matching public key.
    public var publicKey: VerificationKey {
        switch key {
        case .p256(let k): return VerificationKey(.p256(k.publicKey))
        case .p384(let k): return VerificationKey(.p384(k.publicKey))
        case .ed25519(let k): return VerificationKey(.ed25519(k.publicKey))
        }
    }

    /// Signs `data` (ECDSA signatures are raw `r‖s`).
    public func sign(_ data: Data) throws -> Data {
        switch key {
        case .p256(let k): return try k.signature(for: data).rawRepresentation
        case .p384(let k): return try k.signature(for: data).rawRepresentation
        case .ed25519(let k): return try k.signature(for: data)
        }
    }

    /// The private JWK, including `d`. Keep it secret.
    public var jwk: JSONObject {
        var j = publicKey.jwk
        switch key {
        case .p256(let k): j["d"] = .string(Base64URL.encode(k.rawRepresentation))
        case .p384(let k): j["d"] = .string(Base64URL.encode(k.rawRepresentation))
        case .ed25519(let k): j["d"] = .string(Base64URL.encode(k.rawRepresentation))
        }
        return j
    }

    /// Imports a private JWK (`EC` P-256 / P-384 or `OKP` Ed25519, with `d`). Its public members, when present,
    /// must match the private key.
    /// - Throws: ``LWSError/invalidArgument(_:)`` when the JWK is malformed, public only, or of an unsupported type.
    public init(jwk: JSONObject) throws {
        guard jwk.string("d") != nil else { throw LWSError.invalidArgument("The JWK has no private key member 'd'") }
        guard let kty = jwk.string("kty") else { throw LWSError.invalidArgument("JWK member 'kty' is missing") }
        guard let crv = jwk.string("crv") else { throw LWSError.invalidArgument("JWK member 'crv' is missing") }
        let key: Key
        do {
            switch (kty, crv) {
            case ("EC", "P-256"): key = .p256(try P256.Signing.PrivateKey(rawRepresentation: try JWKs.member(jwk, "d", 32)))
            case ("EC", "P-384"): key = .p384(try P384.Signing.PrivateKey(rawRepresentation: try JWKs.member(jwk, "d", 48)))
            case ("EC", _): throw LWSError.invalidArgument("Unsupported EC curve for signing: \(crv)")
            case ("OKP", "Ed25519"): key = .ed25519(try Curve25519.Signing.PrivateKey(rawRepresentation: try JWKs.member(jwk, "d", 32)))
            case ("OKP", _): throw LWSError.invalidArgument("Unsupported OKP curve: \(crv)")
            default: throw LWSError.invalidArgument("Unsupported private JWK kty: \(kty)")
            }
        } catch let e as LWSError {
            throw e
        } catch {
            throw LWSError.invalidArgument("Invalid \(crv) private key: \(error)")
        }
        self.init(key)
        let pub = publicKey.jwk
        for m in ["x", "y"] where jwk.string(m) != nil {
            guard let given = Base64URL.decode(jwk.string(m)!), let actual = pub.string(m).flatMap(Base64URL.decode),
                  JWKs.unpad(given) == JWKs.unpad(actual)
            else { throw LWSError.invalidArgument("The JWK's '\(m)' does not match its 'd'") }
        }
    }

    public var description: String { "\(algorithm) private key" }
}

/// JSON Web Key (RFC 7517) helpers (internal).
enum JWKs {
    /// A base64url member decoded to exactly `size` bytes (left-padded with zeros when shorter).
    static func member(_ jwk: JSONObject, _ name: String, _ size: Int) throws -> Data {
        guard let v = jwk.string(name) else { throw LWSError.invalidArgument("JWK member '\(name)' is missing") }
        guard let bytes = Base64URL.decode(v) else { throw LWSError.invalidArgument("JWK member '\(name)' is not base64url") }
        if bytes.count == size { return bytes }
        guard bytes.count < size, !bytes.isEmpty else { throw LWSError.invalidArgument("JWK member '\(name)' has the wrong length") }
        return Data(repeating: 0, count: size - bytes.count) + bytes
    }

    static func unpad(_ d: Data) -> Data {
        Data(d.drop { $0 == 0 })
    }
}
