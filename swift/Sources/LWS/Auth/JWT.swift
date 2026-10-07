// SPDX-License-Identifier: MIT
import Foundation

/// Compact JSON Web Signature helpers for JWT credentials (`ES256`, `ES384`, `EdDSA`).
public enum JWT {
    /// Signs `claims`; the header's `alg` is set from the key.
    public static func sign(header: JSONObject, claims: JSONObject, key: SigningKey) throws -> String {
        var h = header
        h["alg"] = .string(key.algorithm)
        let input = Base64URL.encode(JSONValue.object(h).serializedData()) + "." + Base64URL.encode(JSONValue.object(claims).serializedData())
        return input + "." + Base64URL.encode(try key.sign(Data(input.utf8)))
    }

    /// Verifies the signature of a compact JWS with `key`. The header `alg` must be the key's algorithm (never
    /// `none`).
    public static func verify(_ jwt: String, key: VerificationKey) -> Bool {
        let parts = jwt.split(separator: ".", omittingEmptySubsequences: false)
        guard parts.count == 3, let header = try? decodeHeader(jwt), header.string("alg") == key.algorithm,
              let signature = Base64URL.decode(String(parts[2]))
        else { return false }
        return key.verify(signature, for: Data((parts[0] + "." + parts[1]).utf8))
    }

    /// Decodes the header without verifying.
    /// - Throws: ``LWSError/invalidArgument(_:)`` when the value is not a JWT.
    public static func decodeHeader(_ jwt: String) throws -> JSONObject { try part(jwt, 0) }

    /// Decodes the claims without verifying.
    /// - Throws: ``LWSError/invalidArgument(_:)`` when the value is not a JWT.
    public static func decodeClaims(_ jwt: String) throws -> JSONObject { try part(jwt, 1) }

    /// The `exp` claim of a JWT, or nil when the token is not a JWT or has none.
    public static func expiration(_ token: String) -> Date? {
        guard let exp = (try? decodeClaims(token))?.integer("exp") else { return nil }
        return Date(timeIntervalSince1970: TimeInterval(exp))
    }

    private static func part(_ jwt: String, _ index: Int) throws -> JSONObject {
        let parts = jwt.split(separator: ".", omittingEmptySubsequences: false)
        guard parts.count >= 2 else { throw LWSError.invalidArgument("Not a JWT") }
        guard let bytes = Base64URL.decode(String(parts[index])) else { throw LWSError.invalidArgument("Not a JWT: invalid base64url") }
        guard case .object(let o)? = try? JSONValue(parsing: bytes) else { throw LWSError.invalidArgument("Not a JWT: a part is not a JSON object") }
        return o
    }
}
