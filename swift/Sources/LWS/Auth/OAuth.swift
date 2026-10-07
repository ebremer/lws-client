// SPDX-License-Identifier: MIT
import Foundation

/// Authorization server metadata (RFC 8414), served at `/.well-known/lws-configuration`.
public struct AuthorizationServerMetadata: Sendable {
    /// The issuer identifier, as the server states it.
    public let issuer: String
    /// The token endpoint.
    public let tokenEndpoint: URL
    /// The JWK set URL, if any.
    public let jwksURI: URL?
    /// The supported grant types.
    public let grantTypesSupported: [String]
    /// The supported `subject_token_type` values (empty when not advertised).
    public let subjectTokenTypesSupported: [String]
    /// The supported subject identifier types (`["https"]` when not advertised).
    public let subjectIdentifierTypesSupported: [String]
    /// The JSON document.
    public let raw: JSONObject

    /// Whether the server accepts subject tokens of `tokenType` (true when it advertises none).
    public func supportsSubjectTokenType(_ tokenType: String) -> Bool {
        subjectTokenTypesSupported.isEmpty || subjectTokenTypesSupported.contains(tokenType)
    }

    /// Parses a metadata document retrieved from `base`.
    /// - Throws: ``LWSError/protocolError(_:)`` when it lacks `issuer` or `token_endpoint`.
    public static func parse(_ json: JSONValue, base: URL?) throws -> AuthorizationServerMetadata {
        let o = try LWSJSON.object(json, "Authorization server metadata")
        guard let issuer = o.string("issuer") else { throw LWSError.protocolError("Authorization server metadata has no issuer") }
        guard let token = o.url("token_endpoint", base: base) else {
            throw LWSError.protocolError("Authorization server metadata has no token_endpoint")
        }
        let idTypes = o.strings("subject_identifier_types_supported")
        return AuthorizationServerMetadata(issuer: issuer, tokenEndpoint: token, jwksURI: o.url("jwks_uri", base: base),
                                           grantTypesSupported: o.strings("grant_types_supported"),
                                           subjectTokenTypesSupported: o.strings("subject_token_types_supported"),
                                           subjectIdentifierTypesSupported: idTypes.isEmpty ? ["https"] : idTypes, raw: o)
    }

    /// The metadata URL of an issuer (RFC 8414 section 3.1): `https://as.example` →
    /// `https://as.example/.well-known/lws-configuration`; `https://as.example/t1` →
    /// `https://as.example/.well-known/lws-configuration/t1`.
    public static func metadataURL(issuer: URL) -> URL {
        var path = issuer.path(percentEncoded: true)
        if path.hasSuffix("/") { path.removeLast() }
        var c = URLComponents(url: issuer, resolvingAgainstBaseURL: true) ?? URLComponents()
        c.percentEncodedPath = Vocabulary.wellKnownLWSConfiguration + path
        c.percentEncodedQuery = nil
        c.fragment = nil
        return c.url ?? issuer
    }
}

/// An access token issued by an authorization server.
public struct AccessToken: Sendable, CustomStringConvertible {
    /// The lifetime assumed when neither `expires_in` nor a JWT `exp` is available, in seconds.
    public static let defaultLifetime: TimeInterval = 300

    /// The token.
    public let value: String
    /// The token type (`Bearer`).
    public let tokenType: String
    /// When it expires.
    public let expiresAt: Date
    /// The granted scope, if any.
    public let scope: String?

    public init(value: String, tokenType: String, expiresAt: Date, scope: String? = nil) {
        self.value = value
        self.tokenType = tokenType
        self.expiresAt = expiresAt
        self.scope = scope
    }

    /// Parses a token endpoint success response (RFC 6749 section 5.1). The expiry is `expires_in`, else the token's
    /// JWT `exp` claim, else ``defaultLifetime``.
    /// - Throws: ``LWSError/authentication(_:)`` without a token, or with a token type other than Bearer.
    public static func fromTokenResponse(_ json: JSONObject, now: Date) throws -> AccessToken {
        guard let token = json.string("access_token"), !token.isEmpty else {
            throw LWSError.authFailure("The token response has no access_token")
        }
        let type = json.string("token_type")
        guard type?.lowercased() == "bearer" else { throw LWSError.authFailure("Unsupported token_type: \(type ?? "none")") }
        let expires: Date
        if let seconds = json["expires_in"]?.doubleValue {
            expires = now.addingTimeInterval(seconds)
        } else {
            expires = JWT.expiration(token) ?? now.addingTimeInterval(defaultLifetime)
        }
        return AccessToken(value: token, tokenType: "Bearer", expiresAt: expires, scope: json.string("scope"))
    }

    /// Whether the token is still usable at `now`, keeping `margin` seconds in reserve.
    public func isValid(at now: Date, margin: TimeInterval) -> Bool {
        now.addingTimeInterval(margin) < expiresAt
    }

    public var description: String { "AccessToken(\(tokenType), expires \(Dates.formatRFC3339(expiresAt)))" }
}
