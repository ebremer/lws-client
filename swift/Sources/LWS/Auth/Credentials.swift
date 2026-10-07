// SPDX-License-Identifier: MIT
import Foundation

/// Where a subject token will be presented.
public struct CredentialContext: Sendable {
    /// The authorization server (`as_uri`).
    public let issuer: URL
    /// The protection realm the access token is requested for.
    public let realm: URL
    /// The authorization server metadata; its ``AuthorizationServerMetadata/issuer`` is the audience of
    /// self-signed tokens.
    public let metadata: AuthorizationServerMetadata
}

/// Supplies the subject token (an LWS authentication credential) presented to an authorization server in the
/// OAuth 2.0 token exchange. One implementation per LWS authentication suite: ``OpenIDCredentials``,
/// ``SAMLCredentials``, ``SelfSignedCredentials``.
public protocol CredentialProvider: Sendable {
    /// The `subject_token_type` URI (see ``TokenType``).
    var tokenType: String { get }

    /// Returns a subject token for the given authorization server.
    func subjectToken(for context: CredentialContext) async throws -> String
}

/// OpenID Connect authentication suite (`lws10-authn-openid`): presents an OpenID Connect ID token
/// (`urn:ietf:params:oauth:token-type:id_token`). Interactive login is up to the application (use your OIDC
/// library); this provider hands the resulting ID token to the authorization server.
///
/// Prefer ID tokens whose `aud` includes the authorization server, or pick one per authorization server with the
/// supplier.
public struct OpenIDCredentials: CredentialProvider {
    private let tokens: @Sendable (CredentialContext) async throws -> String

    /// A fixed ID token.
    public init(idToken: String) {
        tokens = { _ in idToken }
    }

    /// ID tokens chosen per authorization server (asked whenever a new access token is needed).
    public init(idTokens: @escaping @Sendable (CredentialContext) async throws -> String) {
        tokens = idTokens
    }

    public var tokenType: String { TokenType.idToken }

    public func subjectToken(for context: CredentialContext) async throws -> String {
        try await tokens(context)
    }
}

/// SAML 2.0 authentication suite (`lws10-authn-saml`): presents a signed SAML 2.0 assertion
/// (`urn:ietf:params:oauth:token-type:saml2`). Per RFC 8693 the subject token is the base64url-encoded assertion;
/// ``fromXML(_:)`` does the encoding.
public struct SAMLCredentials: CredentialProvider {
    private let assertions: @Sendable (CredentialContext) async throws -> String

    /// Base64url-encoded assertions chosen per authorization server.
    public init(encodedAssertions: @escaping @Sendable (CredentialContext) async throws -> String) {
        assertions = encodedAssertions
    }

    /// A fixed, already base64url-encoded assertion.
    public static func fromEncoded(_ encodedAssertion: String) -> SAMLCredentials {
        SAMLCredentials { _ in encodedAssertion }
    }

    /// A fixed assertion given as XML; it is base64url-encoded for the token exchange.
    public static func fromXML(_ assertionXML: String) -> SAMLCredentials {
        fromEncoded(encode(assertionXML))
    }

    /// Base64url-encodes (without padding) an assertion XML document.
    public static func encode(_ assertionXML: String) -> String {
        Base64URL.encode(assertionXML)
    }

    public var tokenType: String { TokenType.saml2 }

    public func subjectToken(for context: CredentialContext) async throws -> String {
        try await assertions(context)
    }
}

/// Self-signed identity authentication suite (`lws10-authn-ssi-cid`, including `did:key` subjects): the agent
/// signs its own JWT credential (`urn:ietf:params:oauth:token-type:jwt`) with `sub = iss = client_id = agent`,
/// `aud = [authorization server]`, `iat`, `exp` and a random `jti`. Supports `ES256` (P-256) and `EdDSA`
/// (Ed25519). Tokens are cached per audience until 60 seconds before they expire.
///
/// ```swift
/// let credentials = try SelfSignedCredentials.didKey(.generateP256())   // agent = did:key:zDn…
/// ```
public actor SelfSignedCredentials: CredentialProvider {
    private static let reuseMargin: TimeInterval = 60

    private let key: SigningKey
    private var cache: [String: (token: String, expires: Date)] = [:]

    /// The agent identifier (`sub`, `iss` and `client_id`).
    public nonisolated let agent: String
    /// The key id placed in the JWT header, or nil.
    public nonisolated let keyID: String?
    /// How long minted tokens live, in seconds (default 300).
    public nonisolated let lifetime: TimeInterval
    /// The clock.
    public nonisolated let now: @Sendable () -> Date

    private init(agent: String, key: SigningKey, keyID: String?, lifetime: TimeInterval, now: @escaping @Sendable () -> Date) {
        self.agent = agent
        self.key = key
        self.keyID = keyID
        self.lifetime = lifetime
        self.now = now
    }

    /// Credentials for an agent whose controlled identifier document (at `agent`) lists the key under
    /// `authentication`; `keyID` identifies that verification method.
    public static func forAgent(_ agent: String, key: SigningKey, keyID: String?) -> SelfSignedCredentials {
        SelfSignedCredentials(agent: agent, key: key, keyID: keyID, lifetime: 300, now: { Date() })
    }

    /// Credentials for an agent with a URL identifier.
    public static func forAgent(_ agent: URL, key: SigningKey, keyID: String?) -> SelfSignedCredentials {
        forAgent(agent.absoluteString, key: key, keyID: keyID)
    }

    /// Credentials for a `did:key` agent derived from a P-256 or Ed25519 key.
    /// - Throws: ``LWSError/invalidArgument(_:)`` for a P-384 key.
    public static func didKey(_ key: SigningKey) throws -> SelfSignedCredentials {
        SelfSignedCredentials(agent: try DIDKey.did(for: key.publicKey), key: key, keyID: try DIDKey.keyID(for: key.publicKey),
                              lifetime: 300, now: { Date() })
    }

    /// The JOSE algorithm (`ES256`, `EdDSA`).
    public nonisolated var algorithm: String { key.algorithm }

    /// The public key.
    public nonisolated var publicKey: VerificationKey { key.publicKey }

    public nonisolated var tokenType: String { TokenType.jwt }

    /// A copy whose tokens live for `lifetime` seconds.
    public nonisolated func withLifetime(_ lifetime: TimeInterval) -> SelfSignedCredentials {
        SelfSignedCredentials(agent: agent, key: key, keyID: keyID, lifetime: lifetime, now: now)
    }

    /// A copy using another clock (for tests).
    public nonisolated func withClock(_ now: @escaping @Sendable () -> Date) -> SelfSignedCredentials {
        SelfSignedCredentials(agent: agent, key: key, keyID: keyID, lifetime: lifetime, now: now)
    }

    public func subjectToken(for context: CredentialContext) async throws -> String {
        let audience = context.metadata.issuer
        let t = now()
        if let c = cache[audience], t.addingTimeInterval(Self.reuseMargin) < c.expires { return c.token }
        let token = try createToken(audience: audience)
        cache[audience] = (token, t.addingTimeInterval(lifetime))
        return token
    }

    /// Creates and signs a new credential for `audience`.
    public nonisolated func createToken(audience: String) throws -> String {
        let iat = Int64(now().timeIntervalSince1970.rounded(.down))
        var header: JSONObject = ["alg": .string(key.algorithm), "typ": "JWT"]
        if let keyID { header["kid"] = .string(keyID) }
        let claims: JSONObject = [
            "sub": .string(agent),
            "iss": .string(agent),
            "client_id": .string(agent),
            "aud": .array([.string(audience)]),
            "iat": .int(iat),
            "exp": .int(iat + Int64(lifetime)),
            "jti": .string(UUID().uuidString.lowercased()),
        ]
        return try JWT.sign(header: header, claims: claims, key: key)
    }
}
