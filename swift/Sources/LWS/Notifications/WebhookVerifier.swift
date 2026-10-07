// SPDX-License-Identifier: MIT
import Crypto
import Foundation

/// Options of ``WebhookVerifier``.
public struct WebhookVerifierOptions: Sendable {
    /// The client that retrieves storage descriptions (the signing keys). Default: a new anonymous client.
    public var client: LWSClient?
    /// A custom storage description source; overrides ``client``.
    public var storageDescriptionResolver: (@Sendable (URL) async throws -> StorageDescription)?
    /// Only accept deliveries signed by these storages (compared as URLs). When set, even to an empty list, the
    /// signing storage must be in it.
    public var trustedStorages: [URL]?
    /// The maximum age of a signature's `created` time, in seconds (default 300).
    public var maxAge: TimeInterval
    /// The tolerated clock skew for `created` times in the future, in seconds (default 300).
    public var clockSkew: TimeInterval
    /// How long storage descriptions (keys) are cached, in seconds (default 600).
    public var keyCacheTTL: TimeInterval
    /// The clock.
    public var now: @Sendable () -> Date

    public init(client: LWSClient? = nil, storageDescriptionResolver: (@Sendable (URL) async throws -> StorageDescription)? = nil,
                trustedStorages: [URL]? = nil, maxAge: TimeInterval = 300, clockSkew: TimeInterval = 300, keyCacheTTL: TimeInterval = 600,
                now: @escaping @Sendable () -> Date = { Date() })
    {
        self.client = client
        self.storageDescriptionResolver = storageDescriptionResolver
        self.trustedStorages = trustedStorages
        self.maxAge = maxAge
        self.clockSkew = clockSkew
        self.keyCacheTTL = keyCacheTTL
        self.now = now
    }
}

/// A webhook delivery whose digest and signature verified.
public struct VerifiedNotification: Sendable {
    /// The parsed notification.
    public let notification: Notification
    /// The `keyid` of the signing key.
    public let keyID: String
    /// The storage that signed the delivery.
    public let storage: URL
    /// The signature label used (e.g. `sig1`).
    public let label: String
    /// The RFC 9421 algorithm (e.g. `ecdsa-p256-sha256`).
    public let algorithm: String
}

/// Verifies signed webhook deliveries (`lws10-notifications-webhook`): RFC 9530 `Content-Digest` and RFC 9421 HTTP
/// Message Signatures, whose key is published in the signing storage's description (found through the signature
/// `keyid`).
///
/// ```swift
/// let verifier = WebhookVerifier(options: .init(client: client, trustedStorages: [storage.id]))
/// let verified = try await verifier.verify(method: "POST", url: registeredInboxURL, headers: headers, body: body)
/// ```
///
/// The URL must be the inbox URL as registered in the subscription (not the URL a reverse proxy forwarded to),
/// because `@scheme`, `@authority` and `@path` are signed.
public actor WebhookVerifier {
    /// The components every LWS webhook signature must cover.
    public static let requiredComponents = ["@method", "@scheme", "@authority", "@path", "content-type", "content-digest"]

    private let options: WebhookVerifierOptions
    private let descriptions: @Sendable (URL) async throws -> StorageDescription
    private let trusted: Set<String>?
    private var cache: [String: (description: StorageDescription, fetched: Date)] = [:]

    /// Creates a verifier.
    public init(options: WebhookVerifierOptions = WebhookVerifierOptions()) {
        self.options = options
        if let resolver = options.storageDescriptionResolver {
            descriptions = resolver
        } else {
            let client = options.client ?? LWSClient()
            descriptions = { try await client.getStorageDescription($0) }
        }
        trusted = options.trustedStorages.map { Set($0.map(URLs.canonical)) }
    }

    /// Verifies a delivery: the request method (`POST`), the inbox URL as registered, every request header field
    /// line, and the raw body.
    /// - Throws: ``LWSError/signatureVerification(_:)`` when anything does not verify.
    public func verify(method: String, url inboxURL: URL, headers: HTTPHeaders, body: Data) async throws -> VerifiedNotification {
        guard inboxURL.scheme != nil, inboxURL.host != nil else { throw LWSError.invalidArgument("The inbox URL must be absolute") }

        try Self.checkDigest(try Self.field(headers, "content-digest"), body)

        let inputs = try Self.dictionary(try Self.field(headers, "signature-input"), "Signature-Input")
        let signatures = try Self.dictionary(try Self.field(headers, "signature"), "Signature")
        var chosen: (label: String, covered: SFInnerList)?
        for e in inputs {
            if case .innerList(let il) = e.member, case .string? = il.parameters["keyid"], signatures[e.key] != nil {
                chosen = (e.key, il)
                break
            }
        }
        guard let (label, covered) = chosen else { throw Self.fail("No signature with a keyid in Signature-Input and Signature") }
        guard case .item(let sigItem)? = signatures[label], case .byteSequence(let signature) = sigItem.value else {
            throw Self.fail("Signature \(label) is not a byte sequence")
        }

        var components = Set<String>()
        for item in covered.items {
            guard case .string(let name) = item.value else { throw Self.fail("A covered component is not a string") }
            guard item.parameters.isEmpty else { throw Self.fail("Unsupported component parameters on \(name)") }
            guard components.insert(name).inserted else { throw Self.fail("Duplicate covered component \(name)") }
        }
        for r in Self.requiredComponents where !components.contains(r) { throw Self.fail("Required component not covered: \(r)") }
        let parameters = covered.parameters
        guard case .integer(let created)? = parameters["created"] else { throw Self.fail("The signature parameters lack an integer 'created'") }
        let now = Int64(options.now().timeIntervalSince1970.rounded(.down))
        if created < now - Int64(options.maxAge) { throw Self.fail("Signature too old (created \(created))") }
        if created > now + Int64(options.clockSkew) { throw Self.fail("Signature created in the future (created \(created))") }
        if let expires = parameters["expires"] {
            guard case .integer(let exp) = expires, exp >= now else { throw Self.fail("Signature expired") }
        }
        guard case .string(let keyid)? = parameters["keyid"] else { throw Self.fail("The signature has no keyid") }
        let alg = parameters["alg"]?.stringValue

        guard let hash = keyid.firstIndex(of: "#"), hash != keyid.startIndex, keyid.index(after: hash) != keyid.endIndex else {
            throw Self.fail("keyid is not a URL with a fragment: \(keyid)")
        }
        guard let storageID = URLs.resolve(String(keyid[..<hash]), against: nil), URLs.isHTTP(storageID) else {
            throw Self.fail("keyid is not an absolute http(s) URL: \(keyid)")
        }
        if let trusted, !trusted.contains(URLs.canonical(storageID)) { throw Self.fail("Storage \(storageID.absoluteString) is not trusted") }

        let base = try Self.signatureBase(method: method, url: inboxURL, headers: headers, covered: covered)

        let cacheKey = URLs.canonical(storageID)
        var description: StorageDescription
        var fromCache = false
        if let c = cache[cacheKey], c.fetched.addingTimeInterval(options.keyCacheTTL) > options.now() {
            description = c.description
            fromCache = true
        } else {
            description = try await fetch(storageID)
        }
        let algorithm: String
        do {
            algorithm = try Self.verify(description, storageID, keyid, alg, base, signature)
        } catch LWSError.signatureVerification where fromCache {
            // The key may have rotated: fetch the description again, once.
            description = try await fetch(storageID)
            algorithm = try Self.verify(description, storageID, keyid, alg, base, signature)
        }

        let notification: Notification
        do {
            notification = try Notification.parse(body)
        } catch LWSError.protocolError(let m) {
            throw Self.fail("The signed body is not a valid notification: \(m)")
        }
        guard URLs.canonical(notification.storage) == URLs.canonical(storageID) else {
            throw Self.fail("Notification storage \(notification.storage.absoluteString) does not match the signing storage \(storageID.absoluteString)")
        }
        return VerifiedNotification(notification: notification, keyID: keyid, storage: storageID, label: label, algorithm: algorithm)
    }

    /// Builds the RFC 9421 signature base for the covered components (exposed for diagnostics).
    /// - Throws: ``LWSError/signatureVerification(_:)`` when a component is unsupported or missing.
    public static func signatureBase(method: String, url: URL, headers: HTTPHeaders, covered: SFInnerList) throws -> String {
        var s = ""
        for item in covered.items {
            guard case .string(let name) = item.value else { throw fail("A covered component is not a string") }
            s += (try? StructuredFields.serializeBareItem(.string(name))) ?? "\"\(name)\""
            s += ": " + (try componentValue(name, method, url, headers)) + "\n"
        }
        do {
            s += "\"@signature-params\": " + (try StructuredFields.serialize(covered))
        } catch {
            throw fail("The signature parameters cannot be serialized: \(error)")
        }
        return s
    }

    private static func componentValue(_ name: String, _ method: String, _ url: URL, _ headers: HTTPHeaders) throws -> String {
        let path = URLs.path(url)
        switch name {
        case "@method":
            return method.uppercased()
        case "@scheme":
            return (url.scheme ?? "").lowercased()
        case "@authority":
            let host = (url.host(percentEncoded: true) ?? "").lowercased()
            let h = host.contains(":") && !host.hasPrefix("[") ? "[" + host + "]" : host
            guard let port = url.port, port != (url.scheme?.lowercased() == "https" ? 443 : 80) else { return h }
            return h + ":" + String(port)
        case "@path":
            return path
        case "@query":
            let q = URLs.query(url)
            return q.isEmpty ? "?" : q
        case "@target-uri":
            return url.absoluteString
        case "@request-target":
            return path + URLs.query(url)
        default:
            if name.hasPrefix("@") { throw fail("Unsupported derived component \(name)") }
            let values = headers.all(name)
            guard !values.isEmpty else { throw fail("Covered header field missing: \(name)") }
            return values.map { $0.trimmingCharacters(in: .whitespaces) }.joined(separator: ", ")
        }
    }

    private static func verify(_ description: StorageDescription, _ storageID: URL, _ keyid: String, _ alg: String?, _ base: String,
                               _ signature: Data) throws -> String
    {
        guard URLs.canonical(description.id) == URLs.canonical(storageID) else {
            throw fail("Storage description id \(description.id.absoluteString) does not match the keyid storage \(storageID.absoluteString)")
        }
        guard let method = description.verificationMethod(keyid) else { throw fail("Verification method \(keyid) not found in the storage description") }
        guard description.isAuthenticationMethod(method) else { throw fail("Verification method \(keyid) is not referenced from authentication") }
        guard let jwk = method.publicKeyJwk else { throw fail("Verification method \(keyid) has no publicKeyJwk") }
        let key: VerificationKey
        do {
            key = try VerificationKey(jwk: jwk)
        } catch {
            throw fail("Unusable verification key \(keyid): \(error)")
        }
        let keyAlgorithm: String
        switch key.curve {
        case "P-256": keyAlgorithm = "ecdsa-p256-sha256"
        case "P-384": keyAlgorithm = "ecdsa-p384-sha384"
        case "Ed25519": keyAlgorithm = "ed25519"
        default: throw fail("Unsupported verification key type \(key.keyType) \(key.curve)")
        }
        if let alg, alg != keyAlgorithm { throw fail("alg \(alg) does not match the key type (\(keyAlgorithm))") }
        guard key.verify(signature, for: Data(base.utf8)) else { throw fail("The signature does not verify") }
        return keyAlgorithm
    }

    private func fetch(_ storageID: URL) async throws -> StorageDescription {
        let description: StorageDescription
        do {
            description = try await descriptions(storageID)
        } catch let e as LWSError {
            throw Self.fail("Cannot retrieve the storage description \(storageID.absoluteString): \(e)")
        }
        cache[URLs.canonical(storageID)] = (description, options.now())
        return description
    }

    private static func checkDigest(_ header: String, _ body: Data) throws {
        let digests = try dictionary(header, "Content-Digest")
        var any = false
        for (name, hash) in [("sha-256", { (d: Data) in Data(SHA256.hash(data: d)) }), ("sha-512", { (d: Data) in Data(SHA512.hash(data: d)) })] {
            guard let member = digests[name] else { continue }
            any = true
            guard case .item(let item) = member, case .byteSequence(let expected) = item.value else { throw fail("Malformed \(name) digest") }
            guard constantTimeEquals(hash(body), expected) else { throw fail("Content-Digest \(name) mismatch") }
        }
        if !any { throw fail("Content-Digest has no supported algorithm (sha-256, sha-512)") }
    }

    private static func field(_ headers: HTTPHeaders, _ name: String) throws -> String {
        guard let v = headers.combined(name) else { throw fail("Missing \(name) header") }
        return v
    }

    private static func dictionary(_ value: String, _ what: String) throws -> SFDictionary {
        do {
            return try StructuredFields.parseDictionary(value)
        } catch {
            throw fail("Malformed \(what): \(error)")
        }
    }

    private static func fail(_ message: String) -> LWSError {
        .signatureVerification(message)
    }
}
