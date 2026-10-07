// SPDX-License-Identifier: MIT
import Foundation

/// A storage description: a W3C Controlled Identifier document describing a storage, its services (storage root,
/// notifications, access requests and grants, type index and search, …), capabilities and verification methods.
public struct StorageDescription: Sendable, CustomStringConvertible {
    /// The canonical storage URL.
    public let id: URL
    /// The raw `type` values (they include `Storage`).
    public let types: [String]
    /// The advertised services.
    public let services: [Service]
    /// The advertised capabilities.
    public let capabilities: [Capability]
    /// The verification methods (e.g. the webhook signing keys).
    public let verificationMethods: [VerificationMethod]
    /// The `authentication` relationship entries (strings or embedded objects).
    public let authentication: [JSONValue]
    /// The JSON document.
    public let raw: JSONObject

    /// The notification service, if advertised.
    public var notificationService: Service? { service(ServiceType.notification) }
    /// The access request service, if advertised.
    public var accessRequestService: Service? { service(ServiceType.accessRequest) }
    /// The access grant service, if advertised.
    public var accessGrantService: Service? { service(ServiceType.accessGrant) }
    /// The type index service, if advertised.
    public var typeIndexService: Service? { service(ServiceType.typeIndex) }
    /// The type search service, if advertised.
    public var typeSearchService: Service? { service(ServiceType.typeSearch) }

    /// The storage root container URL.
    /// - Throws: ``LWSError/protocolError(_:)`` when the description has no `StorageRoot` service.
    public func storageRoot() throws -> URL {
        guard let s = service(ServiceType.storageRoot) else {
            throw LWSError.protocolError("Storage description \(id.absoluteString) has no StorageRoot service")
        }
        return s.serviceEndpoint
    }

    /// The first service of the given type.
    public func service(_ type: String) -> Service? { services.first { $0.hasType(type) } }

    /// Every service of the given type.
    public func services(_ type: String) -> [Service] { services.filter { $0.hasType(type) } }

    /// The first capability of the given type.
    public func capability(_ type: String) -> Capability? { capabilities.first { $0.hasType(type) } }

    /// Finds a verification method by full id, by fragment (`#key` or `key`), or by an id that resolves against
    /// the storage id to the requested one.
    public func verificationMethod(_ idOrFragment: String) -> VerificationMethod? {
        verificationMethods.first { v in
            guard let vid = v.id else { return false }
            return vid == idOrFragment || sameID(vid, idOrFragment)
        }
    }

    /// Whether a verification method is referenced from the `authentication` relationship.
    public func isAuthenticationMethod(_ method: VerificationMethod) -> Bool {
        guard let mid = method.id else { return false }
        return authentication.contains { a in
            guard let ref = a.stringValue ?? a["id"]?.stringValue else { return false }
            return ref == mid || sameID(ref, mid)
        }
    }

    private func sameID(_ a: String, _ b: String) -> Bool {
        guard let ra = resolveRef(a), let rb = resolveRef(b) else { return false }
        return ra.absoluteString == rb.absoluteString
    }

    private func resolveRef(_ reference: String) -> URL? {
        var r = reference
        if !r.contains(":"), !r.hasPrefix("#"), !r.hasPrefix("/") { r = "#" + r }
        return URLs.resolve(r, against: id)
    }

    /// Parses a storage description; relative URLs are resolved against `base`.
    /// - Throws: ``LWSError/protocolError(_:)`` when the document is not a storage description.
    public static func parse(_ json: JSONValue, base: URL?) throws -> StorageDescription {
        let o = try LWSJSON.object(json, "Storage description")
        guard let idText = o.string("id") else { throw LWSError.protocolError("Storage description has no id") }
        guard let id = URLs.resolve(idText, against: base) else { throw LWSError.protocolError("Storage description id is not a URL: \(idText)") }
        let types = o.strings("type")
        guard Vocabulary.hasType(types, ResourceType.storage) else {
            throw LWSError.protocolError("Document type [\(types.joined(separator: ", "))] does not include Storage")
        }
        var services: [Service] = []
        for case .object(let s) in o["service"]?.arrayValue ?? [] {
            guard let endpoint = s.url("serviceEndpoint", base: id) else { continue }
            services.append(Service(id: s.url("id", base: id), types: s.strings("type"), serviceEndpoint: endpoint, raw: s))
        }
        var capabilities: [Capability] = []
        for case .object(let c) in o["capability"]?.arrayValue ?? [] {
            capabilities.append(Capability(id: c.url("id", base: id), types: c.strings("type"), raw: c))
        }
        var methods: [VerificationMethod] = []
        for case .object(let v) in o["verificationMethod"]?.arrayValue ?? [] {
            methods.append(VerificationMethod(json: v))
        }
        var authentication: [JSONValue] = []
        switch o["authentication"] {
        case .array(let a)?: authentication = a
        case .string(let s)?: authentication = [.string(s)]
        case .object(let obj)?: authentication = [.object(obj)]
        default: break
        }
        return StorageDescription(id: id, types: types, services: services, capabilities: capabilities, verificationMethods: methods,
                                  authentication: authentication, raw: o)
    }

    public var description: String { "StorageDescription \(id.absoluteString)" }
}

/// A service of a storage description.
public struct Service: Sendable, CustomStringConvertible {
    /// The optional service id.
    public let id: URL?
    /// The raw type values.
    public let types: [String]
    /// The absolute endpoint URL.
    public let serviceEndpoint: URL
    /// The JSON object (for extra members such as `subscriptionType` or `conformsTo`).
    public let raw: JSONObject

    /// The `subscriptionType` values of a notification service.
    public var subscriptionTypes: [String] { raw.strings("subscriptionType") }
    /// The `conformsTo` values (access profiles).
    public var conformsTo: [String] { raw.strings("conformsTo") }

    /// Whether the service declares `type`.
    public func hasType(_ type: String) -> Bool { Vocabulary.hasType(types, type) }

    /// An extra member of the service object.
    public func property(_ name: String) -> JSONValue? { raw[name] }

    public var description: String { "\(types.joined(separator: ",")) \(serviceEndpoint.absoluteString)" }
}

/// A capability of a storage description.
public struct Capability: Sendable {
    /// The optional capability id.
    public let id: URL?
    /// The raw type values.
    public let types: [String]
    /// The JSON object.
    public let raw: JSONObject

    /// Whether the capability declares `type`.
    public func hasType(_ type: String) -> Bool { Vocabulary.hasType(types, type) }

    /// An extra member of the capability object.
    public func property(_ name: String) -> JSONValue? { raw[name] }
}

/// A verification method of a controlled identifier document.
public struct VerificationMethod: Sendable {
    /// The id as written (it may be relative, e.g. `#key-1`).
    public let id: String?
    /// The method type (e.g. `JsonWebKey`).
    public let type: String?
    /// The controller.
    public let controller: String?
    /// The public key as a JWK.
    public let publicKeyJwk: JSONObject?
    /// The JSON object.
    public let raw: JSONObject

    init(json: JSONObject) {
        id = json.string("id")
        type = json.string("type")
        controller = json.string("controller")
        publicKeyJwk = json["publicKeyJwk"]?.objectValue
        raw = json
    }
}
