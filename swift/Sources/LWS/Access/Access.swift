// SPDX-License-Identifier: MIT
import Foundation

/// An ODRL constraint limiting an access policy (`leftOperand operator rightOperand`). All constraints of a policy
/// must hold.
public struct Constraint: Sendable, Hashable {
    /// The left operand: `client`, `format`, `type`, `purpose`, `dateTime`, …
    public let leftOperand: String
    /// The operator: `eq`, `isAnyOf`, `gteq`, `lteq`, …
    public let `operator`: String
    /// The comparison value (a string, or an array for `isAnyOf`).
    public let rightOperand: JSONValue

    public init(leftOperand: String, operator: String, rightOperand: JSONValue) {
        self.leftOperand = leftOperand
        self.operator = `operator`
        self.rightOperand = rightOperand
    }

    /// `purpose eq <purpose>`.
    public static func purpose(_ purpose: URL) -> Constraint {
        Constraint(leftOperand: ConstraintOperand.purpose, operator: ConstraintOperator.eq, rightOperand: .string(purpose.absoluteString))
    }

    /// `purpose isAnyOf [purposes]`.
    public static func purposeAnyOf(_ purposes: [URL]) -> Constraint {
        Constraint(leftOperand: ConstraintOperand.purpose, operator: ConstraintOperator.isAnyOf,
                   rightOperand: LWSJSON.strings(purposes.map(\.absoluteString)))
    }

    /// `client eq <client>`: restricts access to one client application.
    public static func client(_ clientID: URL) -> Constraint {
        Constraint(leftOperand: ConstraintOperand.client, operator: ConstraintOperator.eq, rightOperand: .string(clientID.absoluteString))
    }

    /// `format eq <mediaType>`.
    public static func format(_ mediaType: String) -> Constraint {
        Constraint(leftOperand: ConstraintOperand.format, operator: ConstraintOperator.eq, rightOperand: .string(mediaType))
    }

    /// `format isAnyOf [mediaTypes]`.
    public static func formatAnyOf(_ mediaTypes: [String]) -> Constraint {
        Constraint(leftOperand: ConstraintOperand.format, operator: ConstraintOperator.isAnyOf, rightOperand: LWSJSON.strings(mediaTypes))
    }

    /// `type eq <type>`: matches the resource's `rel="type"` links.
    public static func type(_ type: URL) -> Constraint {
        Constraint(leftOperand: ConstraintOperand.type, operator: ConstraintOperator.eq, rightOperand: .string(type.absoluteString))
    }

    /// `type isAnyOf [types]`.
    public static func typeAnyOf(_ types: [URL]) -> Constraint {
        Constraint(leftOperand: ConstraintOperand.type, operator: ConstraintOperator.isAnyOf, rightOperand: LWSJSON.strings(types.map(\.absoluteString)))
    }

    /// `dateTime gteq <instant>`: access starts at `instant`.
    public static func notBefore(_ instant: Date) -> Constraint {
        Constraint(leftOperand: ConstraintOperand.dateTime, operator: ConstraintOperator.gteq, rightOperand: .string(Dates.formatRFC3339(instant)))
    }

    /// `dateTime lteq <instant>`: access ends at `instant`.
    public static func notAfter(_ instant: Date) -> Constraint {
        Constraint(leftOperand: ConstraintOperand.dateTime, operator: ConstraintOperator.lteq, rightOperand: .string(Dates.formatRFC3339(instant)))
    }

    var json: JSONObject {
        ["leftOperand": .string(leftOperand), "operator": .string(`operator`), "rightOperand": rightOperand]
    }

    static func parse(_ value: JSONValue) throws -> Constraint {
        guard let left = value["leftOperand"]?.stringValue, let op = value["operator"]?.stringValue, let right = value["rightOperand"] else {
            throw LWSError.protocolError("Incomplete constraint")
        }
        return Constraint(leftOperand: left, operator: op, rightOperand: right)
    }
}

/// The resources an access policy applies to.
public struct AccessTarget: Sendable, Hashable {
    /// The matcher: `StorageResource`, `Container`, `DataResource`, or an IRI.
    public let type: String
    /// The target identifiers.
    public let values: [String]

    /// Creates a target.
    /// - Throws: ``LWSError/invalidArgument(_:)`` without values.
    public init(type: String, values: [String]) throws {
        guard !values.isEmpty else { throw LWSError.invalidArgument("An access target needs at least one value") }
        self.type = type
        self.values = values
    }

    /// Any storage resource among `resources`.
    public static func storageResources(_ resources: URL...) throws -> AccessTarget {
        try AccessTarget(type: "StorageResource", values: resources.map(\.absoluteString))
    }

    /// The containers among `resources`.
    public static func containers(_ resources: URL...) throws -> AccessTarget {
        try AccessTarget(type: "Container", values: resources.map(\.absoluteString))
    }

    /// The data resources among `resources`.
    public static func dataResources(_ resources: URL...) throws -> AccessTarget {
        try AccessTarget(type: "DataResource", values: resources.map(\.absoluteString))
    }

    var json: JSONObject {
        ["type": .string(type), "value": LWSJSON.strings(values)]
    }

    static func parse(_ o: JSONObject) throws -> AccessTarget {
        try wrap { try AccessTarget(type: o.string("type") ?? "StorageResource", values: o.strings("value")) }
    }
}

/// An access policy of the LWS access profile (ODRL-based): who (``assignee``) may do what (``actions``) on which
/// resources (``target``) under which ``constraints``.
public struct AccessPolicy: Sendable, Hashable {
    /// The policy types (they include `AccessPolicy`).
    public let types: [String]
    /// The actions: `read`, `modify`, `create`, `delete`, …
    public let actions: [String]
    /// The agent the policy applies to (a URL or a DID; ``Vocabulary/publicAgent`` for public access).
    public let assignee: String
    /// The target resources.
    public let target: AccessTarget?
    /// The constraints (all must hold).
    public let constraints: [Constraint]

    /// Creates a policy.
    /// - Throws: ``LWSError/invalidArgument(_:)`` without actions, or when the assignee is not an absolute IRI.
    public init(actions: [String], assignee: String, target: AccessTarget? = nil, constraints: [Constraint] = []) throws {
        try self.init(types: [ResourceType.accessPolicy], actions: actions, assignee: assignee, target: target, constraints: constraints)
    }

    private init(types: [String], actions: [String], assignee: String, target: AccessTarget?, constraints: [Constraint]) throws {
        guard !actions.isEmpty else { throw LWSError.invalidArgument("An access policy needs at least one action") }
        guard URLs.hasScheme(assignee) else { throw LWSError.invalidArgument("The assignee must be an absolute IRI: \(assignee)") }
        self.types = types
        self.actions = actions
        self.assignee = assignee
        self.target = target
        self.constraints = constraints
    }

    var json: JSONObject {
        var o: JSONObject = ["type": LWSJSON.strings(types), "action": LWSJSON.strings(actions), "assignee": .string(assignee)]
        if let target { o["target"] = .object(target.json) }
        if !constraints.isEmpty { o["constraint"] = .array(constraints.map { .object($0.json) }) }
        return o
    }

    static func parse(_ value: JSONValue) throws -> AccessPolicy {
        let o = try LWSJSON.object(value, "Access policy")
        guard let assignee = o.string("assignee") else { throw LWSError.protocolError("The access policy has no assignee") }
        let constraints = try (o["constraint"]?.arrayValue ?? []).map(Constraint.parse)
        let target = try o["target"]?.objectValue.map(AccessTarget.parse)
        return try wrap {
            try AccessPolicy(types: o.strings("type"), actions: o.strings("action"), assignee: assignee, target: target, constraints: constraints)
        }
    }
}

/// Turns argument errors of a builder into protocol errors, for documents that came from a server.
private func wrap<T>(_ build: () throws -> T) throws -> T {
    do {
        return try build()
    } catch LWSError.invalidArgument(let m) {
        throw LWSError.protocolError(m)
    }
}

/// The shared structure of ``AccessRequest`` and ``AccessGrant``.
public protocol AccessDocument: Sendable {
    /// The document types (they include `AccessRequest` or `AccessGrant`).
    var types: [String] { get }
    /// The storage the document is scoped to.
    var storage: URL { get }
    /// Where notifications about the document are delivered.
    var inbox: URL? { get }
    /// The requested or granted access.
    var access: [AccessPolicy] { get }
    /// The JSON document when it was parsed from a server, else nil.
    var raw: JSONObject? { get }
}

extension AccessDocument {
    /// The `application/lws+json` serialization.
    public var json: JSONObject {
        var o: JSONObject = ["@context": .array([.string(Vocabulary.context)]), "type": LWSJSON.strings(types)]
        if let inbox { o["inbox"] = .string(inbox.absoluteString) }
        o["storage"] = .string(storage.absoluteString)
        o["access"] = .array(access.map { .object($0.json) })
        return o
    }
}

struct AccessParts {
    let types: [String]
    let storage: URL
    let inbox: URL?
    let access: [AccessPolicy]
    let raw: JSONObject

    static func parse(_ json: JSONValue, _ requiredType: String) throws -> AccessParts {
        let o = try LWSJSON.object(json, requiredType)
        let types = o.strings("type")
        guard Vocabulary.hasType(types, requiredType) else {
            throw LWSError.protocolError("Document type [\(types.joined(separator: ", "))] does not include \(requiredType)")
        }
        guard let storageText = o.string("storage") else { throw LWSError.protocolError("The \(requiredType) has no storage") }
        guard let storage = URLs.resolve(storageText, against: nil) else {
            throw LWSError.protocolError("The \(requiredType) storage is not an absolute URL")
        }
        var inbox: URL?
        if let i = o.string("inbox") {
            guard let u = URLs.resolve(i, against: nil) else { throw LWSError.protocolError("The \(requiredType) inbox is not an absolute URL") }
            inbox = u
        }
        var policies: [AccessPolicy] = []
        switch o["access"] {
        case .array(let a)?: policies = try a.map(AccessPolicy.parse)
        case .object(let p)?: policies = [try AccessPolicy.parse(.object(p))]
        default: break
        }
        guard !policies.isEmpty else { throw LWSError.protocolError("The \(requiredType) has no access") }
        return AccessParts(types: types, storage: storage, inbox: inbox, access: policies, raw: o)
    }
}

/// A request by an agent for access to resources of a storage.
///
/// ```swift
/// let request = try AccessRequest(storage: storage.id,
///     access: [AccessPolicy(actions: [AccessAction.read], assignee: agent, target: .storageResources(projects),
///                           constraints: [.purpose(URL(string: "https://purpose.example/collaboration")!)])],
///     inbox: URL(string: "https://id.example/agent/inbox/"))
/// ```
public struct AccessRequest: AccessDocument, Hashable {
    public let types: [String]
    public let storage: URL
    public let inbox: URL?
    public let access: [AccessPolicy]
    public let raw: JSONObject?

    /// Creates an access request.
    /// - Throws: ``LWSError/invalidArgument(_:)`` without access policies.
    public init(storage: URL, access: [AccessPolicy], inbox: URL? = nil) throws {
        guard !access.isEmpty else { throw LWSError.invalidArgument("At least one access policy is required") }
        self.init(types: [ResourceType.accessRequest], storage: storage, inbox: inbox, access: access, raw: nil)
    }

    private init(types: [String], storage: URL, inbox: URL?, access: [AccessPolicy], raw: JSONObject?) {
        self.types = types
        self.storage = storage
        self.inbox = inbox
        self.access = access
        self.raw = raw
    }

    /// Parses an access request document.
    /// - Throws: ``LWSError/protocolError(_:)`` when it is not a valid access request.
    public static func parse(_ json: JSONValue) throws -> AccessRequest {
        let p = try AccessParts.parse(json, ResourceType.accessRequest)
        return AccessRequest(types: p.types, storage: p.storage, inbox: p.inbox, access: p.access, raw: p.raw)
    }
}

/// A record, created by a storage controller, of access granted to an agent. Creating or revoking (deleting) a
/// grant makes the server adjust its access policies.
public struct AccessGrant: AccessDocument, Hashable {
    public let types: [String]
    public let storage: URL
    public let inbox: URL?
    public let access: [AccessPolicy]
    public let raw: JSONObject?

    /// Creates an access grant.
    /// - Throws: ``LWSError/invalidArgument(_:)`` without access policies.
    public init(storage: URL, access: [AccessPolicy], inbox: URL? = nil) throws {
        guard !access.isEmpty else { throw LWSError.invalidArgument("At least one access policy is required") }
        self.init(types: [ResourceType.accessGrant], storage: storage, inbox: inbox, access: access, raw: nil)
    }

    private init(types: [String], storage: URL, inbox: URL?, access: [AccessPolicy], raw: JSONObject?) {
        self.types = types
        self.storage = storage
        self.inbox = inbox
        self.access = access
        self.raw = raw
    }

    /// A grant mirroring an access request (the same storage, inbox and policies).
    public static func approving(_ request: AccessRequest) -> AccessGrant {
        AccessGrant(types: [ResourceType.accessGrant], storage: request.storage, inbox: request.inbox, access: request.access, raw: nil)
    }

    /// Parses an access grant document.
    /// - Throws: ``LWSError/protocolError(_:)`` when it is not a valid access grant.
    public static func parse(_ json: JSONValue) throws -> AccessGrant {
        let p = try AccessParts.parse(json, ResourceType.accessGrant)
        return AccessGrant(types: p.types, storage: p.storage, inbox: p.inbox, access: p.access, raw: p.raw)
    }
}
