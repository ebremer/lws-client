// SPDX-License-Identifier: MIT
import Foundation

/// A type search filter (`application/lws-query+json`) in conjunctive normal form: every group must match (AND),
/// and a group matches when any of its IRIs does (OR). Each method returns a new query:
///
/// ```swift
/// // (schema:Person OR foaf:Person) AND lws:DataResource, described by a person shape
/// let q = try TypeQuery()
///     .anyOf("https://schema.org/Person", "http://xmlns.com/foaf/0.1/Person")
///     .allOf("https://www.w3.org/ns/lws#DataResource")
///     .relation("describedby").allOf("https://example.org/shapes/person")
/// ```
///
/// The empty query (`{}`) matches everything. Validation mirrors the server's `400` rules: every value must be an
/// absolute IRI and no OR group may be empty (``LWSError/invalidArgument(_:)``).
public struct TypeQuery: Sendable, Hashable, CustomStringConvertible {
    /// The query media type.
    public static let mediaType = MediaType.lwsQueryJSON
    /// The filter key of resource types.
    public static let typeKey = "type"

    /// The filter keys (`type` or relations), in order.
    public let keys: [String]
    /// The groups per key: each group is an OR of IRIs, and the groups are ANDed.
    public let filters: [String: [[String]]]

    /// The empty query, which matches everything.
    public init() {
        keys = []
        filters = [:]
    }

    private init(keys: [String], filters: [String: [[String]]]) {
        self.keys = keys
        self.filters = filters
    }

    /// The empty query.
    public static let empty = TypeQuery()

    /// Resources having all of `types`: each IRI becomes its own AND group.
    public func allOf(_ types: String...) throws -> TypeQuery { try relation(Self.typeKey).allOf(types) }

    /// Resources having all of `types`.
    public func allOf(_ types: [String]) throws -> TypeQuery { try relation(Self.typeKey).allOf(types) }

    /// Resources having any of `types`: one OR group (not empty).
    public func anyOf(_ types: String...) throws -> TypeQuery { try relation(Self.typeKey).anyOf(types) }

    /// Resources having any of `types`.
    public func anyOf(_ types: [String]) throws -> TypeQuery { try relation(Self.typeKey).anyOf(types) }

    /// A filter on an indexed descriptive link relation (the same grammar, under the relation's key).
    public func relation(_ relation: String) throws -> RelationClause {
        guard !relation.isEmpty, !relation.hasPrefix("@") else { throw LWSError.invalidArgument("Invalid filter key: \(relation)") }
        return RelationClause(query: self, key: relation)
    }

    /// Whether `iri` is an absolute IRI: a scheme followed by a non-empty remainder without spaces or `<>"{}|\^\``.
    public static func isAbsoluteIRI(_ iri: String) -> Bool {
        guard URLs.hasScheme(iri), let colon = iri.firstIndex(of: ":") else { return false }
        let rest = iri[iri.index(after: colon)...]
        return !rest.isEmpty && !rest.unicodeScalars.contains { $0.properties.isWhitespace || "<>\"{}|\\^`".unicodeScalars.contains($0) }
    }

    fileprivate func withGroups(_ key: String, _ groups: [[String]]) -> TypeQuery {
        var keys = self.keys
        var filters = self.filters
        if filters[key] == nil {
            keys.append(key)
            filters[key] = []
        }
        for g in groups where !filters[key]!.contains(g) { filters[key]!.append(g) }
        return TypeQuery(keys: keys, filters: filters)
    }

    fileprivate static func validate(_ iri: String) throws -> String {
        guard isAbsoluteIRI(iri) else { throw LWSError.invalidArgument("Not an absolute IRI: \(iri)") }
        return iri
    }

    /// The filter document (no `@context`); one-element OR groups are plain strings.
    public var json: JSONObject {
        JSONObject(keys.map { key in
            (key, .array(filters[key]!.map { g in g.count == 1 ? .string(g[0]) : LWSJSON.strings(g) }))
        })
    }

    /// The serialized filter document (UTF-8).
    public var data: Data { JSONValue.object(json).serializedData() }

    public var description: String { json.description }

    /// Rebuilds a query from an `application/lws-query+json` document: a string group is `allOf(iri)` and an
    /// array group `anyOf(iris)`, on the member's key, in order.
    /// - Throws: ``LWSError/invalidArgument(_:)`` when the document is not a valid filter.
    public static func from(json: JSONValue) throws -> TypeQuery {
        guard case .object(let o) = json else { throw LWSError.invalidArgument("A type query must be a JSON object") }
        var q = TypeQuery.empty
        for m in o {
            guard case .array(let groups) = m.value else {
                throw LWSError.invalidArgument("Query member '\(m.key)' must be a list of groups")
            }
            for g in groups {
                switch g {
                case .string(let iri):
                    q = try q.relation(m.key).allOf(iri)
                case .array(let iris):
                    q = try q.relation(m.key).anyOf(iris.map { e in
                        guard let s = e.stringValue else { throw LWSError.invalidArgument("A group of query member '\(m.key)' must hold IRIs") }
                        return s
                    })
                default:
                    throw LWSError.invalidArgument("A group of query member '\(m.key)' must be an IRI or a list of IRIs")
                }
            }
        }
        return q
    }

    /// A filter clause on one key; ``allOf(_:)-swift.method`` and ``anyOf(_:)-swift.method`` return the
    /// extended query.
    public struct RelationClause: Sendable {
        fileprivate let query: TypeQuery
        /// The filter key.
        public let key: String

        /// Each IRI becomes its own AND group.
        public func allOf(_ iris: String...) throws -> TypeQuery { try allOf(iris) }

        /// Each IRI becomes its own AND group.
        public func allOf(_ iris: [String]) throws -> TypeQuery {
            query.withGroups(key, try iris.map { [try TypeQuery.validate($0)] })
        }

        /// One OR group of IRIs (not empty).
        public func anyOf(_ iris: String...) throws -> TypeQuery { try anyOf(iris) }

        /// One OR group of IRIs (not empty).
        public func anyOf(_ iris: [String]) throws -> TypeQuery {
            let group = try iris.map(TypeQuery.validate)
            guard !group.isEmpty else { throw LWSError.invalidArgument("An OR group must not be empty") }
            return query.withGroups(key, [group])
        }
    }
}

/// One page of a type index: the distinct resource types visible to the client.
public struct TypeIndexPage: Sendable {
    /// The number of types across all pages.
    public let totalItems: Int64?
    /// The type IRIs on this page.
    public let types: [String]
    /// The response metadata.
    public let metadata: ResourceMetadata
    /// The JSON document.
    public let raw: JSONObject

    /// The first page.
    public var first: URL? { metadata.link(LinkRelation.first)?.href }
    /// The next page.
    public var next: URL? { metadata.link(LinkRelation.next)?.href }
    /// The previous page.
    public var prev: URL? { metadata.link(LinkRelation.prev)?.href }
    /// The last page.
    public var last: URL? { metadata.link(LinkRelation.last)?.href }

    /// Parses a type index page.
    /// - Throws: ``LWSError/protocolError(_:)`` when the body is not a type index.
    public static func parse(_ body: JSONValue, metadata: ResourceMetadata) throws -> TypeIndexPage {
        let o = try LWSJSON.object(body, "Type index")
        var types: [String] = []
        switch o["items"] {
        case .array(let a)?:
            types = a.compactMap { $0.stringValue ?? $0["id"]?.stringValue }
        case nil, .null?:
            break
        default:
            throw LWSError.protocolError("Type index 'items' is not an array")
        }
        return TypeIndexPage(totalItems: o.integer("totalItems"), types: types, metadata: metadata, raw: o)
    }
}
