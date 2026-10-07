// SPDX-License-Identifier: MIT
import Foundation

/// One page of a container listing, or of type search results (whose `type` is `ContainerPage`).
///
/// ``id``, ``types`` and ``totalItems`` describe the whole listing, ``items`` only this page; follow ``next``
/// for more.
public struct ContainerPage: Sendable, CustomStringConvertible {
    /// The absolute container URL; the page URL when the body has no `id` (e.g. search results).
    public let id: URL
    /// The raw `type` values of the listing.
    public let types: [String]
    /// The (possibly approximate) number of members across all pages.
    public let totalItems: Int64?
    /// The members on this page.
    public let items: [ContainedResource]
    /// The response metadata (entity tag, links, …).
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
    /// The entity tag of this page.
    public var etag: String? { metadata.etag }

    /// Whether the listing is a container (by its body `type` or its `rel="type"` links).
    public var isContainer: Bool { hasType(ResourceType.container) || metadata.isContainer }

    /// Whether the listing declares `type`.
    public func hasType(_ type: String) -> Bool { Vocabulary.hasType(types, type) }

    /// Parses a container representation; relative ids are resolved against the page URL.
    /// - Throws: ``LWSError/protocolError(_:)`` when the body is not a container representation.
    public static func parse(_ body: JSONValue, metadata: ResourceMetadata) throws -> ContainerPage {
        let o = try LWSJSON.object(body, "Container representation")
        let base = metadata.url
        let id: URL
        if let idText = o.string("id") {
            guard let u = URLs.resolve(idText, against: base) else { throw LWSError.protocolError("Invalid container id: \(idText)") }
            id = u
        } else {
            id = base
        }
        var items: [ContainedResource] = []
        switch o["items"] {
        case .array(let a)?:
            items = try a.map { try ContainedResource.parse($0, base: base) }
        case nil, .null?:
            break
        default:
            throw LWSError.protocolError("Container 'items' is not an array")
        }
        return ContainerPage(id: id, types: o.strings("type"), totalItems: o.integer("totalItems"), items: items, metadata: metadata, raw: o)
    }

    public var description: String { "ContainerPage \(id.absoluteString) (\(items.count) items)" }
}

/// One member of a container listing (or of type search results).
public struct ContainedResource: Sendable, CustomStringConvertible {
    /// The absolute URL of the member.
    public let id: URL
    /// The raw type values, as received.
    public let types: [String]
    /// The media type (required for data resources).
    public let format: String?
    /// The size in bytes.
    public let size: Int64?
    /// The `modified` value as sent.
    public let modifiedRaw: String?
    /// The JSON object.
    public let raw: JSONObject

    /// The last modification time, when parseable (an unparseable date never fails the listing).
    public var modified: Date? { Dates.parseRFC3339(modifiedRaw) }

    /// Whether the member is a container.
    public var isContainer: Bool { hasType(ResourceType.container) }
    /// Whether the member is a data resource.
    public var isDataResource: Bool { hasType(ResourceType.dataResource) }

    /// Whether the member declares `type` (short terms match their full IRIs).
    public func hasType(_ type: String) -> Bool { Vocabulary.hasType(types, type) }

    /// Parses a contained resource description, resolving its id against `base`.
    /// - Throws: ``LWSError/protocolError(_:)`` when the description has no valid id.
    public static func parse(_ json: JSONValue, base: URL?) throws -> ContainedResource {
        let o = try LWSJSON.object(json, "Contained resource description")
        guard let idText = o.string("id") else { throw LWSError.protocolError("Contained resource description without id") }
        guard let id = URLs.resolve(idText, against: base) else { throw LWSError.protocolError("Invalid contained resource id: \(idText)") }
        return ContainedResource(id: id, types: o.strings("type"), format: o.string("format"), size: o.integer("size"),
                                 modifiedRaw: o.string("modified"), raw: o)
    }

    public var description: String { id.absoluteString }
}
