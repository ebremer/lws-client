// SPDX-License-Identifier: MIT
import Foundation

/// The outcome of a move (``LWSClient/move(_:to:options:)``): where the resource and its linkset are now.
///
/// A storage that keeps identifiers answers `204` (or `200` with the linkset), and ``location`` is the URL moved. One
/// that does not answers `200` with the updated linkset, whose `anchor` is the new identifier, and
/// `Content-Location`, the linkset's new URL. Without a ``MoveCapability/preservesIdentifier`` of true, rely on this
/// result for the identifier.
public struct MoveResult: Sendable, CustomStringConvertible {
    /// The status: `200` or `204` (or another 2xx).
    public let status: Int
    /// The absolute URL of the resource after the move.
    public let location: URL
    /// The absolute URL of its linkset after the move.
    public let linkset: URL
    /// Whether the resource kept its URL (``location`` is the URL moved).
    public let identifierPreserved: Bool
    /// The response metadata.
    public let metadata: ResourceMetadata
    /// The updated linkset, when the server returned it (in a `200`).
    public let document: Linkset?

    /// The linkset's new entity tag, when the server returned one.
    public var etag: String? { metadata.etag }

    public var description: String { "Moved to \(location.absoluteString) (\(status))" }

    /// Interprets the answer to a move's patch (internal): `resource` is the URL moved, `linksetURL` the linkset
    /// patched. The new identifier is the anchor of the first link context of a `200`'s linkset that has an `up`
    /// link, resolved against `Content-Location` (else the linkset URL); `Content-Location` is the linkset's.
    /// - Throws: ``LWSError/protocolError(_:)`` when a `200`'s JSON body is not a linkset.
    init(resource: URL, linksetURL: URL, status: Int, headers: HTTPHeaders, body: Data) throws {
        let metadata = ResourceMetadata(url: linksetURL, status: status, headers: headers)
        var document: Linkset?
        if status == 200, !body.allSatisfy({ $0 == 0x20 || $0 == 0x0A || $0 == 0x0D || $0 == 0x09 }),
           HeaderLists.isJSON(metadata.contentType ?? MediaType.linksetJSON)
        {
            document = try Linkset.parse(LWSJSON.parse(body, "Linkset"))
        }
        let contentLocation = headers.first("content-location").flatMap { URLs.resolve($0, against: linksetURL) }
        var location = resource
        if let context = document?.contexts.first(where: { Self.upTarget($0) != nil }), let anchor = context.anchor,
           let moved = URLs.resolve(anchor, against: contentLocation ?? linksetURL), URLs.canonical(moved) != URLs.canonical(resource)
        {
            location = moved
        }
        self.init(status: status, location: location, linkset: contentLocation ?? linksetURL, identifierPreserved: location == resource,
                  metadata: metadata, document: document)
    }

    private init(status: Int, location: URL, linkset: URL, identifierPreserved: Bool, metadata: ResourceMetadata, document: Linkset?) {
        self.status = status
        self.location = location
        self.linkset = linkset
        self.identifierPreserved = identifierPreserved
        self.metadata = metadata
        self.document = document
    }

    /// The JSON Patch that moves `resource` into `destination` (internal): `test` that the resource's `up` link still
    /// holds the target as read, and `replace` it with the destination. The link context is the first whose `anchor`
    /// resolves (against `linksetURL`) to the resource, or the only one when it has no anchor; the `up` link is its
    /// first target with a string `href`.
    /// - Throws: ``LWSError/protocolError(_:)`` when the linkset shows no `up` link of the resource.
    static func patch(_ linkset: Linkset, linksetURL: URL, resource: URL, destination: URL) throws -> JSONPatch {
        let id = URLs.canonical(resource)
        var index = linkset.contexts.firstIndex { c in
            c.anchor.flatMap { URLs.resolve($0, against: linksetURL) }.map { URLs.canonical($0) == id } ?? false
        }
        if index == nil, linkset.contexts.count == 1, linkset.contexts[0].anchor == nil { index = 0 }
        guard let i = index else {
            throw LWSError.protocolError("The linkset \(linksetURL.absoluteString) has no link context for \(resource.absoluteString)")
        }
        guard let (j, href) = upTarget(linkset.contexts[i]) else {
            throw LWSError.protocolError("The linkset \(linksetURL.absoluteString) has no up link for \(resource.absoluteString)")
        }
        let path = JSONPointer.from("linkset", String(i), LinkRelation.up, String(j), "href")
        return JSONPatch().test(path, .string(href)).replace(path, .string(destination.absoluteString))
    }

    /// The position and `href` of a link context's first `up` target with a string `href`.
    private static func upTarget(_ context: LinkContext) -> (Int, String)? {
        if let first = context.targets(LinkRelation.up).first { return (0, first.href) }
        // A relation whose targets are not all objects with an href is kept as received, among the extra members.
        guard case .array(let targets)? = context.extra[LinkRelation.up] else { return nil }
        for (j, t) in targets.enumerated() {
            if t.objectValue != nil, let href = t["href"]?.stringValue { return (j, href) }
        }
        return nil
    }
}
