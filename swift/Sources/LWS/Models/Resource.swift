// SPDX-License-Identifier: MIT
import Foundation

/// The metadata of a storage resource, parsed from response headers.
public struct ResourceMetadata: Sendable, CustomStringConvertible {
    /// The final request URL (after redirects).
    public let url: URL
    /// The HTTP status code.
    public let status: Int
    /// The raw response headers.
    public let headers: HTTPHeaders
    /// Every `Link` header link (one per relation type), resolved against ``url``.
    public let links: [Link]

    public init(url: URL, status: Int, headers: HTTPHeaders) {
        self.url = url
        self.status = status
        self.headers = headers
        links = LinkHeader.parse(headers.all("link"), base: url)
    }

    /// The entity tag, verbatim including quotes and any `W/` prefix: send it back unchanged in `If-Match`.
    public var etag: String? { headers.first("etag") }

    /// The raw `Last-Modified` header value.
    public var lastModifiedRaw: String? { headers.first("last-modified") }

    /// The `Last-Modified` date, when parseable.
    public var lastModified: Date? { Dates.parseHTTPDate(lastModifiedRaw) }

    /// The `Content-Type` header value.
    public var contentType: String? { headers.first("content-type") }

    /// The `Content-Length`, when present.
    public var contentLength: Int64? {
        headers.first("content-length").flatMap { Int64($0.trimmingCharacters(in: .whitespaces)) }.flatMap { $0 >= 0 ? $0 : nil }
    }

    /// The linkset resource (`rel="linkset"`).
    public var linkset: URL? { link(LinkRelation.linkset)?.href }

    /// The parent container (`rel="up"`).
    public var parent: URL? { link(LinkRelation.up)?.href }

    /// The storage (`rel="https://www.w3.org/ns/lws#storage"`).
    public var storage: URL? { link(LinkRelation.storage)?.href }

    /// The resource types: the targets of `rel="type"` links.
    public var types: [String] { links(LinkRelation.type).map(\.href.absoluteString) }

    /// Whether the resource is a container.
    public var isContainer: Bool { hasType(ResourceType.container) }

    /// Whether the resource is a data resource.
    public var isDataResource: Bool { hasType(ResourceType.dataResource) }

    /// The methods of the `Allow` header.
    public var allow: [String] { HeaderLists.split(headers.all("allow")) }

    /// The patch formats of the `Accept-Patch` header.
    public var acceptPatch: [String] { HeaderLists.split(headers.all("accept-patch")) }

    /// Whether a `rel="type"` link declares `type` (short term, compact or full IRI).
    public func hasType(_ type: String) -> Bool { Vocabulary.hasType(types, type) }

    /// The first link with relation `rel`.
    public func link(_ rel: String) -> Link? { links.first(rel: rel) }

    /// Every link with relation `rel`.
    public func links(_ rel: String) -> [Link] { links.all(rel: rel) }

    /// The first value of a header (case-insensitive name).
    public func header(_ name: String) -> String? { headers.first(name) }

    public var description: String { "\(status) \(url.absoluteString)" }
}

/// The result of reading a resource: its metadata and content.
///
/// A conditional read answered `304 Not Modified` is not an error: ``notModified`` is true and the body is
/// empty. A `206 Partial Content` answer exposes ``contentRange``.
public struct Resource: Sendable, CustomStringConvertible {
    /// The response metadata.
    public let metadata: ResourceMetadata
    /// The content (empty for `HEAD` and `304`).
    public let body: Data
    /// Whether the server answered `304 Not Modified`.
    public let notModified: Bool

    public init(metadata: ResourceMetadata, body: Data, notModified: Bool) {
        self.metadata = metadata
        self.body = body
        self.notModified = notModified
    }

    /// The final request URL.
    public var url: URL { metadata.url }
    /// The HTTP status.
    public var status: Int { metadata.status }
    /// The entity tag, verbatim.
    public var etag: String? { metadata.etag }
    /// The content type.
    public var contentType: String? { metadata.contentType }
    /// The `Content-Range` of a partial (`206`) response.
    public var contentRange: String? { metadata.header("content-range") }

    /// The content decoded with the `charset` of the content type (UTF-8 by default).
    public var text: String { HeaderLists.decode(body, contentType: contentType) }

    /// The content parsed as JSON.
    /// - Throws: ``LWSError/protocolError(_:)`` when it is not JSON.
    public func json() throws -> JSONValue {
        try LWSJSON.parse(body, "Content of \(url.absoluteString)")
    }

    /// The content decoded from JSON with `JSONDecoder`.
    /// - Throws: ``LWSError/protocolError(_:)`` when it cannot be decoded as `T`.
    public func decode<T: Decodable>(_ type: T.Type, using decoder: JSONDecoder = JSONDecoder()) throws -> T {
        do {
            return try decoder.decode(T.self, from: body)
        } catch {
            throw LWSError.protocolError("Cannot decode the content of \(url.absoluteString) as \(T.self): \(error)")
        }
    }

    public var description: String { "Resource \(url.absoluteString) (\(status), \(body.count) bytes)" }
}

/// The outcome of a create operation.
public struct CreateResult: Sendable, CustomStringConvertible {
    /// The absolute URL of the new resource (`Location`).
    public let location: URL
    /// The `201` response metadata (links to the linkset, the parent and the types).
    public let metadata: ResourceMetadata
    /// The response body, often empty.
    public let body: Data

    /// The linkset of the new resource, when announced.
    public var linkset: URL? { metadata.linkset }
    /// The entity tag of the new resource, when announced.
    public var etag: String? { metadata.etag }

    public var description: String { "Created \(location.absoluteString)" }
}

/// The outcome of an update (`PUT`) or a patch (`PATCH`).
public struct UpdateResult: Sendable, CustomStringConvertible {
    /// The status: `200` or `204` (or another 2xx).
    public let status: Int
    /// The response metadata.
    public let metadata: ResourceMetadata
    /// The response body, if the server returned a representation.
    public let body: Data

    /// The new entity tag, when the server returned one.
    public var etag: String? { metadata.etag }

    public var description: String { "Updated \(metadata.url.absoluteString) (\(status))" }
}
