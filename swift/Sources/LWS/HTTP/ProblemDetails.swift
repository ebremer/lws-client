// SPDX-License-Identifier: MIT
import Foundation

/// RFC 9457 problem details attached to an error response.
public struct ProblemDetails: Sendable, Hashable, CustomStringConvertible {
    private static let standard: Set<String> = ["type", "title", "status", "detail", "instance"]

    /// The problem type URI reference.
    public let type: String?
    /// A short, human-readable summary.
    public let title: String?
    /// The HTTP status code in the document.
    public let status: Int?
    /// A human-readable explanation of this occurrence.
    public let detail: String?
    /// A URI reference identifying this occurrence.
    public let instance: String?
    /// All other members, in document order.
    public let extensions: JSONObject
    /// The complete document.
    public let raw: JSONObject

    /// Builds problem details from a JSON object.
    public init(json: JSONObject) {
        raw = json
        type = json.string("type")
        title = json.string("title")
        status = json.integer("status").map { Int($0) }
        detail = json.string("detail")
        instance = json.string("instance")
        extensions = JSONObject(json.filter { !Self.standard.contains($0.key) }.map { ($0.key, $0.value) })
    }

    /// Parses a problem document from an error response body: accepted when the content type is
    /// `application/problem+json`, or any JSON type whose object has a `type`, `title` or `detail`.
    public static func parse(contentType: String?, body: Data) -> ProblemDetails? {
        guard !body.isEmpty, HeaderLists.isJSON(contentType), case .object(let o)? = try? JSONValue(parsing: body) else { return nil }
        let problemType = HeaderLists.essence(contentType) == MediaType.problemJSON
        guard problemType || o.contains("type") || o.contains("title") || o.contains("detail") else { return nil }
        return ProblemDetails(json: o)
    }

    public var description: String { raw.description }
}

/// The identity hint of a create request, sent as the `Slug` header (RFC 5023 section 9.7; the LWS core
/// specification defines the hint but not its header).
public enum Slug {
    /// The header field name.
    public static let headerName = "Slug"

    /// Percent-encodes a slug: non-ASCII (as UTF-8), control characters and `%`.
    public static func encode(_ slug: String) -> String {
        var s = ""
        for b in slug.utf8 {
            if b >= 0x20, b < 0x7F, b != UInt8(ascii: "%") {
                s.unicodeScalars.append(Unicode.Scalar(b))
            } else {
                s += "%" + String(format: "%02X", b)
            }
        }
        return s
    }
}
