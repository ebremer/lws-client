// SPDX-License-Identifier: MIT
import Foundation
import LWS

/// A protocol error the adapter itself raises (`InvalidArguments`, `Unsupported`).
struct AdapterError: Error {
    let kind: String
    let message: String

    static func invalid(_ message: String) -> AdapterError { AdapterError(kind: Errors.invalidArguments, message: message) }
}

/// A request body with the content type it implies.
struct BodyArg {
    let bytes: Data
    let contentType: String
}

/// Reads and validates request arguments (an absent member is missing or `null`), and rebuilds the structured ones
/// with the library's own types: bodies, JSON Patches and type queries.
enum Args {
    /// The default `limit` of the lazy sequences.
    static let defaultLimit: Int64 = 1000

    static func get(_ args: JSONObject, _ name: String) -> JSONValue? {
        guard let v = args[name], !v.isNull else { return nil }
        return v
    }

    static func requiredString(_ args: JSONObject, _ name: String) throws -> String {
        guard let s = try optionalString(args, name) else { throw missing(name) }
        return s
    }

    static func optionalString(_ args: JSONObject, _ name: String) throws -> String? {
        guard let v = get(args, name) else { return nil }
        guard let s = v.stringValue else { throw mustBe(name, "a string") }
        return s
    }

    /// An absolute URL argument; a relative reference is `InvalidArguments`.
    static func requiredURL(_ args: JSONObject, _ name: String) throws -> URL {
        try url(try requiredString(args, name), name)
    }

    static func optionalURL(_ args: JSONObject, _ name: String) throws -> URL? {
        try optionalString(args, name).map { try url($0, name) }
    }

    static func url(_ value: String, _ name: String) throws -> URL {
        guard hasScheme(value), let u = URL(string: value), u.scheme != nil else {
            throw AdapterError.invalid("argument '\(name)' is not an absolute URL: \(value)")
        }
        return u
    }

    /// An absolute IRI (a URL or, e.g., a DID).
    static func iri(_ value: String, _ name: String) throws -> String {
        guard hasScheme(value) else { throw AdapterError.invalid("argument '\(name)' is not an absolute IRI: \(value)") }
        return value
    }

    /// Whether a value starts with a URI scheme (`[A-Za-z][A-Za-z0-9+.-]*:`).
    static func hasScheme(_ value: String) -> Bool {
        guard let colon = value.firstIndex(of: ":"), colon != value.startIndex else { return false }
        let scheme = value[..<colon]
        return scheme.first!.isASCII && scheme.first!.isLetter
            && scheme.allSatisfy { $0.isASCII && ($0.isLetter || $0.isNumber || $0 == "+" || $0 == "." || $0 == "-") }
    }

    static func optionalBoolean(_ args: JSONObject, _ name: String) throws -> Bool? {
        guard let v = get(args, name) else { return nil }
        guard let b = v.boolValue else { throw mustBe(name, "a boolean") }
        return b
    }

    /// A non-negative integer argument (`2.0` counts as 2).
    static func optionalNonNegativeInteger(_ args: JSONObject, _ name: String) throws -> Int64? {
        guard let v = get(args, name) else { return nil }
        guard let n = v.intValue, n >= 0 else { throw mustBe(name, "a non-negative integer") }
        return n
    }

    static func requiredObject(_ args: JSONObject, _ name: String) throws -> JSONObject {
        guard let o = try optionalObject(args, name) else { throw missing(name) }
        return o
    }

    static func optionalObject(_ args: JSONObject, _ name: String) throws -> JSONObject? {
        guard let v = get(args, name) else { return nil }
        guard let o = v.objectValue else { throw mustBe(name, "an object") }
        return o
    }

    static func requiredArray(_ args: JSONObject, _ name: String) throws -> [JSONValue] {
        guard let a = try optionalArray(args, name) else { throw missing(name) }
        return a
    }

    static func optionalArray(_ args: JSONObject, _ name: String) throws -> [JSONValue]? {
        guard let v = get(args, name) else { return nil }
        guard let a = v.arrayValue else { throw mustBe(name, "an array") }
        return a
    }

    /// The strings of an array argument.
    static func strings(_ array: [JSONValue], _ name: String) throws -> [String] {
        try array.map {
            guard let s = $0.stringValue else { throw AdapterError.invalid("argument '\(name)' must be a list of strings") }
            return s
        }
    }

    /// The absolute URLs of an array argument.
    static func urls(_ array: [JSONValue], _ name: String) throws -> [URL] {
        try strings(array, name).map { try url($0, name) }
    }

    /// The optional `limit` of a lazy sequence.
    static func limit(_ args: JSONObject) throws -> Int64 {
        try optionalNonNegativeInteger(args, "limit") ?? defaultLimit
    }

    /// Strict, padded, standard base64.
    static func base64(_ value: String, _ name: String) throws -> Data {
        let alphabet = Set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/")
        let body = value.prefix { $0 != "=" }
        let padding = value.dropFirst(body.count)
        guard value.count % 4 == 0, padding.count <= 2, padding.allSatisfy({ $0 == "=" }), body.allSatisfy(alphabet.contains),
              let data = Data(base64Encoded: value)
        else { throw AdapterError.invalid("argument '\(name)' is not base64") }
        return data
    }

    /// An RFC 3339 date-time.
    static func dateTime(_ value: String, _ name: String) throws -> Date {
        let f = ISO8601DateFormatter()
        f.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        if let d = f.date(from: value) { return d }
        f.formatOptions = [.withInternetDateTime]
        if let d = f.date(from: value) { return d }
        throw AdapterError.invalid("argument '\(name)' is not an RFC 3339 date-time: \(value)")
    }

    /// A `body` argument as bytes, with the content type it implies.
    static func body(_ body: JSONValue?, _ contentType: String?) throws -> BodyArg {
        guard let body else { return BodyArg(bytes: Data(), contentType: contentType ?? "application/octet-stream") }
        guard let o = body.objectValue else { throw mustBe("body", "an object") }
        if let t = o["text"]?.stringValue { return BodyArg(bytes: Data(t.utf8), contentType: contentType ?? "text/plain") }
        if let b = o["base64"]?.stringValue {
            return BodyArg(bytes: try base64(b, "body.base64"), contentType: contentType ?? "application/octet-stream")
        }
        if let json = o["json"] { return BodyArg(bytes: json.serializedData(), contentType: contentType ?? "application/json") }
        throw AdapterError.invalid("argument 'body' must have text, base64 or json")
    }

    /// An RFC 6902 operations array, rebuilt with the library's `JSONPatch` builder.
    static func patch(_ operations: JSONValue?) throws -> JSONPatch {
        guard let array = operations?.arrayValue else { throw AdapterError.invalid("argument 'patch' must be an array of operations") }
        var patch = JSONPatch()
        for op in array {
            guard let o = op.objectValue, let kind = o["op"]?.stringValue else {
                throw AdapterError.invalid("a patch operation must be an object with an op")
            }
            switch kind {
            case "add": patch = patch.add(try pointer(o, "path", kind), try value(o, kind))
            case "remove": patch = patch.remove(try pointer(o, "path", kind))
            case "replace": patch = patch.replace(try pointer(o, "path", kind), try value(o, kind))
            case "move": patch = patch.move(from: try pointer(o, "from", kind), to: try pointer(o, "path", kind))
            case "copy": patch = patch.copy(from: try pointer(o, "from", kind), to: try pointer(o, "path", kind))
            case "test": patch = patch.test(try pointer(o, "path", kind), try value(o, kind))
            default: throw AdapterError.invalid("unknown patch operation '\(kind)'")
            }
        }
        return patch
    }

    private static func pointer(_ op: JSONObject, _ member: String, _ kind: String) throws -> String {
        guard let s = op[member]?.stringValue else { throw AdapterError.invalid("patch operation '\(kind)' needs a string '\(member)'") }
        return s
    }

    /// The `value` member; JSON `null` is a value here, only a missing member is not.
    private static func value(_ op: JSONObject, _ kind: String) throws -> JSONValue {
        guard let v = op["value"] else { throw AdapterError.invalid("patch operation '\(kind)' needs a 'value'") }
        return v
    }

    /// An `application/lws-query+json` document, rebuilt with the library's `TypeQuery` builder: a string group is
    /// `allOf(iri)` and an array group `anyOf(iris…)`, on the key's relation, in order.
    static func query(_ query: JSONValue?) throws -> TypeQuery {
        guard let o = query?.objectValue else { throw mustBe("query", "an object") }
        var q = TypeQuery()
        for member in o {
            guard let groups = member.value.arrayValue else { throw AdapterError.invalid("query member '\(member.key)' must be a list of groups") }
            for group in groups {
                switch group {
                case .string(let iri): q = try q.relation(member.key).allOf(iri)
                case .array(let iris): q = try q.relation(member.key).anyOf(try strings(iris, "query." + member.key))
                default: throw AdapterError.invalid("a group of query member '\(member.key)' must be an IRI or a list of IRIs")
                }
            }
        }
        return q
    }

    /// Parses a document argument with the library's parser; a document it rejects is a malformed argument.
    static func document<T>(_ name: String, _ parse: () throws -> T) throws -> T {
        do {
            return try parse()
        } catch LWSError.protocolError(let m) {
            throw AdapterError.invalid("argument '\(name)' is not a valid document: \(m)")
        }
    }

    private static func missing(_ name: String) -> AdapterError { AdapterError.invalid("missing argument '\(name)'") }

    private static func mustBe(_ name: String, _ what: String) -> AdapterError { AdapterError.invalid("argument '\(name)' must be \(what)") }
}
