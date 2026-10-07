// SPDX-License-Identifier: MIT
import Foundation

/// One JSON Patch operation (RFC 6902).
public struct JSONPatchOperation: Sendable, Hashable {
    /// The operation: `add`, `remove`, `replace`, `move`, `copy` or `test`.
    public let op: String
    /// The target JSON Pointer.
    public let path: String
    /// The source JSON Pointer of `move` and `copy`.
    public let from: String?
    /// The value of `add`, `replace` and `test` (`.null` is a value; nil is none).
    public let value: JSONValue?

    public init(op: String, path: String, from: String? = nil, value: JSONValue? = nil) {
        self.op = op
        self.path = path
        self.from = from
        self.value = value
    }

    /// The operation as a JSON object.
    public var json: JSONObject {
        var o: JSONObject = ["op": .string(op)]
        if let from { o["from"] = .string(from) }
        o["path"] = .string(path)
        if let value { o["value"] = value }
        return o
    }
}

/// A JSON Patch document (RFC 6902), the LWS baseline patch format (`application/json-patch+json`). Each method
/// returns a new patch with one more operation:
///
/// ```swift
/// let patch = JSONPatch().replace("/age", 31).add("/city", "Boston")
/// ```
public struct JSONPatch: Sendable, Hashable, CustomStringConvertible {
    /// The patch media type.
    public static let mediaType = MediaType.jsonPatch

    /// The operations, in order.
    public let operations: [JSONPatchOperation]

    /// A patch with these operations (none by default).
    public init(_ operations: [JSONPatchOperation] = []) {
        self.operations = operations
    }

    /// Adds an `add` operation.
    public func add(_ path: String, _ value: JSONValue) -> JSONPatch { with(JSONPatchOperation(op: "add", path: path, value: value)) }

    /// Adds a `remove` operation.
    public func remove(_ path: String) -> JSONPatch { with(JSONPatchOperation(op: "remove", path: path)) }

    /// Adds a `replace` operation.
    public func replace(_ path: String, _ value: JSONValue) -> JSONPatch {
        with(JSONPatchOperation(op: "replace", path: path, value: value))
    }

    /// Adds a `move` operation.
    public func move(from: String, to path: String) -> JSONPatch { with(JSONPatchOperation(op: "move", path: path, from: from)) }

    /// Adds a `copy` operation.
    public func copy(from: String, to path: String) -> JSONPatch { with(JSONPatchOperation(op: "copy", path: path, from: from)) }

    /// Adds a `test` operation.
    public func test(_ path: String, _ value: JSONValue) -> JSONPatch { with(JSONPatchOperation(op: "test", path: path, value: value)) }

    private func with(_ op: JSONPatchOperation) -> JSONPatch { JSONPatch(operations + [op]) }

    /// The patch as a JSON array.
    public var json: JSONValue { .array(operations.map { .object($0.json) }) }

    /// The serialized patch document (UTF-8).
    public var data: Data { json.serializedData() }

    public var description: String { json.serialized() }
}

/// JSON Pointer (RFC 6901) helpers. Escaping matters for linkset patches, whose relation keys are often URIs:
/// `JSONPointer.from(["linkset", "0", "https://example.org/rel", "-"])` is `/linkset/0/https:~1~1example.org~1rel/-`.
public enum JSONPointer {
    /// Escapes one reference token: `~` becomes `~0` and `/` becomes `~1`.
    public static func escape(_ segment: String) -> String {
        segment.replacingOccurrences(of: "~", with: "~0").replacingOccurrences(of: "/", with: "~1")
    }

    /// Reverses ``escape(_:)``.
    public static func unescape(_ token: String) -> String {
        token.replacingOccurrences(of: "~1", with: "/").replacingOccurrences(of: "~0", with: "~")
    }

    /// Builds a pointer from unescaped segments; no segments is the whole-document pointer `""`.
    public static func from<S: Sequence>(_ segments: S) -> String where S.Element == String {
        segments.map { "/" + escape($0) }.joined()
    }

    /// Builds a pointer from unescaped segments.
    public static func from(_ segments: String...) -> String {
        from(segments)
    }

    /// Splits a pointer into unescaped segments.
    /// - Throws: ``LWSError/invalidArgument(_:)`` when the pointer does not start with `/`.
    public static func parse(_ pointer: String) throws -> [String] {
        if pointer.isEmpty { return [] }
        guard pointer.hasPrefix("/") else { throw LWSError.invalidArgument("A JSON Pointer must start with '/': \(pointer)") }
        return pointer.dropFirst().split(separator: "/", omittingEmptySubsequences: false).map { unescape(String($0)) }
    }
}
