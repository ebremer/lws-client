// SPDX-License-Identifier: MIT
import Foundation

/// A JSON value (RFC 8259).
///
/// Objects keep their members in document order, so documents round-trip unchanged: the models of this
/// library keep the JSON they were parsed from (`raw`), and linksets and access documents preserve members
/// they do not know. Integers that fit in 64 bits stay exact (``int(_:)``); other numbers are ``double(_:)``.
/// Two numbers are equal when their values are, whichever case holds them.
///
/// ```swift
/// let profile: JSONValue = ["name": "Alice", "age": 30]
/// let parsed = try JSONValue(parsing: #"{"name":"Alice","age":30}"#)
/// assert(parsed == profile && parsed["age"]?.intValue == 30)
/// ```
public enum JSONValue: Sendable, Hashable {
    /// `null`.
    case null
    /// `true` or `false`.
    case bool(Bool)
    /// A number without a fraction or exponent that fits in 64 bits.
    case int(Int64)
    /// Any other number.
    case double(Double)
    /// A string.
    case string(String)
    /// An array.
    case array([JSONValue])
    /// An object, with its members in order.
    case object(JSONObject)

    /// Parses a JSON text (UTF-8, an optional byte order mark is skipped).
    /// - Throws: ``JSONParseError`` when the text is not valid JSON.
    public init(parsing data: Data) throws {
        var parser = JSONParser(Array(data))
        self = try parser.parseDocument()
    }

    /// Parses a JSON text.
    /// - Throws: ``JSONParseError`` when the text is not valid JSON.
    public init(parsing text: String) throws {
        var parser = JSONParser(Array(text.utf8))
        self = try parser.parseDocument()
    }

    /// The string, when this is a string.
    public var stringValue: String? {
        if case .string(let s) = self { return s }
        return nil
    }

    /// The boolean, when this is a boolean.
    public var boolValue: Bool? {
        if case .bool(let b) = self { return b }
        return nil
    }

    /// The number as an integer, when it is one (an integral ``double(_:)`` included).
    public var intValue: Int64? {
        switch self {
        case .int(let i): return i
        case .double(let d) where d.rounded() == d && abs(d) < 9.2e18: return Int64(d)
        default: return nil
        }
    }

    /// The number, when this is a number.
    public var doubleValue: Double? {
        switch self {
        case .int(let i): return Double(i)
        case .double(let d): return d
        default: return nil
        }
    }

    /// The elements, when this is an array.
    public var arrayValue: [JSONValue]? {
        if case .array(let a) = self { return a }
        return nil
    }

    /// The members, when this is an object.
    public var objectValue: JSONObject? {
        if case .object(let o) = self { return o }
        return nil
    }

    /// Whether this is `null`.
    public var isNull: Bool {
        if case .null = self { return true }
        return false
    }

    /// Whether this is a number.
    public var isNumber: Bool {
        switch self {
        case .int, .double: return true
        default: return false
        }
    }

    /// A member of an object (nil when absent, or when this is not an object).
    public subscript(key: String) -> JSONValue? {
        objectValue?[key]
    }

    /// An element of an array (nil when out of range, or when this is not an array).
    public subscript(index: Int) -> JSONValue? {
        guard case .array(let a) = self, a.indices.contains(index) else { return nil }
        return a[index]
    }

    /// The compact serialization: no insignificant whitespace, `/` and non-ASCII characters unescaped.
    public func serialized(pretty: Bool = false) -> String {
        var out = ""
        JSONWriter.write(self, into: &out, pretty: pretty, indent: 0)
        return out
    }

    /// The compact serialization, UTF-8 encoded.
    public func serializedData() -> Data {
        Data(serialized().utf8)
    }

    public static func == (lhs: JSONValue, rhs: JSONValue) -> Bool {
        switch (lhs, rhs) {
        case (.null, .null): return true
        case (.bool(let a), .bool(let b)): return a == b
        case (.int(let a), .int(let b)): return a == b
        case (.double(let a), .double(let b)): return a == b
        case (.int(let a), .double(let b)), (.double(let b), .int(let a)): return Double(a) == b
        case (.string(let a), .string(let b)): return a == b
        case (.array(let a), .array(let b)): return a == b
        case (.object(let a), .object(let b)): return a == b
        default: return false
        }
    }

    public func hash(into hasher: inout Hasher) {
        switch self {
        case .null: hasher.combine(0)
        case .bool(let b): hasher.combine(1); hasher.combine(b)
        case .int(let i): hasher.combine(2); hasher.combine(Double(i))
        case .double(let d): hasher.combine(2); hasher.combine(d)
        case .string(let s): hasher.combine(3); hasher.combine(s)
        case .array(let a): hasher.combine(4); hasher.combine(a)
        case .object(let o): hasher.combine(5); hasher.combine(o)
        }
    }
}

extension JSONValue: CustomStringConvertible {
    public var description: String { serialized() }
}

extension JSONValue: ExpressibleByNilLiteral, ExpressibleByBooleanLiteral, ExpressibleByIntegerLiteral,
    ExpressibleByFloatLiteral, ExpressibleByStringLiteral, ExpressibleByArrayLiteral, ExpressibleByDictionaryLiteral
{
    public init(nilLiteral: ()) { self = .null }
    public init(booleanLiteral value: Bool) { self = .bool(value) }
    public init(integerLiteral value: Int64) { self = .int(value) }
    public init(floatLiteral value: Double) { self = .double(value) }
    public init(stringLiteral value: String) { self = .string(value) }
    public init(arrayLiteral elements: JSONValue...) { self = .array(elements) }
    public init(dictionaryLiteral elements: (String, JSONValue)...) { self = .object(JSONObject(elements)) }
}

extension JSONValue {
    /// A JSON string.
    public init(_ value: String) { self = .string(value) }
    /// A JSON number.
    public init(_ value: Int) { self = .int(Int64(value)) }
    /// A JSON number.
    public init(_ value: Double) { self = .double(value) }
    /// A JSON boolean.
    public init(_ value: Bool) { self = .bool(value) }
    /// A JSON array of strings.
    public init(_ values: [String]) { self = .array(values.map { .string($0) }) }
}

/// A JSON object: string keys with values, kept in insertion (document) order.
///
/// Setting a key that exists keeps its position; setting `nil` removes it. Equality ignores member order, as
/// JSON does.
public struct JSONObject: Sendable, Hashable, RandomAccessCollection, ExpressibleByDictionaryLiteral {
    private var order: [String]
    private var members: [String: JSONValue]

    /// An empty object.
    public init() {
        order = []
        members = [:]
    }

    /// An object with these members, in order (a repeated key keeps its first position and its last value).
    public init<S: Sequence>(_ members: S) where S.Element == (String, JSONValue) {
        self.init()
        for (k, v) in members { self[k] = v }
    }

    public init(dictionaryLiteral elements: (String, JSONValue)...) {
        self.init(elements)
    }

    /// The number of members.
    public var count: Int { order.count }

    /// Whether there are no members.
    public var isEmpty: Bool { order.isEmpty }

    public var startIndex: Int { 0 }
    public var endIndex: Int { order.count }

    /// The member at a position, in order.
    public subscript(position: Int) -> (key: String, value: JSONValue) {
        (key: order[position], value: members[order[position]]!)
    }

    /// The keys, in order.
    public var keys: [String] { order }

    /// A member's value; assigning `nil` removes the member.
    public subscript(key: String) -> JSONValue? {
        get { members[key] }
        set {
            if let newValue {
                if members.updateValue(newValue, forKey: key) == nil { order.append(key) }
            } else {
                removeValue(forKey: key)
            }
        }
    }

    /// Removes a member, returning its value.
    @discardableResult
    public mutating func removeValue(forKey key: String) -> JSONValue? {
        guard let v = members.removeValue(forKey: key) else { return nil }
        order.removeAll { $0 == key }
        return v
    }

    /// Whether the object has a member named `key`.
    public func contains(_ key: String) -> Bool { members[key] != nil }

    public static func == (lhs: JSONObject, rhs: JSONObject) -> Bool {
        lhs.members == rhs.members
    }

    public func hash(into hasher: inout Hasher) {
        hasher.combine(members.count)
        for k in order.sorted() {
            hasher.combine(k)
            hasher.combine(members[k])
        }
    }
}

extension JSONObject: CustomStringConvertible {
    public var description: String { JSONValue.object(self).serialized() }
}

/// A JSON text that does not parse.
public struct JSONParseError: Error, Sendable, CustomStringConvertible {
    /// What is wrong.
    public let message: String
    /// The byte offset where parsing stopped.
    public let offset: Int

    public var description: String { "\(message) at byte \(offset)" }
}

// MARK: - Parser

struct JSONParser {
    private let bytes: [UInt8]
    private var i = 0
    private var depth = 0
    private static let maxDepth = 512

    init(_ bytes: [UInt8]) {
        self.bytes = bytes
    }

    mutating func parseDocument() throws -> JSONValue {
        if bytes.count >= 3, bytes[0] == 0xEF, bytes[1] == 0xBB, bytes[2] == 0xBF { i = 3 }
        skipWhitespace()
        let v = try value()
        skipWhitespace()
        if i != bytes.count { throw fail("Unexpected content after the JSON value") }
        return v
    }

    private func fail(_ message: String) -> JSONParseError {
        JSONParseError(message: message, offset: i)
    }

    private mutating func skipWhitespace() {
        while i < bytes.count, bytes[i] == 0x20 || bytes[i] == 0x0A || bytes[i] == 0x0D || bytes[i] == 0x09 { i += 1 }
    }

    private mutating func value() throws -> JSONValue {
        guard i < bytes.count else { throw fail("Unexpected end of JSON") }
        switch bytes[i] {
        case UInt8(ascii: "{"): return try object()
        case UInt8(ascii: "["): return try array()
        case UInt8(ascii: "\""): return .string(try string())
        case UInt8(ascii: "t"): try literal("true"); return .bool(true)
        case UInt8(ascii: "f"): try literal("false"); return .bool(false)
        case UInt8(ascii: "n"): try literal("null"); return .null
        case UInt8(ascii: "-"), UInt8(ascii: "0")...UInt8(ascii: "9"): return try number()
        default: throw fail("Unexpected character")
        }
    }

    private mutating func literal(_ word: String) throws {
        for b in word.utf8 {
            guard i < bytes.count, bytes[i] == b else { throw fail("Invalid literal") }
            i += 1
        }
    }

    private mutating func enter() throws {
        depth += 1
        if depth > Self.maxDepth { throw fail("JSON nested too deeply") }
    }

    private mutating func object() throws -> JSONValue {
        try enter()
        i += 1
        var o = JSONObject()
        skipWhitespace()
        if i < bytes.count, bytes[i] == UInt8(ascii: "}") {
            i += 1
            depth -= 1
            return .object(o)
        }
        while true {
            skipWhitespace()
            guard i < bytes.count, bytes[i] == UInt8(ascii: "\"") else { throw fail("Expected a member name") }
            let key = try string()
            skipWhitespace()
            guard i < bytes.count, bytes[i] == UInt8(ascii: ":") else { throw fail("Expected ':'") }
            i += 1
            skipWhitespace()
            o[key] = try value()
            skipWhitespace()
            guard i < bytes.count else { throw fail("Unterminated object") }
            if bytes[i] == UInt8(ascii: ",") {
                i += 1
                continue
            }
            if bytes[i] == UInt8(ascii: "}") {
                i += 1
                depth -= 1
                return .object(o)
            }
            throw fail("Expected ',' or '}'")
        }
    }

    private mutating func array() throws -> JSONValue {
        try enter()
        i += 1
        var a: [JSONValue] = []
        skipWhitespace()
        if i < bytes.count, bytes[i] == UInt8(ascii: "]") {
            i += 1
            depth -= 1
            return .array(a)
        }
        while true {
            skipWhitespace()
            a.append(try value())
            skipWhitespace()
            guard i < bytes.count else { throw fail("Unterminated array") }
            if bytes[i] == UInt8(ascii: ",") {
                i += 1
                continue
            }
            if bytes[i] == UInt8(ascii: "]") {
                i += 1
                depth -= 1
                return .array(a)
            }
            throw fail("Expected ',' or ']'")
        }
    }

    private mutating func hex4() throws -> UInt32 {
        guard i + 4 <= bytes.count else { throw fail("Invalid \\u escape") }
        var v: UInt32 = 0
        for _ in 0..<4 {
            let c = bytes[i]
            let d: UInt32
            switch c {
            case UInt8(ascii: "0")...UInt8(ascii: "9"): d = UInt32(c - UInt8(ascii: "0"))
            case UInt8(ascii: "a")...UInt8(ascii: "f"): d = UInt32(c - UInt8(ascii: "a") + 10)
            case UInt8(ascii: "A")...UInt8(ascii: "F"): d = UInt32(c - UInt8(ascii: "A") + 10)
            default: throw fail("Invalid \\u escape")
            }
            v = v << 4 | d
            i += 1
        }
        return v
    }

    private mutating func string() throws -> String {
        i += 1
        var buffer: [UInt8] = []
        var plainStart = i
        while true {
            guard i < bytes.count else { throw fail("Unterminated string") }
            let c = bytes[i]
            if c == UInt8(ascii: "\"") {
                buffer.append(contentsOf: bytes[plainStart..<i])
                i += 1
                break
            }
            if c < 0x20 { throw fail("Control character in string") }
            if c != UInt8(ascii: "\\") {
                i += 1
                continue
            }
            buffer.append(contentsOf: bytes[plainStart..<i])
            i += 1
            guard i < bytes.count else { throw fail("Unterminated escape") }
            let e = bytes[i]
            i += 1
            switch e {
            case UInt8(ascii: "\""): buffer.append(0x22)
            case UInt8(ascii: "\\"): buffer.append(0x5C)
            case UInt8(ascii: "/"): buffer.append(0x2F)
            case UInt8(ascii: "b"): buffer.append(0x08)
            case UInt8(ascii: "f"): buffer.append(0x0C)
            case UInt8(ascii: "n"): buffer.append(0x0A)
            case UInt8(ascii: "r"): buffer.append(0x0D)
            case UInt8(ascii: "t"): buffer.append(0x09)
            case UInt8(ascii: "u"):
                var scalar = try hex4()
                if (0xD800...0xDBFF).contains(scalar) {
                    // A high surrogate needs its low surrogate; a lone one becomes U+FFFD.
                    let save = i
                    if i + 6 <= bytes.count, bytes[i] == UInt8(ascii: "\\"), bytes[i + 1] == UInt8(ascii: "u") {
                        i += 2
                        let low = try hex4()
                        if (0xDC00...0xDFFF).contains(low) {
                            scalar = 0x10000 + ((scalar - 0xD800) << 10) + (low - 0xDC00)
                        } else {
                            i = save
                            scalar = 0xFFFD
                        }
                    } else {
                        scalar = 0xFFFD
                    }
                } else if (0xDC00...0xDFFF).contains(scalar) {
                    scalar = 0xFFFD
                }
                buffer.append(contentsOf: String(Unicode.Scalar(scalar)!).utf8)
            default:
                throw fail("Invalid escape")
            }
            plainStart = i
        }
        guard let s = String(bytes: buffer, encoding: .utf8) else { throw fail("Invalid UTF-8 in string") }
        return s
    }

    private mutating func number() throws -> JSONValue {
        let start = i
        if bytes[i] == UInt8(ascii: "-") { i += 1 }
        guard i < bytes.count, isDigit(bytes[i]) else { throw fail("Invalid number") }
        if bytes[i] == UInt8(ascii: "0") {
            i += 1
        } else {
            while i < bytes.count, isDigit(bytes[i]) { i += 1 }
        }
        var integral = true
        if i < bytes.count, bytes[i] == UInt8(ascii: ".") {
            integral = false
            i += 1
            guard i < bytes.count, isDigit(bytes[i]) else { throw fail("Invalid number") }
            while i < bytes.count, isDigit(bytes[i]) { i += 1 }
        }
        if i < bytes.count, bytes[i] == UInt8(ascii: "e") || bytes[i] == UInt8(ascii: "E") {
            integral = false
            i += 1
            if i < bytes.count, bytes[i] == UInt8(ascii: "+") || bytes[i] == UInt8(ascii: "-") { i += 1 }
            guard i < bytes.count, isDigit(bytes[i]) else { throw fail("Invalid number") }
            while i < bytes.count, isDigit(bytes[i]) { i += 1 }
        }
        let text = String(decoding: bytes[start..<i], as: UTF8.self)
        if integral, let n = Int64(text) { return .int(n) }
        guard let d = Double(text) else { throw fail("Invalid number") }
        return .double(d)
    }

    private func isDigit(_ b: UInt8) -> Bool {
        b >= UInt8(ascii: "0") && b <= UInt8(ascii: "9")
    }
}

// MARK: - Writer

enum JSONWriter {
    static func write(_ v: JSONValue, into out: inout String, pretty: Bool, indent: Int) {
        switch v {
        case .null: out += "null"
        case .bool(let b): out += b ? "true" : "false"
        case .int(let n): out += String(n)
        case .double(let d): out += format(d)
        case .string(let s): writeString(s, into: &out)
        case .array(let a):
            if a.isEmpty {
                out += "[]"
                return
            }
            out += "["
            for (n, e) in a.enumerated() {
                if n > 0 { out += "," }
                if pretty { newline(&out, indent + 1) }
                write(e, into: &out, pretty: pretty, indent: indent + 1)
            }
            if pretty { newline(&out, indent) }
            out += "]"
        case .object(let o):
            if o.isEmpty {
                out += "{}"
                return
            }
            out += "{"
            for (n, m) in o.enumerated() {
                if n > 0 { out += "," }
                if pretty { newline(&out, indent + 1) }
                writeString(m.key, into: &out)
                out += pretty ? ": " : ":"
                write(m.value, into: &out, pretty: pretty, indent: indent + 1)
            }
            if pretty { newline(&out, indent) }
            out += "}"
        }
    }

    private static func newline(_ out: inout String, _ indent: Int) {
        out += "\n" + String(repeating: "  ", count: indent)
    }

    static func format(_ d: Double) -> String {
        guard d.isFinite else { return "null" }
        if d.rounded() == d, abs(d) < 1e15 { return String(Int64(d)) }
        return String(d)
    }

    static func writeString(_ s: String, into out: inout String) {
        out += "\""
        for u in s.unicodeScalars {
            switch u {
            case "\"": out += "\\\""
            case "\\": out += "\\\\"
            case "\n": out += "\\n"
            case "\r": out += "\\r"
            case "\t": out += "\\t"
            case "\u{08}": out += "\\b"
            case "\u{0C}": out += "\\f"
            default:
                if u.value < 0x20 {
                    out += "\\u00" + (u.value < 0x10 ? "0" : "") + String(u.value, radix: 16)
                } else {
                    out.unicodeScalars.append(u)
                }
            }
        }
        out += "\""
    }
}
