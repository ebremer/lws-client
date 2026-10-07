// SPDX-License-Identifier: MIT
import Foundation

/// A bare item of a structured field (RFC 8941 / RFC 9651).
public enum SFBareItem: Sendable, Hashable {
    /// An integer (at most 15 digits).
    case integer(Int64)
    /// A decimal (at most 12 integer and 3 fraction digits).
    case decimal(Double)
    /// A string (printable ASCII).
    case string(String)
    /// A token.
    case token(String)
    /// A byte sequence (`:base64:`).
    case byteSequence(Data)
    /// A boolean (`?1` / `?0`).
    case boolean(Bool)
    /// A date (RFC 9651): seconds since the epoch.
    case date(Int64)
    /// A display string (RFC 9651): Unicode text.
    case displayString(String)

    /// The string, when this is a string.
    public var stringValue: String? {
        if case .string(let s) = self { return s }
        return nil
    }

    /// The integer, when this is an integer.
    public var integerValue: Int64? {
        if case .integer(let i) = self { return i }
        return nil
    }

    /// The bytes, when this is a byte sequence.
    public var bytesValue: Data? {
        if case .byteSequence(let d) = self { return d }
        return nil
    }
}

/// Ordered parameters of a structured field item or inner list. A repeated key keeps its first position and
/// takes the last value.
public struct SFParameters: Sendable, Hashable, Sequence, ExpressibleByDictionaryLiteral {
    /// One parameter.
    public struct Entry: Sendable, Hashable {
        public var key: String
        public var value: SFBareItem
    }

    /// The parameters, in order.
    public private(set) var entries: [Entry] = []

    public init() {}

    public init(dictionaryLiteral elements: (String, SFBareItem)...) {
        for (k, v) in elements { self[k] = v }
    }

    /// A parameter's value; assigning replaces it in place, or appends it.
    public subscript(key: String) -> SFBareItem? {
        get { entries.first { $0.key == key }?.value }
        set {
            if let idx = entries.firstIndex(where: { $0.key == key }) {
                if let newValue { entries[idx].value = newValue } else { entries.remove(at: idx) }
            } else if let newValue {
                entries.append(Entry(key: key, value: newValue))
            }
        }
    }

    /// The number of parameters.
    public var count: Int { entries.count }

    /// Whether there are none.
    public var isEmpty: Bool { entries.isEmpty }

    public func makeIterator() -> IndexingIterator<[Entry]> { entries.makeIterator() }
}

/// An item: a bare item with parameters.
public struct SFItem: Sendable, Hashable {
    public var value: SFBareItem
    public var parameters: SFParameters

    public init(_ value: SFBareItem, parameters: SFParameters = SFParameters()) {
        self.value = value
        self.parameters = parameters
    }
}

/// An inner list of items, with parameters.
public struct SFInnerList: Sendable, Hashable {
    public var items: [SFItem]
    public var parameters: SFParameters

    public init(_ items: [SFItem], parameters: SFParameters = SFParameters()) {
        self.items = items
        self.parameters = parameters
    }
}

/// A member of a dictionary or list: an item or an inner list.
public enum SFMember: Sendable, Hashable {
    case item(SFItem)
    case innerList(SFInnerList)

    /// The member's parameters.
    public var parameters: SFParameters {
        switch self {
        case .item(let i): return i.parameters
        case .innerList(let l): return l.parameters
        }
    }
}

/// An ordered structured field dictionary. A repeated key keeps its first position and takes the last value.
public struct SFDictionary: Sendable, Hashable, Sequence {
    /// One member.
    public struct Entry: Sendable, Hashable {
        public var key: String
        public var member: SFMember
    }

    /// The members, in order.
    public private(set) var entries: [Entry] = []

    public init() {}

    /// A member by key; assigning replaces it in place, or appends it.
    public subscript(key: String) -> SFMember? {
        get { entries.first { $0.key == key }?.member }
        set {
            if let idx = entries.firstIndex(where: { $0.key == key }) {
                if let newValue { entries[idx].member = newValue } else { entries.remove(at: idx) }
            } else if let newValue {
                entries.append(Entry(key: key, member: newValue))
            }
        }
    }

    /// The keys, in order.
    public var keys: [String] { entries.map(\.key) }

    /// The number of members.
    public var count: Int { entries.count }

    public func makeIterator() -> IndexingIterator<[Entry]> { entries.makeIterator() }
}

/// Input that is not a valid structured field, or a value that cannot be serialized as one.
public struct StructuredFieldError: Error, Sendable, CustomStringConvertible {
    public let message: String
    public var description: String { message }
}

/// Structured Field Values (RFC 8941 / RFC 9651): dictionaries, lists, items, inner lists and parameters, as
/// used by `Signature-Input`, `Signature` and `Content-Digest`.
public enum StructuredFields {
    /// Parses a dictionary (RFC 8941 section 4.2.2). Join several field lines with `", "` first.
    public static func parseDictionary(_ input: String) throws -> SFDictionary {
        var p = Parser(input)
        p.skipSP()
        let d = try p.dictionary()
        p.skipSP()
        guard p.eof else { throw StructuredFieldError(message: "Trailing characters in structured field") }
        return d
    }

    /// Parses a list (RFC 8941 section 4.2.1).
    public static func parseList(_ input: String) throws -> [SFMember] {
        var p = Parser(input)
        p.skipSP()
        var out: [SFMember] = []
        while !p.eof {
            out.append(try p.itemOrInnerList())
            p.skipOWS()
            if p.eof { break }
            try p.expect(",")
            p.skipOWS()
            if p.eof { throw StructuredFieldError(message: "Trailing comma in list") }
        }
        return out
    }

    /// Parses an item (RFC 8941 section 4.2.3).
    public static func parseItem(_ input: String) throws -> SFItem {
        var p = Parser(input)
        p.skipSP()
        let item = try p.item()
        p.skipSP()
        guard p.eof else { throw StructuredFieldError(message: "Trailing characters in structured field") }
        return item
    }

    private struct Parser {
        let s: [UInt8]
        var i = 0

        init(_ input: String) {
            s = Array(input.utf8)
        }

        var eof: Bool { i >= s.count }

        func fail(_ message: String) -> StructuredFieldError {
            StructuredFieldError(message: "\(message) at \(i)")
        }

        mutating func expect(_ c: Character) throws {
            guard !eof, s[i] == c.asciiValue! else { throw fail("Expected '\(c)'") }
            i += 1
        }

        mutating func skipSP() {
            while !eof, s[i] == 0x20 { i += 1 }
        }

        mutating func skipOWS() {
            while !eof, s[i] == 0x20 || s[i] == 0x09 { i += 1 }
        }

        mutating func dictionary() throws -> SFDictionary {
            var d = SFDictionary()
            while !eof {
                let key = try key()
                let member: SFMember
                if !eof, s[i] == UInt8(ascii: "=") {
                    i += 1
                    member = try itemOrInnerList()
                } else {
                    member = .item(SFItem(.boolean(true), parameters: try parameters()))
                }
                d[key] = member
                skipOWS()
                if eof { break }
                try expect(",")
                skipOWS()
                if eof { throw StructuredFieldError(message: "Trailing comma in dictionary") }
            }
            return d
        }

        mutating func itemOrInnerList() throws -> SFMember {
            if !eof, s[i] == UInt8(ascii: "(") { return .innerList(try innerList()) }
            return .item(try item())
        }

        private mutating func innerList() throws -> SFInnerList {
            try expect("(")
            var items: [SFItem] = []
            while !eof {
                skipSP()
                if eof { break }
                if s[i] == UInt8(ascii: ")") {
                    i += 1
                    return SFInnerList(items, parameters: try parameters())
                }
                items.append(try item())
                if eof { break }
                guard s[i] == 0x20 || s[i] == UInt8(ascii: ")") else { throw fail("Invalid inner list") }
            }
            throw StructuredFieldError(message: "Unterminated inner list")
        }

        mutating func item() throws -> SFItem {
            let bare = try bareItem()
            return SFItem(bare, parameters: try parameters())
        }

        private mutating func parameters() throws -> SFParameters {
            var p = SFParameters()
            while !eof, s[i] == UInt8(ascii: ";") {
                i += 1
                skipSP()
                let k = try key()
                var v = SFBareItem.boolean(true)
                if !eof, s[i] == UInt8(ascii: "=") {
                    i += 1
                    v = try bareItem()
                }
                p[k] = v
            }
            return p
        }

        private mutating func key() throws -> String {
            guard !eof else { throw fail("Expected a key") }
            guard isLCAlpha(s[i]) || s[i] == UInt8(ascii: "*") else { throw fail("Invalid key") }
            let start = i
            while !eof, isLCAlpha(s[i]) || isDigit(s[i]) || "_-.*".utf8.contains(s[i]) { i += 1 }
            return String(decoding: s[start..<i], as: UTF8.self)
        }

        private func isLCAlpha(_ b: UInt8) -> Bool { b >= UInt8(ascii: "a") && b <= UInt8(ascii: "z") }
        private func isAlpha(_ b: UInt8) -> Bool { isLCAlpha(b) || (b >= UInt8(ascii: "A") && b <= UInt8(ascii: "Z")) }
        private func isDigit(_ b: UInt8) -> Bool { b >= UInt8(ascii: "0") && b <= UInt8(ascii: "9") }

        private mutating func bareItem() throws -> SFBareItem {
            guard !eof else { throw fail("Expected a bare item") }
            let c = s[i]
            if c == UInt8(ascii: "-") || isDigit(c) { return try number() }
            if c == UInt8(ascii: "\"") { return .string(try string()) }
            if c == UInt8(ascii: "*") || isAlpha(c) { return .token(token()) }
            if c == UInt8(ascii: ":") { return .byteSequence(try bytes()) }
            if c == UInt8(ascii: "?") { return .boolean(try boolean()) }
            if c == UInt8(ascii: "@") {
                i += 1
                guard case .integer(let n) = try number() else { throw fail("A date must be an integer") }
                return .date(n)
            }
            if c == UInt8(ascii: "%") { return .displayString(try displayString()) }
            throw fail("Unexpected character")
        }

        private mutating func number() throws -> SFBareItem {
            let start = i
            if s[i] == UInt8(ascii: "-") { i += 1 }
            guard !eof, isDigit(s[i]) else { throw fail("Expected a digit") }
            var isDecimal = false
            let digitsStart = i
            var intDigits = -1
            while !eof {
                let c = s[i]
                if isDigit(c) {
                    i += 1
                } else if c == UInt8(ascii: "."), !isDecimal {
                    intDigits = i - digitsStart
                    if intDigits > 12 { throw StructuredFieldError(message: "Decimal integer part too long") }
                    isDecimal = true
                    i += 1
                } else {
                    break
                }
                let len = i - digitsStart
                if !isDecimal, len > 15 { throw StructuredFieldError(message: "Integer too long") }
                if isDecimal, len > 16 { throw StructuredFieldError(message: "Decimal too long") }
            }
            let text = String(decoding: s[start..<i], as: UTF8.self)
            if !isDecimal {
                guard let n = Int64(text) else { throw fail("Invalid integer") }
                return .integer(n)
            }
            if text.hasSuffix(".") { throw StructuredFieldError(message: "Decimal ends with '.'") }
            let frac = i - digitsStart - intDigits - 1
            if frac > 3 { throw StructuredFieldError(message: "Decimal fraction too long") }
            guard let d = Double(text) else { throw fail("Invalid decimal") }
            return .decimal(d)
        }

        private mutating func string() throws -> String {
            try expect("\"")
            var out: [UInt8] = []
            while !eof {
                let c = s[i]
                i += 1
                if c == UInt8(ascii: "\\") {
                    guard !eof else { throw StructuredFieldError(message: "Unterminated escape") }
                    let n = s[i]
                    i += 1
                    guard n == UInt8(ascii: "\"") || n == UInt8(ascii: "\\") else { throw StructuredFieldError(message: "Invalid escape") }
                    out.append(n)
                } else if c == UInt8(ascii: "\"") {
                    return String(decoding: out, as: UTF8.self)
                } else if c < 0x20 || c > 0x7E {
                    throw StructuredFieldError(message: "Invalid string character")
                } else {
                    out.append(c)
                }
            }
            throw StructuredFieldError(message: "Unterminated string")
        }

        private mutating func token() -> String {
            let start = i
            i += 1
            while !eof, LinkHeader.isTokenChar(Unicode.Scalar(s[i])) || s[i] == UInt8(ascii: ":") || s[i] == UInt8(ascii: "/") { i += 1 }
            return String(decoding: s[start..<i], as: UTF8.self)
        }

        private mutating func bytes() throws -> Data {
            try expect(":")
            guard let end = s[i...].firstIndex(of: UInt8(ascii: ":")) else { throw StructuredFieldError(message: "Unterminated byte sequence") }
            let b64 = s[i..<end]
            for c in b64 where !(isAlpha(c) || isDigit(c) || c == UInt8(ascii: "+") || c == UInt8(ascii: "/") || c == UInt8(ascii: "=")) {
                throw StructuredFieldError(message: "Invalid base64 in byte sequence")
            }
            i = end + 1
            guard let data = Data(base64Encoded: String(decoding: b64, as: UTF8.self)) else {
                throw StructuredFieldError(message: "Invalid base64 in byte sequence")
            }
            return data
        }

        private mutating func boolean() throws -> Bool {
            try expect("?")
            guard !eof else { throw StructuredFieldError(message: "Expected a boolean") }
            let c = s[i]
            i += 1
            switch c {
            case UInt8(ascii: "1"): return true
            case UInt8(ascii: "0"): return false
            default: throw StructuredFieldError(message: "Invalid boolean")
            }
        }

        private mutating func displayString() throws -> String {
            try expect("%")
            try expect("\"")
            var out: [UInt8] = []
            while !eof {
                let c = s[i]
                i += 1
                if c == UInt8(ascii: "%") {
                    guard i + 2 <= s.count, let h = UInt8(String(decoding: s[i..<(i + 2)], as: UTF8.self), radix: 16),
                          s[i..<(i + 2)].allSatisfy({ isDigit($0) || ($0 >= UInt8(ascii: "a") && $0 <= UInt8(ascii: "f")) })
                    else { throw StructuredFieldError(message: "Invalid percent-encoding") }
                    out.append(h)
                    i += 2
                } else if c == UInt8(ascii: "\"") {
                    guard let text = String(bytes: out, encoding: .utf8) else {
                        throw StructuredFieldError(message: "Invalid UTF-8 in display string")
                    }
                    return text
                } else if c < 0x20 || c > 0x7E {
                    throw StructuredFieldError(message: "Invalid display string character")
                } else {
                    out.append(c)
                }
            }
            throw StructuredFieldError(message: "Unterminated display string")
        }
    }

    /// Serializes a member (an item or an inner list, with parameters) canonically, e.g.
    /// `("@method" "@path");created=1;keyid="k"`.
    public static func serialize(_ member: SFMember) throws -> String {
        switch member {
        case .item(let item): return try serialize(item)
        case .innerList(let list): return try serialize(list)
        }
    }

    /// Serializes an inner list canonically.
    public static func serialize(_ list: SFInnerList) throws -> String {
        var s = "(" + (try list.items.map(serialize).joined(separator: " ")) + ")"
        s += try serialize(list.parameters)
        return s
    }

    /// Serializes an item canonically.
    public static func serialize(_ item: SFItem) throws -> String {
        try serializeBareItem(item.value) + serialize(item.parameters)
    }

    /// Serializes a dictionary canonically.
    public static func serialize(_ dictionary: SFDictionary) throws -> String {
        try dictionary.map { e -> String in
            if case .item(let item) = e.member, item.value == .boolean(true) {
                return e.key + (try serialize(item.parameters))
            }
            return e.key + "=" + (try serialize(e.member))
        }.joined(separator: ", ")
    }

    private static func serialize(_ parameters: SFParameters) throws -> String {
        var s = ""
        for p in parameters {
            s += ";" + p.key
            if p.value != .boolean(true) { s += "=" + (try serializeBareItem(p.value)) }
        }
        return s
    }

    /// Serializes a bare item.
    public static func serializeBareItem(_ value: SFBareItem) throws -> String {
        switch value {
        case .integer(let n):
            return String(n)
        case .decimal(let d):
            let r = (d * 1000).rounded(.toNearestOrEven) / 1000
            var t = String(format: "%.3f", r)
            while t.hasSuffix("0"), !t.hasSuffix(".0") { t.removeLast() }
            return t
        case .string(let str):
            var s = "\""
            for u in str.unicodeScalars {
                guard u.value >= 0x20, u.value <= 0x7E else { throw StructuredFieldError(message: "Invalid character in an sf-string") }
                if u == "\"" || u == "\\" { s += "\\" }
                s.unicodeScalars.append(u)
            }
            return s + "\""
        case .token(let t):
            return t
        case .byteSequence(let b):
            return ":" + b.base64EncodedString() + ":"
        case .boolean(let flag):
            return flag ? "?1" : "?0"
        case .date(let n):
            return "@" + String(n)
        case .displayString(let text):
            var s = "%\""
            for b in text.utf8 {
                if b == UInt8(ascii: "%") || b == UInt8(ascii: "\"") || b < 0x20 || b > 0x7E {
                    s += "%" + (b < 0x10 ? "0" : "") + String(b, radix: 16)
                } else {
                    s.unicodeScalars.append(Unicode.Scalar(b))
                }
            }
            return s + "\""
        }
    }
}
