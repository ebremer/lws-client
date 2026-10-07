// SPDX-License-Identifier: MIT
import Foundation

/// JSON helpers shared by the models (internal).
enum LWSJSON {
    /// Parses JSON; malformed input is a ``LWSError/protocolError(_:)``.
    static func parse(_ data: Data, _ what: String) throws -> JSONValue {
        do {
            return try JSONValue(parsing: data)
        } catch let e as JSONParseError {
            throw LWSError.protocolError("\(what) is not valid JSON: \(e)")
        }
    }

    /// Parses JSON text; malformed input is a ``LWSError/protocolError(_:)``.
    static func parse(_ text: String, _ what: String) throws -> JSONValue {
        try parse(Data(text.utf8), what)
    }

    /// Requires a JSON object.
    static func object(_ value: JSONValue, _ what: String) throws -> JSONObject {
        guard case .object(let o) = value else { throw LWSError.protocolError("\(what) is not a JSON object") }
        return o
    }

    /// A value that is a string or an array of strings, as a list (non-strings are skipped).
    static func stringOrArray(_ value: JSONValue?) -> [String] {
        switch value {
        case .string(let s)?: return [s]
        case .array(let a)?: return a.compactMap(\.stringValue)
        default: return []
        }
    }

    /// A JSON array of strings.
    static func strings<S: Sequence>(_ values: S) -> JSONValue where S.Element == String {
        .array(values.map { .string($0) })
    }
}

extension JSONObject {
    /// A string member, if present and a string.
    func string(_ key: String) -> String? {
        self[key]?.stringValue
    }

    /// An integral number member.
    func integer(_ key: String) -> Int64? {
        self[key]?.intValue
    }

    /// A string member resolved as a URI reference against `base`.
    func url(_ key: String, base: URL?) -> URL? {
        guard let s = string(key) else { return nil }
        return URLs.resolve(s, against: base)
    }

    /// A member that is a string or an array of strings, as a list.
    func strings(_ key: String) -> [String] {
        LWSJSON.stringOrArray(self[key])
    }
}
