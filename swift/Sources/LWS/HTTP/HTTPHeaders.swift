// SPDX-License-Identifier: MIT

/// An ordered multimap of HTTP header fields. Names are case-insensitive; the order of fields, and of a
/// field's values (one per field line), is kept. Values are the raw strings.
public struct HTTPHeaders: Sendable, Hashable, Sequence, ExpressibleByDictionaryLiteral, CustomStringConvertible {
    /// One header field line.
    public struct Field: Sendable, Hashable {
        /// The field name, as given.
        public var name: String
        /// The field value.
        public var value: String

        public init(name: String, value: String) {
            self.name = name
            self.value = value
        }
    }

    /// The field lines, in order.
    public private(set) var fields: [Field]

    /// No fields.
    public init() {
        fields = []
    }

    /// Fields from name/value pairs (repeated names accumulate values).
    public init<S: Sequence>(_ pairs: S) where S.Element == (String, String) {
        fields = pairs.map { Field(name: $0.0, value: $0.1) }
    }

    /// Fields from names with several values each.
    public init(_ dictionary: [String: [String]]) {
        fields = dictionary.sorted { $0.key < $1.key }.flatMap { kv in kv.value.map { Field(name: kv.key, value: $0) } }
    }

    public init(dictionaryLiteral elements: (String, String)...) {
        self.init(elements)
    }

    /// The first value of a field, or nil.
    public func first(_ name: String) -> String? {
        fields.first { Self.same($0.name, name) }?.value
    }

    /// Every value of a field (one per field line), possibly none.
    public func all(_ name: String) -> [String] {
        fields.filter { Self.same($0.name, name) }.map(\.value)
    }

    /// All values of a field joined with `", "` (RFC 9110 section 5.3), or nil when absent.
    public func combined(_ name: String) -> String? {
        let v = all(name)
        return v.isEmpty ? nil : v.joined(separator: ", ")
    }

    /// Whether the field is present.
    public func contains(_ name: String) -> Bool {
        fields.contains { Self.same($0.name, name) }
    }

    /// The distinct field names, in order of first appearance.
    public var names: [String] {
        var seen = Set<String>()
        return fields.compactMap { seen.insert($0.name.lowercased()).inserted ? $0.name : nil }
    }

    /// Whether there are no fields.
    public var isEmpty: Bool { fields.isEmpty }

    /// Adds a field line, keeping existing ones.
    public mutating func add(_ name: String, _ value: String) {
        fields.append(Field(name: name, value: value))
    }

    /// Replaces every value of a field; `nil` removes it.
    public mutating func set(_ name: String, _ value: String?) {
        remove(name)
        if let value { add(name, value) }
    }

    /// Removes every value of a field.
    public mutating func remove(_ name: String) {
        fields.removeAll { Self.same($0.name, name) }
    }

    /// The first value of a field; assigning replaces every value (`nil` removes the field).
    public subscript(name: String) -> String? {
        get { first(name) }
        set { set(name, newValue) }
    }

    public func makeIterator() -> IndexingIterator<[Field]> {
        fields.makeIterator()
    }

    public var description: String {
        fields.map { "\($0.name): \($0.value)" }.joined(separator: "\n")
    }

    static func same(_ a: String, _ b: String) -> Bool {
        a.count == b.count && a.lowercased() == b.lowercased()
    }
}
