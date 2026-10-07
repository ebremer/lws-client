// SPDX-License-Identifier: MIT
import Foundation

/// A typed web link (RFC 8288): a target, one relation type, and target attributes.
public struct Link: Sendable, Hashable, CustomStringConvertible {
    /// The link target (absolute when parsed from a response).
    public let href: URL
    /// The relation type: registered names lower-case, extension relation URIs as written.
    public let rel: String
    /// The target attributes, excluding `rel`: lower-case names, unquoted values (`""` for a valueless one).
    public let parameters: [String: String]
    /// The attribute names, in order.
    public let parameterNames: [String]

    /// Creates a link; attribute names are lower-cased (a repeated name keeps its last value).
    public init(href: URL, rel: String, parameters: [(String, String)] = []) {
        self.href = href
        self.rel = rel
        var names: [String] = []
        var values: [String: String] = [:]
        for (k, v) in parameters {
            let name = k.lowercased()
            if values.updateValue(v, forKey: name) == nil { names.append(name) }
        }
        parameterNames = names
        self.parameters = values
    }

    /// A `rel="type"` link declaring a resource type, or nil when `typeIRI` is not a URI.
    public static func type(_ typeIRI: String) -> Link? {
        URL(string: typeIRI).map { Link(href: $0, rel: LinkRelation.type) }
    }

    /// The `type` attribute (target media type hint).
    public var type: String? { parameters["type"] }

    /// The `anchor` attribute (link context override, unresolved).
    public var anchor: String? { parameters["anchor"] }

    /// A target attribute by (case-insensitive) name.
    public func parameter(_ name: String) -> String? {
        parameters[name.lowercased()]
    }

    /// A copy with one more attribute.
    public func with(parameter name: String, _ value: String) -> Link {
        Link(href: href, rel: rel, parameters: orderedParameters + [(name, value)])
    }

    /// The attributes in order.
    public var orderedParameters: [(String, String)] {
        parameterNames.map { ($0, parameters[$0]!) }
    }

    /// This link as a `Link` header field value: `<href>; rel="rel"; name="value"`.
    public var headerValue: String { LinkHeader.format(self) }

    public var description: String { headerValue }

    public static func == (lhs: Link, rhs: Link) -> Bool {
        lhs.href.absoluteString == rhs.href.absoluteString && lhs.rel == rhs.rel && lhs.parameters == rhs.parameters
    }

    public func hash(into hasher: inout Hasher) {
        hasher.combine(href.absoluteString)
        hasher.combine(rel)
        hasher.combine(parameters)
    }
}

extension Sequence where Element == Link {
    /// The first link with relation `rel`.
    public func first(rel: String) -> Link? {
        let r = LinkHeader.normalizeRel(rel)
        return first { $0.rel == r }
    }

    /// Every link with relation `rel`.
    public func all(rel: String) -> [Link] {
        let r = LinkHeader.normalizeRel(rel)
        return filter { $0.rel == r }
    }
}

/// Parser and serializer for the `Link` header field (RFC 8288).
public enum LinkHeader {
    /// Parses every link-value of the given `Link` field lines. Targets are resolved against `base`; a `rel` with
    /// several space-separated relation types yields one link per type. Malformed link-values are skipped.
    public static func parse<S: Sequence>(_ fieldValues: S, base: URL?) -> [Link] where S.Element == String {
        var out: [Link] = []
        for v in fieldValues { parseLine(Array(v.unicodeScalars), base, &out) }
        return out
    }

    /// Parses a single `Link` field line.
    public static func parse(_ fieldValue: String, base: URL?) -> [Link] {
        parse([fieldValue], base: base)
    }

    private static func parseLine(_ s: [Unicode.Scalar], _ base: URL?, _ out: inout [Link]) {
        let n = s.count
        var i = 0
        while i < n {
            while i < n, isWS(s[i]) || s[i] == "," { i += 1 }
            if i >= n { break }
            if s[i] != "<" {
                i = skipToNextLinkValue(s, i)
                continue
            }
            guard let close = s[(i + 1)...].firstIndex(of: ">") else { break }
            let target = string(s[(i + 1)..<close]).trimmingCharacters(in: .whitespaces)
            i = close + 1
            var params: [(String, String)] = []
            var seen = Set<String>()
            var rel: String?
            while true {
                while i < n, isWS(s[i]) { i += 1 }
                if i >= n || s[i] == "," { break }
                if s[i] != ";" {
                    i = skipToNextLinkValue(s, i)
                    break
                }
                i += 1
                while i < n, isWS(s[i]) { i += 1 }
                let start = i
                while i < n, isTokenChar(s[i]) { i += 1 }
                let name = string(s[start..<i]).lowercased()
                while i < n, isWS(s[i]) { i += 1 }
                var value = ""
                if i < n, s[i] == "=" {
                    i += 1
                    while i < n, isWS(s[i]) { i += 1 }
                    if i < n, s[i] == "\"" {
                        var v = String.UnicodeScalarView()
                        i += 1
                        while i < n, s[i] != "\"" {
                            if s[i] == "\\", i + 1 < n {
                                v.append(s[i + 1])
                                i += 2
                            } else {
                                v.append(s[i])
                                i += 1
                            }
                        }
                        if i < n { i += 1 }
                        value = String(v)
                    } else {
                        let vs = i
                        while i < n, s[i] != ";", s[i] != ",", !isWS(s[i]) { i += 1 }
                        value = string(s[vs..<i])
                    }
                }
                if name.isEmpty { continue }
                if name == "rel" {
                    if rel == nil { rel = value }
                } else if seen.insert(name).inserted {
                    params.append((name, value))
                }
            }
            guard let rel, let href = URLs.resolve(target, against: base) else { continue }
            for r in rel.split(whereSeparator: { $0 == " " || $0 == "\t" }) {
                out.append(Link(href: href, rel: normalizeRel(String(r)), parameters: params))
            }
        }
    }

    private static func skipToNextLinkValue(_ s: [Unicode.Scalar], _ start: Int) -> Int {
        var i = start
        var quoted = false
        var angle = false
        while i < s.count {
            let c = s[i]
            if quoted {
                if c == "\\" {
                    i += 1
                } else if c == "\"" {
                    quoted = false
                }
            } else if angle {
                if c == ">" { angle = false }
            } else if c == "\"" {
                quoted = true
            } else if c == "<" {
                angle = true
            } else if c == "," {
                return i + 1
            }
            i += 1
        }
        return i
    }

    /// Registered relation types are case-insensitive (lower-cased); extension relation URIs are kept.
    public static func normalizeRel(_ rel: String) -> String {
        rel.contains(":") ? rel : rel.lowercased()
    }

    static func isWS(_ c: Unicode.Scalar) -> Bool {
        c == " " || c == "\t" || c == "\r" || c == "\n"
    }

    static func isTokenChar(_ c: Unicode.Scalar) -> Bool {
        ("a"..."z").contains(c) || ("A"..."Z").contains(c) || ("0"..."9").contains(c) || "!#$%&'*+-.^_`|~".unicodeScalars.contains(c)
    }

    static func string<C: Collection>(_ scalars: C) -> String where C.Element == Unicode.Scalar {
        var v = String.UnicodeScalarView()
        v.append(contentsOf: scalars)
        return String(v)
    }

    /// Serializes a link: `<href>; rel="rel"; name="value"`.
    public static func format(_ link: Link) -> String {
        format(href: link.href.absoluteString, rel: link.rel, parameters: link.orderedParameters)
    }

    /// Serializes a link given as strings.
    public static func format(href: String, rel: String, parameters: [(String, String)] = []) -> String {
        var s = "<" + href + ">; rel=" + quote(rel)
        for (k, v) in parameters {
            s += "; " + k
            if !v.isEmpty { s += "=" + quote(v) }
        }
        return s
    }

    /// Serializes several links into one field value, separated by `", "`.
    public static func format<S: Sequence>(_ links: S) -> String where S.Element == Link {
        links.map(format).joined(separator: ", ")
    }

    private static func quote(_ v: String) -> String {
        "\"" + v.replacingOccurrences(of: "\\", with: "\\\\").replacingOccurrences(of: "\"", with: "\\\"") + "\""
    }
}
