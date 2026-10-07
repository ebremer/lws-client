// SPDX-License-Identifier: MIT
import Foundation

/// A linkset document (`application/linkset+json`, RFC 9264) holding a resource's metadata links.
///
/// It is a value: ``adding(anchor:rel:href:attributes:)`` and ``removing(anchor:rel:href:)`` return modified
/// copies. Members it does not know are preserved on round trip.
public struct Linkset: Sendable, Hashable, CustomStringConvertible {
    /// The link context objects.
    public let contexts: [LinkContext]

    /// Creates a linkset.
    public init(_ contexts: [LinkContext] = []) {
        self.contexts = contexts
    }

    /// An empty linkset.
    public static let empty = Linkset()

    /// Parses an `application/linkset+json` document.
    /// - Throws: ``LWSError/protocolError(_:)`` when it is not a linkset.
    public static func parse(_ json: JSONValue) throws -> Linkset {
        let o = try LWSJSON.object(json, "Linkset")
        guard case .array(let ls)? = o["linkset"] else { throw LWSError.protocolError("Linkset document has no 'linkset' array") }
        return Linkset(try ls.map { c in
            guard case .object(let co) = c else { throw LWSError.protocolError("Linkset context is not an object") }
            return LinkContext(json: co)
        })
    }

    /// Parses an `application/linkset+json` document from text.
    public static func parse(_ text: String) throws -> Linkset {
        try parse(LWSJSON.parse(text, "Linkset"))
    }

    /// The `application/linkset+json` document.
    public var json: JSONObject {
        ["linkset": .array(contexts.map { .object($0.json) })]
    }

    /// Every link, flattened; targets are resolved against their anchor.
    public var links: [Link] {
        var out: [Link] = []
        for c in contexts {
            let anchor = c.anchor.flatMap { URLs.resolve($0, against: nil) }
            for rel in c.relationNames {
                for t in c.targets(rel) {
                    guard let href = URLs.resolve(t.href, against: anchor) else { continue }
                    var params: [(String, String)] = []
                    if let a = c.anchor { params.append(("anchor", a)) }
                    for attr in t.attributes {
                        if let s = attr.value.stringValue { params.append((attr.key, s)) }
                    }
                    out.append(Link(href: href, rel: rel, parameters: params))
                }
            }
        }
        return out
    }

    /// The targets of `rel` across all contexts.
    public func targets(_ rel: String) -> [LinkTarget] {
        contexts.flatMap { $0.targets(rel) }
    }

    /// The targets of `rel` for one anchor.
    public func targets(anchor: String?, rel: String) -> [LinkTarget] {
        context(anchor: anchor)?.targets(rel) ?? []
    }

    /// The context object for `anchor` (nil for a context without one).
    public func context(anchor: String?) -> LinkContext? {
        contexts.first { $0.anchor == anchor }
    }

    /// A copy with a link added (creating the context for `anchor` if needed).
    public func adding(anchor: String?, rel: String, href: String, attributes: JSONObject = JSONObject()) -> Linkset {
        let target = LinkTarget(href: href, attributes: attributes)
        var out = contexts
        if let i = out.firstIndex(where: { $0.anchor == anchor }) {
            out[i] = out[i].with(rel, target)
        } else {
            out.append(LinkContext(anchor: anchor, relations: [(rel, [target])]))
        }
        return Linkset(out)
    }

    /// A copy without the links of `rel` for `anchor`; with `href`, only that target is removed. Relations left
    /// empty are dropped.
    public func removing(anchor: String?, rel: String, href: String? = nil) -> Linkset {
        Linkset(contexts.map { $0.anchor == anchor ? $0.without(rel, href) : $0 })
    }

    public var description: String { json.description }
}

/// One link context object of a linkset.
public struct LinkContext: Sendable, Hashable {
    /// The context URI as written (nil when the object has none).
    public let anchor: String?
    /// The relation types, in document order.
    public let relationNames: [String]
    /// Relation type → targets.
    public let relations: [String: [LinkTarget]]
    /// Members other than the anchor and relations (preserved on round trip).
    public let extra: JSONObject

    /// Creates a link context.
    public init(anchor: String?, relations: [(String, [LinkTarget])], extra: JSONObject = JSONObject()) {
        self.anchor = anchor
        var names: [String] = []
        var rels: [String: [LinkTarget]] = [:]
        for (rel, targets) in relations {
            if rels.updateValue(targets, forKey: rel) == nil { names.append(rel) }
        }
        relationNames = names
        self.relations = rels
        self.extra = extra
    }

    init(json o: JSONObject) {
        var anchor: String?
        var rels: [(String, [LinkTarget])] = []
        var extra = JSONObject()
        for m in o {
            if m.key == "anchor", case .string(let a) = m.value {
                anchor = a
            } else if case .array(let a) = m.value,
                      a.allSatisfy({ $0["href"]?.stringValue != nil && $0.objectValue != nil })
            {
                rels.append((m.key, a.map { LinkTarget(json: $0.objectValue!) }))
            } else {
                extra[m.key] = m.value
            }
        }
        self.init(anchor: anchor, relations: rels, extra: extra)
    }

    /// The targets of `rel`.
    public func targets(_ rel: String) -> [LinkTarget] { relations[rel] ?? [] }

    var json: JSONObject {
        var o = JSONObject()
        if let anchor { o["anchor"] = .string(anchor) }
        for rel in relationNames { o[rel] = .array(targets(rel).map { .object($0.json) }) }
        for e in extra { o[e.key] = e.value }
        return o
    }

    func with(_ rel: String, _ target: LinkTarget) -> LinkContext {
        var rels = relationNames.map { ($0, targets($0)) }
        if let i = rels.firstIndex(where: { $0.0 == rel }) {
            rels[i].1.append(target)
        } else {
            rels.append((rel, [target]))
        }
        return LinkContext(anchor: anchor, relations: rels, extra: extra)
    }

    func without(_ rel: String, _ href: String?) -> LinkContext {
        var rels: [(String, [LinkTarget])] = []
        for name in relationNames {
            if name != rel {
                rels.append((name, targets(name)))
                continue
            }
            guard let href else { continue }
            let kept = targets(name).filter { $0.href != href }
            if !kept.isEmpty { rels.append((name, kept)) }
        }
        return LinkContext(anchor: anchor, relations: rels, extra: extra)
    }
}

/// A link target object of a linkset.
public struct LinkTarget: Sendable, Hashable, CustomStringConvertible {
    /// The target URI as written.
    public let href: String
    /// The target attributes (`type`, `title`, `hreflang`, `title*`, …), in document order.
    public let attributes: JSONObject

    /// Creates a link target (an `href` among `attributes` is ignored).
    public init(href: String, attributes: JSONObject = JSONObject()) {
        self.href = href
        var a = attributes
        a["href"] = nil
        self.attributes = a
    }

    init(json o: JSONObject) {
        self.init(href: o.string("href")!, attributes: o)
    }

    /// A string attribute.
    public func attribute(_ name: String) -> String? { attributes[name]?.stringValue }

    var json: JSONObject {
        var o: JSONObject = ["href": .string(href)]
        for a in attributes { o[a.key] = a.value }
        return o
    }

    public var description: String { href }
}

/// A retrieved linkset resource: its URL, entity tag and content, and what the server allows.
public struct LinksetDocument: Sendable {
    /// The linkset resource URL: pass it to ``LWSClient/updateLinkset(_:linkset:options:)`` or
    /// ``LWSClient/patchLinkset(_:patch:options:)``.
    public let url: URL
    /// The parsed linkset.
    public let linkset: Linkset
    /// The response metadata.
    public let metadata: ResourceMetadata

    /// The entity tag: use it as `ifMatch` for conditional updates.
    public var etag: String? { metadata.etag }
    /// The methods allowed on the linkset resource.
    public var allow: [String] { metadata.allow }
    /// The patch formats the linkset resource accepts.
    public var acceptPatch: [String] { metadata.acceptPatch }
    /// Whether the server advertises `PUT` for full replacement.
    public var supportsPut: Bool { allow.contains { $0.uppercased() == "PUT" } }
}
