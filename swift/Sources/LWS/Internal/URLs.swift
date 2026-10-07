// SPDX-License-Identifier: MIT
import Foundation

/// URI reference resolution and comparisons (internal).
enum URLs {
    /// Whether a reference starts with a scheme (`[A-Za-z][A-Za-z0-9+.-]*:`).
    static func hasScheme(_ reference: String) -> Bool {
        var first = true
        for c in reference.unicodeScalars {
            if first {
                guard isAlpha(c) else { return false }
                first = false
                continue
            }
            if c == ":" { return true }
            if !(isAlpha(c) || ("0"..."9").contains(c) || c == "+" || c == "." || c == "-") { return false }
        }
        return false
    }

    private static func isAlpha(_ c: Unicode.Scalar) -> Bool {
        ("a"..."z").contains(c) || ("A"..."Z").contains(c)
    }

    /// Resolves a URI reference against a base (RFC 3986 section 5.2), or nil when it is malformed or relative
    /// without a base.
    static func resolve(_ reference: String, against base: URL?) -> URL? {
        let r = reference.trimmingCharacters(in: .whitespaces)
        if hasScheme(r) {
            guard let u = URL(string: r), u.scheme != nil else { return nil }
            return u
        }
        guard let base, base.scheme != nil else { return nil }
        guard let u = URL(string: r, relativeTo: base)?.absoluteURL, u.scheme != nil else { return nil }
        return u
    }

    /// The string form used on the wire and in comparisons.
    static func text(_ url: URL) -> String {
        url.absoluteString
    }

    /// Whether the URL is an absolute http(s) URL.
    static func isHTTP(_ url: URL) -> Bool {
        guard let s = url.scheme?.lowercased(), s == "http" || s == "https" else { return false }
        return url.host != nil && hasScheme(url.absoluteString)
    }

    /// Requires an absolute http(s) URL as a request target.
    static func requireHTTP(_ url: URL, _ what: String) throws -> URL {
        let u = url.absoluteURL
        guard isHTTP(u) else { throw LWSError.invalidArgument("\(what) is not an absolute http(s) URL: \(url.absoluteString)") }
        return u
    }

    /// The port a URL uses: its explicit port, or the scheme's default.
    static func effectivePort(_ url: URL) -> Int? {
        if let p = url.port { return p }
        switch url.scheme?.lowercased() {
        case "http": return 80
        case "https": return 443
        default: return nil
        }
    }

    /// The host, lower-cased, without IPv6 brackets.
    static func host(_ url: URL) -> String {
        var h = (url.host ?? "").lowercased()
        if h.hasPrefix("["), h.hasSuffix("]") { h = String(h.dropFirst().dropLast()) }
        return h
    }

    /// Whether two URLs share scheme, host and effective port.
    static func sameOrigin(_ a: URL, _ b: URL) -> Bool {
        a.scheme?.lowercased() == b.scheme?.lowercased() && host(a) == host(b) && effectivePort(a) == effectivePort(b)
    }

    /// The percent-encoded path, `/` when empty.
    static func path(_ url: URL) -> String {
        let p = url.path(percentEncoded: true)
        return p.isEmpty ? "/" : p
    }

    /// The percent-encoded query including its `?`, or the empty string.
    static func query(_ url: URL) -> String {
        guard let q = url.query(percentEncoded: true) else { return "" }
        return "?" + q
    }

    /// Whether `url` is logically contained in `realm`: same origin, and the path equals the realm path or lies
    /// beneath it (the realm path is treated as a directory).
    static func contains(realm: URL, _ url: URL) -> Bool {
        guard sameOrigin(realm, url) else { return false }
        let rp = realm.path(percentEncoded: true)
        let up = path(url)
        if rp.isEmpty || rp == "/" { return true }
        if up == rp { return true }
        let dir = rp.hasSuffix("/") ? rp : rp + "/"
        return up.hasPrefix(dir) || up + "/" == dir
    }

    /// Loopback hosts, which may use plain HTTP for authorization servers.
    static func isLoopback(_ url: URL) -> Bool {
        let h = host(url)
        return h == "localhost" || h == "127.0.0.1" || h == "::1" || h.hasSuffix(".localhost")
    }

    /// The string without its fragment.
    static func withoutFragment(_ s: String) -> String {
        guard let i = s.firstIndex(of: "#") else { return s }
        return String(s[..<i])
    }

    /// A URL as compared for storage identity: scheme and host lower-cased, the default port dropped, no fragment.
    static func canonical(_ url: URL) -> String {
        guard var c = URLComponents(url: url.absoluteURL, resolvingAgainstBaseURL: true) else {
            return withoutFragment(url.absoluteString)
        }
        c.scheme = c.scheme?.lowercased()
        if let h = c.percentEncodedHost { c.percentEncodedHost = h.lowercased() }
        if let p = c.port, p == (c.scheme == "https" ? 443 : c.scheme == "http" ? 80 : -1) { c.port = nil }
        c.fragment = nil
        if c.percentEncodedPath.isEmpty, c.host != nil { c.percentEncodedPath = "/" }
        return c.string ?? withoutFragment(url.absoluteString)
    }

    /// Compares two URI strings, ignoring one trailing slash.
    static func equalsIgnoringTrailingSlash(_ a: String, _ b: String) -> Bool {
        func strip(_ s: String) -> Substring { s.hasSuffix("/") ? s.dropLast() : Substring(s) }
        return strip(a) == strip(b)
    }

    /// `URL(string:)` for a string known to be valid.
    static func make(_ s: String) -> URL {
        URL(string: s)!
    }
}
