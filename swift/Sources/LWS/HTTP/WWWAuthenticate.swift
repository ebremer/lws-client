// SPDX-License-Identifier: MIT

/// One challenge of a `WWW-Authenticate` header (RFC 9110 section 11.6.1).
public struct AuthChallenge: Sendable, Hashable {
    /// The authentication scheme as sent (compare it case-insensitively, or use ``isScheme(_:)``).
    public let scheme: String
    /// The auth-params: lower-case names, unquoted values.
    public let parameters: [String: String]
    /// The token68 credential form, when the challenge uses it.
    public let token68: String?

    /// Creates a challenge; parameter names are lower-cased (a repeated name keeps its first value).
    public init(scheme: String, parameters: [(String, String)] = [], token68: String? = nil) {
        self.scheme = scheme
        var p: [String: String] = [:]
        for (k, v) in parameters where p[k.lowercased()] == nil { p[k.lowercased()] = v }
        self.parameters = p
        self.token68 = token68
    }

    /// LWS: the authorization server issuer (`as_uri`).
    public var asURI: String? { parameters["as_uri"] }
    /// LWS: the protection scope (`realm`).
    public var realm: String? { parameters["realm"] }
    /// The `error` parameter (e.g. `invalid_token`).
    public var error: String? { parameters["error"] }
    /// The `error_description` parameter.
    public var errorDescription: String? { parameters["error_description"] }

    /// Whether the scheme is `scheme`, ignoring case.
    public func isScheme(_ scheme: String) -> Bool {
        self.scheme.lowercased() == scheme.lowercased()
    }

    /// A parameter by (case-insensitive) name.
    public func parameter(_ name: String) -> String? {
        parameters[name.lowercased()]
    }
}

/// Parser for `WWW-Authenticate` header fields, including several challenges per field line.
public enum WWWAuthenticate {
    /// Parses every challenge of the given field lines, in order.
    public static func parse<S: Sequence>(_ fieldValues: S) -> [AuthChallenge] where S.Element == String {
        var out: [AuthChallenge] = []
        for v in fieldValues {
            var p = Parser(Array(v.unicodeScalars))
            p.parse(into: &out)
        }
        return out
    }

    /// Parses a single field line.
    public static func parse(_ fieldValue: String) -> [AuthChallenge] {
        parse([fieldValue])
    }

    private struct Parser {
        let s: [Unicode.Scalar]
        var i = 0

        init(_ s: [Unicode.Scalar]) {
            self.s = s
        }

        mutating func parse(into out: inout [AuthChallenge]) {
            while true {
                while i < s.count, LinkHeader.isWS(s[i]) || s[i] == "," { i += 1 }
                if i >= s.count { return }
                let scheme = token()
                if scheme.isEmpty {
                    i += 1
                    continue
                }
                skipWS()
                let afterScheme = i
                let t68 = token68()
                if !t68.isEmpty {
                    skipWS()
                    if i >= s.count || s[i] == "," {
                        out.append(AuthChallenge(scheme: scheme, token68: t68))
                        continue
                    }
                }
                i = afterScheme
                var params: [(String, String)] = []
                parseParams(&params)
                out.append(AuthChallenge(scheme: scheme, parameters: params))
            }
        }

        private mutating func parseParams(_ params: inout [(String, String)]) {
            while true {
                skipWS()
                let save = i
                let name = token()
                if name.isEmpty {
                    i = save
                    return
                }
                skipWS()
                if i >= s.count || s[i] != "=" {
                    i = save
                    return
                }
                i += 1
                skipWS()
                let value = i < s.count && s[i] == "\"" ? quoted() : token()
                params.append((name.lowercased(), value))
                skipWS()
                guard i < s.count, s[i] == "," else { return }
                i += 1
                skipWS()
                while i < s.count, s[i] == "," {
                    i += 1
                    skipWS()
                }
                let look = i
                let next = token()
                skipWS()
                let isParam = !next.isEmpty && i < s.count && s[i] == "="
                i = look
                if !isParam { return }
            }
        }

        private mutating func token() -> String {
            let start = i
            while i < s.count, LinkHeader.isTokenChar(s[i]) { i += 1 }
            return LinkHeader.string(s[start..<i])
        }

        private mutating func token68() -> String {
            let start = i
            while i < s.count, ("a"..."z").contains(s[i]) || ("A"..."Z").contains(s[i]) || ("0"..."9").contains(s[i])
                || "-._~+/".unicodeScalars.contains(s[i])
            {
                i += 1
            }
            if i == start { return "" }
            while i < s.count, s[i] == "=" { i += 1 }
            return LinkHeader.string(s[start..<i])
        }

        private mutating func quoted() -> String {
            var v = String.UnicodeScalarView()
            i += 1
            while i < s.count, s[i] != "\"" {
                if s[i] == "\\", i + 1 < s.count {
                    v.append(s[i + 1])
                    i += 2
                } else {
                    v.append(s[i])
                    i += 1
                }
            }
            if i < s.count { i += 1 }
            return String(v)
        }

        private mutating func skipWS() {
            while i < s.count, LinkHeader.isWS(s[i]) { i += 1 }
        }
    }
}
