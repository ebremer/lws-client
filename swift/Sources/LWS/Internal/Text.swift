// SPDX-License-Identifier: MIT
import Foundation

/// List-based header fields and media type helpers (internal).
enum HeaderLists {
    /// Splits list-based field values on commas outside quoted strings; elements are trimmed, empties dropped.
    static func split<S: Sequence>(_ values: S) -> [String] where S.Element == String {
        var out: [String] = []
        for v in values {
            var cur = ""
            var quoted = false
            var escaped = false
            for c in v {
                if quoted {
                    cur.append(c)
                    if escaped {
                        escaped = false
                    } else if c == "\\" {
                        escaped = true
                    } else if c == "\"" {
                        quoted = false
                    }
                } else if c == "\"" {
                    quoted = true
                    cur.append(c)
                } else if c == "," {
                    add(&out, cur)
                    cur = ""
                } else {
                    cur.append(c)
                }
            }
            add(&out, cur)
        }
        return out
    }

    private static func add(_ out: inout [String], _ cur: String) {
        let s = cur.trimmingCharacters(in: .whitespaces)
        if !s.isEmpty { out.append(s) }
    }

    /// The media type without parameters, lower-cased, or nil.
    static func essence(_ contentType: String?) -> String? {
        guard let contentType else { return nil }
        let base = contentType.split(separator: ";", maxSplits: 1, omittingEmptySubsequences: false).first ?? ""
        let s = base.trimmingCharacters(in: .whitespaces).trimmingCharacters(in: CharacterSet(charactersIn: "\""))
        return s.isEmpty ? nil : s.lowercased()
    }

    /// Whether the media type is JSON (`application/json` or any `+json` suffix).
    static func isJSON(_ contentType: String?) -> Bool {
        guard let e = essence(contentType) else { return false }
        return e == "application/json" || e.hasSuffix("+json")
    }

    /// The `charset` parameter of a content type, or nil.
    static func charset(_ contentType: String?) -> String? {
        guard let contentType else { return nil }
        for part in contentType.split(separator: ";").dropFirst() {
            let p = part.trimmingCharacters(in: .whitespaces)
            if p.lowercased().hasPrefix("charset=") {
                let name = p.dropFirst(8).trimmingCharacters(in: .whitespaces).trimmingCharacters(in: CharacterSet(charactersIn: "\""))
                return name.isEmpty ? nil : name
            }
        }
        return nil
    }

    /// Decodes text with the charset of the content type (UTF-8 by default and when unknown; malformed
    /// sequences become U+FFFD).
    static func decode(_ bytes: Data, contentType: String?) -> String {
        if let charset = charset(contentType)?.lowercased(), let encoding = encoding(charset), encoding != .utf8 {
            if let s = String(data: bytes, encoding: encoding) { return s }
        }
        var data = bytes
        if data.starts(with: [0xEF, 0xBB, 0xBF]) { data = data.dropFirst(3) }
        return String(decoding: data, as: UTF8.self)
    }

    private static func encoding(_ name: String) -> String.Encoding? {
        switch name {
        case "utf-8", "utf8": return .utf8
        case "us-ascii", "ascii": return .ascii
        case "iso-8859-1", "latin1", "iso_8859-1", "l1": return .isoLatin1
        case "iso-8859-2", "latin2": return .isoLatin2
        case "windows-1252", "cp1252": return .windowsCP1252
        case "windows-1250", "cp1250": return .windowsCP1250
        case "utf-16": return .utf16
        case "utf-16le": return .utf16LittleEndian
        case "utf-16be": return .utf16BigEndian
        case "utf-32": return .utf32
        case "shift_jis", "shift-jis", "sjis": return .shiftJIS
        case "euc-jp": return .japaneseEUC
        default: return nil
        }
    }

    /// Strips one pair of surrounding double quotes.
    static func unquote(_ s: String) -> String {
        s.count >= 2 && s.hasPrefix("\"") && s.hasSuffix("\"") ? String(s.dropFirst().dropLast()) : s
    }
}

/// RFC 3339 and HTTP dates (internal).
enum Dates {
    private static let utc: Calendar = {
        var c = Calendar(identifier: .gregorian)
        c.timeZone = TimeZone(identifier: "UTC")!
        return c
    }()

    /// Parses an RFC 3339 date-time (a missing offset is UTC, a date alone is midnight UTC); anything
    /// unparseable is nil, never an error.
    static func parseRFC3339(_ text: String?) -> Date? {
        guard let text else { return nil }
        let s = Array(text.trimmingCharacters(in: .whitespaces).utf8)
        var i = 0
        func digits(_ n: Int) -> Int? {
            guard i + n <= s.count else { return nil }
            var v = 0
            for k in 0..<n {
                let b = s[i + k]
                guard b >= 0x30, b <= 0x39 else { return nil }
                v = v * 10 + Int(b - 0x30)
            }
            i += n
            return v
        }
        func expect(_ c: Character) -> Bool {
            guard i < s.count, s[i] == c.asciiValue! else { return false }
            i += 1
            return true
        }
        guard let year = digits(4), expect("-"), let month = digits(2), expect("-"), let day = digits(2) else { return nil }
        var comps = DateComponents(year: year, month: month, day: day, hour: 0, minute: 0, second: 0)
        var fraction = 0.0
        var offset = 0
        if i < s.count {
            guard s[i] == UInt8(ascii: "T") || s[i] == UInt8(ascii: "t") || s[i] == UInt8(ascii: " ") else { return nil }
            i += 1
            guard let h = digits(2), expect(":"), let m = digits(2) else { return nil }
            comps.hour = h
            comps.minute = m
            if expect(":") {
                guard let sec = digits(2) else { return nil }
                comps.second = min(sec, 59)
                if expect(".") || expect(",") {
                    let start = i
                    while i < s.count, s[i] >= 0x30, s[i] <= 0x39 { i += 1 }
                    guard i > start, let f = Double("0." + String(decoding: s[start..<i], as: UTF8.self)) else { return nil }
                    fraction = f
                }
            }
            if i < s.count {
                if s[i] == UInt8(ascii: "Z") || s[i] == UInt8(ascii: "z") {
                    i += 1
                } else if s[i] == UInt8(ascii: "+") || s[i] == UInt8(ascii: "-") {
                    let sign = s[i] == UInt8(ascii: "-") ? -1 : 1
                    i += 1
                    guard let oh = digits(2) else { return nil }
                    _ = expect(":")
                    guard let om = digits(2) else { return nil }
                    offset = sign * (oh * 3600 + om * 60)
                } else {
                    return nil
                }
            }
        }
        guard i == s.count, (1...12).contains(month), (1...31).contains(day), (0...23).contains(comps.hour!),
              (0...59).contains(comps.minute!), let date = utc.date(from: comps),
              utc.component(.day, from: date) == day
        else { return nil }
        return date.addingTimeInterval(fraction - Double(offset))
    }

    /// Formats an instant as RFC 3339 in UTC, with fractional seconds only when present.
    static func formatRFC3339(_ date: Date) -> String {
        let seconds = date.timeIntervalSince1970.rounded(.down)
        let whole = Date(timeIntervalSince1970: seconds)
        let c = utc.dateComponents([.year, .month, .day, .hour, .minute, .second], from: whole)
        var s = String(format: "%04d-%02d-%02dT%02d:%02d:%02d", c.year!, c.month!, c.day!, c.hour!, c.minute!, c.second!)
        let micros = Int(((date.timeIntervalSince1970 - seconds) * 1_000_000).rounded())
        if micros > 0, micros < 1_000_000 {
            var f = String(format: "%06d", micros)
            while f.hasSuffix("0") { f.removeLast() }
            s += "." + f
        }
        return s + "Z"
    }

    private static let days = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"]
    private static let months = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]

    /// Formats an HTTP date (IMF-fixdate, RFC 9110 section 5.6.7).
    static func formatHTTPDate(_ date: Date) -> String {
        let c = utc.dateComponents([.year, .month, .day, .hour, .minute, .second, .weekday], from: date)
        let time = String(format: "%02d:%02d:%02d", c.hour!, c.minute!, c.second!)
        return days[c.weekday! - 1] + ", " + String(format: "%02d", c.day!) + " " + months[c.month! - 1] + " "
            + String(format: "%04d", c.year!) + " " + time + " GMT"
    }

    /// Parses an HTTP date in the IMF-fixdate form, or nil.
    static func parseHTTPDate(_ text: String?) -> Date? {
        guard let text else { return nil }
        let parts = text.trimmingCharacters(in: .whitespaces).split(separator: " ")
        guard parts.count == 6, parts[5] == "GMT", parts[0].hasSuffix(","), let day = Int(parts[1]),
              let month = months.firstIndex(of: String(parts[2])), let year = Int(parts[3])
        else { return nil }
        let t = parts[4].split(separator: ":")
        guard t.count == 3, let h = Int(t[0]), let m = Int(t[1]), let sec = Int(t[2]) else { return nil }
        return utc.date(from: DateComponents(year: year, month: month + 1, day: day, hour: h, minute: m, second: sec))
    }
}

/// Base64url without padding (RFC 4648 section 5), as JOSE uses it.
enum Base64URL {
    static func encode(_ data: Data) -> String {
        data.base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }

    static func encode(_ s: String) -> String {
        encode(Data(s.utf8))
    }

    /// Decodes base64url, with or without padding; nil when the text is not base64url.
    static func decode(_ s: String) -> Data? {
        var t = Substring(s)
        while t.hasSuffix("=") { t = t.dropLast() }
        guard t.allSatisfy({ $0.isASCII && ($0.isLetter || $0.isNumber || $0 == "-" || $0 == "_") }) else { return nil }
        var b = t.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
        if b.count % 4 == 1 { return nil }
        while b.count % 4 != 0 { b += "=" }
        return Data(base64Encoded: b)
    }
}

/// Constant-time comparison of two byte strings (internal).
func constantTimeEquals(_ a: Data, _ b: Data) -> Bool {
    guard a.count == b.count else { return false }
    var diff: UInt8 = 0
    for (x, y) in zip(a, b) { diff |= x ^ y }
    return diff == 0
}
