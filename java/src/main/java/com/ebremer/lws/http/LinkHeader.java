// SPDX-License-Identifier: MIT
package com.ebremer.lws.http;

import com.ebremer.lws.internal.Uris;
import java.net.URI;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;

/** Parser and serialiser for the {@code Link} header field (RFC 8288). */
public final class LinkHeader {
    private LinkHeader() {}

    /**
     * Parses all link-values of the given {@code Link} header field lines. Targets are resolved against
     * {@code base}; a {@code rel} with several space-separated relation types yields one link per type.
     * Malformed link-values are skipped.
     */
    public static List<Link> parse(Collection<String> headerValues, URI base) {
        List<Link> out = new ArrayList<>();
        if (headerValues == null) return out;
        for (String v : headerValues) {
            if (v != null) parseLine(v, base, out);
        }
        return Collections.unmodifiableList(out);
    }

    /** Parses a single {@code Link} header field line. */
    public static List<Link> parse(String headerValue, URI base) {
        return parse(headerValue == null ? List.of() : List.of(headerValue), base);
    }

    private static void parseLine(String s, URI base, List<Link> out) {
        int n = s.length();
        int i = 0;
        while (i < n) {
            // Skip separators between link-values.
            while (i < n && (isWs(s.charAt(i)) || s.charAt(i) == ',')) i++;
            if (i >= n) break;
            if (s.charAt(i) != '<') {
                i = skipToNextLinkValue(s, i);
                continue;
            }
            int close = s.indexOf('>', i + 1);
            if (close < 0) break;
            String target = s.substring(i + 1, close).trim();
            i = close + 1;
            Map<String, String> params = new LinkedHashMap<>();
            String rel = null;
            while (true) {
                while (i < n && isWs(s.charAt(i))) i++;
                if (i >= n || s.charAt(i) == ',') break;
                if (s.charAt(i) != ';') {
                    i = skipToNextLinkValue(s, i);
                    break;
                }
                i++;
                while (i < n && isWs(s.charAt(i))) i++;
                int start = i;
                while (i < n && isTokenChar(s.charAt(i))) i++;
                String name = s.substring(start, i).toLowerCase(Locale.ROOT);
                while (i < n && isWs(s.charAt(i))) i++;
                String value = "";
                if (i < n && s.charAt(i) == '=') {
                    i++;
                    while (i < n && isWs(s.charAt(i))) i++;
                    if (i < n && s.charAt(i) == '"') {
                        StringBuilder sb = new StringBuilder();
                        i++;
                        while (i < n && s.charAt(i) != '"') {
                            char c = s.charAt(i);
                            if (c == '\\' && i + 1 < n) {
                                sb.append(s.charAt(i + 1));
                                i += 2;
                            } else {
                                sb.append(c);
                                i++;
                            }
                        }
                        i++; // closing quote
                        value = sb.toString();
                    } else {
                        int vs = i;
                        while (i < n && s.charAt(i) != ';' && s.charAt(i) != ',' && !isWs(s.charAt(i))) i++;
                        value = s.substring(vs, i);
                    }
                }
                if (name.isEmpty()) continue;
                if (name.equals("rel")) {
                    if (rel == null) rel = value;
                } else {
                    params.putIfAbsent(name, value);
                }
            }
            if (rel == null) continue;
            URI href = Uris.resolveOrNull(base, target);
            if (href == null) continue;
            for (String r : rel.trim().split("[ \\t]+")) {
                if (r.isEmpty()) continue;
                out.add(new Link(href, normalizeRel(r), params));
            }
        }
    }

    private static int skipToNextLinkValue(String s, int i) {
        boolean quoted = false;
        boolean angle = false;
        while (i < s.length()) {
            char c = s.charAt(i);
            if (quoted) {
                if (c == '\\') i++;
                else if (c == '"') quoted = false;
            } else if (angle) {
                if (c == '>') angle = false;
            } else if (c == '"') {
                quoted = true;
            } else if (c == '<') {
                angle = true;
            } else if (c == ',') {
                return i + 1;
            }
            i++;
        }
        return i;
    }

    /** Registered relation types are case-insensitive (lower-cased); extension relation URIs are kept. */
    public static String normalizeRel(String rel) {
        return rel.indexOf(':') >= 0 ? rel : rel.toLowerCase(Locale.ROOT);
    }

    private static boolean isWs(char c) {
        return c == ' ' || c == '\t' || c == '\r' || c == '\n';
    }

    static boolean isTokenChar(char c) {
        if (c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9') return true;
        return "!#$%&'*+-.^_`|~".indexOf(c) >= 0;
    }

    /** Serialises a link: {@code <href>; rel="rel"; name="value"}. */
    public static String format(Link link) {
        StringBuilder sb = new StringBuilder();
        sb.append('<').append(link.href()).append(">; rel=").append(quote(link.rel()));
        for (Map.Entry<String, String> p : link.params().entrySet()) {
            sb.append("; ").append(p.getKey());
            if (!p.getValue().isEmpty()) sb.append('=').append(quote(p.getValue()));
        }
        return sb.toString();
    }

    /** Serialises several links into one field value, separated by {@code ", "}. */
    public static String format(Collection<Link> links) {
        StringBuilder sb = new StringBuilder();
        for (Link l : links) {
            if (sb.length() > 0) sb.append(", ");
            sb.append(format(l));
        }
        return sb.toString();
    }

    private static String quote(String v) {
        return '"' + v.replace("\\", "\\\\").replace("\"", "\\\"") + '"';
    }

    /** The first link with relation {@code rel}. */
    public static Optional<Link> first(Collection<Link> links, String rel) {
        String r = normalizeRel(rel);
        for (Link l : links) {
            if (l.rel().equals(r)) return Optional.of(l);
        }
        return Optional.empty();
    }

    /** All links with relation {@code rel}. */
    public static List<Link> all(Collection<Link> links, String rel) {
        String r = normalizeRel(rel);
        List<Link> out = new ArrayList<>();
        for (Link l : links) {
            if (l.rel().equals(r)) out.add(l);
        }
        return out;
    }
}
