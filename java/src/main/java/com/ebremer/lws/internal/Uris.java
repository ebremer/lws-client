// SPDX-License-Identifier: MIT
package com.ebremer.lws.internal;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.Locale;

/**
 * RFC 3986 reference resolution and URI comparisons. {@link URI#resolve} follows RFC 2396 and gets
 * query-only and empty references wrong, so resolution is implemented here (internal).
 */
public final class Uris {
    private Uris() {}

    /** Resolves {@code reference} against {@code base} (RFC 3986 section 5.2). */
    public static URI resolve(URI base, String reference) {
        URI r = parse(reference);
        if (base == null || r.getScheme() != null) {
            return r.getScheme() != null ? normalizeAbsolute(r) : r;
        }
        String scheme = base.getScheme();
        String authority;
        String path;
        String query;
        if (r.getRawAuthority() != null) {
            authority = r.getRawAuthority();
            path = removeDotSegments(nz(r.getRawPath()));
            query = r.getRawQuery();
        } else {
            authority = base.getRawAuthority();
            String rPath = nz(r.getRawPath());
            if (rPath.isEmpty()) {
                path = nz(base.getRawPath());
                query = r.getRawQuery() != null ? r.getRawQuery() : base.getRawQuery();
            } else {
                if (rPath.startsWith("/")) {
                    path = removeDotSegments(rPath);
                } else {
                    path = removeDotSegments(merge(base, rPath));
                }
                query = r.getRawQuery();
            }
        }
        StringBuilder sb = new StringBuilder();
        sb.append(scheme).append(':');
        if (authority != null) sb.append("//").append(authority);
        sb.append(path);
        if (query != null) sb.append('?').append(query);
        if (r.getRawFragment() != null) sb.append('#').append(r.getRawFragment());
        return parse(sb.toString());
    }

    /** Like {@link #resolve} but returns null instead of throwing for malformed references. */
    public static URI resolveOrNull(URI base, String reference) {
        try {
            return resolve(base, reference);
        } catch (IllegalArgumentException e) {
            return null;
        }
    }

    public static URI parse(String s) {
        try {
            return new URI(s);
        } catch (URISyntaxException e) {
            throw new IllegalArgumentException("Invalid URI: " + s, e);
        }
    }

    private static URI normalizeAbsolute(URI u) {
        if (u.isOpaque() || u.getRawPath() == null) return u;
        String p = u.getRawPath();
        if (!p.contains("/.")) return u;
        StringBuilder sb = new StringBuilder();
        sb.append(u.getScheme()).append(':');
        if (u.getRawAuthority() != null) sb.append("//").append(u.getRawAuthority());
        sb.append(removeDotSegments(p));
        if (u.getRawQuery() != null) sb.append('?').append(u.getRawQuery());
        if (u.getRawFragment() != null) sb.append('#').append(u.getRawFragment());
        return parse(sb.toString());
    }

    private static String nz(String s) {
        return s == null ? "" : s;
    }

    private static String merge(URI base, String rPath) {
        String bPath = nz(base.getRawPath());
        if (base.getRawAuthority() != null && bPath.isEmpty()) return "/" + rPath;
        int i = bPath.lastIndexOf('/');
        return (i >= 0 ? bPath.substring(0, i + 1) : "") + rPath;
    }

    static String removeDotSegments(String input) {
        StringBuilder out = new StringBuilder();
        String in = input;
        while (!in.isEmpty()) {
            if (in.startsWith("../")) {
                in = in.substring(3);
            } else if (in.startsWith("./")) {
                in = in.substring(2);
            } else if (in.startsWith("/./")) {
                in = in.substring(2);
            } else if (in.equals("/.")) {
                in = "/";
            } else if (in.startsWith("/../")) {
                in = in.substring(3);
                removeLastSegment(out);
            } else if (in.equals("/..")) {
                in = "/";
                removeLastSegment(out);
            } else if (in.equals(".") || in.equals("..")) {
                in = "";
            } else {
                int start = in.startsWith("/") ? 1 : 0;
                int next = in.indexOf('/', start);
                if (next < 0) next = in.length();
                out.append(in, 0, next);
                in = in.substring(next);
            }
        }
        return out.toString();
    }

    private static void removeLastSegment(StringBuilder out) {
        int i = out.lastIndexOf("/");
        out.setLength(Math.max(i, 0));
    }

    /** Effective port: explicit port or the scheme default. */
    public static int port(URI u) {
        if (u.getPort() >= 0) return u.getPort();
        String s = u.getScheme() == null ? "" : u.getScheme().toLowerCase(Locale.ROOT);
        return switch (s) {
            case "https", "wss" -> 443;
            case "http", "ws" -> 80;
            default -> -1;
        };
    }

    /** Whether two URIs share scheme, host and effective port (case-insensitive). */
    public static boolean sameOrigin(URI a, URI b) {
        return a.getScheme() != null && b.getScheme() != null
                && a.getScheme().equalsIgnoreCase(b.getScheme())
                && a.getHost() != null && b.getHost() != null
                && a.getHost().equalsIgnoreCase(b.getHost())
                && port(a) == port(b);
    }

    /**
     * Whether {@code uri} is logically contained in {@code realm}: same origin, and the path equals the
     * realm path or lies beneath it (the realm path is treated as a directory).
     */
    public static boolean contains(URI realm, URI uri) {
        if (!sameOrigin(realm, uri)) return false;
        String rp = nz(realm.getRawPath());
        String up = nz(uri.getRawPath());
        if (up.isEmpty()) up = "/";
        if (rp.isEmpty() || rp.equals("/")) return true;
        if (up.equals(rp)) return true;
        String dir = rp.endsWith("/") ? rp : rp + "/";
        return up.startsWith(dir) || (up + "/").equals(dir);
    }

    /** Loopback hosts that are allowed to use plain HTTP for authorization servers. */
    public static boolean isLoopback(URI u) {
        String h = u.getHost();
        if (h == null) return false;
        h = h.toLowerCase(Locale.ROOT);
        return h.equals("localhost") || h.equals("127.0.0.1") || h.equals("[::1]") || h.equals("::1")
                || h.endsWith(".localhost");
    }

    /** The URI without its fragment. */
    public static String withoutFragment(String s) {
        int i = s.indexOf('#');
        return i < 0 ? s : s.substring(0, i);
    }

    /** Compares two URI strings ignoring a single trailing slash difference. */
    public static boolean equalsIgnoringTrailingSlash(String a, String b) {
        if (a == null || b == null) return false;
        return stripSlash(a).equals(stripSlash(b));
    }

    private static String stripSlash(String s) {
        return s.endsWith("/") ? s.substring(0, s.length() - 1) : s;
    }
}
