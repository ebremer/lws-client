// SPDX-License-Identifier: MIT
package com.ebremer.lws.http;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/** Parser for {@code WWW-Authenticate} header fields, including several challenges per field line. */
public final class WwwAuthenticate {
    private WwwAuthenticate() {}

    /** Parses every challenge from the given header field lines, in order. */
    public static List<AuthChallenge> parse(Collection<String> headerValues) {
        List<AuthChallenge> out = new ArrayList<>();
        if (headerValues == null) return out;
        for (String v : headerValues) {
            if (v != null) new Parser(v).parseInto(out);
        }
        return Collections.unmodifiableList(out);
    }

    /** Parses a single header field line. */
    public static List<AuthChallenge> parse(String headerValue) {
        return parse(headerValue == null ? List.of() : List.of(headerValue));
    }

    private static final class Parser {
        private final String s;
        private int i;

        Parser(String s) {
            this.s = s;
        }

        void parseInto(List<AuthChallenge> out) {
            while (true) {
                while (i < s.length() && (isWs(s.charAt(i)) || s.charAt(i) == ',')) i++;
                if (i >= s.length()) return;
                String scheme = token();
                if (scheme.isEmpty()) {
                    i++; // skip junk
                    continue;
                }
                Map<String, String> params = new LinkedHashMap<>();
                skipWs();
                int afterScheme = i;
                String t68 = token68();
                if (!t68.isEmpty()) {
                    int j = i;
                    skipWs();
                    if (i >= s.length() || s.charAt(i) == ',') {
                        out.add(new AuthChallenge(scheme, Map.of(), t68));
                        continue;
                    }
                    i = j;
                }
                i = afterScheme;
                parseParams(params);
                out.add(new AuthChallenge(scheme, params, null));
            }
        }

        private void parseParams(Map<String, String> params) {
            while (true) {
                skipWs();
                int save = i;
                String name = token();
                if (name.isEmpty()) {
                    i = save;
                    return;
                }
                skipWs();
                if (i >= s.length() || s.charAt(i) != '=') {
                    i = save; // next challenge's scheme
                    return;
                }
                i++;
                skipWs();
                String value = (i < s.length() && s.charAt(i) == '"') ? quoted() : token();
                params.putIfAbsent(name.toLowerCase(Locale.ROOT), value);
                skipWs();
                if (i < s.length() && s.charAt(i) == ',') {
                    int afterComma = i + 1;
                    i = afterComma;
                    skipWs();
                    while (i < s.length() && s.charAt(i) == ',') {
                        i++;
                        skipWs();
                    }
                    int look = i;
                    String next = token();
                    skipWs();
                    boolean isParam = !next.isEmpty() && i < s.length() && s.charAt(i) == '=';
                    i = look;
                    if (!isParam) return;
                } else {
                    return;
                }
            }
        }

        private String token() {
            int start = i;
            while (i < s.length() && LinkHeader.isTokenChar(s.charAt(i))) i++;
            return s.substring(start, i);
        }

        private String token68() {
            int start = i;
            while (i < s.length()) {
                char c = s.charAt(i);
                if (Character.isLetterOrDigit(c) && c < 128 || "-._~+/".indexOf(c) >= 0) i++;
                else break;
            }
            if (i == start) return "";
            while (i < s.length() && s.charAt(i) == '=') i++;
            return s.substring(start, i);
        }

        private String quoted() {
            StringBuilder sb = new StringBuilder();
            i++; // opening quote
            while (i < s.length() && s.charAt(i) != '"') {
                char c = s.charAt(i);
                if (c == '\\' && i + 1 < s.length()) {
                    sb.append(s.charAt(i + 1));
                    i += 2;
                } else {
                    sb.append(c);
                    i++;
                }
            }
            i++; // closing quote
            return sb.toString();
        }

        private void skipWs() {
            while (i < s.length() && isWs(s.charAt(i))) i++;
        }

        private static boolean isWs(char c) {
            return c == ' ' || c == '\t' || c == '\r' || c == '\n';
        }
    }
}
