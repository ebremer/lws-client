// SPDX-License-Identifier: MIT
package com.ebremer.lws.internal;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/** Splitting of comma-separated list header fields (internal). */
public final class HeaderLists {
    private HeaderLists() {}

    /** Splits list-based field values on commas outside quoted strings; elements are trimmed, empties dropped. */
    public static List<String> split(List<String> values) {
        List<String> out = new ArrayList<>();
        for (String v : values) {
            if (v == null) continue;
            StringBuilder cur = new StringBuilder();
            boolean quoted = false;
            for (int i = 0; i < v.length(); i++) {
                char c = v.charAt(i);
                if (quoted) {
                    cur.append(c);
                    if (c == '\\' && i + 1 < v.length()) {
                        cur.append(v.charAt(++i));
                    } else if (c == '"') {
                        quoted = false;
                    }
                } else if (c == '"') {
                    quoted = true;
                    cur.append(c);
                } else if (c == ',') {
                    add(out, cur);
                    cur.setLength(0);
                } else {
                    cur.append(c);
                }
            }
            add(out, cur);
        }
        return Collections.unmodifiableList(out);
    }

    private static void add(List<String> out, StringBuilder cur) {
        String s = cur.toString().trim();
        if (!s.isEmpty()) out.add(s);
    }

    /** Tokens such as the methods of an {@code Allow} header. */
    public static List<String> tokens(List<String> values) {
        return split(values);
    }

    /** Media types such as {@code Accept-Patch} / {@code Accept-Query} entries (parameters kept). */
    public static List<String> mediaTypes(List<String> values) {
        return split(values);
    }

    /** The media type without parameters, lower-cased, or null. */
    public static String essence(String contentType) {
        if (contentType == null) return null;
        int i = contentType.indexOf(';');
        String s = (i < 0 ? contentType : contentType.substring(0, i)).trim();
        return s.isEmpty() ? null : s.toLowerCase(java.util.Locale.ROOT);
    }

    /** Whether the media type is JSON ({@code application/json} or any {@code +json} suffix). */
    public static boolean isJson(String contentType) {
        String e = essence(contentType);
        return e != null && (e.equals("application/json") || e.endsWith("+json"));
    }
}
