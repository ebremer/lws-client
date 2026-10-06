// SPDX-License-Identifier: MIT
package com.ebremer.lws.patch;

import java.util.ArrayList;
import java.util.List;

/**
 * JSON Pointer (RFC 6901) helpers. Escaping matters for linkset patches, whose relation keys are often
 * URIs: {@code JsonPointer.of("linkset", "0", "https://example.org/rel", "-")} yields
 * {@code /linkset/0/https:~1~1example.org~1rel/-}.
 */
public final class JsonPointer {
    private JsonPointer() {}

    /** Escapes one reference token: {@code ~} becomes {@code ~0} and {@code /} becomes {@code ~1}. */
    public static String escape(String segment) {
        return segment.replace("~", "~0").replace("/", "~1");
    }

    /** Reverses {@link #escape}. */
    public static String unescape(String token) {
        return token.replace("~1", "/").replace("~0", "~");
    }

    /** Builds a pointer from unescaped segments; no segments yields the whole-document pointer {@code ""}. */
    public static String of(String... segments) {
        StringBuilder sb = new StringBuilder();
        for (String s : segments) sb.append('/').append(escape(s));
        return sb.toString();
    }

    /** Builds a pointer from unescaped segments. */
    public static String of(List<String> segments) {
        return of(segments.toArray(String[]::new));
    }

    /** Splits a pointer into unescaped segments. */
    public static List<String> segments(String pointer) {
        List<String> out = new ArrayList<>();
        if (pointer == null || pointer.isEmpty()) return out;
        if (!pointer.startsWith("/")) throw new IllegalArgumentException("JSON Pointer must start with '/': " + pointer);
        for (String t : pointer.substring(1).split("/", -1)) out.add(unescape(t));
        return out;
    }
}
