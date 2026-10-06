// SPDX-License-Identifier: MIT
package com.ebremer.lws.http;

import java.math.BigDecimal;
import java.math.RoundingMode;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * Structured Field Values (RFC 8941 / RFC 9651) — dictionaries, items, inner lists and parameters, as
 * used by {@code Signature-Input}, {@code Signature} and {@code Content-Digest}.
 *
 * <p>Bare items map to Java values as follows: integer → {@link Long}, decimal → {@link BigDecimal},
 * string → {@link String}, token → {@link Token}, byte sequence → {@link Bytes}, boolean →
 * {@link Boolean}, date → {@link Date}, display string → {@link DisplayString}.
 */
public final class StructuredFields {
    private StructuredFields() {}

    /** A dictionary member: either an {@link Item} or an {@link InnerList}. */
    public sealed interface Member permits Item, InnerList {
        /** The member's parameters. */
        Map<String, Object> params();
    }

    /** An item: a bare item with parameters. */
    public record Item(Object value, Map<String, Object> params) implements Member {
        public Item {
            Objects.requireNonNull(value, "value");
            params = params == null ? Map.of() : Collections.unmodifiableMap(new LinkedHashMap<>(params));
        }

        public static Item of(Object value) {
            return new Item(value, Map.of());
        }
    }

    /** An inner list of items with parameters. */
    public record InnerList(List<Item> items, Map<String, Object> params) implements Member {
        public InnerList {
            items = List.copyOf(items);
            params = params == null ? Map.of() : Collections.unmodifiableMap(new LinkedHashMap<>(params));
        }
    }

    /** An sf-token bare item. */
    public record Token(String value) {
        public Token {
            Objects.requireNonNull(value);
        }

        @Override
        public String toString() {
            return value;
        }
    }

    /** An sf-binary (byte sequence) bare item. */
    public record Bytes(byte[] value) {
        public Bytes {
            value = value.clone();
        }

        @Override
        public byte[] value() {
            return value.clone();
        }

        @Override
        public boolean equals(Object o) {
            return o instanceof Bytes b && Arrays.equals(value, b.value);
        }

        @Override
        public int hashCode() {
            return Arrays.hashCode(value);
        }

        @Override
        public String toString() {
            return ":" + Base64.getEncoder().encodeToString(value) + ":";
        }
    }

    /** An sf-date bare item (RFC 9651): seconds since the epoch. */
    public record Date(long epochSeconds) {}

    /** An sf-displaystring bare item (RFC 9651). */
    public record DisplayString(String value) {}

    /** Thrown for input that is not a valid structured field. */
    public static final class ParseException extends IllegalArgumentException {
        public ParseException(String message) {
            super(message);
        }
    }

    // ------------------------------------------------------------------------------------------------
    // Parsing
    // ------------------------------------------------------------------------------------------------

    /** Parses a dictionary (RFC 8941 section 4.2.2). Field lines must be joined with {@code ", "} first. */
    public static Map<String, Member> parseDictionary(String input) {
        Parser p = new Parser(input);
        p.skipSp();
        Map<String, Member> dict = p.dictionary();
        p.skipSp();
        if (!p.eof()) throw new ParseException("Trailing characters in structured field");
        return Collections.unmodifiableMap(dict);
    }

    /** Parses an item (RFC 8941 section 4.2.3). */
    public static Item parseItem(String input) {
        Parser p = new Parser(input);
        p.skipSp();
        Item item = p.item();
        p.skipSp();
        if (!p.eof()) throw new ParseException("Trailing characters in structured field");
        return item;
    }

    /** Parses a list (RFC 8941 section 4.2.1). */
    public static List<Member> parseList(String input) {
        Parser p = new Parser(input);
        p.skipSp();
        List<Member> out = new ArrayList<>();
        while (!p.eof()) {
            out.add(p.itemOrInnerList());
            p.skipOws();
            if (p.eof()) break;
            p.expect(',');
            p.skipOws();
            if (p.eof()) throw new ParseException("Trailing comma in list");
        }
        return Collections.unmodifiableList(out);
    }

    private static final class Parser {
        private final String s;
        private int i;

        Parser(String s) {
            this.s = Objects.requireNonNull(s);
        }

        boolean eof() {
            return i >= s.length();
        }

        char peek() {
            return s.charAt(i);
        }

        void expect(char c) {
            if (eof() || s.charAt(i) != c) throw new ParseException("Expected '" + c + "' at " + i);
            i++;
        }

        void skipSp() {
            while (!eof() && s.charAt(i) == ' ') i++;
        }

        void skipOws() {
            while (!eof() && (s.charAt(i) == ' ' || s.charAt(i) == '\t')) i++;
        }

        Map<String, Member> dictionary() {
            Map<String, Member> dict = new LinkedHashMap<>();
            while (!eof()) {
                String key = key();
                Member member;
                if (!eof() && peek() == '=') {
                    i++;
                    member = itemOrInnerList();
                } else {
                    member = new Item(Boolean.TRUE, parameters());
                }
                dict.put(key, member);
                skipOws();
                if (eof()) break;
                expect(',');
                skipOws();
                if (eof()) throw new ParseException("Trailing comma in dictionary");
            }
            return dict;
        }

        Member itemOrInnerList() {
            if (!eof() && peek() == '(') return innerList();
            return item();
        }

        InnerList innerList() {
            expect('(');
            List<Item> items = new ArrayList<>();
            while (!eof()) {
                skipSp();
                if (eof()) break;
                if (peek() == ')') {
                    i++;
                    return new InnerList(items, parameters());
                }
                items.add(item());
                if (eof()) break;
                char c = peek();
                if (c != ' ' && c != ')') throw new ParseException("Invalid inner list at " + i);
            }
            throw new ParseException("Unterminated inner list");
        }

        Item item() {
            Object bare = bareItem();
            return new Item(bare, parameters());
        }

        Map<String, Object> parameters() {
            Map<String, Object> params = new LinkedHashMap<>();
            while (!eof() && peek() == ';') {
                i++;
                skipSp();
                String key = key();
                Object value = Boolean.TRUE;
                if (!eof() && peek() == '=') {
                    i++;
                    value = bareItem();
                }
                params.put(key, value);
            }
            return params;
        }

        String key() {
            if (eof()) throw new ParseException("Expected key");
            char c = peek();
            if (!(c >= 'a' && c <= 'z') && c != '*') throw new ParseException("Invalid key at " + i);
            int start = i;
            while (!eof()) {
                c = peek();
                if (c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '_' || c == '-' || c == '.' || c == '*') i++;
                else break;
            }
            return s.substring(start, i);
        }

        Object bareItem() {
            if (eof()) throw new ParseException("Expected bare item");
            char c = peek();
            if (c == '-' || c >= '0' && c <= '9') return number();
            if (c == '"') return string();
            if (c == '*' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z') return token();
            if (c == ':') return bytes();
            if (c == '?') return bool();
            if (c == '@') {
                i++;
                Object n = number();
                if (!(n instanceof Long l)) throw new ParseException("Date must be an integer");
                return new Date(l);
            }
            if (c == '%') return displayString();
            throw new ParseException("Unexpected character '" + c + "' at " + i);
        }

        Object number() {
            int start = i;
            if (peek() == '-') i++;
            if (eof() || !(peek() >= '0' && peek() <= '9')) throw new ParseException("Expected digit at " + i);
            boolean decimal = false;
            int digitsStart = i;
            int intDigits = -1;
            while (!eof()) {
                char c = peek();
                if (c >= '0' && c <= '9') {
                    i++;
                } else if (c == '.' && !decimal) {
                    intDigits = i - digitsStart;
                    if (intDigits > 12) throw new ParseException("Decimal integer part too long");
                    decimal = true;
                    i++;
                } else {
                    break;
                }
                int len = i - digitsStart;
                if (!decimal && len > 15) throw new ParseException("Integer too long");
                if (decimal && len > 16) throw new ParseException("Decimal too long");
            }
            String num = s.substring(start, i);
            if (!decimal) return Long.parseLong(num);
            if (num.endsWith(".")) throw new ParseException("Decimal ends with '.'");
            int frac = (i - digitsStart) - intDigits - 1;
            if (frac > 3) throw new ParseException("Decimal fraction too long");
            return new BigDecimal(num);
        }

        String string() {
            expect('"');
            StringBuilder sb = new StringBuilder();
            while (!eof()) {
                char c = s.charAt(i++);
                if (c == '\\') {
                    if (eof()) throw new ParseException("Unterminated escape");
                    char n = s.charAt(i++);
                    if (n != '"' && n != '\\') throw new ParseException("Invalid escape");
                    sb.append(n);
                } else if (c == '"') {
                    return sb.toString();
                } else if (c < 0x20 || c > 0x7e) {
                    throw new ParseException("Invalid string character");
                } else {
                    sb.append(c);
                }
            }
            throw new ParseException("Unterminated string");
        }

        Token token() {
            int start = i;
            i++;
            while (!eof()) {
                char c = peek();
                if (LinkHeader.isTokenChar(c) || c == ':' || c == '/') i++;
                else break;
            }
            return new Token(s.substring(start, i));
        }

        Bytes bytes() {
            expect(':');
            int end = s.indexOf(':', i);
            if (end < 0) throw new ParseException("Unterminated byte sequence");
            String b64 = s.substring(i, end);
            for (int k = 0; k < b64.length(); k++) {
                char c = b64.charAt(k);
                if (!(Character.isLetterOrDigit(c) && c < 128 || c == '+' || c == '/' || c == '=')) {
                    throw new ParseException("Invalid base64 in byte sequence");
                }
            }
            i = end + 1;
            try {
                return new Bytes(Base64.getDecoder().decode(b64));
            } catch (IllegalArgumentException e) {
                throw new ParseException("Invalid base64 in byte sequence");
            }
        }

        Boolean bool() {
            expect('?');
            if (eof()) throw new ParseException("Expected boolean");
            char c = s.charAt(i++);
            if (c == '1') return Boolean.TRUE;
            if (c == '0') return Boolean.FALSE;
            throw new ParseException("Invalid boolean");
        }

        DisplayString displayString() {
            expect('%');
            expect('"');
            java.io.ByteArrayOutputStream bytes = new java.io.ByteArrayOutputStream();
            while (!eof()) {
                char c = s.charAt(i++);
                if (c == '%') {
                    if (i + 2 > s.length()) throw new ParseException("Invalid percent-encoding");
                    String hex = s.substring(i, i + 2);
                    if (!hex.matches("[0-9a-f]{2}")) throw new ParseException("Invalid percent-encoding");
                    bytes.write(Integer.parseInt(hex, 16));
                    i += 2;
                } else if (c == '"') {
                    return new DisplayString(bytes.toString(java.nio.charset.StandardCharsets.UTF_8));
                } else if (c < 0x20 || c > 0x7e) {
                    throw new ParseException("Invalid display string character");
                } else {
                    bytes.write(c);
                }
            }
            throw new ParseException("Unterminated display string");
        }
    }

    // ------------------------------------------------------------------------------------------------
    // Serialisation (RFC 8941 section 4.1)
    // ------------------------------------------------------------------------------------------------

    /** Serialises a dictionary member value (item or inner list with parameters). */
    public static String serialize(Member member) {
        StringBuilder sb = new StringBuilder();
        if (member instanceof InnerList list) {
            sb.append('(');
            boolean first = true;
            for (Item it : list.items()) {
                if (!first) sb.append(' ');
                first = false;
                serializeItem(it, sb);
            }
            sb.append(')');
            serializeParams(list.params(), sb);
        } else {
            serializeItem((Item) member, sb);
        }
        return sb.toString();
    }

    /** Serialises a dictionary. */
    public static String serializeDictionary(Map<String, Member> dict) {
        StringBuilder sb = new StringBuilder();
        for (Map.Entry<String, Member> e : dict.entrySet()) {
            if (sb.length() > 0) sb.append(", ");
            sb.append(e.getKey());
            Member m = e.getValue();
            if (m instanceof Item it && Boolean.TRUE.equals(it.value())) {
                serializeParams(it.params(), sb);
            } else {
                sb.append('=').append(serialize(m));
            }
        }
        return sb.toString();
    }

    private static void serializeItem(Item item, StringBuilder sb) {
        sb.append(serializeBareItem(item.value()));
        serializeParams(item.params(), sb);
    }

    private static void serializeParams(Map<String, Object> params, StringBuilder sb) {
        for (Map.Entry<String, Object> p : params.entrySet()) {
            sb.append(';').append(p.getKey());
            if (!Boolean.TRUE.equals(p.getValue())) sb.append('=').append(serializeBareItem(p.getValue()));
        }
    }

    /** Serialises a bare item. */
    public static String serializeBareItem(Object v) {
        if (v instanceof Long || v instanceof Integer || v instanceof Short) return v.toString();
        if (v instanceof BigDecimal d) {
            BigDecimal r = d.setScale(Math.min(Math.max(d.scale(), 1), 3), RoundingMode.HALF_EVEN).stripTrailingZeros();
            String str = r.toPlainString();
            return str.contains(".") ? str : str + ".0";
        }
        if (v instanceof String str) return quote(str);
        if (v instanceof Token t) return t.value();
        if (v instanceof Bytes b) return b.toString();
        if (v instanceof byte[] b) return ":" + Base64.getEncoder().encodeToString(b) + ":";
        if (v instanceof Boolean b) return b ? "?1" : "?0";
        if (v instanceof Date d) return "@" + d.epochSeconds();
        if (v instanceof DisplayString d) {
            StringBuilder sb = new StringBuilder("%\"");
            for (byte b : d.value().getBytes(java.nio.charset.StandardCharsets.UTF_8)) {
                int c = b & 0xff;
                if (c == '%' || c == '"' || c < 0x20 || c > 0x7e) sb.append('%').append(String.format("%02x", c));
                else sb.append((char) c);
            }
            return sb.append('"').toString();
        }
        throw new IllegalArgumentException("Not a structured field bare item: " + v);
    }

    private static String quote(String str) {
        StringBuilder sb = new StringBuilder("\"");
        for (int k = 0; k < str.length(); k++) {
            char c = str.charAt(k);
            if (c < 0x20 || c > 0x7e) throw new IllegalArgumentException("Invalid character in sf-string");
            if (c == '"' || c == '\\') sb.append('\\');
            sb.append(c);
        }
        return sb.append('"').toString();
    }
}
