// SPDX-License-Identifier: MIT
package com.ebremer.lws.auth;

import com.ebremer.lws.internal.Json;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.interfaces.ECKey;
import java.security.interfaces.EdECKey;
import java.security.interfaces.RSAKey;
import java.time.Instant;
import java.util.Base64;
import java.util.Optional;

/** Compact JSON Web Signature helpers for JWT credentials (ES256, ES384, EdDSA, RS256). */
public final class Jwt {
    private Jwt() {}

    private static final Base64.Encoder B64U = Base64.getUrlEncoder().withoutPadding();
    private static final Base64.Decoder B64U_DEC = Base64.getUrlDecoder();

    /** The JOSE {@code alg} for a key: {@code ES256}, {@code ES384}, {@code ES512}, {@code EdDSA} or {@code RS256}. */
    public static String algorithm(Key key) {
        if (key instanceof ECKey ec) {
            int bits = ec.getParams().getCurve().getField().getFieldSize();
            return switch (bits) {
                case 256 -> "ES256";
                case 384 -> "ES384";
                case 521 -> "ES512";
                default -> throw new IllegalArgumentException("Unsupported EC curve size " + bits);
            };
        }
        if (key instanceof EdECKey ed) {
            if (!"Ed25519".equalsIgnoreCase(ed.getParams().getName())) {
                throw new IllegalArgumentException("Unsupported EdDSA curve " + ed.getParams().getName());
            }
            return "EdDSA";
        }
        if (key instanceof RSAKey) return "RS256";
        String a = key.getAlgorithm();
        if ("Ed25519".equalsIgnoreCase(a) || "EdDSA".equalsIgnoreCase(a)) return "EdDSA";
        throw new IllegalArgumentException("Unsupported key type " + key.getAlgorithm());
    }

    /** The JCA signature algorithm for a JOSE {@code alg}. ECDSA uses the raw (IEEE P1363) {@code r||s} format. */
    static String jcaAlgorithm(String alg) {
        return switch (alg) {
            case "ES256" -> "SHA256withECDSAinP1363Format";
            case "ES384" -> "SHA384withECDSAinP1363Format";
            case "ES512" -> "SHA512withECDSAinP1363Format";
            case "EdDSA" -> "Ed25519";
            case "RS256" -> "SHA256withRSA";
            default -> throw new IllegalArgumentException("Unsupported JWS algorithm " + alg);
        };
    }

    /** Signs {@code claims} with {@code key}; {@code header} must contain {@code alg} (added when absent). */
    public static String sign(ObjectNode header, ObjectNode claims, PrivateKey key) {
        ObjectNode h = header.deepCopy();
        if (!h.has("alg")) h.put("alg", algorithm(key));
        String input = B64U.encodeToString(Json.toBytes(h)) + "." + B64U.encodeToString(Json.toBytes(claims));
        try {
            Signature s = Signature.getInstance(jcaAlgorithm(h.get("alg").asText()));
            s.initSign(key);
            s.update(input.getBytes(StandardCharsets.US_ASCII));
            return input + "." + B64U.encodeToString(s.sign());
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("Cannot sign JWT: " + e.getMessage(), e);
        }
    }

    /** Verifies the signature of a compact JWS with {@code key} (the {@code alg} header must not be {@code none}). */
    public static boolean verify(String jwt, PublicKey key) {
        String[] parts = jwt.split("\\.");
        if (parts.length != 3) return false;
        try {
            String alg = header(jwt).path("alg").asText("none");
            if ("none".equals(alg)) return false;
            Signature s = Signature.getInstance(jcaAlgorithm(alg));
            s.initVerify(key);
            s.update((parts[0] + "." + parts[1]).getBytes(StandardCharsets.US_ASCII));
            return s.verify(B64U_DEC.decode(parts[2]));
        } catch (GeneralSecurityException | RuntimeException e) {
            return false;
        }
    }

    /** Decodes the header without verifying. */
    public static ObjectNode header(String jwt) {
        return part(jwt, 0);
    }

    /** Decodes the claims without verifying. */
    public static ObjectNode claims(String jwt) {
        return part(jwt, 1);
    }

    /** The {@code exp} claim of a JWT, if the token is a JWT with one. */
    public static Optional<Instant> expiration(String token) {
        try {
            JsonNode exp = claims(token).get("exp");
            return exp != null && exp.isNumber() ? Optional.of(Instant.ofEpochSecond(exp.asLong())) : Optional.empty();
        } catch (RuntimeException e) {
            return Optional.empty();
        }
    }

    private static ObjectNode part(String jwt, int index) {
        String[] parts = jwt.split("\\.");
        if (parts.length < 2) throw new IllegalArgumentException("Not a JWT");
        return Json.requireObject(Json.parse(B64U_DEC.decode(parts[index])), "JWT part");
    }

    static String base64Url(byte[] bytes) {
        return B64U.encodeToString(bytes);
    }

    static byte[] base64UrlDecode(String s) {
        return B64U_DEC.decode(s);
    }
}
