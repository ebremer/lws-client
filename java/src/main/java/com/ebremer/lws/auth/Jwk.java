// SPDX-License-Identifier: MIT
package com.ebremer.lws.auth;

import com.ebremer.lws.internal.Json;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.math.BigInteger;
import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.EdECPrivateKey;
import java.security.interfaces.EdECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPrivateKeySpec;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.HexFormat;

/**
 * Conversion between JSON Web Keys (RFC 7517) and JCA keys, for EC (P-256, P-384, P-521), OKP (Ed25519)
 * and RSA public keys.
 */
public final class Jwk {
    private Jwk() {}

    private static final byte[] ED25519_X509_PREFIX = HexFormat.of().parseHex("302a300506032b6570032100");
    private static final byte[] ED25519_PKCS8_PREFIX = HexFormat.of().parseHex("302e020100300506032b657004220420");

    /** Converts a public JWK to a public key. */
    public static PublicKey toPublicKey(JsonNode jwk) {
        String kty = jwk.path("kty").asText();
        try {
            switch (kty) {
                case "EC" -> {
                    ECParameterSpec params = curve(jwk.path("crv").asText());
                    ECPoint w = new ECPoint(uint(jwk, "x"), uint(jwk, "y"));
                    return KeyFactory.getInstance("EC").generatePublic(new ECPublicKeySpec(w, params));
                }
                case "OKP" -> {
                    requireEd25519(jwk);
                    byte[] x = Jwt.base64UrlDecode(jwk.path("x").asText());
                    if (x.length != 32) throw new IllegalArgumentException("Ed25519 key must be 32 bytes");
                    return KeyFactory.getInstance("Ed25519").generatePublic(new X509EncodedKeySpec(concat(ED25519_X509_PREFIX, x)));
                }
                case "RSA" -> {
                    return KeyFactory.getInstance("RSA").generatePublic(new RSAPublicKeySpec(uint(jwk, "n"), uint(jwk, "e")));
                }
                default -> throw new IllegalArgumentException("Unsupported JWK kty: " + kty);
            }
        } catch (GeneralSecurityException e) {
            throw new IllegalArgumentException("Invalid JWK: " + e.getMessage(), e);
        }
    }

    /** Converts a private JWK (with {@code d}) to a private key (EC or Ed25519). */
    public static PrivateKey toPrivateKey(JsonNode jwk) {
        String kty = jwk.path("kty").asText();
        if (!jwk.hasNonNull("d")) throw new IllegalArgumentException("JWK has no private key member 'd'");
        try {
            switch (kty) {
                case "EC" -> {
                    return KeyFactory.getInstance("EC").generatePrivate(new ECPrivateKeySpec(uint(jwk, "d"), curve(jwk.path("crv").asText())));
                }
                case "OKP" -> {
                    requireEd25519(jwk);
                    byte[] d = Jwt.base64UrlDecode(jwk.path("d").asText());
                    return KeyFactory.getInstance("Ed25519").generatePrivate(new PKCS8EncodedKeySpec(concat(ED25519_PKCS8_PREFIX, d)));
                }
                default -> throw new IllegalArgumentException("Unsupported private JWK kty: " + kty);
            }
        } catch (GeneralSecurityException e) {
            throw new IllegalArgumentException("Invalid JWK: " + e.getMessage(), e);
        }
    }

    /** Converts a private JWK (with {@code d}, {@code x}, …) to a key pair. */
    public static KeyPair toKeyPair(JsonNode privateJwk) {
        return new KeyPair(toPublicKey(privateJwk), toPrivateKey(privateJwk));
    }

    /** Converts a public key to a JWK. */
    public static ObjectNode fromPublicKey(PublicKey key) {
        ObjectNode o = Json.object();
        if (key instanceof ECPublicKey ec) {
            int size = fieldBytes(ec.getParams());
            o.put("kty", "EC");
            o.put("crv", curveName(ec.getParams()));
            o.put("x", Jwt.base64Url(fixed(ec.getW().getAffineX(), size)));
            o.put("y", Jwt.base64Url(fixed(ec.getW().getAffineY(), size)));
        } else if (key instanceof EdECPublicKey || "Ed25519".equalsIgnoreCase(key.getAlgorithm()) || "EdDSA".equalsIgnoreCase(key.getAlgorithm())) {
            o.put("kty", "OKP");
            o.put("crv", "Ed25519");
            o.put("x", Jwt.base64Url(ed25519Raw(key)));
        } else if (key instanceof RSAPublicKey rsa) {
            o.put("kty", "RSA");
            o.put("n", Jwt.base64Url(unsigned(rsa.getModulus())));
            o.put("e", Jwt.base64Url(unsigned(rsa.getPublicExponent())));
        } else {
            throw new IllegalArgumentException("Unsupported key type " + key.getAlgorithm());
        }
        return o;
    }

    /** Converts a key pair to a private JWK (including {@code d}). Keep it secret. */
    public static ObjectNode fromKeyPair(KeyPair keyPair) {
        ObjectNode o = fromPublicKey(keyPair.getPublic());
        PrivateKey priv = keyPair.getPrivate();
        if (priv instanceof ECPrivateKey ec) {
            o.put("d", Jwt.base64Url(fixed(ec.getS(), fieldBytes(ec.getParams()))));
        } else if (priv instanceof EdECPrivateKey ed) {
            byte[] d = ed.getBytes().orElseThrow(() -> new IllegalArgumentException("Ed25519 private key bytes unavailable"));
            o.put("d", Jwt.base64Url(d));
        } else {
            throw new IllegalArgumentException("Unsupported private key type " + priv.getAlgorithm());
        }
        return o;
    }

    /** The raw 32-byte Ed25519 public key. */
    static byte[] ed25519Raw(PublicKey key) {
        byte[] enc = key.getEncoded();
        return Arrays.copyOfRange(enc, enc.length - 32, enc.length);
    }

    /** Named curve parameters for a JWK {@code crv}. */
    static ECParameterSpec curve(String crv) throws GeneralSecurityException {
        String std = switch (crv) {
            case "P-256" -> "secp256r1";
            case "P-384" -> "secp384r1";
            case "P-521" -> "secp521r1";
            default -> throw new IllegalArgumentException("Unsupported EC curve: " + crv);
        };
        AlgorithmParameters p = AlgorithmParameters.getInstance("EC");
        p.init(new ECGenParameterSpec(std));
        return p.getParameterSpec(ECParameterSpec.class);
    }

    static String curveName(ECParameterSpec params) {
        return switch (params.getCurve().getField().getFieldSize()) {
            case 256 -> "P-256";
            case 384 -> "P-384";
            case 521 -> "P-521";
            default -> throw new IllegalArgumentException("Unsupported EC curve");
        };
    }

    static int fieldBytes(ECParameterSpec params) {
        return (params.getCurve().getField().getFieldSize() + 7) / 8;
    }

    private static void requireEd25519(JsonNode jwk) {
        if (!"Ed25519".equals(jwk.path("crv").asText())) {
            throw new IllegalArgumentException("Unsupported OKP curve: " + jwk.path("crv").asText());
        }
    }

    private static BigInteger uint(JsonNode jwk, String member) {
        String v = jwk.path(member).asText(null);
        if (v == null) throw new IllegalArgumentException("JWK member '" + member + "' missing");
        return new BigInteger(1, Jwt.base64UrlDecode(v));
    }

    static byte[] fixed(BigInteger v, int size) {
        byte[] b = unsigned(v);
        if (b.length == size) return b;
        if (b.length > size) throw new IllegalArgumentException("Integer too large");
        byte[] out = new byte[size];
        System.arraycopy(b, 0, out, size - b.length, b.length);
        return out;
    }

    private static byte[] unsigned(BigInteger v) {
        byte[] b = v.toByteArray();
        if (b.length > 1 && b[0] == 0) return Arrays.copyOfRange(b, 1, b.length);
        return b;
    }

    private static byte[] concat(byte[] a, byte[] b) {
        byte[] out = Arrays.copyOf(a, a.length + b.length);
        System.arraycopy(b, 0, out, a.length, b.length);
        return out;
    }
}
