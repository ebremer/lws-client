// SPDX-License-Identifier: MIT
package com.ebremer.lws.auth;

import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.util.Arrays;

/**
 * {@code did:key} identifiers for P-256 and Ed25519 public keys: {@code did:key:} + multibase base58btc
 * ({@code z}) of the multicodec varint prefix and the public key (P-256 as a 33-byte compressed point).
 * P-256 identifiers start with {@code zDn}, Ed25519 identifiers with {@code z6Mk}.
 */
public final class DidKey {
    private DidKey() {}

    private static final byte[] P256_PREFIX = {(byte) 0x80, 0x24};
    private static final byte[] ED25519_PREFIX = {(byte) 0xed, 0x01};
    private static final String B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

    /** The {@code did:key} identifier of a P-256 or Ed25519 public key. */
    public static String fromPublicKey(PublicKey key) {
        return "did:key:" + multibase(key);
    }

    /** The verification method id ({@code did:key:z…#z…}) used as JWT {@code kid}. */
    public static String keyId(PublicKey key) {
        String mb = multibase(key);
        return "did:key:" + mb + "#" + mb;
    }

    /** The verification method id for an existing {@code did:key} identifier. */
    public static String keyId(String did) {
        if (!did.startsWith("did:key:")) throw new IllegalArgumentException("Not a did:key: " + did);
        String mb = did.substring("did:key:".length());
        int hash = mb.indexOf('#');
        if (hash >= 0) mb = mb.substring(0, hash);
        return "did:key:" + mb + "#" + mb;
    }

    /** Decodes a {@code did:key} (or its key id) into the public key. */
    public static PublicKey toPublicKey(String did) {
        if (!did.startsWith("did:key:z")) throw new IllegalArgumentException("Not a base58btc did:key: " + did);
        String mb = did.substring("did:key:z".length());
        int hash = mb.indexOf('#');
        if (hash >= 0) mb = mb.substring(0, hash);
        byte[] bytes = base58Decode(mb);
        try {
            if (startsWith(bytes, ED25519_PREFIX)) {
                byte[] x = Arrays.copyOfRange(bytes, 2, bytes.length);
                return Jwk.toPublicKey(com.ebremer.lws.internal.Json.object().put("kty", "OKP").put("crv", "Ed25519")
                        .put("x", Jwt.base64Url(x)));
            }
            if (startsWith(bytes, P256_PREFIX) && bytes.length == 35) {
                ECParameterSpec params = Jwk.curve("P-256");
                BigInteger p = new BigInteger("ffffffff00000001000000000000000000000000ffffffffffffffffffffffff", 16);
                BigInteger x = new BigInteger(1, Arrays.copyOfRange(bytes, 3, 35));
                BigInteger a = params.getCurve().getA();
                BigInteger b = params.getCurve().getB();
                BigInteger rhs = x.pow(3).add(a.multiply(x)).add(b).mod(p);
                BigInteger y = rhs.modPow(p.add(BigInteger.ONE).shiftRight(2), p);
                if (!y.multiply(y).mod(p).equals(rhs)) throw new IllegalArgumentException("Invalid P-256 point");
                boolean odd = bytes[2] == 0x03;
                if (y.testBit(0) != odd) y = p.subtract(y);
                return KeyFactory.getInstance("EC").generatePublic(new ECPublicKeySpec(new ECPoint(x, y), params));
            }
        } catch (GeneralSecurityException e) {
            throw new IllegalArgumentException("Invalid did:key: " + e.getMessage(), e);
        }
        throw new IllegalArgumentException("Unsupported did:key key type: " + did);
    }

    private static String multibase(PublicKey key) {
        byte[] data;
        if (key instanceof ECPublicKey ec) {
            if (ec.getParams().getCurve().getField().getFieldSize() != 256) {
                throw new IllegalArgumentException("Only P-256 EC keys are supported for did:key");
            }
            byte[] x = Jwk.fixed(ec.getW().getAffineX(), 32);
            byte[] compressed = new byte[33];
            compressed[0] = (byte) (ec.getW().getAffineY().testBit(0) ? 0x03 : 0x02);
            System.arraycopy(x, 0, compressed, 1, 32);
            data = concat(P256_PREFIX, compressed);
        } else if ("EdDSA".equalsIgnoreCase(key.getAlgorithm()) || "Ed25519".equalsIgnoreCase(key.getAlgorithm())) {
            data = concat(ED25519_PREFIX, Jwk.ed25519Raw(key));
        } else {
            throw new IllegalArgumentException("Unsupported key type for did:key: " + key.getAlgorithm());
        }
        return "z" + base58Encode(data);
    }

    /** Base58 (Bitcoin alphabet) encoding. */
    public static String base58Encode(byte[] data) {
        BigInteger n = new BigInteger(1, data);
        StringBuilder sb = new StringBuilder();
        BigInteger base = BigInteger.valueOf(58);
        while (n.signum() > 0) {
            BigInteger[] qr = n.divideAndRemainder(base);
            sb.append(B58.charAt(qr[1].intValue()));
            n = qr[0];
        }
        for (byte b : data) {
            if (b != 0) break;
            sb.append('1');
        }
        return sb.reverse().toString();
    }

    /** Base58 (Bitcoin alphabet) decoding. */
    public static byte[] base58Decode(String s) {
        BigInteger n = BigInteger.ZERO;
        BigInteger base = BigInteger.valueOf(58);
        for (int i = 0; i < s.length(); i++) {
            int d = B58.indexOf(s.charAt(i));
            if (d < 0) throw new IllegalArgumentException("Invalid base58 character");
            n = n.multiply(base).add(BigInteger.valueOf(d));
        }
        byte[] raw = n.toByteArray();
        if (raw.length > 1 && raw[0] == 0) raw = Arrays.copyOfRange(raw, 1, raw.length);
        if (n.signum() == 0) raw = new byte[0];
        int zeros = 0;
        while (zeros < s.length() && s.charAt(zeros) == '1') zeros++;
        byte[] out = new byte[zeros + raw.length];
        System.arraycopy(raw, 0, out, zeros, raw.length);
        return out;
    }

    private static boolean startsWith(byte[] a, byte[] prefix) {
        if (a.length < prefix.length) return false;
        for (int i = 0; i < prefix.length; i++) if (a[i] != prefix[i]) return false;
        return true;
    }

    private static byte[] concat(byte[] a, byte[] b) {
        byte[] out = Arrays.copyOf(a, a.length + b.length);
        System.arraycopy(b, 0, out, a.length, b.length);
        return out;
    }
}
