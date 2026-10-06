// SPDX-License-Identifier: MIT
package com.ebremer.lws.auth;

import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.spec.ECGenParameterSpec;

/** Key pair generation for self-signed LWS credentials. */
public final class KeyPairs {
    private KeyPairs() {}

    /** A new P-256 key pair (for {@code ES256}). */
    public static KeyPair generateP256() {
        try {
            KeyPairGenerator g = KeyPairGenerator.getInstance("EC");
            g.initialize(new ECGenParameterSpec("secp256r1"));
            return g.generateKeyPair();
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("P-256 is not available", e);
        }
    }

    /** A new Ed25519 key pair (for {@code EdDSA}). */
    public static KeyPair generateEd25519() {
        try {
            return KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("Ed25519 is not available", e);
        }
    }
}
