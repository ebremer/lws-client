// SPDX-License-Identifier: MIT
package com.ebremer.lws;

/** A webhook delivery failed RFC 9421 / RFC 9530 verification. */
public class SignatureVerificationException extends LwsException {
    public SignatureVerificationException(String message) {
        super(message);
    }

    public SignatureVerificationException(String message, Throwable cause) {
        super(message, cause);
    }
}
