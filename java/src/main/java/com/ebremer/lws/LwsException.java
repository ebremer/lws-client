// SPDX-License-Identifier: MIT
package com.ebremer.lws;

/**
 * Base class of every exception thrown by the LWS client. All LWS exceptions are unchecked.
 *
 * <ul>
 *   <li>{@link HttpStatusException} and its subclasses — the server answered with an error status.</li>
 *   <li>{@link AuthenticationException} — obtaining an access token failed.</li>
 *   <li>{@link LwsProtocolException} — the server response violates the LWS specification.</li>
 *   <li>{@link SignatureVerificationException} — a webhook delivery failed verification.</li>
 *   <li>{@link LwsTransportException} — an I/O error or interruption occurred.</li>
 * </ul>
 */
public class LwsException extends RuntimeException {
    public LwsException(String message) {
        super(message);
    }

    public LwsException(String message, Throwable cause) {
        super(message, cause);
    }
}
