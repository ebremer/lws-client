// SPDX-License-Identifier: MIT
package com.ebremer.lws;

/**
 * A server response violates the LWS specification: a missing {@code Location} on {@code 201}, an
 * unexpected media type, malformed JSON, a storage description without a {@code StorageRoot}, …
 */
public class LwsProtocolException extends LwsException {
    public LwsProtocolException(String message) {
        super(message);
    }

    public LwsProtocolException(String message, Throwable cause) {
        super(message, cause);
    }
}
