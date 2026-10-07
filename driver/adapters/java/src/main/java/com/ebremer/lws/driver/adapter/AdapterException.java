// SPDX-License-Identifier: MIT
package com.ebremer.lws.driver.adapter;

/** An error the adapter itself reports, with its protocol {@code kind} (for example {@code InvalidArguments}). */
final class AdapterException extends RuntimeException {
    private static final long serialVersionUID = 1L;

    private final String kind;

    AdapterException(String kind, String message) {
        super(message);
        this.kind = kind;
    }

    /** The request's arguments are missing or malformed. */
    static AdapterException invalid(String message) {
        return new AdapterException(Errors.INVALID_ARGUMENTS, message);
    }

    /** The protocol error kind. */
    String kind() {
        return kind;
    }
}
