// SPDX-License-Identifier: MIT
package com.ebremer.lws;

/** An I/O failure, timeout or interruption while talking to a server. The cause holds the original exception. */
public class LwsTransportException extends LwsException {
    public LwsTransportException(String message, Throwable cause) {
        super(message, cause);
    }
}
