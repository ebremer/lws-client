// SPDX-License-Identifier: MIT
package com.ebremer.lws.driver;

/**
 * A failure of the driver itself, as opposed to an outcome of an operation: an unknown client, an adapter
 * that will not start or stopped answering, a target outside the allowed ones. Tools report it as an MCP
 * tool error.
 */
public class DriverException extends RuntimeException {

    public DriverException(String message) {
        super(message);
    }

    public DriverException(String message, Throwable cause) {
        super(message, cause);
    }
}
