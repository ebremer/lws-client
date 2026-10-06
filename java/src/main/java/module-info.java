// SPDX-License-Identifier: MIT

/**
 * Client for the W3C Linked Web Storage (LWS) Protocol 1.0.
 *
 * <p>Start with {@link com.ebremer.lws.LwsClient}.
 */
module com.ebremer.lws {
    requires transitive java.net.http;
    requires transitive com.fasterxml.jackson.databind;
    requires static jdk.httpserver;

    exports com.ebremer.lws;
    exports com.ebremer.lws.http;
    exports com.ebremer.lws.patch;
    exports com.ebremer.lws.auth;
    exports com.ebremer.lws.notify;
    exports com.ebremer.lws.access;
    exports com.ebremer.lws.index;
}
