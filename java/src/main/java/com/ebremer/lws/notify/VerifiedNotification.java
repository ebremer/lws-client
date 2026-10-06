// SPDX-License-Identifier: MIT
package com.ebremer.lws.notify;

import java.net.URI;

/**
 * A webhook delivery whose signature and digest verified.
 *
 * @param notification the parsed notification
 * @param keyId the {@code keyid} of the signing key
 * @param storage the storage that signed the delivery
 * @param label the signature label used (e.g. {@code sig1})
 * @param algorithm the RFC 9421 algorithm (e.g. {@code ecdsa-p256-sha256})
 */
public record VerifiedNotification(Notification notification, String keyId, URI storage, String label, String algorithm) {}
