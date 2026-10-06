// SPDX-License-Identifier: MIT
package com.ebremer.lws.auth;

/**
 * Supplies the subject token (an LWS authentication credential) presented to an authorization server in
 * the OAuth 2.0 token exchange. One implementation per LWS authentication suite:
 * {@link OpenIdCredentials}, {@link SamlCredentials}, {@link SelfSignedCredentials}.
 * Implementations must be thread-safe.
 */
public interface CredentialProvider {
    /** The {@code subject_token_type} URI (see {@link com.ebremer.lws.Lws.TokenType}). */
    String tokenType();

    /** Returns a subject token for the given authorization server. May block. */
    String subjectToken(CredentialContext context);
}
