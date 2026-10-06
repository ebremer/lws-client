// SPDX-License-Identifier: MIT
package com.ebremer.lws.auth;

import com.ebremer.lws.Lws;
import java.util.Objects;
import java.util.function.Function;
import java.util.function.Supplier;

/**
 * OpenID Connect authentication suite ({@code lws10-authn-openid}): presents an OpenID Connect ID Token
 * ({@code urn:ietf:params:oauth:token-type:id_token}). Interactive login is up to the application (use
 * your OIDC library); this provider only hands the resulting ID token to the authorization server.
 *
 * <p>Security: prefer ID tokens whose {@code aud} includes the authorization server, or use
 * {@link #from(Function)} to obtain an audience-restricted token per authorization server.
 */
public final class OpenIdCredentials implements CredentialProvider {
    private final Function<CredentialContext, String> tokens;

    private OpenIdCredentials(Function<CredentialContext, String> tokens) {
        this.tokens = Objects.requireNonNull(tokens, "tokens");
    }

    /** A fixed ID token. */
    public static OpenIdCredentials of(String idToken) {
        Objects.requireNonNull(idToken, "idToken");
        return new OpenIdCredentials(ctx -> idToken);
    }

    /** ID tokens from a supplier (asked whenever a new access token is needed). */
    public static OpenIdCredentials from(Supplier<String> idTokens) {
        Objects.requireNonNull(idTokens, "idTokens");
        return new OpenIdCredentials(ctx -> idTokens.get());
    }

    /** ID tokens chosen per authorization server. */
    public static OpenIdCredentials from(Function<CredentialContext, String> idTokens) {
        return new OpenIdCredentials(idTokens);
    }

    @Override
    public String tokenType() {
        return Lws.TokenType.ID_TOKEN;
    }

    @Override
    public String subjectToken(CredentialContext context) {
        return Objects.requireNonNull(tokens.apply(context), "ID token supplier returned null");
    }
}
