// SPDX-License-Identifier: MIT
package com.ebremer.lws.auth;

import com.ebremer.lws.Lws;
import java.nio.charset.StandardCharsets;
import java.util.Objects;
import java.util.function.Function;
import java.util.function.Supplier;

/**
 * SAML 2.0 authentication suite ({@code lws10-authn-saml}): presents a signed SAML 2.0 assertion
 * ({@code urn:ietf:params:oauth:token-type:saml2}). Per RFC 8693 the subject token is the
 * base64url-encoded assertion; {@link #ofXml(String)} performs the encoding.
 */
public final class SamlCredentials implements CredentialProvider {
    private final Function<CredentialContext, String> assertions;

    private SamlCredentials(Function<CredentialContext, String> assertions) {
        this.assertions = Objects.requireNonNull(assertions, "assertions");
    }

    /** A fixed, already base64url-encoded assertion. */
    public static SamlCredentials ofEncoded(String base64UrlAssertion) {
        Objects.requireNonNull(base64UrlAssertion, "base64UrlAssertion");
        return new SamlCredentials(ctx -> base64UrlAssertion);
    }

    /** A fixed assertion given as XML; it is base64url-encoded for the token exchange. */
    public static SamlCredentials ofXml(String assertionXml) {
        return ofEncoded(encode(assertionXml));
    }

    /** Base64url-encoded assertions from a supplier. */
    public static SamlCredentials from(Supplier<String> base64UrlAssertions) {
        Objects.requireNonNull(base64UrlAssertions, "base64UrlAssertions");
        return new SamlCredentials(ctx -> base64UrlAssertions.get());
    }

    /** Base64url-encoded assertions chosen per authorization server. */
    public static SamlCredentials from(Function<CredentialContext, String> base64UrlAssertions) {
        return new SamlCredentials(base64UrlAssertions);
    }

    /** Base64url-encodes (without padding) an assertion XML document. */
    public static String encode(String assertionXml) {
        return Jwt.base64Url(assertionXml.getBytes(StandardCharsets.UTF_8));
    }

    @Override
    public String tokenType() {
        return Lws.TokenType.SAML2;
    }

    @Override
    public String subjectToken(CredentialContext context) {
        return Objects.requireNonNull(assertions.apply(context), "SAML assertion supplier returned null");
    }
}
