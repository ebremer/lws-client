<?php
// SPDX-License-Identifier: MIT
declare(strict_types=1);

namespace Ebremer\Lws\Auth;

use Ebremer\Lws\Internal\Base64Url;
use Ebremer\Lws\TokenType;

/**
 * SAML 2.0 authentication suite (`lws10-authn-saml`): presents a signed SAML 2.0 assertion. Per RFC 8693 the subject
 * token is the base64url-encoded assertion; {@see fromXml()} does the encoding.
 */
final class SamlCredentials implements CredentialProvider
{
    /** @var \Closure(CredentialContext): string */
    private readonly \Closure $assertions;

    /** @param \Closure(CredentialContext): string $encodedAssertions base64url-encoded assertions, asked per exchange */
    public function __construct(\Closure $encodedAssertions)
    {
        $this->assertions = $encodedAssertions;
    }

    /** A fixed, already base64url-encoded assertion. */
    public static function fromEncoded(#[\SensitiveParameter] string $encodedAssertion): self
    {
        return new self(static fn (): string => $encodedAssertion);
    }

    /** A fixed assertion given as XML. */
    public static function fromXml(#[\SensitiveParameter] string $assertionXml): self
    {
        return self::fromEncoded(self::encode($assertionXml));
    }

    /** Base64url-encodes (without padding) an assertion XML document. */
    public static function encode(string $assertionXml): string
    {
        return Base64Url::encode($assertionXml);
    }

    public function tokenType(): string
    {
        return TokenType::SAML2;
    }

    public function subjectToken(CredentialContext $context): string
    {
        return ($this->assertions)($context);
    }

    /** @return array<string, mixed> */
    public function __debugInfo(): array
    {
        return ['tokenType' => $this->tokenType()];
    }
}
