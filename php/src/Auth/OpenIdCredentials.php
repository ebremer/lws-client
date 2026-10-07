<?php
// SPDX-License-Identifier: MIT
declare(strict_types=1);

namespace Ebremer\Lws\Auth;

use Ebremer\Lws\TokenType;

/**
 * OpenID Connect authentication suite (`lws10-authn-openid`): presents an OpenID Connect ID token. Interactive login
 * is up to the application (use your OIDC library); this provider hands the resulting ID token to the
 * authorization server.
 *
 * Prefer ID tokens whose `aud` includes the authorization server, or pick one per server with a function.
 */
final class OpenIdCredentials implements CredentialProvider
{
    /** @var \Closure(CredentialContext): string */
    private readonly \Closure $idTokens;

    /** @param string|\Closure(CredentialContext): string $idToken a fixed ID token, or a function asked per exchange */
    public function __construct(#[\SensitiveParameter] string|\Closure $idToken)
    {
        $this->idTokens = is_string($idToken) ? static fn (): string => $idToken : $idToken;
    }

    public function tokenType(): string
    {
        return TokenType::ID_TOKEN;
    }

    public function subjectToken(CredentialContext $context): string
    {
        return ($this->idTokens)($context);
    }

    /** @return array<string, mixed> */
    public function __debugInfo(): array
    {
        return ['tokenType' => $this->tokenType()];
    }
}
