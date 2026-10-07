<?php
// SPDX-License-Identifier: MIT
declare(strict_types=1);

namespace Ebremer\Lws\Auth;

use Ebremer\Lws\Internal\Url;

/**
 * Sends a known access token as `Authorization: Bearer …`, optionally only to URLs inside a realm (recommended, so
 * that the token never reaches another server).
 */
final class BearerTokenAuthenticator implements Authenticator
{
    /** @var \Closure(): ?string */
    private readonly \Closure $token;

    /**
     * @param string|\Closure(): ?string $token the token, or a function asked for it per request (null: send none)
     * @param ?string $realm send the token only to URLs inside this realm (null: everywhere, so use a dedicated client)
     */
    public function __construct(#[\SensitiveParameter] string|\Closure $token, public readonly ?string $realm = null)
    {
        $this->token = is_string($token) ? static fn (): string => $token : $token;
    }

    public function authorize(AuthRequest $request): AuthRequest
    {
        if ($this->realm !== null && !Url::contains($this->realm, $request->url)) {
            return $request;
        }
        $t = ($this->token)();
        return $t === null ? $request : $request->withBearerToken($t);
    }

    public function handleChallenge(AuthRequest $request, AuthResponse $response): bool
    {
        return false;
    }

    /** @return array<string, mixed> without the token */
    public function __debugInfo(): array
    {
        return ['realm' => $this->realm];
    }
}
