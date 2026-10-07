<?php
// SPDX-License-Identifier: MIT
declare(strict_types=1);

namespace Ebremer\Lws\Auth;

use Ebremer\Lws\Http\AuthChallenge;
use Ebremer\Lws\Http\Headers;
use Ebremer\Lws\Http\WwwAuthenticate;

/** A `401` response passed to {@see Authenticator::handleChallenge()}. */
final class AuthResponse
{
    public function __construct(public readonly string $url, public readonly int $status, public readonly Headers $headers)
    {
    }

    /**
     * The parsed `WWW-Authenticate` challenges.
     *
     * @return list<AuthChallenge>
     */
    public function challenges(): array
    {
        return WwwAuthenticate::parse($this->headers->all('www-authenticate'));
    }
}
