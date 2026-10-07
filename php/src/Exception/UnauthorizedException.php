<?php
// SPDX-License-Identifier: MIT
declare(strict_types=1);

namespace Ebremer\Lws\Exception;

use Ebremer\Lws\Http\AuthChallenge;
use Ebremer\Lws\Http\WwwAuthenticate;

/** A `401 Unauthorized` that authentication did not resolve (or that no authenticator was there to handle). */
class UnauthorizedException extends HttpException
{
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
