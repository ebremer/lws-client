<?php
// SPDX-License-Identifier: MIT
declare(strict_types=1);

namespace Ebremer\Lws\Auth;

use Ebremer\Lws\Http\Headers;

/** A request attempt as an {@see Authenticator} sees it: method, target and headers. */
final class AuthRequest implements \Stringable
{
    public function __construct(public readonly string $method, public readonly string $url, public readonly Headers $headers = new Headers())
    {
    }

    /** A copy with other headers. */
    public function withHeaders(Headers $headers): self
    {
        return new self($this->method, $this->url, $headers);
    }

    /** A copy with `Authorization: Bearer <token>`. */
    public function withBearerToken(#[\SensitiveParameter] string $token): self
    {
        return $this->withHeaders($this->headers->with('Authorization', 'Bearer ' . $token));
    }

    public function __toString(): string
    {
        return "{$this->method} {$this->url}";
    }
}
