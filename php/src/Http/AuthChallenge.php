<?php
// SPDX-License-Identifier: MIT
declare(strict_types=1);

namespace Ebremer\Lws\Http;

/**
 * One authentication challenge of a `WWW-Authenticate` field: a scheme (compared case-insensitively), parameters
 * with lower-cased names, or a token68.
 */
final class AuthChallenge
{
    /** @var array<string, string> */
    public readonly array $params;

    /** @param array<string, string> $params names are lower-cased; the first of a name wins */
    public function __construct(public readonly string $scheme, array $params = [], public readonly ?string $token68 = null)
    {
        $p = [];
        foreach ($params as $k => $v) {
            $p[strtolower((string) $k)] ??= $v;
        }
        $this->params = $p;
    }

    /** Whether the scheme is `$scheme`, ignoring case. */
    public function isScheme(string $scheme): bool
    {
        return strcasecmp($this->scheme, $scheme) === 0;
    }

    /** A parameter by name (case-insensitive), or null. */
    public function param(string $name): ?string
    {
        return $this->params[strtolower($name)] ?? null;
    }

    /** The LWS `as_uri` parameter: the authorization server to obtain a token from. */
    public function asUri(): ?string
    {
        return $this->params['as_uri'] ?? null;
    }

    /** The `realm` parameter: the protection space the token is for. */
    public function realm(): ?string
    {
        return $this->params['realm'] ?? null;
    }

    /** The `error` parameter (`invalid_token`, …). */
    public function error(): ?string
    {
        return $this->params['error'] ?? null;
    }

    /** The `error_description` parameter. */
    public function errorDescription(): ?string
    {
        return $this->params['error_description'] ?? null;
    }
}
