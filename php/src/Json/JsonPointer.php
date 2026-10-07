<?php
// SPDX-License-Identifier: MIT
declare(strict_types=1);

namespace Ebremer\Lws\Json;

/**
 * JSON Pointer (RFC 6901) escaping, needed for linkset relation keys that are URIs:
 * `JsonPointer::fromSegments('linkset', '0', 'https://example.org/rel', '-')` is
 * `/linkset/0/https:~1~1example.org~1rel/-`.
 */
final class JsonPointer
{
    private function __construct()
    {
    }

    /** Escapes one reference token (`~` → `~0`, `/` → `~1`). */
    public static function escape(string $segment): string
    {
        return str_replace(['~', '/'], ['~0', '~1'], $segment);
    }

    /** Unescapes one reference token. */
    public static function unescape(string $token): string
    {
        return str_replace(['~1', '~0'], ['/', '~'], $token);
    }

    /** Builds a pointer from unescaped segments (none: the whole document, `""`). */
    public static function fromSegments(string|int ...$segments): string
    {
        $out = '';
        foreach ($segments as $s) {
            $out .= '/' . self::escape((string) $s);
        }
        return $out;
    }

    /**
     * Splits a pointer into unescaped segments.
     *
     * @return list<string>
     * @throws \InvalidArgumentException when it is neither empty nor starts with `/`
     */
    public static function segments(string $pointer): array
    {
        if ($pointer === '') {
            return [];
        }
        if (!str_starts_with($pointer, '/')) {
            throw new \InvalidArgumentException("A JSON Pointer must start with '/': $pointer");
        }
        return array_map(self::unescape(...), explode('/', substr($pointer, 1)));
    }
}
