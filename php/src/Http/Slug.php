<?php
// SPDX-License-Identifier: MIT
declare(strict_types=1);

namespace Ebremer\Lws\Http;

/**
 * The identity hint of a create, sent as the `Slug` header (RFC 5023 section 9.7, as in the Solid Protocol).
 * Non-ASCII, control and `%` characters are percent-encoded as UTF-8.
 */
final class Slug
{
    public const HEADER = 'Slug';

    public static function encode(string $slug): string
    {
        $out = '';
        $n = strlen($slug);
        for ($i = 0; $i < $n; $i++) {
            $b = ord($slug[$i]);
            $out .= ($b >= 0x20 && $b < 0x7f && $b !== 0x25) ? $slug[$i] : sprintf('%%%02X', $b);
        }
        return $out;
    }
}
