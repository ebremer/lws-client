<?php
// SPDX-License-Identifier: MIT
declare(strict_types=1);

namespace Ebremer\Lws\Internal;

/**
 * base64url without padding (RFC 4648 section 5).
 *
 * @internal
 */
final class Base64Url
{
    public static function encode(string $bytes): string
    {
        return rtrim(strtr(base64_encode($bytes), '+/', '-_'), '=');
    }

    /** Decodes base64url (padding optional), or returns null for other characters. */
    public static function decode(string $text): ?string
    {
        $t = rtrim($text, '=');
        if (preg_match('/^[A-Za-z0-9_-]*$/', $t) !== 1 || strlen($t) % 4 === 1) {
            return null;
        }
        $d = base64_decode(strtr($t, '-_', '+/'), true);
        return $d === false ? null : $d;
    }
}
