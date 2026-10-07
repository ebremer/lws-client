<?php
// SPDX-License-Identifier: MIT
declare(strict_types=1);

namespace Ebremer\Lws\Internal;

/**
 * Comma-separated header lists and media types.
 *
 * @internal
 */
final class HeaderLists
{
    /**
     * Splits field values at commas outside quoted strings; members are trimmed and empty ones dropped.
     *
     * @param iterable<string> $values
     * @return list<string>
     */
    public static function split(iterable $values): array
    {
        $out = [];
        foreach ($values as $v) {
            $cur = '';
            $quoted = false;
            $escaped = false;
            $n = strlen($v);
            for ($i = 0; $i < $n; $i++) {
                $c = $v[$i];
                if ($quoted) {
                    $cur .= $c;
                    if ($escaped) {
                        $escaped = false;
                    } elseif ($c === '\\') {
                        $escaped = true;
                    } elseif ($c === '"') {
                        $quoted = false;
                    }
                } elseif ($c === '"') {
                    $quoted = true;
                    $cur .= $c;
                } elseif ($c === ',') {
                    self::add($out, $cur);
                    $cur = '';
                } else {
                    $cur .= $c;
                }
            }
            self::add($out, $cur);
        }
        return $out;
    }

    /** @param list<string> $out */
    private static function add(array &$out, string $cur): void
    {
        $s = trim($cur, " \t");
        if ($s !== '') {
            $out[] = $s;
        }
    }

    /** The media type without parameters, lower-cased, or null. */
    public static function essence(?string $contentType): ?string
    {
        if ($contentType === null) {
            return null;
        }
        $base = explode(';', $contentType, 2)[0];
        $s = trim(trim($base, " \t"), '"');
        return $s === '' ? null : strtolower($s);
    }

    /** Whether a media type is JSON (`application/json` or a `+json` suffix). */
    public static function isJson(?string $contentType): bool
    {
        $e = self::essence($contentType);
        return $e !== null && ($e === 'application/json' || str_ends_with($e, '+json'));
    }

    /** The `charset` parameter, or null. */
    public static function charset(?string $contentType): ?string
    {
        if ($contentType === null) {
            return null;
        }
        $parts = explode(';', $contentType);
        array_shift($parts);
        foreach ($parts as $part) {
            $p = trim($part, " \t");
            if (strncasecmp($p, 'charset=', 8) === 0) {
                $name = trim(trim(substr($p, 8), " \t"), '"');
                return $name === '' ? null : $name;
            }
        }
        return null;
    }

    /**
     * Decodes a body to UTF-8 text by the charset of its content type (UTF-8 by default; a UTF-8 byte order mark is
     * dropped). Other charsets are converted with mbstring or iconv when available.
     */
    public static function decode(string $bytes, ?string $contentType): string
    {
        $charset = self::charset($contentType);
        if ($charset !== null) {
            $cs = strtolower($charset);
            if ($cs !== 'utf-8' && $cs !== 'utf8' && $cs !== 'us-ascii' && $cs !== 'ascii') {
                if (function_exists('mb_convert_encoding') && in_array($cs, array_map('strtolower', mb_list_encodings()), true)) {
                    $s = @mb_convert_encoding($bytes, 'UTF-8', $charset);
                    if (is_string($s)) {
                        return $s;
                    }
                }
                if (function_exists('iconv')) {
                    $s = @iconv($charset, 'UTF-8', $bytes);
                    if (is_string($s)) {
                        return $s;
                    }
                }
            }
        }
        return str_starts_with($bytes, "\xEF\xBB\xBF") ? substr($bytes, 3) : $bytes;
    }

    /** Removes one pair of surrounding double quotes. */
    public static function unquote(string $s): string
    {
        return strlen($s) >= 2 && $s[0] === '"' && $s[-1] === '"' ? substr($s, 1, -1) : $s;
    }
}
