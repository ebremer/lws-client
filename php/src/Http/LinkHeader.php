<?php
// SPDX-License-Identifier: MIT
declare(strict_types=1);

namespace Ebremer\Lws\Http;

use Ebremer\Lws\Internal\Url;

/**
 * Parses and formats `Link` header fields (RFC 8288).
 *
 * Any number of field lines, each with comma-separated link-values (commas inside `<…>` and quoted strings do not
 * split). Parameter names are lower-cased; a `rel` with several relation types yields one link per type. Targets
 * are resolved against the request URL. Malformed link-values are skipped.
 */
final class LinkHeader
{
    private const TOKEN = "!#$%&'*+-.^_`|~0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";

    /**
     * Parses `Link` field values.
     *
     * @param string|iterable<string> $fieldValues one field value or several field lines
     * @param string|null $base the URL the response came from, against which targets are resolved
     * @return list<Link>
     */
    public static function parse(string|iterable $fieldValues, ?string $base = null): array
    {
        $out = [];
        foreach (is_string($fieldValues) ? [$fieldValues] : $fieldValues as $v) {
            self::parseLine($v, $base, $out);
        }
        return $out;
    }

    /** @param list<Link> $out */
    private static function parseLine(string $s, ?string $base, array &$out): void
    {
        $n = strlen($s);
        $i = 0;
        while ($i < $n) {
            while ($i < $n && (self::isWs($s[$i]) || $s[$i] === ',')) {
                $i++;
            }
            if ($i >= $n) {
                break;
            }
            if ($s[$i] !== '<') {
                $i = self::skipToNextLinkValue($s, $i);
                continue;
            }
            $close = strpos($s, '>', $i + 1);
            if ($close === false) {
                break;
            }
            $target = trim(substr($s, $i + 1, $close - $i - 1), " \t");
            $i = $close + 1;
            $params = [];
            $rel = null;
            while (true) {
                while ($i < $n && self::isWs($s[$i])) {
                    $i++;
                }
                if ($i >= $n || $s[$i] === ',') {
                    break;
                }
                if ($s[$i] !== ';') {
                    $i = self::skipToNextLinkValue($s, $i);
                    break;
                }
                $i++;
                while ($i < $n && self::isWs($s[$i])) {
                    $i++;
                }
                $len = strspn($s, self::TOKEN, $i);
                $name = strtolower(substr($s, $i, $len));
                $i += $len;
                while ($i < $n && self::isWs($s[$i])) {
                    $i++;
                }
                $value = '';
                if ($i < $n && $s[$i] === '=') {
                    $i++;
                    while ($i < $n && self::isWs($s[$i])) {
                        $i++;
                    }
                    if ($i < $n && $s[$i] === '"') {
                        [$value, $i] = self::quoted($s, $i);
                    } else {
                        $vs = $i;
                        while ($i < $n && $s[$i] !== ';' && $s[$i] !== ',' && !self::isWs($s[$i])) {
                            $i++;
                        }
                        $value = substr($s, $vs, $i - $vs);
                    }
                }
                if ($name === '') {
                    continue;
                }
                if ($name === 'rel') {
                    $rel ??= $value;
                } elseif (!array_key_exists($name, $params)) {
                    $params[$name] = $value;
                }
            }
            $href = Url::resolve($target, $base);
            if ($rel === null || $href === null) {
                continue;
            }
            foreach (preg_split('/[ \t]+/', $rel, -1, PREG_SPLIT_NO_EMPTY) ?: [] as $r) {
                $out[] = new Link($href, self::normalizeRel($r), $params);
            }
        }
    }

    /**
     * Reads a quoted string starting at `$i` (the opening quote).
     *
     * @return array{0: string, 1: int} the unescaped value and the index after the closing quote
     * @internal
     */
    public static function quoted(string $s, int $i): array
    {
        $n = strlen($s);
        $v = '';
        $i++;
        while ($i < $n && $s[$i] !== '"') {
            if ($s[$i] === '\\' && $i + 1 < $n) {
                $v .= $s[$i + 1];
                $i += 2;
            } else {
                $v .= $s[$i];
                $i++;
            }
        }
        return [$v, $i < $n ? $i + 1 : $i];
    }

    private static function skipToNextLinkValue(string $s, int $i): int
    {
        $n = strlen($s);
        $quoted = false;
        $angle = false;
        for (; $i < $n; $i++) {
            $c = $s[$i];
            if ($quoted) {
                if ($c === '\\') {
                    $i++;
                } elseif ($c === '"') {
                    $quoted = false;
                }
            } elseif ($angle) {
                if ($c === '>') {
                    $angle = false;
                }
            } elseif ($c === '"') {
                $quoted = true;
            } elseif ($c === '<') {
                $angle = true;
            } elseif ($c === ',') {
                return $i + 1;
            }
        }
        return $i;
    }

    /** @internal */
    public static function isWs(string $c): bool
    {
        return $c === ' ' || $c === "\t" || $c === "\r" || $c === "\n";
    }

    /** Lower-cases a registered relation name; extension relation URIs (with a `:`) are kept as they are. */
    public static function normalizeRel(string $rel): string
    {
        return str_contains($rel, ':') ? $rel : strtolower($rel);
    }

    /**
     * Formats a link, or a target and relation, as a `Link` header value: `<href>; rel="rel"; name="value"`.
     *
     * @param array<string, string> $params
     */
    public static function format(Link|string $link, ?string $rel = null, array $params = []): string
    {
        if ($link instanceof Link) {
            return self::format($link->href, $link->rel, $link->params);
        }
        $s = '<' . $link . '>; rel=' . self::quote($rel ?? '');
        foreach ($params as $k => $v) {
            $s .= '; ' . $k . ($v === '' ? '' : '=' . self::quote($v));
        }
        return $s;
    }

    /**
     * Formats several links as one `Link` header value.
     *
     * @param iterable<Link> $links
     */
    public static function formatAll(iterable $links): string
    {
        $parts = [];
        foreach ($links as $l) {
            $parts[] = self::format($l);
        }
        return implode(', ', $parts);
    }

    private static function quote(string $v): string
    {
        return '"' . str_replace(['\\', '"'], ['\\\\', '\\"'], $v) . '"';
    }

    /** Decodes an RFC 8187 ext-value (`UTF-8''n%C3%A4me`), or returns null when it is not one. */
    public static function decodeExtValue(string $value): ?string
    {
        if (preg_match("/^([A-Za-z0-9!#$%&+\\-^_`{}~]+)'([A-Za-z0-9\\-]*)'(.*)$/s", $value, $m) !== 1) {
            return null;
        }
        $charset = strtolower($m[1]);
        if (preg_match('/%(?![0-9A-Fa-f]{2})/', $m[3]) === 1) {
            return null;
        }
        $bytes = rawurldecode($m[3]);
        if ($charset === 'utf-8') {
            return preg_match('//u', $bytes) === 1 ? $bytes : null;
        }
        if ($charset === 'iso-8859-1') {
            return self::latin1ToUtf8($bytes);
        }
        return null;
    }

    private static function latin1ToUtf8(string $latin1): string
    {
        $out = '';
        $n = strlen($latin1);
        for ($i = 0; $i < $n; $i++) {
            $c = ord($latin1[$i]);
            $out .= $c < 0x80 ? $latin1[$i] : chr(0xC0 | ($c >> 6)) . chr(0x80 | ($c & 0x3F));
        }
        return $out;
    }
}
