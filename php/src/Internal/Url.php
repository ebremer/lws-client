<?php
// SPDX-License-Identifier: MIT
declare(strict_types=1);

namespace Ebremer\Lws\Internal;

/**
 * URI reference resolution (RFC 3986 section 5) and the comparisons the client needs.
 *
 * @internal
 */
final class Url
{
    private const PATTERN = '~^(?:([A-Za-z][A-Za-z0-9+.\-]*):)?(?://([^/?#]*))?([^?#]*)(?:\?([^#]*))?(?:#(.*))?$~s';

    /**
     * Splits a URI reference into its five components (RFC 3986 appendix B); absent components are null.
     *
     * @return array{scheme: ?string, authority: ?string, path: string, query: ?string, fragment: ?string}
     */
    public static function parse(string $reference): array
    {
        preg_match(self::PATTERN, $reference, $m, PREG_UNMATCHED_AS_NULL);
        return [
            'scheme' => $m[1] ?? null,
            'authority' => $m[2] ?? null,
            'path' => $m[3] ?? '',
            'query' => $m[4] ?? null,
            'fragment' => $m[5] ?? null,
        ];
    }

    /** Whether a reference starts with a scheme (`[A-Za-z][A-Za-z0-9+.-]*:`). */
    public static function hasScheme(string $reference): bool
    {
        return preg_match('~^[A-Za-z][A-Za-z0-9+.\-]*:~', $reference) === 1;
    }

    /**
     * Resolves a URI reference against a base (RFC 3986 section 5.2), or returns null when it is malformed
     * (spaces or control characters) or relative without an absolute base.
     */
    public static function resolve(string $reference, ?string $base = null): ?string
    {
        $r = trim($reference, " \t");
        if (preg_match('/[\x00-\x20\x7f]/', $r) === 1) {
            return null;
        }
        $ref = self::parse($r);
        if ($ref['scheme'] !== null) {
            $t = $ref;
            $t['path'] = self::removeDotSegments($ref['path']);
            return self::compose($t);
        }
        if ($base === null || !self::hasScheme($base)) {
            return null;
        }
        $b = self::parse($base);
        $t = ['scheme' => $b['scheme'], 'authority' => null, 'path' => '', 'query' => null, 'fragment' => $ref['fragment']];
        if ($ref['authority'] !== null) {
            $t['authority'] = $ref['authority'];
            $t['path'] = self::removeDotSegments($ref['path']);
            $t['query'] = $ref['query'];
        } else {
            $t['authority'] = $b['authority'];
            if ($ref['path'] === '') {
                $t['path'] = $b['path'];
                $t['query'] = $ref['query'] ?? $b['query'];
            } else {
                if (str_starts_with($ref['path'], '/')) {
                    $t['path'] = self::removeDotSegments($ref['path']);
                } elseif ($b['authority'] !== null && $b['path'] === '') {
                    $t['path'] = self::removeDotSegments('/' . $ref['path']);
                } else {
                    $i = strrpos($b['path'], '/');
                    $t['path'] = self::removeDotSegments(($i === false ? '' : substr($b['path'], 0, $i + 1)) . $ref['path']);
                }
                $t['query'] = $ref['query'];
            }
        }
        return self::compose($t);
    }

    /** RFC 3986 section 5.2.4. */
    public static function removeDotSegments(string $path): string
    {
        if (!str_contains($path, '.')) {
            return $path;
        }
        $in = $path;
        $out = '';
        while ($in !== '') {
            if (str_starts_with($in, '../')) {
                $in = substr($in, 3);
            } elseif (str_starts_with($in, './')) {
                $in = substr($in, 2);
            } elseif (str_starts_with($in, '/./')) {
                $in = substr($in, 2);
            } elseif ($in === '/.') {
                $in = '/';
            } elseif (str_starts_with($in, '/../')) {
                $in = substr($in, 3);
                $out = self::dropLastSegment($out);
            } elseif ($in === '/..') {
                $in = '/';
                $out = self::dropLastSegment($out);
            } elseif ($in === '.' || $in === '..') {
                $in = '';
            } else {
                $start = str_starts_with($in, '/') ? 1 : 0;
                $next = strpos($in, '/', $start);
                $segment = $next === false ? $in : substr($in, 0, $next);
                $out .= $segment;
                $in = $next === false ? '' : substr($in, $next);
            }
        }
        return $out;
    }

    private static function dropLastSegment(string $out): string
    {
        $i = strrpos($out, '/');
        return $i === false ? '' : substr($out, 0, $i);
    }

    /** @param array{scheme: ?string, authority: ?string, path: string, query: ?string, fragment: ?string} $c */
    private static function compose(array $c): string
    {
        $s = '';
        if ($c['scheme'] !== null) {
            $s .= $c['scheme'] . ':';
        }
        if ($c['authority'] !== null) {
            $s .= '//' . $c['authority'];
        }
        $s .= $c['path'];
        if ($c['query'] !== null) {
            $s .= '?' . $c['query'];
        }
        if ($c['fragment'] !== null) {
            $s .= '#' . $c['fragment'];
        }
        return $s;
    }

    /** Whether a string is an absolute http(s) URL with a host. */
    public static function isHttp(string $url): bool
    {
        $c = self::parse($url);
        $scheme = strtolower($c['scheme'] ?? '');
        return ($scheme === 'http' || $scheme === 'https') && $c['authority'] !== null && self::host($url) !== ''
            && preg_match('/[\x00-\x20\x7f]/', $url) !== 1;
    }

    /**
     * Requires an absolute http(s) URL as a request target.
     *
     * @throws \InvalidArgumentException when it is not one
     */
    public static function requireHttp(string $url, string $what): string
    {
        if (!self::isHttp($url)) {
            throw new \InvalidArgumentException("$what is not an absolute http(s) URL: $url");
        }
        return $url;
    }

    /** The scheme, lower-cased ('' when there is none). */
    public static function scheme(string $url): string
    {
        return strtolower(self::parse($url)['scheme'] ?? '');
    }

    /** The host, lower-cased, without IPv6 brackets ('' when there is none). */
    public static function host(string $url): string
    {
        return self::splitAuthority(self::parse($url)['authority'] ?? '')[0];
    }

    /** The explicit port, or null. */
    public static function port(string $url): ?int
    {
        return self::splitAuthority(self::parse($url)['authority'] ?? '')[1];
    }

    /** The explicit port or the scheme's default (80, 443). */
    public static function effectivePort(string $url): ?int
    {
        return self::port($url) ?? match (self::scheme($url)) {
            'http' => 80,
            'https' => 443,
            default => null,
        };
    }

    /** @return array{0: string, 1: ?int} the lower-cased host and the explicit port */
    private static function splitAuthority(string $authority): array
    {
        $at = strrpos($authority, '@');
        $hostPort = $at === false ? $authority : substr($authority, $at + 1);
        if (str_starts_with($hostPort, '[')) {
            $close = strpos($hostPort, ']');
            if ($close === false) {
                return [strtolower($hostPort), null];
            }
            $host = substr($hostPort, 1, $close - 1);
            $rest = substr($hostPort, $close + 1);
        } else {
            $colon = strrpos($hostPort, ':');
            $host = $colon === false ? $hostPort : substr($hostPort, 0, $colon);
            $rest = $colon === false ? '' : substr($hostPort, $colon);
        }
        $port = null;
        if (str_starts_with($rest, ':') && strlen($rest) > 1 && ctype_digit(substr($rest, 1))) {
            $port = (int) substr($rest, 1);
        }
        return [strtolower($host), $port];
    }

    /** Whether two URLs share scheme, host and effective port. */
    public static function sameOrigin(string $a, string $b): bool
    {
        return self::scheme($a) === self::scheme($b) && self::host($a) === self::host($b)
            && self::effectivePort($a) === self::effectivePort($b);
    }

    /** The path as it appears in the URL (percent-encoded), `/` when empty. */
    public static function path(string $url): string
    {
        $p = self::parse($url)['path'];
        return $p === '' ? '/' : $p;
    }

    /** The query including its `?`, or the empty string. */
    public static function query(string $url): string
    {
        $q = self::parse($url)['query'];
        return $q === null ? '' : '?' . $q;
    }

    /**
     * Whether `url` is logically contained in `realm`: same origin, and the path equals the realm path or lies
     * beneath it (the realm path is treated as a directory).
     */
    public static function contains(string $realm, string $url): bool
    {
        if (!self::sameOrigin($realm, $url)) {
            return false;
        }
        $rp = self::parse($realm)['path'];
        $up = self::path($url);
        if ($rp === '' || $rp === '/' || $up === $rp) {
            return true;
        }
        $dir = str_ends_with($rp, '/') ? $rp : $rp . '/';
        return str_starts_with($up, $dir) || $up . '/' === $dir;
    }

    /** Loopback hosts, which may use plain HTTP for authorization servers. */
    public static function isLoopback(string $url): bool
    {
        $h = self::host($url);
        return $h === 'localhost' || $h === '127.0.0.1' || $h === '::1' || str_ends_with($h, '.localhost');
    }

    /** The string without its fragment. */
    public static function withoutFragment(string $s): string
    {
        $i = strpos($s, '#');
        return $i === false ? $s : substr($s, 0, $i);
    }

    /** The fragment (without `#`), or null. */
    public static function fragment(string $s): ?string
    {
        $i = strpos($s, '#');
        return $i === false ? null : substr($s, $i + 1);
    }

    /** A URL as compared for identity: scheme and host lower-cased, the default port dropped, no fragment. */
    public static function canonical(string $url): string
    {
        $c = self::parse($url);
        if ($c['scheme'] === null || $c['authority'] === null) {
            return self::withoutFragment($url);
        }
        $scheme = strtolower($c['scheme']);
        [$host, $port] = self::splitAuthority($c['authority']);
        $at = strrpos($c['authority'], '@');
        $authority = ($at === false ? '' : substr($c['authority'], 0, $at + 1)) . (str_contains($host, ':') ? "[$host]" : $host);
        $default = match ($scheme) {
            'http' => 80,
            'https' => 443,
            default => null,
        };
        if ($port !== null && $port !== $default) {
            $authority .= ':' . $port;
        }
        $path = $c['path'] === '' ? '/' : $c['path'];
        return $scheme . '://' . $authority . $path . ($c['query'] === null ? '' : '?' . $c['query']);
    }

    /** Compares two URI strings, ignoring one trailing slash on each. */
    public static function equalsIgnoringTrailingSlash(string $a, string $b): bool
    {
        $strip = static fn (string $s): string => str_ends_with($s, '/') ? substr($s, 0, -1) : $s;
        return $strip($a) === $strip($b);
    }
}
