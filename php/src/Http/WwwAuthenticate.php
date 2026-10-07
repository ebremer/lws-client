<?php
// SPDX-License-Identifier: MIT
declare(strict_types=1);

namespace Ebremer\Lws\Http;

/**
 * Parses `WWW-Authenticate` fields (RFC 9110 section 11.6.1), including several challenges in one field value
 * (`Bearer as_uri="…", realm="…", DPoP algs="ES256"`).
 */
final class WwwAuthenticate
{
    private const TOKEN = "!#$%&'*+-.^_`|~0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
    private const TOKEN68 = '-._~+/0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';

    /**
     * @param string|iterable<string> $fieldValues one field value or several field lines
     * @return list<AuthChallenge>
     */
    public static function parse(string|iterable $fieldValues): array
    {
        $out = [];
        foreach (is_string($fieldValues) ? [$fieldValues] : $fieldValues as $v) {
            self::parseLine($v, $out);
        }
        return $out;
    }

    /** @param list<AuthChallenge> $out */
    private static function parseLine(string $s, array &$out): void
    {
        $n = strlen($s);
        $i = 0;
        while (true) {
            while ($i < $n && (LinkHeader::isWs($s[$i]) || $s[$i] === ',')) {
                $i++;
            }
            if ($i >= $n) {
                return;
            }
            $scheme = self::token($s, $i);
            if ($scheme === '') {
                $i++;
                continue;
            }
            self::skipWs($s, $i);
            $afterScheme = $i;
            $len = strspn($s, self::TOKEN68, $i);
            if ($len > 0) {
                $j = $i + $len;
                $j += strspn($s, '=', $j);
                $t68 = substr($s, $i, $j - $i);
                $k = $j;
                self::skipWs($s, $k);
                if ($k >= $n || $s[$k] === ',') {
                    $out[] = new AuthChallenge($scheme, [], $t68);
                    $i = $k;
                    continue;
                }
            }
            $i = $afterScheme;
            $out[] = new AuthChallenge($scheme, self::params($s, $i));
        }
    }

    /** @return array<string, string> */
    private static function params(string $s, int &$i): array
    {
        $n = strlen($s);
        $params = [];
        while (true) {
            self::skipWs($s, $i);
            $save = $i;
            $name = self::token($s, $i);
            if ($name === '') {
                $i = $save;
                return $params;
            }
            self::skipWs($s, $i);
            if ($i >= $n || $s[$i] !== '=') {
                $i = $save;
                return $params;
            }
            $i++;
            self::skipWs($s, $i);
            if ($i < $n && $s[$i] === '"') {
                [$value, $i] = LinkHeader::quoted($s, $i);
            } else {
                $value = self::token($s, $i);
            }
            $params[strtolower($name)] ??= $value;
            self::skipWs($s, $i);
            if ($i >= $n || $s[$i] !== ',') {
                return $params;
            }
            $i++;
            self::skipWs($s, $i);
            while ($i < $n && $s[$i] === ',') {
                $i++;
                self::skipWs($s, $i);
            }
            $look = $i;
            $next = self::token($s, $i);
            self::skipWs($s, $i);
            $isParam = $next !== '' && $i < $n && $s[$i] === '=';
            $i = $look;
            if (!$isParam) {
                return $params;
            }
        }
    }

    private static function token(string $s, int &$i): string
    {
        $len = strspn($s, self::TOKEN, $i);
        $t = substr($s, $i, $len);
        $i += $len;
        return $t;
    }

    private static function skipWs(string $s, int &$i): void
    {
        $n = strlen($s);
        while ($i < $n && LinkHeader::isWs($s[$i])) {
            $i++;
        }
    }
}
