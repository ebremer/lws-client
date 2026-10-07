<?php
// SPDX-License-Identifier: MIT
declare(strict_types=1);

namespace Ebremer\Lws\Internal;

use Ebremer\Lws\Exception\ProtocolException;
use Ebremer\Lws\Json\Json;

/**
 * Reading members of decoded JSON documents.
 *
 * @internal
 */
final class JsonAccess
{
    /**
     * Parses a response body.
     *
     * @throws ProtocolException when it is not JSON
     */
    public static function parse(string $body, string $what): mixed
    {
        try {
            return Json::decode($body);
        } catch (\JsonException $e) {
            throw new ProtocolException("$what is not valid JSON: {$e->getMessage()}", 0, $e);
        }
    }

    /**
     * The members of a JSON object.
     *
     * @return array<array-key, mixed>
     * @throws ProtocolException when the value is not an object
     */
    public static function object(mixed $value, string $what): array
    {
        $m = Json::members($value);
        if ($m === null) {
            if ($value instanceof \stdClass || $value === []) {
                return [];
            }
            throw new ProtocolException("$what is not a JSON object");
        }
        return $m;
    }

    /** @param array<array-key, mixed> $o */
    public static function str(array $o, string $key): ?string
    {
        $v = $o[$key] ?? null;
        return is_string($v) ? $v : null;
    }

    /**
     * A member that is a string or a list of strings, as a list (other values are skipped).
     *
     * @param array<array-key, mixed> $o
     * @return list<string>
     */
    public static function strings(array $o, string $key): array
    {
        $v = $o[$key] ?? null;
        if (is_string($v)) {
            return [$v];
        }
        if (!is_array($v) || !array_is_list($v)) {
            return [];
        }
        return array_values(array_filter($v, 'is_string'));
    }

    /** @param array<array-key, mixed> $o */
    public static function int(array $o, string $key): ?int
    {
        $v = $o[$key] ?? null;
        if (is_int($v)) {
            return $v;
        }
        if (is_float($v) && floor($v) === $v && abs($v) < 9.0e18) {
            return (int) $v;
        }
        return null;
    }

    /** @param array<array-key, mixed> $o */
    public static function bool(array $o, string $key): ?bool
    {
        $v = $o[$key] ?? null;
        return is_bool($v) ? $v : null;
    }

    /**
     * A string member resolved against a base URL (null when absent or not resolvable).
     *
     * @param array<array-key, mixed> $o
     */
    public static function url(array $o, string $key, ?string $base): ?string
    {
        $s = self::str($o, $key);
        return $s === null ? null : Url::resolve($s, $base);
    }

    /**
     * The `type` (or `@type`) values, a single string normalised to a list.
     *
     * @param array<array-key, mixed> $o
     * @return list<string>
     */
    public static function types(array $o): array
    {
        return array_key_exists('type', $o) ? self::strings($o, 'type') : self::strings($o, '@type');
    }

    /**
     * A member that is an object or a list of objects, as a list of member arrays.
     *
     * @param array<array-key, mixed> $o
     * @return list<array<array-key, mixed>>
     */
    public static function objects(array $o, string $key): array
    {
        $v = $o[$key] ?? null;
        if ($v === null) {
            return [];
        }
        $items = Json::isList($v) ? $v : [$v];
        $out = [];
        foreach ($items as $item) {
            $m = Json::members($item);
            if ($m !== null) {
                $out[] = $m;
            } elseif ($item instanceof \stdClass) {
                $out[] = [];
            }
        }
        return $out;
    }
}
