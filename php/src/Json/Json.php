<?php
// SPDX-License-Identifier: MIT
declare(strict_types=1);

namespace Ebremer\Lws\Json;

/**
 * JSON that round-trips.
 *
 * {@see decode()} turns JSON objects into associative arrays, which is how PHP code usually handles JSON, except
 * for the objects an array would not encode back as an object: an empty object `{}`, and an object whose keys are
 * `"0"`, `"1"`, … in order. Those stay {@see \stdClass}. So `Json::encode(Json::decode($text))` is the same
 * document, and the `raw` documents of the models (linksets, access requests, storage descriptions) can be sent
 * back unchanged.
 *
 * Values given to the client to send (JSON resources, JSON Patch values) may be any value `json_encode()` takes:
 * arrays (a list is a JSON array, any other array an object), `\stdClass`, scalars, null and
 * {@see \JsonSerializable}. Write `new \stdClass()` (or `(object) []`) for `{}`, since `[]` is an empty array.
 */
final class Json
{
    /** The flags of {@see encode()}. */
    public const ENCODE_FLAGS = JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_PRESERVE_ZERO_FRACTION | JSON_THROW_ON_ERROR;

    /**
     * Parses JSON text.
     *
     * @throws \JsonException when it is not JSON
     */
    public static function decode(string $text): mixed
    {
        return self::fromObjects(json_decode($text, false, 512, JSON_THROW_ON_ERROR));
    }

    /**
     * Serializes a value as compact JSON (slashes and Unicode unescaped, `1.0` kept as `1.0`).
     *
     * @throws \JsonException when the value cannot be encoded
     */
    public static function encode(mixed $value): string
    {
        return json_encode($value, self::ENCODE_FLAGS);
    }

    /** Whether a decoded value is a JSON object (a non-list array, or a `\stdClass`). */
    public static function isObject(mixed $value): bool
    {
        return $value instanceof \stdClass || (is_array($value) && $value !== [] && !array_is_list($value));
    }

    /** Whether a decoded value is a JSON array (a list). */
    public static function isList(mixed $value): bool
    {
        return is_array($value) && array_is_list($value);
    }

    /**
     * The members of a JSON object as an array, or null when the value is not an object.
     *
     * @return array<array-key, mixed>|null
     */
    public static function members(mixed $value): ?array
    {
        if ($value instanceof \stdClass) {
            return get_object_vars($value);
        }
        return self::isObject($value) ? (array) $value : null;
    }

    /**
     * Turns a members array back into the value that encodes as that object (an empty or list-like array becomes
     * a `\stdClass`).
     *
     * @param array<array-key, mixed> $members
     * @return array<array-key, mixed>|\stdClass
     */
    public static function object(array $members): array|\stdClass
    {
        if ($members === [] || array_is_list($members)) {
            $o = new \stdClass();
            foreach ($members as $k => $v) {
                $o->{(string) $k} = $v;
            }
            return $o;
        }
        return $members;
    }

    private static function fromObjects(mixed $v): mixed
    {
        if ($v instanceof \stdClass) {
            $a = [];
            foreach (get_object_vars($v) as $k => $x) {
                $a[$k] = self::fromObjects($x);
            }
            return self::object($a);
        }
        if (is_array($v)) {
            return array_map(self::fromObjects(...), $v);
        }
        return $v;
    }
}
