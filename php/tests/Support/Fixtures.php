<?php
// SPDX-License-Identifier: MIT
declare(strict_types=1);

namespace Ebremer\Lws\Tests\Support;

/** The shared fixtures of `conformance/fixtures`. */
final class Fixtures
{
    public const DIR = __DIR__ . '/../../../conformance/fixtures/';

    /** A fixture file, objects as associative arrays. */
    public static function load(string $file): mixed
    {
        $text = file_get_contents(self::DIR . $file);
        if ($text === false) {
            throw new \RuntimeException("Missing fixture $file");
        }
        return json_decode($text, true, 512, JSON_THROW_ON_ERROR);
    }

    /** A fixture file's raw text. */
    public static function text(string $file): string
    {
        return (string) file_get_contents(self::DIR . $file);
    }

    /**
     * The cases of a fixture member, as a PHPUnit data provider keyed by name.
     *
     * @return array<string, array{0: array<string, mixed>}>
     */
    public static function cases(string $file, string $member = 'cases'): array
    {
        $out = [];
        foreach (self::load($file)[$member] as $i => $case) {
            $out[$case['name'] ?? (string) $i] = [$case];
        }
        return $out;
    }
}
