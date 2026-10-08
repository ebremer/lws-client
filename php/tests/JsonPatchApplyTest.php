<?php
// SPDX-License-Identifier: MIT
declare(strict_types=1);

namespace Ebremer\Lws\Tests;

use Ebremer\Lws\Json\Json;
use Ebremer\Lws\Json\JsonPatch;
use Ebremer\Lws\Json\JsonPatchException;
use Ebremer\Lws\Tests\Support\Fixtures;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/** Applying JSON Patch documents (RFC 6902), against conformance/fixtures/json-patch-apply.json. */
final class JsonPatchApplyTest extends TestCase
{
    /** @return array<string, array{0: mixed}> */
    public static function cases(): array
    {
        // Decoded as the client decodes JSON, so {} and [] stay distinct.
        $out = [];
        foreach (Json::members(Json::decode(Fixtures::text('json-patch-apply.json')))['cases'] ?? [] as $case) {
            $out[(string) (Json::members($case)['name'] ?? '')] = [$case];
        }
        return $out;
    }

    #[DataProvider('cases')]
    public function testFixture(mixed $case): void
    {
        $c = Json::members($case) ?? [];
        $patch = JsonPatch::fromJson($c['patch']);
        $before = Json::encode($c['doc']);
        if (($c['error'] ?? false) === true) {
            try {
                $patch->apply($c['doc']);
                self::fail('The patch applied');
            } catch (JsonPatchException $e) {
                self::assertNotSame('', $e->getMessage());
            }
        } else {
            self::assertSame(self::canonical($c['expected']), self::canonical($patch->apply($c['doc'])));
        }
        // The document passed in is never changed.
        self::assertSame($before, Json::encode($c['doc']));
    }

    public function testErrorNamesTheOperation(): void
    {
        $patch = (new JsonPatch())->replace('/a', 2)->test('/a', 3);
        try {
            $patch->apply(['a' => 1]);
            self::fail('The patch applied');
        } catch (JsonPatchException $e) {
            self::assertSame(1, $e->operation);
            self::assertSame('/a', $e->path);
            self::assertStringContainsString('Operation 1 (test /a)', $e->getMessage());
        }
    }

    public function testObjectsInPlaceAreNotMutated(): void
    {
        $inner = new \stdClass();
        $inner->{'0'} = 'x';
        $document = ['a' => $inner];
        $patched = (new JsonPatch())->replace('/a/0', 'y')->add('/a/1', 'z')->apply($document);
        self::assertSame('{"a":{"0":"x"}}', Json::encode($document));
        self::assertSame('{"a":{"0":"y","1":"z"}}', Json::encode($patched));
    }

    public function testBuiltPatchesApplyToPhpValues(): void
    {
        $document = (new JsonPatch())->replace('/age', 31)->add('/city', 'Boston')->apply(['name' => 'Alice', 'age' => 30]);
        self::assertSame('{"name":"Alice","age":31,"city":"Boston"}', Json::encode($document));
    }

    /** A JSON value with object members sorted, so that member order does not matter. */
    private static function canonical(mixed $value): string
    {
        return Json::encode(self::sorted($value));
    }

    private static function sorted(mixed $value): mixed
    {
        if (Json::isList($value)) {
            return array_map(self::sorted(...), $value);
        }
        $members = Json::members($value);
        if ($members === null) {
            return $value;
        }
        ksort($members, SORT_STRING);
        return Json::object(array_map(self::sorted(...), $members));
    }
}
