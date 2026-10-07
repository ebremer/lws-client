<?php
// SPDX-License-Identifier: MIT
declare(strict_types=1);

namespace Ebremer\Lws\Tests;

use Ebremer\Lws\Http\Link;
use Ebremer\Lws\Http\LinkHeader;
use Ebremer\Lws\Http\SfBytes;
use Ebremer\Lws\Http\SfDate;
use Ebremer\Lws\Http\SfDisplayString;
use Ebremer\Lws\Http\SfInnerList;
use Ebremer\Lws\Http\SfItem;
use Ebremer\Lws\Http\SfToken;
use Ebremer\Lws\Http\Slug;
use Ebremer\Lws\Http\StructuredFieldException;
use Ebremer\Lws\Http\StructuredFields;
use Ebremer\Lws\Http\WwwAuthenticate;
use Ebremer\Lws\Internal\Url;
use Ebremer\Lws\Json\Json;
use Ebremer\Lws\Json\JsonPatch;
use Ebremer\Lws\Json\JsonPointer;
use Ebremer\Lws\Model\TypeQuery;
use Ebremer\Lws\Tests\Support\Fixtures;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/** The shared fixtures for Link, WWW-Authenticate, structured fields, JSON Patch and TypeQuery. */
final class ParserFixtureTest extends TestCase
{
    /** @return array<string, array{0: array<string, mixed>}> */
    public static function linkCases(): array
    {
        return Fixtures::cases('link-headers.json');
    }

    /** @param array<string, mixed> $case */
    #[DataProvider('linkCases')]
    public function testLinkHeaderFixture(array $case): void
    {
        $links = LinkHeader::parse($case['headers'], $case['base']);
        $got = array_map(static fn (Link $l): array => ['href' => $l->href, 'rel' => $l->rel, 'params' => $l->params], $links);
        self::assertEquals($case['expected'], $got);
    }

    public function testLinkSerializationRoundTrip(): void
    {
        $links = [
            new Link('https://example.org/a', 'describedby', ['type' => 'text/turtle', 'title' => 'say "hi"']),
            Link::typeLink('https://www.w3.org/ns/lws#Container'),
            new Link('https://example.org/e', 'alternate', ['crossorigin' => '']),
        ];
        $header = LinkHeader::formatAll($links);
        self::assertStringStartsWith('<https://example.org/a>; rel="describedby"; type="text/turtle"', $header);
        $parsed = LinkHeader::parse($header, 'https://example.org/');
        self::assertCount(3, $parsed);
        foreach ($links as $i => $l) {
            self::assertTrue($l->equals($parsed[$i]), (string) $l);
        }
        self::assertSame('text/turtle', $parsed[0]->type());
        self::assertSame('say "hi"', $parsed[0]->title());
    }

    public function testLinkTitleStarAndHelpers(): void
    {
        [$link] = LinkHeader::parse("<https://example.org/h>; rel=related; title*=UTF-8''n%C3%A4me; anchor=\"#x\"");
        self::assertSame("UTF-8''n%C3%A4me", $link->params['title*']);
        self::assertSame('näme', $link->title());
        self::assertSame('#x', $link->anchor());
        self::assertNull(LinkHeader::decodeExtValue('bogus'));
        self::assertSame('é', LinkHeader::decodeExtValue("iso-8859-1'fr'%E9"));
        $all = LinkHeader::parse(['<a>; rel="next prev UP"', '<https://x.example/r>; rel="https://Ext.example/Rel"'], 'https://s.example/d/');
        self::assertSame(['next', 'prev', 'up', 'https://Ext.example/Rel'], array_map(static fn (Link $l): string => $l->rel, $all));
        self::assertSame('https://s.example/d/a', Link::first($all, 'UP')?->href);
        self::assertTrue($all[3]->hasRel('https://Ext.example/Rel'));
        self::assertFalse($all[3]->hasRel('https://ext.example/rel'));
        self::assertCount(2, Link::all([...$all, $all[0]], 'next'));
    }

    /** @return array<string, array{0: array<string, mixed>}> */
    public static function authCases(): array
    {
        return Fixtures::cases('www-authenticate.json');
    }

    /** @param array<string, mixed> $case */
    #[DataProvider('authCases')]
    public function testWwwAuthenticateFixture(array $case): void
    {
        $challenges = WwwAuthenticate::parse($case['headers']);
        self::assertCount(count($case['expected']), $challenges);
        foreach ($case['expected'] as $i => $exp) {
            self::assertTrue($challenges[$i]->isScheme($exp['scheme']));
            self::assertEquals($exp['params'], $challenges[$i]->params);
            self::assertSame($exp['token68'] ?? null, $challenges[$i]->token68);
        }
    }

    public function testChallengeAccessors(): void
    {
        [$ch] = WwwAuthenticate::parse('Bearer as_uri="https://as.example", realm="https://s.example/", error="invalid_token", error_description="expired"');
        self::assertTrue($ch->isScheme('bearer'));
        self::assertSame(['https://as.example', 'https://s.example/', 'invalid_token', 'expired'],
            [$ch->asUri(), $ch->realm(), $ch->error(), $ch->errorDescription()]);
        self::assertSame('https://as.example', $ch->param('AS_URI'));
    }

    private static function bare(mixed $v): mixed
    {
        return match (true) {
            is_bool($v) => ['boolean' => $v],
            is_int($v) => ['integer' => $v],
            is_float($v) => ['decimal' => $v],
            is_string($v) => ['string' => $v],
            $v instanceof SfToken => ['token' => $v->value],
            $v instanceof SfBytes => ['bytes' => base64_encode($v->bytes)],
            $v instanceof SfDate => ['date' => $v->seconds],
            $v instanceof SfDisplayString => ['displayString' => $v->value],
            default => throw new \LogicException('Unexpected bare item'),
        };
    }

    /** @return array<string, mixed> */
    private static function member(SfItem|SfInnerList $m): array
    {
        $params = array_map(self::bare(...), $m->params);
        if ($m instanceof SfInnerList) {
            return ['innerList' => array_map(self::member(...), $m->items), 'params' => $params];
        }
        return ['item' => self::bare($m->value), 'params' => $params];
    }

    /** @return array<string, array{0: array<string, mixed>}> */
    public static function sfCases(): array
    {
        return Fixtures::cases('structured-fields.json');
    }

    /** @param array<string, mixed> $case */
    #[DataProvider('sfCases')]
    public function testStructuredFieldsFixture(array $case): void
    {
        if ($case['error'] ?? false) {
            $this->expectException(StructuredFieldException::class);
            StructuredFields::parseDictionary($case['input']);
            return;
        }
        $parsed = StructuredFields::parseDictionary($case['input']);
        self::assertEquals($case['expected'], array_map(self::member(...), $parsed));
        self::assertSame(array_keys($case['expected']), array_keys($parsed));
        foreach ($case['serialized'] ?? [] as $key => $text) {
            self::assertSame($text, StructuredFields::serializeMember($parsed[$key]));
        }
        // The canonical serialization parses back to the same structure.
        self::assertEquals($parsed, StructuredFields::parseDictionary(StructuredFields::serializeDictionary($parsed)));
    }

    public function testStructuredFieldListsItemsAndErrors(): void
    {
        self::assertEquals(
            [new SfItem('a'), new SfItem(new SfToken('tok')), new SfInnerList([new SfItem(1), new SfItem(2)], ['p' => true])],
            StructuredFields::parseList('"a", tok, (1 2);p'),
        );
        self::assertSame('2.5', StructuredFields::serializeBareItem(2.5));
        self::assertSame('1.0', StructuredFields::serializeBareItem(1.0));
        self::assertSame('0.124', StructuredFields::serializeBareItem(0.1235));
        self::assertSame('@1659578233', StructuredFields::serializeBareItem(new SfDate(1659578233)));
        self::assertSame('("@method");created=1', StructuredFields::serializeInnerList(new SfInnerList([new SfItem('@method')], ['created' => 1])));
        self::assertEquals(['d' => new SfItem(new SfDate(1659578233))], StructuredFields::parseDictionary('d=@1659578233'));
        $display = StructuredFields::parseDictionary('s=%"f%c3%bc%c3%bc"')['s'];
        self::assertInstanceOf(SfItem::class, $display);
        self::assertEquals(new SfDisplayString('füü'), $display->value);
        self::assertSame('%"f%c3%bc%c3%bc"', StructuredFields::serializeBareItem(new SfDisplayString('füü')));
        self::assertEquals(new SfItem(true, ['a' => 1]), StructuredFields::parseItem(' ?1;a=1 '));
        foreach (['a=1,', 'a=(1 2', 'A=1', 'a="\\x"', 'a=1.2345', 'a=:not base64:', 'a=?2', 'a=1 b=2'] as $bad) {
            try {
                StructuredFields::parseDictionary($bad);
                self::fail("Parsed $bad");
            } catch (StructuredFieldException) {
                self::addToAssertionCount(1);
            }
        }
        $this->expectException(StructuredFieldException::class);
        StructuredFields::serializeBareItem("caf\u{e9}");
    }

    public function testJsonPointerFixture(): void
    {
        $f = Fixtures::load('json-patch.json');
        foreach ($f['pointerEscapes'] as $c) {
            self::assertSame($c['escaped'], JsonPointer::escape($c['segment']));
            self::assertSame($c['segment'], JsonPointer::unescape($c['escaped']));
        }
        foreach ($f['pointers'] as $c) {
            self::assertSame($c['pointer'], JsonPointer::fromSegments(...$c['segments']));
            self::assertSame($c['segments'], JsonPointer::segments($c['pointer']));
        }
        $this->expectException(\InvalidArgumentException::class);
        JsonPointer::segments('no-slash');
    }

    public function testJsonPatchFixture(): void
    {
        $ops = Fixtures::load('json-patch.json')['patch']['operations'];
        $patch = (new JsonPatch())
            ->add($ops[0]['path'], $ops[0]['value'])
            ->remove($ops[1]['path'])
            ->replace($ops[2]['path'], $ops[2]['value'])
            ->move($ops[3]['from'], $ops[3]['path'])
            ->copy($ops[4]['from'], $ops[4]['path'])
            ->test($ops[5]['path'], $ops[5]['value']);
        self::assertEquals($ops, json_decode($patch->encode(), true));
        self::assertCount(6, $patch);
        self::assertEquals($patch->operations(), (new JsonPatch($ops))->operations());
        self::assertEquals($patch->operations(), JsonPatch::fromJson(json_encode($ops))->operations());
        // A null value and an empty object survive.
        $p = (new JsonPatch())->add('/a', null)->add('/b', new \stdClass())->add('/c', []);
        self::assertSame('[{"op":"add","path":"/a","value":null},{"op":"add","path":"/b","value":{}},{"op":"add","path":"/c","value":[]}]', $p->encode());
        foreach ([[['op' => 'add', 'path' => '/a']], [['op' => 'nope', 'path' => '/a']], [['op' => 'move', 'path' => '/a']], [['op' => 'remove', 'path' => 'a']], ['x']] as $bad) {
            try {
                new JsonPatch($bad);
                self::fail('Accepted ' . json_encode($bad));
            } catch (\InvalidArgumentException) {
                self::addToAssertionCount(1);
            }
        }
    }

    /** @return array<string, array{0: array<string, mixed>}> */
    public static function queryCases(): array
    {
        return Fixtures::cases('type-queries.json');
    }

    /** @param array<string, mixed> $case */
    #[DataProvider('queryCases')]
    public function testTypeQueryFixture(array $case): void
    {
        $build = static function () use ($case): TypeQuery {
            $q = TypeQuery::create();
            foreach ($case['steps'] as $step) {
                $clause = $q->relation($step['key']);
                isset($step['allOf']) ? $clause->allOf(...$step['allOf']) : $clause->anyOf(...$step['anyOf']);
            }
            return $q;
        };
        if ($case['error'] ?? false) {
            $this->expectException(\InvalidArgumentException::class);
            $build();
            return;
        }
        $q = $build();
        self::assertEquals($case['json'], json_decode($q->encode(), true));
        self::assertSame($q->encode(), TypeQuery::fromJson($q->encode())->encode());
    }

    public function testTypeQueryBuilderAndValidation(): void
    {
        $q = TypeQuery::create()->allOf('https://schema.org/Person')
            ->relation('describedby')->anyOf('https://example.org/shapes/person', 'https://example.org/shapes/agent');
        self::assertSame('{"type":["https://schema.org/Person"],"describedby":[["https://example.org/shapes/person","https://example.org/shapes/agent"]]}', $q->encode());
        self::assertSame('{}', TypeQuery::create()->encode());
        self::assertTrue(TypeQuery::fromJson('{}')->isEmpty());
        self::assertFalse(TypeQuery::isAbsoluteIri('https://x.example/a b'));
        self::assertFalse(TypeQuery::isAbsoluteIri('urn:'));
        self::assertTrue(TypeQuery::isAbsoluteIri('urn:x'));
        foreach (['[]', '{"type":"x"}', '{"type":[1]}', '{"@id":[]}', 'nope'] as $bad) {
            try {
                TypeQuery::fromJson($bad);
                self::fail("Accepted $bad");
            } catch (\InvalidArgumentException) {
                self::addToAssertionCount(1);
            }
        }
    }

    public function testSlugEncoding(): void
    {
        self::assertSame('hello.txt', Slug::encode('hello.txt'));
        self::assertSame('na%C3%AFve 100%25', Slug::encode('naïve 100%'));
    }

    public function testUrlResolution(): void
    {
        // RFC 3986 section 5.4.
        $base = 'http://a/b/c/d;p?q';
        $cases = [
            'g:h' => 'g:h', 'g' => 'http://a/b/c/g', './g' => 'http://a/b/c/g', 'g/' => 'http://a/b/c/g/', '/g' => 'http://a/g',
            '//g' => 'http://g', '?y' => 'http://a/b/c/d;p?y', 'g?y' => 'http://a/b/c/g?y', '#s' => 'http://a/b/c/d;p?q#s',
            'g#s' => 'http://a/b/c/g#s', ';x' => 'http://a/b/c/;x', '' => 'http://a/b/c/d;p?q', '.' => 'http://a/b/c/',
            './' => 'http://a/b/c/', '..' => 'http://a/b/', '../g' => 'http://a/b/g', '../..' => 'http://a/', '../../g' => 'http://a/g',
            '../../../g' => 'http://a/g', '/./g' => 'http://a/g', '/../g' => 'http://a/g', 'g.' => 'http://a/b/c/g.',
            '..g' => 'http://a/b/c/..g', './../g' => 'http://a/b/g', 'g/./h' => 'http://a/b/c/g/h', 'g;x=1/../y' => 'http://a/b/c/y',
        ];
        foreach ($cases as $ref => $expected) {
            self::assertSame($expected, Url::resolve($ref, $base), "resolve($ref)");
        }
        self::assertNull(Url::resolve('relative'));
        self::assertNull(Url::resolve('a b', 'https://x.example/'));
        self::assertSame('https://x.example/p', Url::resolve('/p', 'https://x.example'));
        self::assertTrue(Url::contains('https://s.example/a', 'https://S.EXAMPLE:443/a/b'));
        self::assertFalse(Url::contains('https://s.example/a', 'https://s.example/ab'));
        self::assertSame('https://s.example/', Url::canonical('HTTPS://S.Example:443'));
        self::assertSame('http://[::1]:8080/x?q', Url::canonical('http://[::1]:8080/x?q#f'));
        self::assertSame('::1', Url::host('http://[::1]:8080/'));
        self::assertTrue(Url::isLoopback('http://[::1]:8080/'));
    }

    public function testJsonRoundTrip(): void
    {
        $text = '{"a":{},"b":[],"c":{"0":"x","1":"y"},"d":{"1":"y","0":"x"},"e":[{"f":1.0,"g":null}],"h":"é/"}';
        self::assertSame($text, Json::encode(Json::decode($text)));
        $v = Json::decode($text);
        self::assertIsArray($v);
        self::assertInstanceOf(\stdClass::class, $v['a']);
        self::assertSame([], $v['b']);
        self::assertTrue(Json::isObject($v['d']));
        self::assertFalse(Json::isObject($v['b']));
    }
}
