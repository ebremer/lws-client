<?php
// SPDX-License-Identifier: MIT
declare(strict_types=1);

namespace Ebremer\Lws\Model;

use Ebremer\Lws\Internal\Url;
use Ebremer\Lws\Json\Json;
use Ebremer\Lws\MediaType;

/**
 * A type search filter (`application/lws-query+json`), in conjunctive normal form. A fluent builder:
 *
 * ```php
 * $q = TypeQuery::create()
 *     ->anyOf('https://schema.org/Person', 'http://xmlns.com/foaf/0.1/Person')   // one OR group
 *     ->allOf('https://www.w3.org/ns/lws#DataResource')                          // one AND group per IRI
 *     ->relation('describedby')->allOf('https://example.org/shapes/person');
 * ```
 *
 * Every value must be an absolute IRI and no OR group may be empty (`\InvalidArgumentException` otherwise), as a
 * server would answer `400`. The empty query `{}` matches everything.
 */
final class TypeQuery implements \JsonSerializable, \Stringable
{
    public const MEDIA_TYPE = MediaType::LWS_QUERY_JSON;
    public const TYPE_KEY = 'type';

    /** @var array<string, list<list<string>>> key → AND groups, each an OR group of IRIs */
    private array $filters = [];

    /** The empty query. */
    public static function create(): self
    {
        return new self();
    }

    /**
     * Adds each IRI as its own AND group on `type`.
     *
     * @throws \InvalidArgumentException for an IRI that is not absolute
     */
    public function allOf(string ...$iris): static
    {
        return $this->allOfKey(self::TYPE_KEY, array_values($iris));
    }

    /**
     * Adds one OR group of IRIs on `type`.
     *
     * @throws \InvalidArgumentException for an IRI that is not absolute, or no IRI
     */
    public function anyOf(string ...$iris): static
    {
        return $this->anyOfKey(self::TYPE_KEY, array_values($iris));
    }

    /**
     * The clause for an indexed descriptive relation (same grammar, under the relation's key).
     *
     * @throws \InvalidArgumentException for an empty key or one starting with `@`
     */
    public function relation(string $relation): TypeQueryRelation
    {
        if ($relation === '' || str_starts_with($relation, '@')) {
            throw new \InvalidArgumentException("Invalid filter key: $relation");
        }
        return new TypeQueryRelation($this, $relation);
    }

    /**
     * @param list<string> $iris
     * @internal
     */
    public function allOfKey(string $key, array $iris): static
    {
        $groups = [];
        foreach ($iris as $iri) {
            $groups[] = [self::validate($iri)];
        }
        return $this->addGroups($key, $groups);
    }

    /**
     * @param list<string> $iris
     * @internal
     */
    public function anyOfKey(string $key, array $iris): static
    {
        if ($iris === []) {
            throw new \InvalidArgumentException('An OR group must not be empty');
        }
        return $this->addGroups($key, [array_map(self::validate(...), $iris)]);
    }

    /** @param list<list<string>> $groups */
    private function addGroups(string $key, array $groups): static
    {
        $this->filters[$key] ??= [];
        foreach ($groups as $g) {
            if (!in_array($g, $this->filters[$key], true)) {
                $this->filters[$key][] = $g;
            }
        }
        return $this;
    }

    private static function validate(string $iri): string
    {
        if (!self::isAbsoluteIri($iri)) {
            throw new \InvalidArgumentException("Not an absolute IRI: $iri");
        }
        return $iri;
    }

    /** Whether a value is an absolute IRI: a scheme and something after it, no spaces or `<>"{}|\^\``. */
    public static function isAbsoluteIri(string $iri): bool
    {
        if (!Url::hasScheme($iri)) {
            return false;
        }
        $rest = substr($iri, strpos($iri, ':') + 1);
        return $rest !== '' && preg_match('/[\s<>"{}|\\\\^`]/u', $rest) !== 1;
    }

    /**
     * Rebuilds a query from its JSON (text, or decoded: then an empty array is the empty query): each key holds a
     * list of groups, a group an IRI (AND) or a list of IRIs (OR).
     *
     * @throws \InvalidArgumentException when it is not a valid query document
     */
    public static function fromJson(mixed $json): self
    {
        if (is_string($json)) {
            try {
                $json = Json::decode($json);
            } catch (\JsonException $e) {
                throw new \InvalidArgumentException('A type query is not valid JSON: ' . $e->getMessage(), 0, $e);
            }
            if ($json === []) {
                throw new \InvalidArgumentException('A type query must be a JSON object');
            }
        }
        $members = $json === [] ? [] : Json::members($json);
        if ($members === null) {
            throw new \InvalidArgumentException('A type query must be a JSON object');
        }
        $q = new self();
        foreach ($members as $key => $groups) {
            $key = (string) $key;
            if (!Json::isList($groups)) {
                throw new \InvalidArgumentException("Query member '$key' must be a list of groups");
            }
            $clause = $q->relation($key);
            foreach ($groups as $g) {
                if (is_string($g)) {
                    $clause->allOf($g);
                } elseif (Json::isList($g) && count(array_filter($g, 'is_string')) === count($g)) {
                    $clause->anyOf(...$g);
                } else {
                    throw new \InvalidArgumentException("A group of query member '$key' must be an IRI or a list of IRIs");
                }
            }
        }
        return $q;
    }

    /**
     * The query document (a one-IRI group as a plain string; `{}` as an empty `\stdClass`).
     *
     * @return array<string, list<string|list<string>>>|\stdClass
     */
    public function toJson(): array|\stdClass
    {
        if ($this->filters === []) {
            return new \stdClass();
        }
        $out = [];
        foreach ($this->filters as $key => $groups) {
            $out[$key] = array_map(static fn (array $g): string|array => count($g) === 1 ? $g[0] : $g, $groups);
        }
        return $out;
    }

    /** @return array<string, list<string|list<string>>>|\stdClass */
    public function jsonSerialize(): array|\stdClass
    {
        return $this->toJson();
    }

    /** The serialized query. */
    public function encode(): string
    {
        return Json::encode($this->toJson());
    }

    public function isEmpty(): bool
    {
        return $this->filters === [];
    }

    public function __toString(): string
    {
        return $this->encode();
    }
}
