<?php
// SPDX-License-Identifier: MIT
declare(strict_types=1);

namespace Ebremer\Lws\Model;

/** The filters of a {@see TypeQuery} on one relation: `$query->relation('describedby')->anyOf(…)`. */
final class TypeQueryRelation
{
    /** @internal */
    public function __construct(private readonly TypeQuery $query, public readonly string $key)
    {
    }

    /**
     * Adds each IRI as its own AND group; returns the query.
     *
     * @throws \InvalidArgumentException for an IRI that is not absolute
     */
    public function allOf(string ...$iris): TypeQuery
    {
        return $this->query->allOfKey($this->key, array_values($iris));
    }

    /**
     * Adds one OR group; returns the query.
     *
     * @throws \InvalidArgumentException for an IRI that is not absolute, or no IRI
     */
    public function anyOf(string ...$iris): TypeQuery
    {
        return $this->query->anyOfKey($this->key, array_values($iris));
    }
}
