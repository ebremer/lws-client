<?php
// SPDX-License-Identifier: MIT
declare(strict_types=1);

namespace Ebremer\Lws\Model;

use Ebremer\Lws\Vocabulary;

/** A capability of a storage description, extra members in `raw`. */
final class Capability
{
    /**
     * @param list<string> $types
     * @param array<array-key, mixed> $raw
     */
    public function __construct(public readonly ?string $id, public readonly array $types, public readonly array $raw = [])
    {
    }

    public function hasType(string $type): bool
    {
        return Vocabulary::hasType($this->types, $type);
    }

    public function property(string $name): mixed
    {
        return $this->raw[$name] ?? null;
    }
}
