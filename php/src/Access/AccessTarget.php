<?php
// SPDX-License-Identifier: MIT
declare(strict_types=1);

namespace Ebremer\Lws\Access;

use Ebremer\Lws\Internal\JsonAccess;

/** The resources an access policy applies to: `{"type": "StorageResource", "value": [urls…]}`. */
final class AccessTarget
{
    /**
     * @param string $type `StorageResource`, `Container` or `DataResource`
     * @param list<string> $values the resources
     * @throws \InvalidArgumentException without values
     */
    public function __construct(public readonly string $type, public readonly array $values)
    {
        if ($values === []) {
            throw new \InvalidArgumentException('An access target needs at least one value');
        }
    }

    public static function storageResources(string ...$resources): self
    {
        return new self('StorageResource', array_values($resources));
    }

    public static function containers(string ...$resources): self
    {
        return new self('Container', array_values($resources));
    }

    public static function dataResources(string ...$resources): self
    {
        return new self('DataResource', array_values($resources));
    }

    /** @return array<string, mixed> */
    public function toJson(): array
    {
        return ['type' => $this->type, 'value' => $this->values];
    }

    /**
     * @param array<array-key, mixed> $o
     * @internal
     */
    public static function parse(array $o): self
    {
        return new self(JsonAccess::str($o, 'type') ?? 'StorageResource', JsonAccess::strings($o, 'value'));
    }
}
