<?php
// SPDX-License-Identifier: MIT
declare(strict_types=1);

namespace Ebremer\Lws\Model;

use Ebremer\Lws\Internal\JsonAccess;
use Ebremer\Lws\ResourceType;
use Ebremer\Lws\Vocabulary;

/**
 * The `MoveResource` capability of a storage description: resources of the types in `appliesTo` can move between
 * containers by a change of their `up` link (see {@see \Ebremer\Lws\LwsClient::move()}).
 */
final class MoveCapability
{
    /**
     * @param list<string> $appliesTo the resource types that can move, as the description has them
     * @param ?bool $preservesIdentifier whether a moved resource keeps its URL; null when the description does not say,
     *     and then a client must not assume it does
     * @param array<array-key, mixed> $raw the capability object
     */
    public function __construct(
        public readonly array $appliesTo = ['DataResource'],
        public readonly ?bool $preservesIdentifier = null,
        public readonly array $raw = [],
    ) {
    }

    /** The move capability a capability describes: `appliesTo` a single string normalised to a list, `["DataResource"]` when absent. */
    public static function of(Capability $capability): self
    {
        $raw = $capability->raw;
        $appliesTo = ($raw['appliesTo'] ?? null) === null ? ['DataResource'] : JsonAccess::strings($raw, 'appliesTo');
        return new self($appliesTo, JsonAccess::bool($raw, 'preservesIdentifier'), $raw);
    }

    public function movesDataResources(): bool
    {
        return Vocabulary::hasType($this->appliesTo, ResourceType::DATA_RESOURCE);
    }

    public function movesContainers(): bool
    {
        return Vocabulary::hasType($this->appliesTo, ResourceType::CONTAINER);
    }
}
