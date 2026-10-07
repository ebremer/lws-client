<?php
// SPDX-License-Identifier: MIT
declare(strict_types=1);

namespace Ebremer\Lws\Model;

use Ebremer\Lws\Exception\ProtocolException;
use Ebremer\Lws\Internal\JsonAccess;
use Ebremer\Lws\Internal\Url;
use Ebremer\Lws\Json\Json;
use Ebremer\Lws\LinkRelation;
use Ebremer\Lws\ResourceType;
use Ebremer\Lws\Vocabulary;

/**
 * One page of a container listing (`application/lws+json`), or of type search results. Pagination links come from
 * the `Link` headers; every URL is absolute.
 */
final class ContainerPage implements \Stringable
{
    public readonly ?string $first;
    public readonly ?string $next;
    public readonly ?string $prev;
    public readonly ?string $last;
    public readonly ?string $etag;

    /**
     * @param string $id the container (or the page URL when the body has no `id`)
     * @param list<string> $types
     * @param ?int $totalItems the number of members (may be approximate)
     * @param list<ContainedResource> $items
     * @param array<array-key, mixed> $raw the page object
     */
    public function __construct(
        public readonly string $id,
        public readonly array $types,
        public readonly ?int $totalItems,
        public readonly array $items,
        public readonly ResourceMetadata $metadata,
        public readonly array $raw = [],
    ) {
        $this->first = $metadata->link(LinkRelation::FIRST)?->href;
        $this->next = $metadata->link(LinkRelation::NEXT)?->href;
        $this->prev = $metadata->link(LinkRelation::PREV)?->href;
        $this->last = $metadata->link(LinkRelation::LAST)?->href;
        $this->etag = $metadata->etag;
    }

    /**
     * Parses a page body; ids resolve against the response URL.
     *
     * @throws ProtocolException when it is not a page object
     */
    public static function parse(mixed $json, ResourceMetadata $metadata): self
    {
        $o = JsonAccess::object($json, 'The container representation');
        $base = $metadata->url;
        $id = $base;
        $idText = JsonAccess::str($o, 'id');
        if ($idText !== null) {
            $id = Url::resolve($idText, $base) ?? throw new ProtocolException("Invalid container id: $idText");
        }
        $items = [];
        $raw = $o['items'] ?? null;
        if ($raw !== null) {
            if (!Json::isList($raw)) {
                throw new ProtocolException("The container's items are not an array");
            }
            foreach ($raw as $item) {
                $items[] = ContainedResource::parse($item, $base);
            }
        }
        return new self($id, JsonAccess::types($o), JsonAccess::int($o, 'totalItems'), $items, $metadata, $o);
    }

    /** Whether the body or the `rel="type"` links say this is a container. */
    public function isContainer(): bool
    {
        return $this->hasType(ResourceType::CONTAINER) || $this->metadata->isContainer();
    }

    public function hasType(string $type): bool
    {
        return Vocabulary::hasType($this->types, $type);
    }

    public function __toString(): string
    {
        return "{$this->id} (" . count($this->items) . ' items)';
    }
}
