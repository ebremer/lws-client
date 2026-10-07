<?php
// SPDX-License-Identifier: MIT
declare(strict_types=1);

namespace Ebremer\Lws\Model;

use Ebremer\Lws\Exception\ProtocolException;
use Ebremer\Lws\Internal\JsonAccess;
use Ebremer\Lws\Json\Json;
use Ebremer\Lws\LinkRelation;

/** One page of a type index: the type IRIs in use, with pagination links. */
final class TypeIndexPage
{
    public readonly ?string $first;
    public readonly ?string $next;
    public readonly ?string $prev;
    public readonly ?string $last;

    /**
     * @param list<string> $types
     * @param array<array-key, mixed> $raw
     */
    public function __construct(
        public readonly ?int $totalItems,
        public readonly array $types,
        public readonly ResourceMetadata $metadata,
        public readonly array $raw = [],
    ) {
        $this->first = $metadata->link(LinkRelation::FIRST)?->href;
        $this->next = $metadata->link(LinkRelation::NEXT)?->href;
        $this->prev = $metadata->link(LinkRelation::PREV)?->href;
        $this->last = $metadata->link(LinkRelation::LAST)?->href;
    }

    /**
     * Parses a type index page: `items` holds IRIs, or objects with an `id`.
     *
     * @throws ProtocolException when it is not a page object
     */
    public static function parse(mixed $json, ResourceMetadata $metadata): self
    {
        $o = JsonAccess::object($json, 'The type index');
        $types = [];
        $items = $o['items'] ?? null;
        if ($items !== null) {
            if (!Json::isList($items)) {
                throw new ProtocolException("The type index's items are not an array");
            }
            foreach ($items as $item) {
                $t = is_string($item) ? $item : JsonAccess::str(Json::members($item) ?? [], 'id');
                if ($t !== null) {
                    $types[] = $t;
                }
            }
        }
        return new self(JsonAccess::int($o, 'totalItems'), $types, $metadata, $o);
    }
}
