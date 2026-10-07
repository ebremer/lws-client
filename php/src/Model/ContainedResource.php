<?php
// SPDX-License-Identifier: MIT
declare(strict_types=1);

namespace Ebremer\Lws\Model;

use Ebremer\Lws\Exception\ProtocolException;
use Ebremer\Lws\Internal\Dates;
use Ebremer\Lws\Internal\JsonAccess;
use Ebremer\Lws\Internal\Url;
use Ebremer\Lws\ResourceType;
use Ebremer\Lws\Vocabulary;

/** A member of a container listing (or a search result). */
final class ContainedResource implements \Stringable
{
    /** When {@see $modifiedRaw} is a date-time (an unparseable value is null here, not an error). */
    public readonly ?\DateTimeImmutable $modified;

    /**
     * @param string $id the resource (absolute)
     * @param list<string> $types the `type` values as received
     * @param ?string $format the media type (present for data resources)
     * @param ?int $size the size in bytes
     * @param ?string $modifiedRaw the `modified` value as received
     * @param array<array-key, mixed> $raw the item object
     */
    public function __construct(
        public readonly string $id,
        public readonly array $types = [],
        public readonly ?string $format = null,
        public readonly ?int $size = null,
        public readonly ?string $modifiedRaw = null,
        public readonly array $raw = [],
    ) {
        $this->modified = Dates::parseRfc3339($modifiedRaw);
    }

    /**
     * Parses an item object; its `id` is resolved against `base`.
     *
     * @throws ProtocolException without an `id`
     */
    public static function parse(mixed $json, ?string $base): self
    {
        $o = JsonAccess::object($json, 'A contained resource description');
        $idText = JsonAccess::str($o, 'id') ?? throw new ProtocolException('A contained resource description has no id');
        $id = Url::resolve($idText, $base) ?? throw new ProtocolException("Invalid contained resource id: $idText");
        return new self($id, JsonAccess::types($o), JsonAccess::str($o, 'format'), JsonAccess::int($o, 'size'),
            JsonAccess::str($o, 'modified'), $o);
    }

    public function isContainer(): bool
    {
        return $this->hasType(ResourceType::CONTAINER);
    }

    public function isDataResource(): bool
    {
        return $this->hasType(ResourceType::DATA_RESOURCE);
    }

    public function hasType(string $type): bool
    {
        return Vocabulary::hasType($this->types, $type);
    }

    public function __toString(): string
    {
        return $this->id;
    }
}
