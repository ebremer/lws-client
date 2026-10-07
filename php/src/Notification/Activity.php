<?php
// SPDX-License-Identifier: MIT
declare(strict_types=1);

namespace Ebremer\Lws\Notification;

use Ebremer\Lws\ActivityType;
use Ebremer\Lws\Exception\ProtocolException;
use Ebremer\Lws\Internal\Dates;
use Ebremer\Lws\Internal\JsonAccess;
use Ebremer\Lws\Internal\Url;
use Ebremer\Lws\Json\Json;
use Ebremer\Lws\Vocabulary;

/** One activity of a notification (`Create`, `Update`, `Delete`). */
final class Activity
{
    public readonly ?\DateTimeImmutable $published;

    /**
     * @param list<string> $types
     * @param array<array-key, mixed> $raw
     */
    public function __construct(
        public readonly ?string $id,
        public readonly array $types,
        public readonly ActivityObject $object,
        public readonly ?string $actor = null,
        public readonly ?string $target = null,
        public readonly ?string $origin = null,
        public readonly ?string $publishedRaw = null,
        public readonly array $raw = [],
    ) {
        $this->published = Dates::parseRfc3339($publishedRaw);
    }

    /**
     * @param array<array-key, mixed> $o
     * @throws ProtocolException without an object with an absolute id
     */
    public static function parse(array $o): self
    {
        $obj = Json::members($o['object'] ?? null) ?? throw new ProtocolException('The activity has no object');
        $idText = JsonAccess::str($obj, 'id');
        $id = $idText === null ? null : Url::resolve($idText);
        if ($id === null) {
            throw new ProtocolException('The activity object has no valid id');
        }
        return new self(JsonAccess::str($o, 'id'), JsonAccess::types($o), new ActivityObject($id, JsonAccess::types($obj), $obj),
            JsonAccess::url($o, 'actor', null), JsonAccess::url($o, 'target', null), JsonAccess::url($o, 'origin', null),
            JsonAccess::str($o, 'published'), $o);
    }

    public function isCreate(): bool
    {
        return $this->hasType(ActivityType::CREATE);
    }

    public function isUpdate(): bool
    {
        return $this->hasType(ActivityType::UPDATE);
    }

    public function isDelete(): bool
    {
        return $this->hasType(ActivityType::DELETE);
    }

    /** Whether the activity has a type (`Update`, `as:Update` and the full Activity Streams IRI are equal). */
    public function hasType(string $type): bool
    {
        return in_array($type, $this->types, true) || in_array('as:' . $type, $this->types, true)
            || in_array(Vocabulary::ACTIVITYSTREAMS_CONTEXT . '#' . $type, $this->types, true);
    }
}
