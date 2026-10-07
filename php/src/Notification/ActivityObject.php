<?php
// SPDX-License-Identifier: MIT
declare(strict_types=1);

namespace Ebremer\Lws\Notification;

use Ebremer\Lws\ResourceType;
use Ebremer\Lws\Vocabulary;

/** The resource an activity is about. */
final class ActivityObject
{
    /**
     * @param list<string> $types
     * @param array<array-key, mixed> $raw
     */
    public function __construct(public readonly string $id, public readonly array $types = [], public readonly array $raw = [])
    {
    }

    public function isContainer(): bool
    {
        return Vocabulary::hasType($this->types, ResourceType::CONTAINER);
    }

    public function isDataResource(): bool
    {
        return Vocabulary::hasType($this->types, ResourceType::DATA_RESOURCE);
    }
}
