<?php
// SPDX-License-Identifier: MIT
declare(strict_types=1);

namespace Ebremer\Lws\Notification;

use Ebremer\Lws\Exception\ProtocolException;
use Ebremer\Lws\Internal\JsonAccess;
use Ebremer\Lws\Internal\Url;
use Ebremer\Lws\Json\Json;
use Ebremer\Lws\ResourceType;
use Ebremer\Lws\Vocabulary;

/** A notification: the storage it comes from and its activities (one or many). */
final class Notification
{
    /**
     * @param list<Activity> $activities
     * @param array<array-key, mixed> $raw
     */
    public function __construct(public readonly string $storage, public readonly array $activities, public readonly array $raw = [])
    {
    }

    /**
     * Parses a notification (JSON text or decoded).
     *
     * @throws ProtocolException when it is not a `Notification` with a storage and activities
     */
    public static function parse(mixed $json): self
    {
        if (is_string($json)) {
            $json = JsonAccess::parse($json, 'The notification');
        }
        $o = JsonAccess::object($json, 'The notification');
        if (!Vocabulary::hasType(JsonAccess::types($o), ResourceType::NOTIFICATION)) {
            throw new ProtocolException('The document type is not Notification');
        }
        $storageText = JsonAccess::str($o, 'storage') ?? throw new ProtocolException('The notification has no storage');
        $storage = Url::resolve($storageText) ?? throw new ProtocolException('The notification storage is not an absolute URL');
        $a = $o['activity'] ?? null;
        if (Json::isList($a)) {
            $activities = array_values(array_map(static fn (mixed $x): Activity => Activity::parse(JsonAccess::object($x, 'An activity')), $a));
        } elseif (Json::isObject($a)) {
            $activities = [Activity::parse(JsonAccess::object($a, 'The activity'))];
        } else {
            throw new ProtocolException('The notification has no activity');
        }
        return new self($storage, $activities, $o);
    }
}
