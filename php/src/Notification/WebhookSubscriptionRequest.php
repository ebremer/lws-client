<?php
// SPDX-License-Identifier: MIT
declare(strict_types=1);

namespace Ebremer\Lws\Notification;

use Ebremer\Lws\Internal\Dates;
use Ebremer\Lws\Internal\Url;
use Ebremer\Lws\SubscriptionType;
use Ebremer\Lws\Vocabulary;

/** A webhook subscription to create: the topics (resources or containers to watch), the inbox and an optional expiry. */
final class WebhookSubscriptionRequest implements \JsonSerializable
{
    /** The requested expiry, RFC 3339. */
    public readonly ?string $expires;

    /**
     * @param list<string> $topics absolute URLs
     * @param string $inbox the absolute URL deliveries are POSTed to
     * @param \DateTimeInterface|string|null $expires a date, or an RFC 3339 string (kept as written)
     * @throws \InvalidArgumentException without topics, or for URLs that are not absolute or an invalid date
     */
    public function __construct(public readonly array $topics, public readonly string $inbox, \DateTimeInterface|string|null $expires = null)
    {
        if ($topics === []) {
            throw new \InvalidArgumentException('At least one topic is required');
        }
        foreach ([...$topics, $inbox] as $u) {
            if (!Url::hasScheme($u)) {
                throw new \InvalidArgumentException("Not an absolute URL: $u");
            }
        }
        if (is_string($expires) && Dates::parseRfc3339($expires) === null) {
            throw new \InvalidArgumentException("Not an RFC 3339 date-time: $expires");
        }
        $this->expires = $expires instanceof \DateTimeInterface ? Dates::formatRfc3339($expires) : $expires;
    }

    /** @return array<string, mixed> the request body */
    public function toJson(): array
    {
        $o = [
            '@context' => [Vocabulary::LWS_CONTEXT],
            'type' => SubscriptionType::WEBHOOK,
            'topic' => $this->topics,
            'inbox' => $this->inbox,
        ];
        if ($this->expires !== null) {
            $o['expires'] = $this->expires;
        }
        return $o;
    }

    /** @return array<string, mixed> */
    public function jsonSerialize(): array
    {
        return $this->toJson();
    }
}
