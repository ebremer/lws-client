<?php
// SPDX-License-Identifier: MIT
declare(strict_types=1);

namespace Ebremer\Lws\Notification;

use Ebremer\Lws\Exception\ProtocolException;
use Ebremer\Lws\Internal\Dates;
use Ebremer\Lws\Internal\JsonAccess;

/** A webhook subscription as the notification service describes it. */
final class Subscription implements \Stringable
{
    /** The first `type` (`WebhookSubscription`). */
    public readonly ?string $type;
    /** @var list<string> */
    public readonly array $types;
    /** When it expires, or null. */
    public readonly ?\DateTimeImmutable $expires;

    /**
     * @param string $url the subscription resource (its `subscription` member, else the `Location`)
     * @param ?string $expiresRaw `expires` as received
     * @param array<array-key, mixed> $raw the document
     */
    public function __construct(public readonly string $url, public readonly ?string $expiresRaw, public readonly array $raw)
    {
        $this->types = JsonAccess::types($raw);
        $this->type = $this->types[0] ?? null;
        $this->expires = Dates::parseRfc3339($expiresRaw);
    }

    /**
     * Parses a subscription document; `subscription` resolves against `base`, and `location` stands in for it.
     *
     * @throws ProtocolException when there is no subscription URL
     */
    public static function parse(mixed $json, ?string $base = null, ?string $location = null): self
    {
        $o = JsonAccess::object($json, 'The subscription');
        $url = JsonAccess::url($o, 'subscription', $base) ?? $location
            ?? throw new ProtocolException('The subscription response has no subscription URL');
        return new self($url, JsonAccess::str($o, 'expires'), $o);
    }

    public function __toString(): string
    {
        return $this->url;
    }
}
