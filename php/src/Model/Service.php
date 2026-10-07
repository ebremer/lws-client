<?php
// SPDX-License-Identifier: MIT
declare(strict_types=1);

namespace Ebremer\Lws\Model;

use Ebremer\Lws\Internal\JsonAccess;
use Ebremer\Lws\Vocabulary;

/** A service of a storage description (`StorageRoot`, `NotificationService`, …), extra members in `raw`. */
final class Service implements \Stringable
{
    /**
     * @param list<string> $types
     * @param string $serviceEndpoint absolute
     * @param array<array-key, mixed> $raw
     */
    public function __construct(
        public readonly ?string $id,
        public readonly array $types,
        public readonly string $serviceEndpoint,
        public readonly array $raw = [],
    ) {
    }

    public function hasType(string $type): bool
    {
        return Vocabulary::hasType($this->types, $type);
    }

    /**
     * The `subscriptionType` values of a notification service.
     *
     * @return list<string>
     */
    public function subscriptionTypes(): array
    {
        return JsonAccess::strings($this->raw, 'subscriptionType');
    }

    /** @return list<string> the `conformsTo` values */
    public function conformsTo(): array
    {
        return JsonAccess::strings($this->raw, 'conformsTo');
    }

    /** A member of the service object, or null. */
    public function property(string $name): mixed
    {
        return $this->raw[$name] ?? null;
    }

    public function __toString(): string
    {
        return implode(',', $this->types) . ' ' . $this->serviceEndpoint;
    }
}
