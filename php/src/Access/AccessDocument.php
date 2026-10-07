<?php
// SPDX-License-Identifier: MIT
declare(strict_types=1);

namespace Ebremer\Lws\Access;

use Ebremer\Lws\Exception\ProtocolException;
use Ebremer\Lws\Internal\JsonAccess;
use Ebremer\Lws\Internal\Url;
use Ebremer\Lws\Json\Json;
use Ebremer\Lws\Vocabulary;

/** What access requests and grants share: the storage, an optional inbox and the access policies. */
abstract class AccessDocument implements \JsonSerializable
{
    /** @var list<string> the document types (`AccessRequest` or `AccessGrant` by default) */
    public readonly array $types;

    /**
     * @param string $storage the storage (absolute)
     * @param list<AccessPolicy> $access at least one policy
     * @param ?string $inbox where to send the answer
     * @param list<string> $types the document types (empty: the type of the class)
     * @param ?array<array-key, mixed> $raw the document as received (null for one built here)
     * @throws \InvalidArgumentException without policies, or for URLs that are not absolute
     */
    final public function __construct(
        public readonly string $storage,
        public readonly array $access,
        public readonly ?string $inbox = null,
        array $types = [],
        public readonly ?array $raw = null,
    ) {
        $this->types = $types === [] ? [static::documentType()] : $types;
        if ($access === []) {
            throw new \InvalidArgumentException('At least one access policy is required');
        }
        foreach ([$storage, $inbox] as $u) {
            if ($u !== null && !Url::hasScheme($u)) {
                throw new \InvalidArgumentException("Not an absolute URL: $u");
            }
        }
    }

    /** The document type: `AccessRequest` or `AccessGrant`. */
    abstract protected static function documentType(): string;

    /**
     * Builds a document of this type (the same as the constructor).
     *
     * @param list<AccessPolicy> $access
     */
    public static function create(string $storage, array $access, ?string $inbox = null): static
    {
        return new static($storage, $access, $inbox);
    }

    /**
     * Parses a document (JSON text or decoded); `raw` keeps it as received.
     *
     * @throws ProtocolException when it is not a valid document of this type
     */
    public static function parse(mixed $json): static
    {
        $what = 'The ' . static::documentType();
        if (is_string($json)) {
            $json = JsonAccess::parse($json, $what);
        }
        $o = JsonAccess::object($json, $what);
        $types = JsonAccess::types($o);
        if (!Vocabulary::hasType($types, static::documentType())) {
            throw new ProtocolException('The document type [' . implode(', ', $types) . '] does not include ' . static::documentType());
        }
        $storage = JsonAccess::str($o, 'storage') ?? throw new ProtocolException("$what has no storage");
        if (Url::resolve($storage) === null) {
            throw new ProtocolException("$what storage is not an absolute URL");
        }
        $inbox = JsonAccess::str($o, 'inbox');
        if ($inbox !== null && Url::resolve($inbox) === null) {
            throw new ProtocolException("$what inbox is not an absolute URL");
        }
        $a = $o['access'] ?? null;
        $policies = match (true) {
            Json::isList($a) => array_values(array_map(AccessPolicy::parse(...), $a)),
            Json::isObject($a) => [AccessPolicy::parse($a)],
            default => [],
        };
        if ($policies === []) {
            throw new ProtocolException("$what has no access");
        }
        return new static($storage, $policies, $inbox, $types, $o);
    }

    /** @return array<string, mixed> the document (built from the fields; see {@see $raw} for the one received) */
    public function toJson(): array
    {
        $o = ['@context' => [Vocabulary::LWS_CONTEXT], 'type' => $this->types];
        if ($this->inbox !== null) {
            $o['inbox'] = $this->inbox;
        }
        $o['storage'] = $this->storage;
        $o['access'] = array_map(static fn (AccessPolicy $p): array => $p->toJson(), $this->access);
        return $o;
    }

    /** @return array<array-key, mixed> the document as received, else as built */
    public function document(): array
    {
        return $this->raw ?? $this->toJson();
    }

    /** @return array<array-key, mixed> */
    public function jsonSerialize(): array
    {
        return $this->toJson();
    }
}
