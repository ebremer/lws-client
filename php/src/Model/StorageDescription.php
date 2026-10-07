<?php
// SPDX-License-Identifier: MIT
declare(strict_types=1);

namespace Ebremer\Lws\Model;

use Ebremer\Lws\Exception\ProtocolException;
use Ebremer\Lws\Internal\JsonAccess;
use Ebremer\Lws\Internal\Url;
use Ebremer\Lws\Json\Json;
use Ebremer\Lws\ResourceType;
use Ebremer\Lws\ServiceType;
use Ebremer\Lws\Vocabulary;

/**
 * A storage description (`application/lws+cid`), a controlled identifier document of type `Storage`: its services,
 * capabilities and verification methods (the keys that sign webhook deliveries).
 */
final class StorageDescription implements \Stringable
{
    /**
     * @param string $id the storage identifier (absolute)
     * @param list<string> $types
     * @param list<Service> $services
     * @param list<Capability> $capabilities
     * @param list<VerificationMethod> $verificationMethods
     * @param list<mixed> $authentication references (strings) or embedded verification methods
     * @param array<array-key, mixed> $raw the document
     */
    public function __construct(
        public readonly string $id,
        public readonly array $types,
        public readonly array $services,
        public readonly array $capabilities,
        public readonly array $verificationMethods,
        public readonly array $authentication,
        public readonly array $raw,
    ) {
    }

    /**
     * Parses a description; its `id` resolves against the URL it came from.
     *
     * @throws ProtocolException without an `id`, or when `type` does not include `Storage`
     */
    public static function parse(mixed $json, ?string $base = null): self
    {
        $o = JsonAccess::object($json, 'The storage description');
        $idText = JsonAccess::str($o, 'id') ?? throw new ProtocolException('The storage description has no id');
        $id = Url::resolve($idText, $base) ?? throw new ProtocolException("The storage description id is not a URL: $idText");
        $types = JsonAccess::types($o);
        if (!Vocabulary::hasType($types, ResourceType::STORAGE)) {
            throw new ProtocolException('The document type [' . implode(', ', $types) . '] does not include Storage');
        }
        $services = [];
        foreach (JsonAccess::objects($o, 'service') as $s) {
            $endpoint = JsonAccess::url($s, 'serviceEndpoint', $id);
            if ($endpoint !== null) {
                $services[] = new Service(JsonAccess::url($s, 'id', $id), JsonAccess::types($s), $endpoint, $s);
            }
        }
        $capabilities = [];
        foreach (JsonAccess::objects($o, 'capability') as $c) {
            $capabilities[] = new Capability(JsonAccess::url($c, 'id', $id), JsonAccess::types($c), $c);
        }
        $methods = [];
        foreach (JsonAccess::objects($o, 'verificationMethod') as $v) {
            $methods[] = new VerificationMethod($v);
        }
        $auth = $o['authentication'] ?? null;
        $authentication = match (true) {
            Json::isList($auth) => $auth,
            $auth === null => [],
            default => [$auth],
        };
        return new self($id, $types, $services, $capabilities, $methods, $authentication, $o);
    }

    /**
     * The storage root container.
     *
     * @throws ProtocolException when the description has no `StorageRoot` service
     */
    public function storageRoot(): string
    {
        return $this->service(ServiceType::STORAGE_ROOT)->serviceEndpoint
            ?? throw new ProtocolException("The storage description {$this->id} has no StorageRoot service");
    }

    /** The first service of a type, or null. */
    public function service(string $type): ?Service
    {
        foreach ($this->services as $s) {
            if ($s->hasType($type)) {
                return $s;
            }
        }
        return null;
    }

    /**
     * Every service of a type.
     *
     * @return list<Service>
     */
    public function services(string $type): array
    {
        return array_values(array_filter($this->services, static fn (Service $s): bool => $s->hasType($type)));
    }

    /** The first capability of a type, or null. */
    public function capability(string $type): ?Capability
    {
        foreach ($this->capabilities as $c) {
            if ($c->hasType($type)) {
                return $c;
            }
        }
        return null;
    }

    public function notificationService(): ?Service
    {
        return $this->service(ServiceType::NOTIFICATION);
    }

    public function accessRequestService(): ?Service
    {
        return $this->service(ServiceType::ACCESS_REQUEST);
    }

    public function accessGrantService(): ?Service
    {
        return $this->service(ServiceType::ACCESS_GRANT);
    }

    public function typeIndexService(): ?Service
    {
        return $this->service(ServiceType::TYPE_INDEX);
    }

    public function typeSearchService(): ?Service
    {
        return $this->service(ServiceType::TYPE_SEARCH);
    }

    public function hasType(string $type): bool
    {
        return Vocabulary::hasType($this->types, $type);
    }

    /**
     * The verification method whose `id` is `idOrFragment`, or resolves to the same URL against the storage
     * identifier (`#key-1`, `key-1` and the full URL are equal).
     */
    public function verificationMethod(string $idOrFragment): ?VerificationMethod
    {
        foreach ($this->verificationMethods as $v) {
            if ($v->id !== null && ($v->id === $idOrFragment || $this->sameId($v->id, $idOrFragment))) {
                return $v;
            }
        }
        return null;
    }

    /** Whether a verification method is referenced from `authentication` (by id, or embedded with the same id). */
    public function isAuthenticationMethod(VerificationMethod $method): bool
    {
        if ($method->id === null) {
            return false;
        }
        foreach ($this->authentication as $a) {
            $ref = is_string($a) ? $a : JsonAccess::str(Json::members($a) ?? [], 'id');
            if ($ref !== null && ($ref === $method->id || $this->sameId($ref, $method->id))) {
                return true;
            }
        }
        return false;
    }

    private function sameId(string $a, string $b): bool
    {
        $ra = $this->resolveRef($a);
        $rb = $this->resolveRef($b);
        return $ra !== null && $ra === $rb;
    }

    private function resolveRef(string $reference): ?string
    {
        $r = $reference;
        if (!str_contains($r, ':') && !str_starts_with($r, '#') && !str_starts_with($r, '/')) {
            $r = '#' . $r;
        }
        return Url::resolve($r, $this->id);
    }

    public function __toString(): string
    {
        return $this->id;
    }
}
