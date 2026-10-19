<?php
// SPDX-License-Identifier: MIT
declare(strict_types=1);

namespace Ebremer\Lws\Auth;

use Ebremer\Lws\Exception\ProtocolException;
use Ebremer\Lws\Internal\JsonAccess;
use Ebremer\Lws\Internal\Url;
use Ebremer\Lws\Json\Json;

/**
 * Protected resource metadata (RFC 9728), named by the `resource_metadata` of a `401` challenge: the resource it
 * describes and the authorization servers that issue tokens for it.
 */
final class ProtectedResourceMetadata
{
    /**
     * @param string $resource the resource identifier, as the document states it (the requested URL, not the storage)
     * @param list<string> $authorizationServers the issuer identifiers, in the document's order
     * @param array<array-key, mixed> $raw
     */
    public function __construct(
        public readonly string $resource,
        public readonly array $authorizationServers,
        public readonly array $raw = [],
    ) {
    }

    /**
     * Parses a metadata document.
     *
     * @throws ProtocolException when it is not an object, `resource` is not a string, or `authorization_servers` is
     *     not a non-empty array of strings (RFC 9728 requires `resource`, lws10-core `authorization_servers`)
     */
    public static function parse(mixed $json): self
    {
        $o = JsonAccess::object($json, 'The protected resource metadata');
        $resource = JsonAccess::str($o, 'resource') ?? throw new ProtocolException('The protected resource metadata has no resource');
        $servers = $o['authorization_servers'] ?? null;
        if (!Json::isList($servers) || $servers === [] || count(array_filter($servers, 'is_string')) !== count($servers)) {
            throw new ProtocolException('The protected resource metadata has no authorization_servers array of issuer identifiers');
        }
        /** @var list<string> $servers */
        return new self($resource, $servers, $o);
    }

    /**
     * Whether the metadata describes a URL: `resource` is identical to it, scheme and host compared
     * case-insensitively and a default port the same as none, nothing else normalised (RFC 9728 section 3.3).
     */
    public function describes(string $url): bool
    {
        return Url::identical($this->resource, $url);
    }
}
