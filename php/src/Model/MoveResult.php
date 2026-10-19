<?php
// SPDX-License-Identifier: MIT
declare(strict_types=1);

namespace Ebremer\Lws\Model;

use Ebremer\Lws\Exception\ProtocolException;
use Ebremer\Lws\Internal\Url;
use Ebremer\Lws\LinkRelation;

/**
 * The result of a move: where the resource and its linkset are now, whether the storage kept the resource's URL,
 * and the response's ETag and metadata. A storage that does not promise to keep identifiers (`preservesIdentifier`)
 * may give the resource a new URL, and this is the only place it says which.
 */
final class MoveResult implements \Stringable
{
    public readonly ?string $etag;

    /**
     * @param int $status 200 or 204
     * @param string $location the resource after the move (absolute)
     * @param string $linkset its linkset resource after the move (absolute)
     * @param bool $identifierPreserved whether `location` is the URL the resource had
     * @param ?Linkset $document the updated linkset of a `200`
     */
    public function __construct(
        public readonly int $status,
        public readonly string $location,
        public readonly string $linkset,
        public readonly bool $identifierPreserved,
        public readonly ResourceMetadata $metadata,
        public readonly ?Linkset $document = null,
    ) {
        $this->etag = $metadata->etag;
    }

    /**
     * Interprets the answer to the patch that moved the resource at `resourceUrl`, from its linkset at
     * `metadata->url`. A `204` keeps the identifier. A `200` carries the updated linkset, whose first context with an
     * `up` link is anchored at the resource's identifier after the move (resolved against `Content-Location`, the
     * linkset's own new URL, else the linkset URL).
     *
     * @throws ProtocolException when the body is not a linkset
     */
    public static function fromResponse(string $resourceUrl, ResourceMetadata $metadata, string $body): self
    {
        $contentLocation = $metadata->header('content-location');
        $linkset = ($contentLocation === null ? null : Url::resolve($contentLocation, $metadata->url)) ?? $metadata->url;
        $location = $resourceUrl;
        $document = null;
        if (trim($body) !== '') {
            $document = Linkset::parse($body);
            foreach ($document->contexts as $c) {
                if ($c->targets(LinkRelation::UP) !== []) {
                    $location = $c->anchor === null ? $resourceUrl
                        : Url::resolve($c->anchor, $linkset) ?? throw new ProtocolException("The moved resource's anchor is not a URI reference: {$c->anchor}");
                    break;
                }
            }
        }
        $preserved = Url::canonical($location) === Url::canonical($resourceUrl);
        return new self($metadata->status, $preserved ? $resourceUrl : $location, $linkset, $preserved, $metadata, $document);
    }

    public function __toString(): string
    {
        return "{$this->location} ({$this->status})";
    }
}
