<?php
// SPDX-License-Identifier: MIT
declare(strict_types=1);

namespace Ebremer\Lws\Model;

use Ebremer\Lws\Http\Headers;
use Ebremer\Lws\Http\Link;
use Ebremer\Lws\Http\LinkHeader;
use Ebremer\Lws\Internal\Dates;
use Ebremer\Lws\Internal\HeaderLists;
use Ebremer\Lws\LinkRelation;
use Ebremer\Lws\ResourceType;
use Ebremer\Lws\Vocabulary;

/**
 * A resource's metadata, parsed from response headers: ETag, Last-Modified, Content-Type, the links (linkset,
 * parent, storage, types) and the allowed methods and patch formats. Every URL is absolute.
 */
final class ResourceMetadata implements \Stringable
{
    /** The ETag verbatim, quotes and `W/` included: send it back as is in `If-Match`. */
    public readonly ?string $etag;
    /** The `Last-Modified` header as received (see {@see lastModifiedTime()}). */
    public readonly ?string $lastModified;
    public readonly ?string $contentType;
    public readonly ?int $contentLength;
    /** @var list<Link> every link of the `Link` headers, one per relation type, targets resolved */
    public readonly array $links;
    /** The linkset resource (`rel="linkset"`). */
    public readonly ?string $linkset;
    /** The parent container (`rel="up"`). */
    public readonly ?string $parent;
    /** The storage (`rel="https://www.w3.org/ns/lws#storage"`). */
    public readonly ?string $storage;
    /** @var list<string> the targets of the `rel="type"` links */
    public readonly array $types;
    /** @var list<string> the methods of `Allow` */
    public readonly array $allow;
    /** @var list<string> the patch formats of `Accept-Patch` */
    public readonly array $acceptPatch;

    /**
     * @param string $url the URL that answered (after redirects)
     * @param int $status the status code
     * @param Headers $headers the response headers
     */
    public function __construct(public readonly string $url, public readonly int $status, public readonly Headers $headers)
    {
        $this->etag = $headers->first('etag');
        $this->lastModified = $headers->first('last-modified');
        $this->contentType = $headers->first('content-type');
        $length = $headers->first('content-length');
        $this->contentLength = $length !== null && ctype_digit($length) ? (int) $length : null;
        $this->links = LinkHeader::parse($headers->all('link'), $url);
        $this->linkset = Link::first($this->links, LinkRelation::LINKSET)?->href;
        $this->parent = Link::first($this->links, LinkRelation::UP)?->href;
        $this->storage = Link::first($this->links, LinkRelation::STORAGE)?->href;
        $this->types = array_map(static fn (Link $l): string => $l->href, Link::all($this->links, LinkRelation::TYPE));
        $this->allow = HeaderLists::split($headers->all('allow'));
        $this->acceptPatch = HeaderLists::split($headers->all('accept-patch'));
    }

    /** `Last-Modified` as a date, or null when absent or not an HTTP date. */
    public function lastModifiedTime(): ?\DateTimeImmutable
    {
        return Dates::parseHttpDate($this->lastModified);
    }

    public function isContainer(): bool
    {
        return $this->hasType(ResourceType::CONTAINER);
    }

    public function isDataResource(): bool
    {
        return $this->hasType(ResourceType::DATA_RESOURCE);
    }

    /** Whether a `rel="type"` link names the type (short terms, `lws:` and full IRIs are equal). */
    public function hasType(string $type): bool
    {
        return Vocabulary::hasType($this->types, $type);
    }

    /** The first link with a relation type, or null. */
    public function link(string $rel): ?Link
    {
        return Link::first($this->links, $rel);
    }

    /**
     * The links with a relation type.
     *
     * @return list<Link>
     */
    public function links(string $rel): array
    {
        return Link::all($this->links, $rel);
    }

    /** The first value of a response header, or null. */
    public function header(string $name): ?string
    {
        return $this->headers->first($name);
    }

    public function __toString(): string
    {
        return "{$this->status} {$this->url}";
    }
}
