<?php
// SPDX-License-Identifier: MIT
declare(strict_types=1);

namespace Ebremer\Lws\Model;

/** A linkset as read from its linkset resource: the resource URL, the linkset, its ETag and allowed methods. */
final class LinksetDocument
{
    public readonly ?string $etag;
    /** @var list<string> */
    public readonly array $allow;
    /** @var list<string> */
    public readonly array $acceptPatch;

    /** @param string $url the linkset resource */
    public function __construct(public readonly string $url, public readonly Linkset $linkset, public readonly ResourceMetadata $metadata)
    {
        $this->etag = $metadata->etag;
        $this->allow = $metadata->allow;
        $this->acceptPatch = $metadata->acceptPatch;
    }

    /** Whether the linkset resource allows `PUT` (else update it with `PATCH`). */
    public function supportsPut(): bool
    {
        foreach ($this->allow as $m) {
            if (strcasecmp($m, 'PUT') === 0) {
                return true;
            }
        }
        return false;
    }
}
