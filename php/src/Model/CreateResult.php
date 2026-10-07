<?php
// SPDX-License-Identifier: MIT
declare(strict_types=1);

namespace Ebremer\Lws\Model;

/** The result of a create: the new resource's URL and the metadata of the `201` response. */
final class CreateResult implements \Stringable
{
    public readonly ?string $etag;
    public readonly ?string $linkset;

    /** @param string $location the new resource (absolute) */
    public function __construct(public readonly string $location, public readonly ResourceMetadata $metadata, public readonly string $body = '')
    {
        $this->etag = $metadata->etag;
        $this->linkset = $metadata->linkset;
    }

    public function __toString(): string
    {
        return $this->location;
    }
}
