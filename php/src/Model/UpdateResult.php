<?php
// SPDX-License-Identifier: MIT
declare(strict_types=1);

namespace Ebremer\Lws\Model;

/** The result of a PUT or PATCH: the status (200 or 204), the new ETag and the response metadata. */
final class UpdateResult implements \Stringable
{
    public readonly ?string $etag;

    public function __construct(public readonly int $status, public readonly ResourceMetadata $metadata, public readonly string $body = '')
    {
        $this->etag = $metadata->etag;
    }

    public function __toString(): string
    {
        return "{$this->metadata->url} ({$this->status})";
    }
}
