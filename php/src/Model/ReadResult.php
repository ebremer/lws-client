<?php
// SPDX-License-Identifier: MIT
declare(strict_types=1);

namespace Ebremer\Lws\Model;

use Ebremer\Lws\Internal\HeaderLists;
use Ebremer\Lws\Internal\JsonAccess;

/**
 * A resource as read: its metadata and content (the contract's `Resource`). A conditional read answered
 * `304 Not Modified` is a result too, whose {@see $notModified} is true and whose body is empty.
 */
final class ReadResult implements \Stringable
{
    public readonly string $url;
    public readonly int $status;
    public readonly ?string $etag;
    public readonly ?string $contentType;
    /** The `Content-Range` of a `206 Partial Content`. */
    public readonly ?string $contentRange;

    /** @param string $body the content bytes */
    public function __construct(public readonly ResourceMetadata $metadata, public readonly string $body = '', public readonly bool $notModified = false)
    {
        $this->url = $metadata->url;
        $this->status = $metadata->status;
        $this->etag = $metadata->etag;
        $this->contentType = $metadata->contentType;
        $this->contentRange = $metadata->header('content-range');
    }

    /** The content as UTF-8 text, decoded by the charset of its content type (UTF-8 by default). */
    public function text(): string
    {
        return HeaderLists::decode($this->body, $this->contentType);
    }

    /**
     * The content parsed as JSON (objects as arrays, see {@see \Ebremer\Lws\Json\Json::decode()}).
     *
     * @throws \Ebremer\Lws\Exception\ProtocolException when it is not JSON
     */
    public function json(): mixed
    {
        return JsonAccess::parse($this->body, "The content of {$this->url}");
    }

    public function __toString(): string
    {
        return "{$this->url} ({$this->status}, " . strlen($this->body) . ' bytes)';
    }
}
