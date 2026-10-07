<?php
// SPDX-License-Identifier: MIT
declare(strict_types=1);

namespace Ebremer\Lws\Http;

/** A request as handed to an {@see HttpTransport}. */
final class HttpRequest
{
    /**
     * @param string $method the method (`GET`, `QUERY`, …)
     * @param string $url the absolute target URL
     * @param ?string $body the body bytes, or null for none (an empty string is an empty body, `Content-Length: 0`)
     * @param ?float $timeout the time limit of the whole exchange, in seconds, or null for the transport's own
     */
    public function __construct(
        public readonly string $method,
        public readonly string $url,
        public readonly Headers $headers = new Headers(),
        public readonly ?string $body = null,
        public readonly ?float $timeout = null,
    ) {
    }

    public function withHeaders(Headers $headers): self
    {
        return new self($this->method, $this->url, $headers, $this->body, $this->timeout);
    }

    public function withTimeout(?float $timeout): self
    {
        return new self($this->method, $this->url, $this->headers, $this->body, $timeout);
    }
}
