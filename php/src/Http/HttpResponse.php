<?php
// SPDX-License-Identifier: MIT
declare(strict_types=1);

namespace Ebremer\Lws\Http;

/** A response from an {@see HttpTransport}. */
final class HttpResponse
{
    /** @param string $url the URL that answered (the request URL: transports do not follow redirects) */
    public function __construct(
        public readonly string $url,
        public readonly int $status,
        public readonly Headers $headers = new Headers(),
        public readonly string $body = '',
    ) {
    }
}
