<?php
// SPDX-License-Identifier: MIT
declare(strict_types=1);

namespace Ebremer\Lws\Http;

use Ebremer\Lws\Exception\TransportException;

/**
 * The HTTP engine of {@see \Ebremer\Lws\LwsClient}: sends one request and returns its response.
 *
 * Implementations MUST NOT follow redirects (the client follows them itself, authorizing each hop for its own URL)
 * and should not store cookies or cache. Provided: {@see CurlTransport} (the default) and {@see Psr18Transport}.
 */
interface HttpTransport
{
    /** @throws TransportException when no response arrives (connection refused, TLS failure, timeout) */
    public function send(HttpRequest $request): HttpResponse;
}
