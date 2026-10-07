<?php
// SPDX-License-Identifier: MIT
declare(strict_types=1);

namespace Ebremer\Lws\Http;

use Ebremer\Lws\Exception\TransportException;
use Psr\Http\Client\ClientExceptionInterface;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestFactoryInterface;
use Psr\Http\Message\StreamFactoryInterface;

/**
 * An {@see HttpTransport} over any PSR-18 HTTP client (Guzzle, Symfony HttpClient's `Psr18Client`, …), with
 * PSR-17 factories for the requests. Needs `psr/http-client` and `psr/http-factory`.
 *
 * The client MUST NOT follow redirects (Guzzle's `sendRequest` does not; configure others so), since a PSR-7
 * response does not tell which URL answered.
 */
final class Psr18Transport implements HttpTransport
{
    public function __construct(
        private readonly ClientInterface $client,
        private readonly RequestFactoryInterface $requestFactory,
        private readonly StreamFactoryInterface $streamFactory,
    ) {
    }

    public function send(HttpRequest $request): HttpResponse
    {
        $r = $this->requestFactory->createRequest($request->method, $request->url);
        foreach ($request->headers->names() as $name) {
            $r = $r->withHeader($name, $request->headers->all($name));
        }
        if ($request->body !== null) {
            $r = $r->withBody($this->streamFactory->createStream($request->body));
            if (!$r->hasHeader('Content-Length')) {
                $r = $r->withHeader('Content-Length', (string) strlen($request->body));
            }
        }
        try {
            $response = $this->client->sendRequest($r);
        } catch (ClientExceptionInterface $e) {
            throw new TransportException("{$request->method} {$request->url} failed: {$e->getMessage()}", false, $e);
        }
        $fields = [];
        foreach ($response->getHeaders() as $name => $values) {
            foreach ($values as $v) {
                $fields[] = [(string) $name, $v];
            }
        }
        return new HttpResponse($request->url, $response->getStatusCode(), new Headers($fields), (string) $response->getBody());
    }
}
