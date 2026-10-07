<?php
// SPDX-License-Identifier: MIT
declare(strict_types=1);

namespace Ebremer\Lws\Tests\Support;

use Ebremer\Lws\Http\Headers;
use Ebremer\Lws\Http\HttpRequest;
use Ebremer\Lws\Http\HttpResponse;
use Ebremer\Lws\Http\HttpTransport;
use Ebremer\Lws\Json\Json;

/**
 * An in-process server: a handler answers each request, and every request is recorded.
 */
final class FakeTransport implements HttpTransport
{
    /** @var list<HttpRequest> */
    public array $requests = [];

    /** @param \Closure(HttpRequest): HttpResponse $handler */
    public function __construct(private \Closure $handler)
    {
    }

    public function send(HttpRequest $request): HttpResponse
    {
        $this->requests[] = $request;
        return ($this->handler)($request);
    }

    /**
     * A response.
     *
     * @param array<array-key, mixed> $headers
     */
    public static function response(HttpRequest $request, int $status = 200, array $headers = [], mixed $body = null): HttpResponse
    {
        if ($body !== null && !is_string($body)) {
            $body = Json::encode($body);
        }
        return new HttpResponse($request->url, $status, new Headers($headers), $body ?? '');
    }

    /**
     * The requests to a URL (or all, with null), as "METHOD url".
     *
     * @return list<string>
     */
    public function log(): array
    {
        return array_map(static fn (HttpRequest $r): string => "{$r->method} {$r->url}", $this->requests);
    }

    public function last(): HttpRequest
    {
        return $this->requests[count($this->requests) - 1];
    }
}
