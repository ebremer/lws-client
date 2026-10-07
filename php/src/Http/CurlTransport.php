<?php
// SPDX-License-Identifier: MIT
declare(strict_types=1);

namespace Ebremer\Lws\Http;

use Ebremer\Lws\Exception\TransportException;

/**
 * The default {@see HttpTransport}, on ext-curl: one reused handle (so connections are kept alive), no redirects
 * followed, no cookies, http and https only, any method (`QUERY` included).
 */
final class CurlTransport implements HttpTransport
{
    private ?\CurlHandle $handle = null;

    /**
     * @param float $connectTimeout the time limit for connecting, in seconds
     * @param float $defaultTimeout the time limit of a request that sets none, in seconds (0 for none)
     * @param array<int, mixed> $curlOptions extra `CURLOPT_*` options (a CA bundle, a proxy, …); options the
     *     transport depends on (redirects, the method, headers, the body) are set after them
     */
    public function __construct(
        private readonly float $connectTimeout = 10.0,
        private readonly float $defaultTimeout = 30.0,
        private readonly array $curlOptions = [],
    ) {
    }

    public function send(HttpRequest $request): HttpResponse
    {
        $h = $this->handle ??= curl_init() ?: throw new TransportException('curl_init failed');
        curl_reset($h);
        $headers = [];
        $status = 0;
        $fields = [];
        foreach ($request->headers as $name => $value) {
            $fields[] = $value === '' ? "$name;" : "$name: $value";
        }
        // No `Expect: 100-continue`, and none of curl's own Accept or form Content-Type defaults.
        $fields[] = 'Expect:';
        if (!$request->headers->has('Accept')) {
            $fields[] = 'Accept:';
        }
        if (!$request->headers->has('Content-Type')) {
            $fields[] = 'Content-Type:';
        }
        $timeout = $request->timeout ?? $this->defaultTimeout;
        $options = $this->curlOptions + [CURLOPT_NOSIGNAL => true];
        $options[CURLOPT_URL] = $request->url;
        $options[CURLOPT_FOLLOWLOCATION] = false;
        $options[CURLOPT_PROTOCOLS] = CURLPROTO_HTTP | CURLPROTO_HTTPS;
        $options[CURLOPT_RETURNTRANSFER] = true;
        $options[CURLOPT_HTTPHEADER] = $fields;
        $options[CURLOPT_CONNECTTIMEOUT_MS] = (int) ceil($this->connectTimeout * 1000);
        $options[CURLOPT_TIMEOUT_MS] = $timeout > 0 ? (int) ceil($timeout * 1000) : 0;
        $options[CURLOPT_HEADERFUNCTION] = static function ($ch, string $line) use (&$headers, &$status): int {
            $t = rtrim($line, "\r\n");
            if (preg_match('~^HTTP/\S+\s+(\d{3})~', $t, $m) === 1) {
                // A new status line (after a 1xx): the headers so far belonged to an interim response.
                $status = (int) $m[1];
                $headers = [];
            } elseif ($t !== '' && str_contains($t, ':')) {
                [$name, $value] = explode(':', $t, 2);
                $headers[] = [trim($name), trim($value, " \t")];
            }
            return strlen($line);
        };
        $method = strtoupper($request->method);
        if ($method === 'HEAD') {
            $options[CURLOPT_NOBODY] = true;
        } elseif ($method === 'GET' && $request->body === null) {
            $options[CURLOPT_HTTPGET] = true;
        } else {
            $options[CURLOPT_CUSTOMREQUEST] = $request->method;
            if ($request->body !== null) {
                $options[CURLOPT_POSTFIELDS] = $request->body;
            }
        }
        if (!curl_setopt_array($h, $options)) {
            throw new TransportException("Invalid request options for {$request->method} {$request->url}");
        }
        $body = curl_exec($h);
        if ($body === false) {
            $errno = curl_errno($h);
            $message = curl_error($h);
            throw new TransportException(
                "{$request->method} {$request->url} failed: " . ($message !== '' ? $message : "curl error $errno"),
                $errno === CURLE_OPERATION_TIMEDOUT,
            );
        }
        $code = (int) curl_getinfo($h, CURLINFO_RESPONSE_CODE);
        $parsed = [];
        foreach ($headers as [$name, $value]) {
            if (preg_match('/^[!#$%&\'*+\-.^_`|~0-9A-Za-z]+$/', $name) === 1 && !str_contains($value, "\0")) {
                $parsed[] = [$name, $value];
            }
        }
        return new HttpResponse($request->url, $code !== 0 ? $code : $status, new Headers($parsed), is_string($body) ? $body : '');
    }

    public function __destruct()
    {
        $this->handle = null;
    }
}
