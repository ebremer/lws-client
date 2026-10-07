<?php
// SPDX-License-Identifier: MIT
declare(strict_types=1);

namespace Ebremer\Lws\Tests;

use Ebremer\Lws\Exception\TransportException;
use Ebremer\Lws\Http\CurlTransport;
use Ebremer\Lws\Http\Headers;
use Ebremer\Lws\Http\HttpRequest;
use PHPUnit\Framework\TestCase;

/** {@see CurlTransport} against a socket that answers once (and one that is closed). */
final class CurlTransportTest extends TestCase
{
    public function testRefusedConnectionIsATransportError(): void
    {
        $socket = stream_socket_server('tcp://127.0.0.1:0');
        self::assertNotFalse($socket);
        $name = (string) stream_socket_get_name($socket, false);
        fclose($socket);
        try {
            (new CurlTransport(connectTimeout: 2))->send(new HttpRequest('GET', "http://$name/"));
            self::fail('No transport error');
        } catch (TransportException $e) {
            self::assertFalse($e->isTimeout());
        }
    }

    public function testTimeoutIsReported(): void
    {
        $socket = stream_socket_server('tcp://127.0.0.1:0');
        self::assertNotFalse($socket);
        $name = (string) stream_socket_get_name($socket, false);
        try {
            (new CurlTransport())->send(new HttpRequest('QUERY', "http://$name/", new Headers(), '{}', 0.3));
            self::fail('No timeout');
        } catch (TransportException $e) {
            self::assertTrue($e->isTimeout(), $e->getMessage());
        } finally {
            fclose($socket);
        }
    }
}
