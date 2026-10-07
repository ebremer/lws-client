<?php
// SPDX-License-Identifier: MIT
declare(strict_types=1);

namespace Ebremer\Lws\Tests;

use Ebremer\Lws\Exception\TransportException;
use Ebremer\Lws\Http\Headers;
use Ebremer\Lws\Http\HttpRequest;
use Ebremer\Lws\Http\Psr18Transport;
use Ebremer\Lws\LwsClient;
use Nyholm\Psr7\Factory\Psr17Factory;
use Nyholm\Psr7\Response;
use PHPUnit\Framework\TestCase;
use Psr\Http\Client\ClientExceptionInterface;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;

/** {@see Psr18Transport} over a PSR-18 client double with nyholm/psr7. */
final class Psr18TransportTest extends TestCase
{
    public function testRequestsAndResponsesCrossThePsrInterfaces(): void
    {
        $client = new class () implements ClientInterface {
            public ?RequestInterface $last = null;

            public function sendRequest(RequestInterface $request): ResponseInterface
            {
                $this->last = $request;
                return new Response(201, ['Location' => '/c/new', 'Link' => ['<a>; rel="x"', '<b>; rel="y"']], 'ok');
            }
        };
        $f = new Psr17Factory();
        $lws = new LwsClient(transport: new Psr18Transport($client, $f, $f));
        $created = $lws->createText('https://s.example/c/', 'Hello', slug: 'h.txt', types: ['https://schema.org/Note']);
        self::assertSame('https://s.example/c/new', $created->location);
        self::assertCount(2, $created->metadata->links);
        $r = $client->last;
        self::assertNotNull($r);
        self::assertSame(['POST', 'https://s.example/c/', 'Hello', 'text/plain', '5', 'h.txt'],
            [$r->getMethod(), (string) $r->getUri(), (string) $r->getBody(), $r->getHeaderLine('Content-Type'), $r->getHeaderLine('Content-Length'), $r->getHeaderLine('Slug')]);
        self::assertSame(['<https://schema.org/Note>; rel="type"'], $r->getHeader('Link'));
    }

    public function testClientExceptionsAreTransportErrors(): void
    {
        $client = new class () implements ClientInterface {
            public function sendRequest(RequestInterface $request): ResponseInterface
            {
                throw new class ('refused') extends \RuntimeException implements ClientExceptionInterface {
                };
            }
        };
        $f = new Psr17Factory();
        $this->expectException(TransportException::class);
        (new Psr18Transport($client, $f, $f))->send(new HttpRequest('GET', 'https://s.example/', new Headers()));
    }
}
