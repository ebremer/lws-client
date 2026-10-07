<?php
// SPDX-License-Identifier: MIT
declare(strict_types=1);

namespace Ebremer\Lws\Tests;

use Ebremer\Lws\Access\AccessGrant;
use Ebremer\Lws\Access\AccessPolicy;
use Ebremer\Lws\Access\AccessRequest;
use Ebremer\Lws\Access\AccessTarget;
use Ebremer\Lws\Exception\BadRequestException;
use Ebremer\Lws\Exception\ConflictException;
use Ebremer\Lws\Exception\ForbiddenException;
use Ebremer\Lws\Exception\GoneException;
use Ebremer\Lws\Exception\HttpException;
use Ebremer\Lws\Exception\InsufficientStorageException;
use Ebremer\Lws\Exception\MethodNotAllowedException;
use Ebremer\Lws\Exception\NotAcceptableException;
use Ebremer\Lws\Exception\NotFoundException;
use Ebremer\Lws\Exception\NotImplementedException;
use Ebremer\Lws\Exception\PreconditionFailedException;
use Ebremer\Lws\Exception\ProtocolException;
use Ebremer\Lws\Exception\UnauthorizedException;
use Ebremer\Lws\Exception\UnprocessableContentException;
use Ebremer\Lws\Exception\UnsupportedMediaTypeException;
use Ebremer\Lws\Http\HttpRequest;
use Ebremer\Lws\Http\HttpResponse;
use Ebremer\Lws\Http\Link;
use Ebremer\Lws\Json\Json;
use Ebremer\Lws\Json\JsonPatch;
use Ebremer\Lws\Json\JsonPointer;
use Ebremer\Lws\LwsClient;
use Ebremer\Lws\Model\ByteRange;
use Ebremer\Lws\Model\Linkset;
use Ebremer\Lws\Model\TypeQuery;
use Ebremer\Lws\Notification\WebhookSubscriptionRequest;
use Ebremer\Lws\Tests\Support\FakeTransport;
use Ebremer\Lws\Tests\Support\Fixtures;
use PHPUnit\Framework\TestCase;

/** Every operation over an in-process transport: requests sent, responses parsed, errors mapped. */
final class ClientHttpTest extends TestCase
{
    private const S = 'https://storage.example/';

    private FakeTransport $t;

    /** @param \Closure(HttpRequest): HttpResponse $handler */
    private function client(\Closure $handler): LwsClient
    {
        $this->t = new FakeTransport($handler);
        return new LwsClient(transport: $this->t);
    }

    public function testDiscoverStorageWithHeadAndGetFallback(): void
    {
        $sd = Fixtures::load('responses/storage-description.json');
        foreach ([200, 405] as $headStatus) {
            $client = $this->client(static function (HttpRequest $r) use ($sd, $headStatus): HttpResponse {
                if ($r->url === 'https://storage.example/alice/notes/') {
                    $status = $r->method === 'HEAD' ? $headStatus : 200;
                    return FakeTransport::response($r, $status, $status === 200 ? ['Link' => '</>; rel="https://www.w3.org/ns/lws#storage"'] : []);
                }
                self::assertSame('application/lws+cid, application/ld+json;q=0.9, application/json;q=0.8', $r->headers->first('accept'));
                return FakeTransport::response($r, 200, ['Content-Type' => 'application/lws+cid'], $sd['body']);
            });
            $storage = $client->discoverStorage('https://storage.example/alice/notes/');
            self::assertSame($sd['expected']['storageRoot'], $storage->storageRoot());
            self::assertSame($headStatus === 200 ? ['HEAD', 'GET'] : ['HEAD', 'GET', 'GET'], array_map(static fn ($x) => $x->method, $this->t->requests));
            self::assertSame('lws-client-php/0.1.0', $this->t->requests[0]->headers->first('user-agent'));
        }
        // A 401 with a storage link still discovers (anonymous discovery).
        $client = $this->client(static fn (HttpRequest $r): HttpResponse => $r->method === 'HEAD'
            ? FakeTransport::response($r, 401, ['Link' => '</>; rel="https://www.w3.org/ns/lws#storage"'])
            : FakeTransport::response($r, 200, ['Content-Type' => 'application/json'], $sd['body']));
        self::assertSame($sd['expected']['id'], $client->discoverStorage(self::S . 'x')->id);
        // No storage link.
        $client = $this->client(static fn (HttpRequest $r): HttpResponse => FakeTransport::response($r, 200));
        $this->expectException(ProtocolException::class);
        $client->discoverStorage(self::S . 'x');
    }

    public function testStorageDescriptionMediaTypeIsChecked(): void
    {
        $client = $this->client(static fn (HttpRequest $r): HttpResponse => FakeTransport::response($r, 200, ['Content-Type' => 'text/turtle'], '<> a <x>.'));
        $this->expectException(ProtocolException::class);
        $client->getStorageDescription(self::S);
    }

    public function testReadConditionalRangeAndText(): void
    {
        $client = $this->client(static function (HttpRequest $r): HttpResponse {
            if ($r->headers->first('if-none-match') === '"1"') {
                return FakeTransport::response($r, 304, ['ETag' => '"1"']);
            }
            if ($r->headers->first('range') === 'bytes=0-3') {
                return FakeTransport::response($r, 206, ['Content-Range' => 'bytes 0-3/11', 'Content-Type' => 'text/plain'], 'Hell');
            }
            return FakeTransport::response($r, 200, ['ETag' => '"1"', 'Content-Type' => 'text/plain; charset=iso-8859-1',
                'Link' => ['<a.txt.meta>; rel="linkset"', '<./>; rel="up"']], "caf\xe9");
        });
        $r = $client->read(self::S . 'c/a.txt', accept: 'text/plain', ifModifiedSince: new \DateTimeImmutable('2026-10-06T12:00:00Z'), prefer: 'return=minimal');
        self::assertSame('"1"', $r->etag);
        self::assertSame("caf\xe9", $r->body);
        self::assertSame(function_exists('mb_convert_encoding') || function_exists('iconv') ? 'café' : "caf\xe9", $r->text());
        self::assertSame(self::S . 'c/a.txt.meta', $r->metadata->linkset);
        self::assertSame(self::S . 'c/', $r->metadata->parent);
        self::assertSame('Tue, 06 Oct 2026 12:00:00 GMT', $this->t->last()->headers->first('if-modified-since'));
        self::assertSame('return=minimal', $this->t->last()->headers->first('prefer'));
        $nm = $client->read(self::S . 'c/a.txt', ifNoneMatch: '"1"');
        self::assertTrue($nm->notModified);
        self::assertSame('', $nm->body);
        self::assertSame(304, $nm->status);
        $part = $client->read(self::S . 'c/a.txt', range: ByteRange::of(0, 3));
        self::assertSame([206, 'Hell', 'bytes 0-3/11'], [$part->status, $part->body, $part->contentRange]);
        self::assertSame('bytes=-5', ByteRange::last(5)->headerValue());
        self::assertSame('bytes=7-', ByteRange::from(7)->headerValue());
    }

    /** A container of 12 items, 5 per page, linked by opaque page URLs. */
    private static function pagedContainer(): \Closure
    {
        return static function (HttpRequest $r): HttpResponse {
            $page = 0;
            if (preg_match('~\?page=(\d)$~', $r->url, $m) === 1) {
                $page = (int) $m[1];
            }
            $items = [];
            for ($i = $page * 5; $i < min(12, $page * 5 + 5); $i++) {
                $items[] = ['id' => "item$i", 'type' => 'DataResource', 'format' => 'text/plain'];
            }
            $links = ['<https://www.w3.org/ns/lws#Container>; rel="type"'];
            if ($page < 2) {
                $links[] = '<?page=' . ($page + 1) . '>; rel="next"';
            }
            return FakeTransport::response($r, 200, ['Content-Type' => 'application/lws+json', 'Link' => $links],
                ['id' => '/c/', 'type' => 'Container', 'totalItems' => 12, 'items' => $items]);
        };
    }

    public function testListContainerFollowsNextLazily(): void
    {
        $client = $this->client(self::pagedContainer());
        $page = $client->readContainer(self::S . 'c/');
        self::assertSame(self::S . 'c/', $page->id);
        self::assertSame(12, $page->totalItems);
        self::assertSame(self::S . 'c/?page=1', $page->next);
        self::assertSame('application/lws+json', $this->t->last()->headers->first('accept'));
        $this->t->requests = [];
        $listing = $client->listContainer(self::S . 'c/');
        self::assertSame([], $this->t->requests, 'nothing is fetched before iterating');
        $ids = array_map(static fn ($i): string => $i->id, $listing->toArray());
        self::assertCount(12, $ids);
        self::assertSame(self::S . 'c/item0', $ids[0]);
        self::assertSame(self::S . 'c/item11', $ids[11]);
        self::assertCount(3, $this->t->requests);
        $this->t->requests = [];
        self::assertCount(3, $listing->take(3));
        self::assertCount(1, $this->t->requests, 'take() stops after the page it needs');
        // Iterating again starts from the first page.
        self::assertCount(12, iterator_to_array($listing, false));
    }

    public function testListingStopsAtARepeatedPage(): void
    {
        $client = $this->client(static fn (HttpRequest $r): HttpResponse => FakeTransport::response($r, 200,
            ['Content-Type' => 'application/lws+json', 'Link' => '</c/>; rel="next"'], ['type' => 'Container', 'items' => [['id' => 'x']]]));
        self::assertCount(1, $client->listContainer(self::S . 'c/')->toArray());
    }

    public function testReadContainerRejectsOtherRepresentations(): void
    {
        foreach ([
            ['text/turtle', ['type' => 'Container', 'items' => []]],
            ['application/json', ['id' => '/x', 'type' => 'DataResource']],
            ['application/json', '{not json'],
        ] as [$type, $body]) {
            $client = $this->client(static fn (HttpRequest $r): HttpResponse => FakeTransport::response($r, 200, ['Content-Type' => $type], $body));
            try {
                $client->readContainer(self::S . 'x');
                self::fail("Accepted $type");
            } catch (ProtocolException) {
                self::addToAssertionCount(1);
            }
        }
    }

    public function testCreateVariants(): void
    {
        $client = $this->client(static fn (HttpRequest $r): HttpResponse => FakeTransport::response($r, 201,
            ['Location' => 'new-' . strtolower($r->headers->first('slug') ?? 'x'), 'Link' => '<x.meta>; rel="linkset"']));
        $c = $client->createText(self::S . 'c/', 'Hello', slug: 'naïve.txt', types: ['https://schema.org/Note'],
            links: [new Link('https://example.org/s', 'describedby')]);
        self::assertSame(self::S . 'c/new-na%c3%afve.txt', $c->location);
        self::assertSame(self::S . 'c/x.meta', $c->linkset);
        $r = $this->t->last();
        self::assertSame(['POST', 'Hello', 'text/plain', 'na%C3%AFve.txt'], [$r->method, $r->body, $r->headers->first('content-type'), $r->headers->first('slug')]);
        self::assertSame(['<https://schema.org/Note>; rel="type"', '<https://example.org/s>; rel="describedby"'], $r->headers->all('link'));
        $client->createJson(self::S . 'c/', ['name' => 'Alice', 'tags' => [], 'meta' => new \stdClass()]);
        self::assertSame(['application/json', '{"name":"Alice","tags":[],"meta":{}}'], [$this->t->last()->headers->first('content-type'), $this->t->last()->body]);
        $client->createContainer(self::S . 'c/', slug: 'sub');
        $r = $this->t->last();
        self::assertSame(['', null], [$r->body, $r->headers->first('content-type')]);
        self::assertSame(['<https://www.w3.org/ns/lws#Container>; rel="type"'], $r->headers->all('link'));
        $client->create(self::S . 'c/', "\x00\x01", 'application/octet-stream', headers: ['X-Extra' => 'yes']);
        self::assertSame('yes', $this->t->last()->headers->first('x-extra'));
        // 201 without Location.
        $client = $this->client(static fn (HttpRequest $r): HttpResponse => FakeTransport::response($r, 201));
        try {
            $client->createText(self::S . 'c/', 'x');
            self::fail('Accepted a 201 without Location');
        } catch (ProtocolException) {
            self::assertCount(1, $this->t->requests, 'a POST is never repeated');
        }
        $this->expectException(\InvalidArgumentException::class);
        $client->createJson(self::S . 'c/', NAN);
    }

    public function testUpdatePatchAndDelete(): void
    {
        $etag = '"1"';
        $client = $this->client(static function (HttpRequest $r) use (&$etag): HttpResponse {
            $match = $r->headers->first('if-match');
            if ($match !== null && $match !== $etag) {
                return FakeTransport::response($r, 412);
            }
            if ($r->method === 'DELETE') {
                return $r->headers->first('depth') === 'infinity' ? FakeTransport::response($r, 204)
                    : FakeTransport::response($r, 409, ['Content-Type' => 'application/problem+json'], ['title' => 'Container not empty']);
            }
            $etag = '"' . ((int) trim($etag, '"') + 1) . '"';
            return FakeTransport::response($r, 204, ['ETag' => $etag]);
        });
        $u = $client->update(self::S . 'a.txt', 'Hello again', 'text/plain', ifMatch: '"1"');
        self::assertSame([204, '"2"'], [$u->status, $u->etag]);
        try {
            $client->update(self::S . 'a.txt', 'stale', 'text/plain', ifMatch: '"1"');
            self::fail('No 412');
        } catch (PreconditionFailedException $e) {
            self::assertSame(412, $e->status);
            self::assertSame('PUT', $e->method);
        }
        $p = $client->patch(self::S . 'p.json', (new JsonPatch())->replace('/age', 31)->add('/city', 'Boston'), ifMatch: '"2"');
        self::assertSame('"3"', $p->etag);
        self::assertSame(['application/json-patch+json', '[{"op":"replace","path":"/age","value":31},{"op":"add","path":"/city","value":"Boston"}]'],
            [$this->t->last()->headers->first('content-type'), $this->t->last()->body]);
        $client->patch(self::S . 'p.ttl', 'INSERT DATA {}', 'application/sparql-update');
        self::assertSame('application/sparql-update', $this->t->last()->headers->first('content-type'));
        $client->update(self::S . 'a.txt', 'x', 'text/plain', ifNoneMatch: '*', links: [new Link('https://e.example/l', 'license')], setLinkset: true);
        self::assertSame(['*', 'set-linkset', '<https://e.example/l>; rel="license"'],
            [$this->t->last()->headers->first('if-none-match'), $this->t->last()->headers->first('prefer'), $this->t->last()->headers->first('link')]);
        try {
            $client->delete(self::S . 'c/');
            self::fail('No 409');
        } catch (ConflictException $e) {
            self::assertSame('Container not empty', $e->problem?->title);
        }
        $client->delete(self::S . 'c/', recursive: true);
        self::assertSame(['DELETE', 'infinity'], [$this->t->last()->method, $this->t->last()->headers->first('depth')]);
        $this->expectException(\InvalidArgumentException::class);
        $client->patch(self::S . 'p.ttl', 'bytes');
    }

    public function testLinksets(): void
    {
        $fx = Fixtures::load('responses/linkset.json');
        $client = $this->client(static function (HttpRequest $r) use ($fx): HttpResponse {
            if ($r->method === 'HEAD') {
                return FakeTransport::response($r, 200, ['Link' => '<personalinfo.json.meta>; rel="linkset"; type="application/linkset+json"']);
            }
            if ($r->method === 'GET') {
                return FakeTransport::response($r, 200, $fx['headers'], $fx['body']);
            }
            return $r->method === 'PUT' ? FakeTransport::response($r, 405, ['Allow' => 'GET, HEAD, PATCH']) : FakeTransport::response($r, 204, ['ETag' => '"ls-8"']);
        });
        self::assertSame($fx['url'], $client->linksetUrl('https://storage.example/alice/personalinfo.json'));
        $doc = $client->readLinkset('https://storage.example/alice/personalinfo.json');
        self::assertSame(['HEAD', 'GET'], array_map(static fn ($x) => $x->method, array_slice($this->t->requests, -2)));
        self::assertSame('application/linkset+json, application/json;q=0.5', $this->t->last()->headers->first('accept'));
        self::assertSame($fx['url'], $doc->url);
        self::assertSame('"ls-7"', $doc->etag);
        $pointer = JsonPointer::fromSegments('linkset', '0', 'describedby', '-');
        $updated = $client->patchLinkset($doc->url, (new JsonPatch())->add($pointer, ['href' => 'https://example.org/shapes/person']), ifMatch: $doc->etag);
        self::assertSame('"ls-8"', $updated->etag);
        self::assertSame(['application/json-patch+json', '"ls-7"'], [$this->t->last()->headers->first('content-type'), $this->t->last()->headers->first('if-match')]);
        self::assertStringContainsString('"path":"/linkset/0/describedby/-"', (string) $this->t->last()->body);
        try {
            $client->updateLinkset($doc->url, $doc->linkset->add(null, 'license', 'https://example.org/l'));
            self::fail('No 405');
        } catch (MethodNotAllowedException $e) {
            self::assertSame(['GET', 'HEAD', 'PATCH'], $e->allow());
            self::assertSame('application/linkset+json', $this->t->last()->headers->first('content-type'));
        }
        $client = $this->client(static fn (HttpRequest $r): HttpResponse => FakeTransport::response($r, 200));
        $this->expectException(ProtocolException::class);
        $client->linksetUrl(self::S . 'x');
    }

    public function testSubscriptions(): void
    {
        $sd = Fixtures::load('responses/storage-description.json');
        $sub = Fixtures::load('responses/subscription.json');
        $client = $this->client(static function (HttpRequest $r) use ($sub): HttpResponse {
            return match ($r->method) {
                'POST' => FakeTransport::response($r, 201, $sub['response']['headers'], $sub['response']['body']),
                'GET' => FakeTransport::response($r, 200, ['Content-Type' => 'application/lws+json'], ['type' => 'WebhookSubscription', 'expires' => '2026-06-09T12:00:00Z']),
                default => FakeTransport::response($r, 204),
            };
        });
        $storage = \Ebremer\Lws\Model\StorageDescription::parse($sd['body'], $sd['url']);
        $service = $storage->notificationService();
        self::assertNotNull($service);
        $request = new WebhookSubscriptionRequest($sub['input']['topics'], $sub['input']['inbox'], $sub['input']['expires']);
        $s = $client->subscribe($service, $request);
        self::assertSame($sub['expected']['subscription'], $s->url);
        self::assertSame(Json::encode($sub['expectedRequestBody']), $this->t->last()->body);
        self::assertSame(['application/lws+json', 'application/lws+json'], [$this->t->last()->headers->first('content-type'), $this->t->last()->headers->first('accept')]);
        $got = $client->getSubscription($s->url);
        self::assertSame($s->url, $got->url);
        self::assertSame('WebhookSubscription', $got->type);
        $client->unsubscribe($s->url);
        self::assertSame('DELETE', $this->t->last()->method);
        // A body-less 201 with a Location.
        $client = $this->client(static fn (HttpRequest $r): HttpResponse => FakeTransport::response($r, 201, ['Location' => '/subs/1']));
        self::assertSame(self::S . 'subs/1', $client->subscribe(self::S . 'notifications/', $request)->url);
        // A service without webhooks.
        $other = new \Ebremer\Lws\Model\Service(null, ['NotificationService'], self::S . 'n/', ['subscriptionType' => ['StreamingSubscription']]);
        $this->expectException(ProtocolException::class);
        $client->subscribe($other, $request);
    }

    public function testAccessRequestsAndGrants(): void
    {
        $fx = Fixtures::load('responses/access.json');
        $client = $this->client(static fn (HttpRequest $r): HttpResponse => match ($r->method) {
            'POST' => FakeTransport::response($r, 201, ['Location' => 'r1']),
            'GET' => FakeTransport::response($r, 200, ['Content-Type' => 'application/lws+json'], str_contains($r->url, 'grants') ? $fx['grant'] : $fx['request']),
            default => FakeTransport::response($r, 204),
        });
        $policy = new AccessPolicy(['read'], 'did:key:zDnae', AccessTarget::containers(self::S . 'c/'));
        $location = $client->requestAccess(self::S . 'access/requests/', AccessRequest::create(self::S, [$policy]));
        self::assertSame(self::S . 'access/requests/r1', $location);
        self::assertSame('{"@context":["https://www.w3.org/ns/lws/v1"],"type":["AccessRequest"],"storage":"https://storage.example/","access":[{"type":["AccessPolicy"],"action":["read"],"assignee":"did:key:zDnae","target":{"type":"Container","value":["https://storage.example/c/"]}}]}', $this->t->last()->body);
        self::assertEquals($fx['request'], $client->getAccessRequest($location)->raw);
        self::assertSame(self::S . 'access/grants/r1', $client->grantAccess(self::S . 'access/grants/', AccessGrant::create(self::S, [$policy])));
        self::assertSame('AccessGrant', $client->getAccessGrant(self::S . 'access/grants/r1')->types[0]);
        $client->revokeAccessGrant(self::S . 'access/grants/r1');
        $client->cancelAccessRequest($location);
        self::assertSame(['DELETE', 'DELETE'], array_map(static fn ($x) => $x->method, array_slice($this->t->requests, -2)));
    }

    public function testTypeIndexAndSearch(): void
    {
        $client = $this->client(static function (HttpRequest $r): HttpResponse {
            if ($r->method === 'OPTIONS') {
                return FakeTransport::response($r, 204, ['Accept-Query' => '"application/lws-query+json", application/sparql-query', 'Allow' => 'QUERY, OPTIONS']);
            }
            if ($r->method === 'QUERY') {
                return FakeTransport::response($r, 200, ['Content-Type' => 'application/lws+json', 'Link' => '</types/search/p/2>; rel="next"'],
                    ['type' => 'ContainerPage', 'items' => [['id' => '/a', 'type' => 'DataResource']]]);
            }
            if (str_contains($r->url, '/search/p/2')) {
                return FakeTransport::response($r, 200, ['Content-Type' => 'application/lws+json'], ['type' => 'ContainerPage', 'items' => [['id' => '/b']]]);
            }
            if (str_ends_with($r->url, '/types/index')) {
                return FakeTransport::response($r, 200, ['Content-Type' => 'application/lws+json', 'Link' => '<index?p=2>; rel="next"'],
                    ['type' => 'TypeIndex', 'totalItems' => 3, 'items' => ['https://schema.org/Person', ['id' => 'https://schema.org/Event']]]);
            }
            return FakeTransport::response($r, 200, ['Content-Type' => 'application/lws+json'], ['type' => 'TypeIndex', 'items' => ['https://schema.org/Place']]);
        });
        $page = $client->readTypeIndex(self::S . 'types/index');
        self::assertSame([3, ['https://schema.org/Person', 'https://schema.org/Event'], self::S . 'types/index?p=2'], [$page->totalItems, $page->types, $page->next]);
        self::assertSame(['https://schema.org/Person', 'https://schema.org/Event', 'https://schema.org/Place'], $client->listTypes(self::S . 'types/index')->toArray());
        $q = TypeQuery::create()->allOf('https://schema.org/Person');
        $first = $client->searchTypes(self::S . 'types/search', $q);
        self::assertSame(self::S . 'types/search', $first->id, 'the page URL stands in for a missing id');
        $r = $this->t->last();
        self::assertSame(['QUERY', 'application/lws-query+json', 'application/lws+json', '{"type":["https://schema.org/Person"]}'],
            [$r->method, $r->headers->first('content-type'), $r->headers->first('accept'), $r->body]);
        $this->t->requests = [];
        self::assertSame([self::S . 'a', self::S . 'b'], array_map(static fn ($i) => $i->id, $client->searchAll(self::S . 'types/search', $q)->toArray()));
        self::assertSame(['QUERY', 'GET'], array_map(static fn ($x) => $x->method, $this->t->requests));
        self::assertSame(['application/lws-query+json', 'application/sparql-query'], $client->acceptedQueryFormats(self::S . 'types/search'));
    }

    public function testErrorMapping(): void
    {
        $classes = [400 => BadRequestException::class, 401 => UnauthorizedException::class, 403 => ForbiddenException::class,
            404 => NotFoundException::class, 405 => MethodNotAllowedException::class, 406 => NotAcceptableException::class,
            409 => ConflictException::class, 410 => GoneException::class, 412 => PreconditionFailedException::class,
            415 => UnsupportedMediaTypeException::class, 422 => UnprocessableContentException::class, 501 => NotImplementedException::class,
            507 => InsufficientStorageException::class, 500 => HttpException::class, 418 => HttpException::class];
        foreach ($classes as $status => $class) {
            $client = $this->client(static fn (HttpRequest $r): HttpResponse => FakeTransport::response($r, $status,
                ['Accept-Patch' => 'application/json-patch+json', 'Accept-Query' => 'application/lws-query+json', 'WWW-Authenticate' => 'Basic realm="x"', 'Content-Type' => 'text/plain'],
                str_repeat('e', 10000)));
            try {
                $client->head(self::S . 'x');
                self::fail("No exception for $status");
            } catch (HttpException $e) {
                self::assertSame($class, $e::class);
                self::assertSame($status, $e->status);
                self::assertSame(HttpException::BODY_LIMIT, strlen($e->body));
                if ($e instanceof UnsupportedMediaTypeException) {
                    self::assertSame(['application/json-patch+json'], $e->acceptPatch());
                    self::assertSame(['application/lws-query+json'], $e->acceptQuery());
                }
                if ($e instanceof UnauthorizedException) {
                    self::assertTrue($e->challenges()[0]->isScheme('basic'));
                }
            }
        }
    }

    public function testRedirectsAreFollowedByTheClient(): void
    {
        $client = $this->client(static function (HttpRequest $r): HttpResponse {
            return match ($r->url) {
                self::S . 'old' => FakeTransport::response($r, 301, ['Location' => '/new']),
                self::S . 'new' => FakeTransport::response($r, 200, [], 'moved'),
                self::S . 'post' => FakeTransport::response($r, 303, ['Location' => '/result']),
                self::S . 'result' => FakeTransport::response($r, 200, [], $r->method . ' ' . ($r->body ?? 'none') . ' ' . ($r->headers->first('content-type') ?? 'none')),
                self::S . 'temp' => FakeTransport::response($r, 307, ['Location' => 'https://other.example/put']),
                'https://other.example/put' => FakeTransport::response($r, 204, [], ''),
                self::S . 'loop' => FakeTransport::response($r, 302, ['Location' => '/loop']),
                default => FakeTransport::response($r, 302, ['Location' => '/new']),
            };
        });
        $r = $client->read(self::S . 'old');
        self::assertSame(['moved', self::S . 'new'], [$r->body, $r->url]);
        self::assertSame('GET none none', $client->request('QUERY', self::S . 'post', 'q', 'text/plain')->body);
        // 307 keeps the method and body; a caller's Authorization does not cross origins.
        $client->update(self::S . 'temp', 'body', 'text/plain', headers: ['Authorization' => 'Basic abc']);
        self::assertSame(['PUT', 'body', null], [$this->t->last()->method, $this->t->last()->body, $this->t->last()->headers->first('authorization')]);
        self::assertSame('Basic abc', $this->t->requests[count($this->t->requests) - 2]->headers->first('authorization'));
        // A 302 answer to a POST is not followed.
        try {
            $client->createText(self::S . 'elsewhere', 'x');
            self::fail('Followed a POST redirect');
        } catch (HttpException $e) {
            self::assertSame(302, $e->status);
        }
        $this->expectException(ProtocolException::class);
        $client->head(self::S . 'loop');
    }

    public function testDefaultHeadersUserAgentAndTimeout(): void
    {
        $t = new FakeTransport(static fn (HttpRequest $r): HttpResponse => FakeTransport::response($r, 200));
        $client = new LwsClient(transport: $t, userAgent: 'my-app/1', defaultHeaders: ['X-App' => 'a', 'Accept-Language' => 'en'], timeout: 5.0);
        $client->head(self::S, headers: ['Accept-Language' => 'de'], timeout: 2.5);
        $r = $t->last();
        self::assertSame(['my-app/1', 'a', 'de', 2.5], [$r->headers->first('user-agent'), $r->headers->first('x-app'), $r->headers->first('accept-language'), $r->timeout]);
        $client->head(self::S);
        self::assertSame(5.0, $t->last()->timeout);
        (new LwsClient(transport: $t, userAgent: null))->head(self::S);
        self::assertNull($t->last()->headers->first('user-agent'));
        self::assertSame($client->transport, $client->withAuthenticator(null)->transport);
    }

    public function testInvalidArguments(): void
    {
        $client = $this->client(static fn (HttpRequest $r): HttpResponse => throw new \LogicException('No request may be sent'));
        foreach ([
            static fn () => $client->read('/relative'),
            static fn () => $client->head('ftp://x.example/'),
            static fn () => $client->listContainer('nope'),
            static fn () => $client->createText('https:///no-host', 'x'),
            static fn () => $client->request('BAD METHOD', self::S),
            static fn () => $client->read(self::S, headers: ['X-Bad' => "a\r\nInjected: b"]),
            static fn () => $client->searchAll('/x', TypeQuery::create()),
        ] as $bad) {
            try {
                $bad();
                self::fail('Accepted an invalid argument');
            } catch (\InvalidArgumentException) {
                self::addToAssertionCount(1);
            }
        }
    }
}
