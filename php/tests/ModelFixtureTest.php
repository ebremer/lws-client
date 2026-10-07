<?php
// SPDX-License-Identifier: MIT
declare(strict_types=1);

namespace Ebremer\Lws\Tests;

use Ebremer\Lws\Access\AccessGrant;
use Ebremer\Lws\Access\AccessPolicy;
use Ebremer\Lws\Access\AccessRequest;
use Ebremer\Lws\Access\AccessTarget;
use Ebremer\Lws\Access\Constraint;
use Ebremer\Lws\Auth\AccessToken;
use Ebremer\Lws\Auth\AuthorizationServerMetadata;
use Ebremer\Lws\Exception\ConflictException;
use Ebremer\Lws\Exception\HttpException;
use Ebremer\Lws\Exception\ProtocolException;
use Ebremer\Lws\Http\Headers;
use Ebremer\Lws\Internal\Url;
use Ebremer\Lws\Json\Json;
use Ebremer\Lws\Model\ContainedResource;
use Ebremer\Lws\Model\ContainerPage;
use Ebremer\Lws\Model\Linkset;
use Ebremer\Lws\Model\LinksetDocument;
use Ebremer\Lws\Model\LinkTarget;
use Ebremer\Lws\Model\ResourceMetadata;
use Ebremer\Lws\Model\StorageDescription;
use Ebremer\Lws\Model\TypeIndexPage;
use Ebremer\Lws\Notification\Notification;
use Ebremer\Lws\Notification\Subscription;
use Ebremer\Lws\Notification\WebhookSubscriptionRequest;
use Ebremer\Lws\Tests\Support\Fixtures;
use PHPUnit\Framework\TestCase;

/** The shared fixtures for response models. */
final class ModelFixtureTest extends TestCase
{
    /** @param array<string, mixed> $headers */
    private static function metadata(string $url, int $status, array $headers): ResourceMetadata
    {
        return new ResourceMetadata($url, $status, new Headers($headers));
    }

    /** The fixture body as the client would decode it from the wire. */
    private static function wire(mixed $body): mixed
    {
        return Json::decode(json_encode($body, JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR));
    }

    public function testStorageDescriptionFixture(): void
    {
        $f = Fixtures::load('responses/storage-description.json');
        $sd = StorageDescription::parse(self::wire($f['body']), $f['url']);
        $e = $f['expected'];
        self::assertSame($e['id'], $sd->id);
        self::assertSame($e['types'], $sd->types);
        self::assertSame($e['storageRoot'], $sd->storageRoot());
        self::assertSame($e['notificationService'], $sd->notificationService()?->serviceEndpoint);
        self::assertSame($e['notificationSubscriptionTypes'], $sd->notificationService()?->subscriptionTypes());
        self::assertSame($e['typeIndexService'], $sd->typeIndexService()?->serviceEndpoint);
        self::assertSame($e['typeSearchService'], $sd->typeSearchService()?->serviceEndpoint);
        self::assertSame($e['accessRequestService'], $sd->accessRequestService()?->serviceEndpoint);
        self::assertSame($e['accessGrantService'], $sd->accessGrantService()?->serviceEndpoint);
        self::assertCount($e['serviceCount'], $sd->services);
        self::assertSame($e['capabilityTypes'], array_map(static fn ($c): string => $c->types[0], $sd->capabilities));
        $custom = $sd->service($e['customService']['type']);
        self::assertNotNull($custom);
        self::assertSame($e['customService']['id'], $custom->id);
        self::assertSame($e['customService']['serviceEndpoint'], $custom->serviceEndpoint);
        self::assertNotNull($sd->capability('https://feature.example/PatchSupport'));
        self::assertTrue($sd->hasType('https://www.w3.org/ns/lws#Storage'));
    }

    public function testStorageDescriptionInvalid(): void
    {
        $invalid = Fixtures::load('responses/storage-description.json')['invalid'];
        try {
            StorageDescription::parse(self::wire($invalid['notStorage']));
            self::fail('Accepted a document that is not a Storage');
        } catch (ProtocolException) {
            self::addToAssertionCount(1);
        }
        $sd = StorageDescription::parse(self::wire($invalid['noRoot']));
        $this->expectException(ProtocolException::class);
        $sd->storageRoot();
    }

    public function testContainerPageFixture(): void
    {
        $f = Fixtures::load('responses/container-page.json');
        $page = ContainerPage::parse(self::wire($f['body']), self::metadata($f['url'], $f['status'], $f['headers']));
        $e = $f['expected'];
        self::assertSame($e['id'], $page->id);
        self::assertSame($e['isContainer'], $page->metadata->isContainer());
        self::assertSame($e['totalItems'], $page->totalItems);
        self::assertSame($e['etag'], $page->etag);
        self::assertSame($e['linkset'], $page->metadata->linkset);
        self::assertSame($e['parent'], $page->metadata->parent);
        self::assertSame($e['storage'], $page->metadata->storage);
        self::assertSame([$e['first'], $e['next'], $e['prev'], $e['last']], [$page->first, $page->next, $page->prev, $page->last]);
        self::assertCount(count($e['items']), $page->items);
        foreach ($e['items'] as $i => $x) {
            $item = $page->items[$i];
            self::assertSame($x['id'], $item->id);
            self::assertSame($x['isContainer'], $item->isContainer());
            self::assertSame($x['isDataResource'], $item->isDataResource());
            self::assertSame($x['format'], $item->format);
            self::assertSame($x['size'], $item->size);
            self::assertSame($x['types'], $item->types);
            if (array_key_exists('modified', $x)) {
                self::assertSame($x['modified'], $item->modified?->format('Y-m-d\TH:i:s\Z'));
            }
            if (isset($x['modifiedRaw'])) {
                self::assertSame($x['modifiedRaw'], $item->modifiedRaw);
            }
            if (isset($x['hasType'])) {
                self::assertTrue($item->hasType($x['hasType']));
            }
        }
        // A page body that is not a page.
        $this->expectException(ProtocolException::class);
        ContainerPage::parse(self::wire(['items' => 'nope']), self::metadata($f['url'], 200, []));
    }

    public function testContainedResourceDates(): void
    {
        $item = ContainedResource::parse(['id' => 'x', 'modified' => '2026-10-07T12:00:00.250+02:00', 'type' => 'Container'], 'https://s.example/');
        self::assertSame('https://s.example/x', $item->id);
        self::assertSame('2026-10-07T10:00:00.250000Z', $item->modified?->format('Y-m-d\TH:i:s.u\Z'));
        self::assertSame(['Container'], $item->types);
        self::assertTrue($item->isContainer());
        self::assertNull(ContainedResource::parse(['id' => 'y', 'modified' => '2026-02-30T00:00:00Z'], 'https://s.example/')->modified);
        $this->expectException(ProtocolException::class);
        ContainedResource::parse(['type' => 'DataResource'], 'https://s.example/');
    }

    public function testLinksetFixture(): void
    {
        $f = Fixtures::load('responses/linkset.json');
        $body = Fixtures::text('responses/linkset.json');
        $raw = Json::decode($body);
        self::assertIsArray($raw);
        $doc = new LinksetDocument($f['url'], Linkset::parse($raw['body']), self::metadata($f['url'], $f['status'], $f['headers']));
        $e = $f['expected'];
        self::assertSame($e['url'], $doc->url);
        self::assertSame($e['etag'], $doc->etag);
        self::assertSame($e['allow'], $doc->allow);
        self::assertSame($e['acceptPatch'], $doc->acceptPatch);
        self::assertTrue($doc->supportsPut());
        self::assertCount($e['contexts'], $doc->linkset->contexts);
        self::assertSame($e['anchor'], $doc->linkset->contexts[0]->anchor);
        self::assertCount($e['linkCount'], $doc->linkset);
        self::assertCount($e['linkCount'], $doc->linkset->links());
        foreach ($e['targets'] as $rel => $targets) {
            self::assertSame($targets, $doc->linkset->hrefs($rel));
        }
        // Lossless round trip, member order and the hreflang / title* members included.
        $original = Json::encode($raw['body']);
        self::assertSame($original, $doc->linkset->encode());
        $op = $e['afterAdd']['operation'];
        $doc->linkset->add($op['anchor'], $op['rel'], $op['href']);
        self::assertSame($e['afterAdd']['licenseTargets'], $doc->linkset->hrefs('license', $op['anchor']));
        self::assertSame(1, $doc->linkset->remove($op['anchor'], 'license', $op['href']));
        self::assertSame($original, $doc->linkset->encode());
        $links = $doc->linkset->links();
        self::assertSame($op['anchor'], $links[0]->anchor());
        self::assertSame('application/schema+json', $links[0]->type());
        self::assertSame('Bob', $doc->linkset->targets('https://example.org/rel/reviewer')[0]->attribute('title'));
        self::assertSame(2, $doc->linkset->remove($op['anchor'], 'https://example.org/rel/reviewer'));
        self::assertSame([], $doc->linkset->hrefs('https://example.org/rel/reviewer'));
        $fresh = (new Linkset())->add('https://s.example/a', 'describedby', 'https://s.example/shape', ['type' => 'text/turtle']);
        self::assertSame('{"linkset":[{"anchor":"https://s.example/a","describedby":[{"href":"https://s.example/shape","type":"text/turtle"}]}]}', $fresh->encode());
        self::assertEquals(new LinkTarget('x', ['href' => 'ignored', 'type' => 't']), new LinkTarget('x', ['type' => 't']));
        $this->expectException(ProtocolException::class);
        Linkset::parse('{"nolinkset": []}');
    }

    public function testNotificationFixture(): void
    {
        $f = Fixtures::load('responses/notification.json');
        foreach (['single', 'batch'] as $key) {
            $n = Notification::parse(self::wire($f[$key]));
            $e = $f[$key . 'Expected'];
            self::assertSame($e['storage'], $n->storage);
            self::assertCount(count($e['activities']), $n->activities);
            foreach ($e['activities'] as $i => $x) {
                $a = $n->activities[$i];
                self::assertSame($x['id'], $a->id);
                self::assertSame($x['types'], $a->types);
                self::assertSame($x['objectId'], $a->object->id);
                foreach (['isCreate', 'isUpdate', 'isDelete'] as $flag) {
                    if (isset($x[$flag])) {
                        self::assertSame($x[$flag], $a->$flag());
                    }
                }
                if (isset($x['objectTypes'])) {
                    self::assertSame($x['objectTypes'], $a->object->types);
                }
                foreach (['origin', 'target', 'actor'] as $name) {
                    if (isset($x[$name])) {
                        self::assertSame($x[$name], $a->$name);
                    }
                }
                if (isset($x['published'])) {
                    self::assertSame($x['published'], $a->publishedRaw);
                    self::assertNotNull($a->published);
                }
            }
        }
        self::assertCount(0, Notification::parse('{"type":"Notification","storage":"https://s.example/","activity":[]}')->activities);
        $this->expectException(ProtocolException::class);
        Notification::parse(self::wire($f['invalid']));
    }

    public function testAccessFixture(): void
    {
        $f = Fixtures::load('responses/access.json');
        $request = AccessRequest::parse(self::wire($f['request']));
        self::assertSame('https://storage.example/', $request->storage);
        self::assertSame(['read', 'create'], $request->access[0]->actions);
        self::assertEquals($f['request'], $request->toJson());
        self::assertSame(Json::encode(self::wire($f['request'])), Json::encode($request->document()));
        $grant = AccessGrant::parse(Json::encode($f['grant']));
        self::assertEquals($f['grant'], $grant->toJson());
        self::assertSame(['image/jpeg', 'image/png'], $grant->access[0]->constraints[0]->rightOperand);
        $built = AccessRequest::create('https://storage.example/', [
            new AccessPolicy(['read', 'create'], 'https://id.example/agent', AccessTarget::storageResources('https://storage.example/root/projects/'), [
                Constraint::purpose('https://purpose.example/collaboration'),
                Constraint::notAfter('2026-06-09T10:00:00Z'),
            ]),
        ], 'https://id.example/agent/inbox/');
        self::assertSame(Json::encode($f['request']), Json::encode($built->toJson()));
        self::assertNull($built->raw);
        foreach ([
            static fn () => AccessGrant::parse(self::wire($f['request'])),
            static fn () => AccessRequest::parse(['type' => 'AccessRequest', 'storage' => 'https://s.example/']),
            static fn () => AccessRequest::parse(['type' => 'AccessRequest', 'storage' => 'https://s.example/', 'access' => [['action' => ['read']]]]),
        ] as $bad) {
            try {
                $bad();
                self::fail('Accepted an invalid access document');
            } catch (ProtocolException) {
                self::addToAssertionCount(1);
            }
        }
        foreach ([
            static fn () => new AccessPolicy([], 'https://id.example/agent'),
            static fn () => new AccessPolicy(['read'], 'agent'),
            static fn () => AccessRequest::create('https://storage.example/', []),
            static fn () => new AccessTarget('Container', []),
        ] as $bad) {
            try {
                $bad();
                self::fail('Built an invalid access document');
            } catch (\InvalidArgumentException) {
                self::addToAssertionCount(1);
            }
        }
    }

    public function testConstraintFactories(): void
    {
        self::assertSame(['leftOperand' => 'dateTime', 'operator' => 'gteq', 'rightOperand' => '2026-03-09T12:00:00Z'],
            Constraint::notBefore(new \DateTimeImmutable('2026-03-09T12:00:00Z'))->toJson());
        self::assertSame(['image/png'], Constraint::formatAnyOf('image/png')->rightOperand);
        self::assertSame('type', Constraint::type('https://type.example/Song')->leftOperand);
        self::assertSame('isAnyOf', Constraint::typeAnyOf('https://type.example/Song')->operator);
        self::assertSame('eq', Constraint::client('https://app.example/id')->operator);
        self::assertSame(['a:1', 'b:2'], Constraint::purposeAnyOf('a:1', 'b:2')->rightOperand);
        self::assertSame('image/png', Constraint::format('image/png')->rightOperand);
        $this->expectException(\InvalidArgumentException::class);
        Constraint::notAfter('tomorrow');
    }

    public function testTypeIndexAndSearchFixture(): void
    {
        $f = Fixtures::load('responses/type-index.json');
        $ti = $f['typeIndex'];
        $page = TypeIndexPage::parse(self::wire($ti['body']), self::metadata($ti['url'], 200, $ti['headers']));
        self::assertSame($ti['expected']['totalItems'], $page->totalItems);
        self::assertSame($ti['expected']['types'], $page->types);
        self::assertSame($ti['expected']['next'], $page->next);
        $se = $f['search'];
        $sp = ContainerPage::parse(self::wire($se['body']), self::metadata($se['url'], 200, $se['headers']));
        self::assertSame($se['expected']['totalItems'], $sp->totalItems);
        self::assertSame($se['expected']['ids'], array_map(static fn ($i): string => $i->id, $sp->items));
        self::assertSame($se['expected']['next'], $sp->next);
        self::assertTrue($sp->items[2]->isContainer());
        self::assertSame(Url::resolve($se['body']['id'] ?? $se['url'], $se['url']), $sp->id);
    }

    public function testOauthFixture(): void
    {
        $f = Fixtures::load('responses/oauth.json');
        foreach ($f['metadataUrls'] as $c) {
            self::assertSame($c['url'], AuthorizationServerMetadata::metadataUrl($c['issuer']));
        }
        foreach ($f['realmChecks'] as $c) {
            self::assertSame($c['contained'], Url::contains($c['realm'], $c['url']), json_encode($c) ?: '');
        }
        $now = 1_700_000_000.0;
        $t = AccessToken::fromTokenResponse($f['tokenResponse']['body'], $now);
        self::assertSame($now + $f['tokenResponse']['expectedExpiresIn'], $t->expiresAt);
        self::assertTrue($t->isValid($now, 30));
        self::assertSame((float) $f['tokenResponseNoExpiry']['expectedExp'], AccessToken::fromTokenResponse($f['tokenResponseNoExpiry']['body'], $now)->expiresAt);
        self::assertSame($now + AccessToken::DEFAULT_LIFETIME, AccessToken::fromTokenResponse(['access_token' => 'opaque', 'token_type' => 'bearer'], $now)->expiresAt);
        $md = AuthorizationServerMetadata::parse(self::wire($f['metadata']), 'https://authorization.example/.well-known/lws-configuration');
        self::assertNotSame('', $md->tokenEndpoint);
        self::assertTrue(Url::isHttp($md->tokenEndpoint));
        self::assertNotEmpty($md->raw);
    }

    public function testProblemDetailsFixture(): void
    {
        $f = Fixtures::load('responses/problem-details.json');
        $e = HttpException::fromResponse($f['status'], 'DELETE', 'https://storage.example/alice/notes/', new Headers($f['headers']), json_encode($f['body']) ?: '');
        self::assertInstanceOf(ConflictException::class, $e);
        self::assertSame(409, $e->status);
        self::assertSame(409, $e->getCode());
        $x = $f['expected'];
        self::assertNotNull($e->problem);
        self::assertSame([$x['type'], $x['title'], $x['detail'], $x['instance']], [$e->problem->type, $e->problem->title, $e->problem->detail, $e->problem->instance]);
        self::assertSame($x['extension'], $e->problem->extensions);
        self::assertStringContainsString('container is not empty', $e->getMessage());
        self::assertStringContainsString('DELETE https://storage.example/alice/notes/', $e->getMessage());
    }

    public function testSubscriptionFixture(): void
    {
        $f = Fixtures::load('responses/subscription.json');
        $request = new WebhookSubscriptionRequest($f['input']['topics'], $f['input']['inbox'], $f['input']['expires']);
        self::assertSame(Json::encode($f['expectedRequestBody']), Json::encode($request->toJson()));
        $sub = Subscription::parse(self::wire($f['response']['body']));
        self::assertSame([$f['expected']['type'], $f['expected']['subscription'], $f['expected']['expires']], [$sub->type, $sub->url, $sub->expiresRaw]);
        self::assertNotNull($sub->expires);
        self::assertSame($f['input']['expires'], (new WebhookSubscriptionRequest($f['input']['topics'], $f['input']['inbox'], new \DateTimeImmutable($f['input']['expires'])))->expires);
        $this->expectException(\InvalidArgumentException::class);
        new WebhookSubscriptionRequest([], $f['input']['inbox']);
    }

    public function testResourceMetadata(): void
    {
        $m = self::metadata('https://s.example/c/a.txt', 200, [
            'ETag' => 'W/"3"',
            'Last-Modified' => 'Tue, 06 Oct 2026 12:00:00 GMT',
            'Content-Type' => 'text/plain; charset=utf-8',
            'Content-Length' => '11',
            'Link' => ['<a.txt.meta>; rel="linkset"; type="application/linkset+json"', '<./>; rel="up"', '</>; rel="https://www.w3.org/ns/lws#storage"',
                '<https://www.w3.org/ns/lws#DataResource>; rel="type"'],
            'Allow' => 'GET, HEAD, PUT',
            'Accept-Patch' => 'application/json-patch+json',
        ]);
        self::assertSame('W/"3"', $m->etag);
        self::assertSame('2026-10-06T12:00:00+00:00', $m->lastModifiedTime()?->format('c'));
        self::assertSame(11, $m->contentLength);
        self::assertSame('https://s.example/c/a.txt.meta', $m->linkset);
        self::assertSame('https://s.example/c/', $m->parent);
        self::assertSame('https://s.example/', $m->storage);
        self::assertTrue($m->isDataResource());
        self::assertFalse($m->isContainer());
        self::assertSame(['GET', 'HEAD', 'PUT'], $m->allow);
        self::assertSame(['application/json-patch+json'], $m->acceptPatch);
        self::assertSame('application/linkset+json', $m->link('linkset')?->type());
        self::assertCount(1, $m->links('up'));
    }
}
