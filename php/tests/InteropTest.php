<?php
// SPDX-License-Identifier: MIT
declare(strict_types=1);

namespace Ebremer\Lws\Tests;

use Ebremer\Lws\Access\AccessGrant;
use Ebremer\Lws\Access\AccessPolicy;
use Ebremer\Lws\Access\AccessRequest;
use Ebremer\Lws\Access\AccessTarget;
use Ebremer\Lws\Access\Constraint;
use Ebremer\Lws\Auth\SelfSignedCredentials;
use Ebremer\Lws\Auth\SigningKey;
use Ebremer\Lws\Auth\TokenExchangeAuthenticator;
use Ebremer\Lws\Exception\ConflictException;
use Ebremer\Lws\Exception\NotFoundException;
use Ebremer\Lws\Exception\PreconditionFailedException;
use Ebremer\Lws\Json\Json;
use Ebremer\Lws\Json\JsonPatch;
use Ebremer\Lws\Json\JsonPointer;
use Ebremer\Lws\LwsClient;
use Ebremer\Lws\Model\TypeQuery;
use Ebremer\Lws\Notification\WebhookSubscriptionRequest;
use Ebremer\Lws\Notification\WebhookVerifier;
use PHPUnit\Framework\TestCase;

/**
 * The cross-language interop scenario (conformance/scenario.md) against the mock server, over the real
 * {@see \Ebremer\Lws\Http\CurlTransport}. Skipped unless `LWS_TEST_SERVER` is set to its base URL.
 */
final class InteropTest extends TestCase
{
    public function testScenario(): void
    {
        $server = getenv('LWS_TEST_SERVER');
        if ($server === false || $server === '') {
            self::markTestSkipped('LWS_TEST_SERVER is not set');
        }
        $base = rtrim($server, '/');
        $person = 'https://schema.org/Person';

        // 1. Authenticate and discover.
        $me = SelfSignedCredentials::didKey(SigningKey::generateP256());
        $client = new LwsClient(authenticator: new TokenExchangeAuthenticator($me));
        $storage = $client->discoverStorage("$base/root/");
        self::assertSame("$base/root/", $storage->storageRoot());
        foreach (['notificationService', 'accessRequestService', 'accessGrantService', 'typeIndexService', 'typeSearchService'] as $s) {
            self::assertNotNull($storage->$s(), $s);
        }
        $root = $storage->storageRoot();

        // 2. A container for this run.
        $c = $client->createContainer($root, slug: 'interop-php-' . (int) (microtime(true) * 1000))->location;

        // 3, 4. Create and read text.
        $h = $client->createText($c, 'Hello, LWS!', slug: 'hello.txt')->location;
        $read = $client->read($h);
        self::assertSame('Hello, LWS!', $read->text());
        $etag = $read->etag;
        self::assertNotNull($etag);
        self::assertTrue($read->metadata->isDataResource());
        self::assertSame($c, $read->metadata->parent);
        self::assertNotNull($read->metadata->linkset);
        self::assertSame("$base/", $read->metadata->storage);

        // 5. Conditional read.
        self::assertTrue($client->read($h, ifNoneMatch: $etag)->notModified);

        // 6. Update with If-Match; the old ETag then fails.
        $client->update($h, 'Hello again', 'text/plain', ifMatch: $etag);
        try {
            $client->update($h, 'stale', 'text/plain', ifMatch: $etag);
            self::fail('No 412');
        } catch (PreconditionFailedException) {
            self::addToAssertionCount(1);
        }

        // 7. Create JSON with a type, patch it.
        $p = $client->createJson($c, ['name' => 'Alice', 'age' => 30], slug: 'profile.json', types: [$person])->location;
        $client->patch($p, (new JsonPatch())->replace('/age', 31)->add('/city', 'Boston'));
        self::assertSame(['name' => 'Alice', 'age' => 31, 'city' => 'Boston'], $client->read($p)->json());

        // 8. Linkset: add describedby to the first context.
        $doc = $client->readLinkset($p);
        $shape = 'https://example.org/shapes/person';
        $client->patchLinkset($doc->url, (new JsonPatch())->add(JsonPointer::fromSegments('linkset', '0', 'describedby'), [['href' => $shape]]), ifMatch: $doc->etag);
        self::assertContains($shape, $client->readLinkset($p)->linkset->hrefs('describedby'));

        // 9. Pagination: eight members.
        for ($i = 0; $i < 6; $i++) {
            $client->createText($c, "item $i", slug: "item-$i.txt");
        }
        $page = $client->readContainer($c);
        self::assertSame(8, $page->totalItems);
        self::assertNotNull($page->next);
        $ids = array_map(static fn ($item): string => $item->id, $client->listContainer($c)->toArray());
        self::assertCount(8, $ids);
        self::assertContains($h, $ids);
        self::assertContains($p, $ids);

        // 10. Type index and search.
        $typeIndex = $storage->typeIndexService()->serviceEndpoint ?? '';
        $typeSearch = $storage->typeSearchService()->serviceEndpoint ?? '';
        self::assertContains($person, $client->listTypes($typeIndex)->toArray());
        self::assertContains($p, array_map(static fn ($item): string => $item->id, $client->searchAll($typeSearch, TypeQuery::create()->allOf($person))->toArray()));
        self::assertContains('application/lws-query+json', $client->acceptedQueryFormats($typeSearch));

        // 11. Notifications, with a local inbox.
        $listener = stream_socket_server('tcp://127.0.0.1:0', $errno, $errstr);
        self::assertNotFalse($listener, (string) $errstr);
        $port = (int) substr((string) strrchr((string) stream_socket_get_name($listener, false), ':'), 1);
        $inbox = "http://127.0.0.1:$port/inbox";
        $service = $storage->notificationService();
        self::assertNotNull($service);
        $subscription = $client->subscribe($service, new WebhookSubscriptionRequest([$c], $inbox));
        $client->update($h, 'Hello, notifications', 'text/plain');
        [$method, $headers, $body] = self::receive($listener, 5.0);
        fclose($listener);
        $verified = (new WebhookVerifier(client: $client, trustedStorages: ["$base/"]))->verify($method, $inbox, $headers, $body);
        $update = array_values(array_filter($verified->notification->activities, static fn ($a): bool => $a->isUpdate()));
        self::assertNotEmpty($update);
        self::assertSame($h, $update[0]->object->id);
        $listed = array_map(static fn ($item): string => $item->id, $client->listSubscriptions($service->serviceEndpoint)->toArray());
        self::assertContains($subscription->url, $listed);
        $client->unsubscribe($subscription->url);

        // 12. Access requests and grants.
        $policy = new AccessPolicy(['read'], $me->agent, AccessTarget::containers($c), [Constraint::purpose('https://purpose.example/interop')]);
        $requests = $storage->accessRequestService()->serviceEndpoint ?? '';
        $grants = $storage->accessGrantService()->serviceEndpoint ?? '';
        $requestUrl = $client->requestAccess($requests, AccessRequest::create("$base/", [$policy]));
        $got = $client->getAccessRequest($requestUrl);
        self::assertSame("$base/", $got->storage);
        self::assertSame($me->agent, $got->access[0]->assignee);
        self::assertContains($requestUrl, array_map(static fn ($item): string => $item->id, $client->listAccessRequests($requests)->toArray()));
        $grantUrl = $client->grantAccess($grants, AccessGrant::create("$base/", [$policy]));
        self::assertSame(['read'], $client->getAccessGrant($grantUrl)->access[0]->actions);
        $client->revokeAccessGrant($grantUrl);
        $client->cancelAccessRequest($requestUrl);

        // 13. Delete.
        try {
            $client->delete($c);
            self::fail('Deleted a non-empty container');
        } catch (ConflictException) {
            self::addToAssertionCount(1);
        }
        $client->delete($c, recursive: true);
        $this->expectException(NotFoundException::class);
        $client->read($h);
    }

    /**
     * Accepts one request on the inbox and answers it `204`.
     *
     * @param resource $listener
     * @return array{0: string, 1: list<array{0: string, 1: string}>, 2: string}
     */
    private static function receive($listener, float $timeout): array
    {
        $connection = @stream_socket_accept($listener, $timeout);
        self::assertNotFalse($connection, 'No notification within 5 seconds');
        stream_set_timeout($connection, 5);
        $head = '';
        while (!str_contains($head, "\r\n\r\n") && !feof($connection)) {
            $head .= (string) fread($connection, 1);
        }
        $lines = explode("\r\n", rtrim($head));
        $method = explode(' ', (string) array_shift($lines))[0];
        $headers = [];
        $length = 0;
        foreach ($lines as $line) {
            [$name, $value] = array_map('trim', explode(':', $line, 2)) + [1 => ''];
            $headers[] = [$name, $value];
            if (strcasecmp($name, 'content-length') === 0) {
                $length = (int) $value;
            }
        }
        $body = '';
        while (strlen($body) < $length && !feof($connection)) {
            $body .= (string) fread($connection, max(1, $length - strlen($body)));
        }
        fwrite($connection, "HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n");
        fclose($connection);
        Json::decode($body);
        return [$method, $headers, $body];
    }
}
