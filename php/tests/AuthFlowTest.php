<?php
// SPDX-License-Identifier: MIT
declare(strict_types=1);

namespace Ebremer\Lws\Tests;

use Ebremer\Lws\Auth\BearerTokenAuthenticator;
use Ebremer\Lws\Auth\CredentialContext;
use Ebremer\Lws\Auth\DidKey;
use Ebremer\Lws\Auth\Jwt;
use Ebremer\Lws\Auth\OpenIdCredentials;
use Ebremer\Lws\Auth\SamlCredentials;
use Ebremer\Lws\Auth\SelfSignedCredentials;
use Ebremer\Lws\Auth\SigningKey;
use Ebremer\Lws\Auth\TokenExchangeAuthenticator;
use Ebremer\Lws\Exception\AuthenticationException;
use Ebremer\Lws\Exception\UnauthorizedException;
use Ebremer\Lws\Http\HttpRequest;
use Ebremer\Lws\Http\HttpResponse;
use Ebremer\Lws\LwsClient;
use Ebremer\Lws\Tests\Support\FakeTransport;
use Ebremer\Lws\Tests\Support\Fixtures;
use Ebremer\Lws\TokenType;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * The LWS authorization flow against a fake storage and authorization server: `401 → protected resource metadata →
 * storage description → authorization server metadata → token exchange → retry`, proactive reuse, refresh, the
 * challenge of the drafts before 19 October 2026, and every check that keeps credentials from the wrong servers.
 */
final class AuthFlowTest extends TestCase
{
    private const STORAGE = 'https://storage.example/';
    private const AS = 'https://as.example';
    private const PRM = 'https://storage.example/.well-known/oauth-protected-resource/';

    /** @var list<array<string, string>> token requests received */
    private array $exchanges = [];
    private int $issued = 0;
    /** @var array<string, string> the token each storage accepts */
    private array $valid = [];
    private float $now = 1_800_000_000.0;
    /** @var array<string, mixed> */
    private array $metadata = [];
    /** Whether the storage answers with the challenge of the drafts before 19 October 2026. */
    private bool $legacy = false;
    private string $challengeRealm = self::STORAGE;
    private string $asUri = self::AS;
    /** @var ?list<string> the authorization servers of the protected resource metadata (null: [asUri]) */
    private ?array $authorizationServers = null;
    private string $root = self::STORAGE;
    private FakeTransport $transport;
    private TokenExchangeAuthenticator $auth;
    /** @var \Closure(HttpRequest): ?HttpResponse|null */
    private ?\Closure $override = null;
    /** Whether a discovery case has reached its later requests (`then`). */
    private bool $later = false;

    protected function setUp(): void
    {
        $this->metadata = ['issuer' => self::AS, 'token_endpoint' => self::AS . '/token',
            'subject_token_types_supported' => [TokenType::JWT, TokenType::ID_TOKEN, TokenType::SAML2]];
    }

    private function handle(HttpRequest $r): HttpResponse
    {
        if ($this->override !== null) {
            $o = ($this->override)($r);
            if ($o !== null) {
                return $o;
            }
        }
        if ($r->url === self::AS . '/.well-known/lws-configuration') {
            return FakeTransport::response($r, 200, ['Content-Type' => 'application/json'], $this->metadata);
        }
        if ($r->url === self::AS . '/token') {
            parse_str((string) $r->body, $form);
            /** @var array<string, string> $form */
            $this->exchanges[] = $form;
            $token = 'tok-' . ++$this->issued;
            $this->valid[$form['resource']] = $token;
            return FakeTransport::response($r, 200, ['Content-Type' => 'application/json'], ['access_token' => $token, 'token_type' => 'Bearer', 'expires_in' => 3600]);
        }
        if (str_starts_with($r->url, 'https://other.example/')) {
            return FakeTransport::response($r, 200, [], (string) ($r->headers->first('authorization') ?? 'anonymous'));
        }
        if (str_starts_with($r->url, self::PRM)) {
            return FakeTransport::response($r, 200, ['Content-Type' => 'application/json'],
                ['resource' => self::STORAGE . substr($r->url, strlen(self::PRM)), 'authorization_servers' => $this->authorizationServers ?? [$this->asUri]]);
        }
        if ($r->url === self::STORAGE && $r->method === 'GET' && !$r->headers->has('authorization')) {
            return FakeTransport::response($r, 200, ['Content-Type' => 'application/lws+cid'], self::description(self::STORAGE, $this->root));
        }
        $expected = $this->valid[self::STORAGE] ?? null;
        if ($expected !== null && $r->headers->first('authorization') === "Bearer $expected") {
            return FakeTransport::response($r, $r->method === 'POST' ? 201 : 200, $r->method === 'POST' ? ['Location' => '/c/new'] : [], 'secret');
        }
        return $this->challenge($r);
    }

    /** The storage's 401: the RFC 9728 challenge with a link to the storage, or the as_uri and realm of earlier drafts. */
    private function challenge(HttpRequest $r, string $storage = self::STORAGE): HttpResponse
    {
        if ($this->legacy) {
            return FakeTransport::response($r, 401, ['WWW-Authenticate' => "Bearer as_uri=\"{$this->asUri}\", realm=\"{$this->challengeRealm}\", error=\"invalid_token\""]);
        }
        return FakeTransport::response($r, 401, [
            'WWW-Authenticate' => 'Bearer resource_metadata="' . self::PRM . substr($r->url, strlen(self::STORAGE)) . '", error="invalid_token"',
            'Link' => "<$storage>; rel=\"https://www.w3.org/ns/lws#storage\"",
        ]);
    }

    /** @return array<string, mixed> a storage description with only its root */
    private static function description(string $id, string $root): array
    {
        return ['@context' => ['https://www.w3.org/ns/cid/v1', 'https://www.w3.org/ns/lws/v1'], 'id' => $id, 'type' => 'Storage',
            'service' => [['type' => 'StorageRoot', 'serviceEndpoint' => $root]]];
    }

    private function client(?SelfSignedCredentials $credentials = null, bool $allowInsecureHttp = false, ?\Closure $filter = null): LwsClient
    {
        $this->transport = new FakeTransport($this->handle(...));
        $credentials ??= SelfSignedCredentials::didKey(SigningKey::generateP256())->withClock(fn (): float => $this->now);
        $this->auth = new TokenExchangeAuthenticator($credentials, allowInsecureHttp: $allowInsecureHttp, authorizationServerFilter: $filter,
            transport: $this->transport, clock: fn (): float => $this->now);
        return new LwsClient(authenticator: $this->auth, transport: $this->transport);
    }

    public function testFullFlowAndProactiveReuse(): void
    {
        $key = SigningKey::generateP256();
        $me = SelfSignedCredentials::didKey($key)->withClock(fn (): float => $this->now);
        $client = $this->client($me);
        self::assertSame('secret', $client->read(self::STORAGE . 'notes/a.txt')->body);
        self::assertSame([
            'GET https://storage.example/notes/a.txt',
            'GET https://storage.example/.well-known/oauth-protected-resource/notes/a.txt',
            'GET https://storage.example/',
            'GET https://as.example/.well-known/lws-configuration',
            'POST https://as.example/token',
            'GET https://storage.example/notes/a.txt',
        ], $this->transport->log());
        [$form] = $this->exchanges;
        self::assertSame(['urn:ietf:params:oauth:grant-type:token-exchange', self::STORAGE, TokenType::JWT],
            [$form['grant_type'], $form['resource'], $form['subject_token_type']]);
        $requests = $this->transport->requests;
        self::assertSame(['application/json', null], [$requests[1]->headers->first('accept'), $requests[1]->headers->first('authorization')]);
        self::assertSame(['application/lws+cid, application/ld+json;q=0.9, application/json;q=0.8', null],
            [$requests[2]->headers->first('accept'), $requests[2]->headers->first('authorization')]);
        self::assertSame('application/x-www-form-urlencoded', $requests[4]->headers->first('content-type'));
        self::assertSame('Bearer tok-1', $requests[5]->headers->first('authorization'));
        // The subject token: a self-signed JWT for the authorization server.
        $jwt = $form['subject_token'];
        self::assertTrue(Jwt::verify($jwt, $key->publicKey));
        $claims = Jwt::decodeClaims($jwt);
        $did = DidKey::did($key->publicKey);
        self::assertSame([$did, $did, $did, [self::AS]], [$claims['sub'], $claims['iss'], $claims['client_id'], $claims['aud']]);
        self::assertSame(300, $claims['exp'] - $claims['iat']);
        self::assertSame(['ES256', 'JWT', DidKey::keyId($key->publicKey)], array_values(Jwt::decodeHeader($jwt)));
        self::assertMatchesRegularExpression('/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/', $claims['jti']);
        // Proactive: the next request inside the storage carries the token at once.
        $this->transport->requests = [];
        $client->read(self::STORAGE . 'other/b.txt');
        self::assertSame(['GET https://storage.example/other/b.txt'], $this->transport->log());
        self::assertSame('Bearer tok-1', $this->transport->last()->headers->first('authorization'));
        self::assertSame('tok-1', $this->auth->accessToken(self::AS, self::STORAGE)->value);
        // Never outside the storage and its root.
        self::assertSame('anonymous', $client->read('https://other.example/x')->body);
        self::assertStringNotContainsString('tok-1', print_r($this->auth, true));
    }

    public function testTheTokenIsSentToTheStorageAndItsRootTheLongestScopeWinning(): void
    {
        // A storage described at /s whose root is /data/: the token is for the storage, and is sent to both.
        $this->override = function (HttpRequest $r): ?HttpResponse {
            if ($r->url === self::STORAGE . 's' && !$r->headers->has('authorization')) {
                return FakeTransport::response($r, 200, ['Content-Type' => 'application/lws+cid'], self::description(self::STORAGE . 's', self::STORAGE . 'data/'));
            }
            if (str_starts_with($r->url, self::STORAGE . 'data/') || str_starts_with($r->url, self::STORAGE . 's/')) {
                $auth = $r->headers->first('authorization');
                return $auth === null ? $this->challenge($r, self::STORAGE . 's') : FakeTransport::response($r, 200, [], $auth);
            }
            return null;
        };
        $client = $this->client();
        self::assertSame('Bearer tok-1', $client->read(self::STORAGE . 'data/a.txt')->body);
        self::assertSame(self::STORAGE . 's', $this->exchanges[0]['resource']);
        $this->transport->requests = [];
        self::assertSame('Bearer tok-1', $client->read(self::STORAGE . 's/x')->body);
        self::assertSame('Bearer tok-1', $client->read(self::STORAGE . 'data/b/c')->body);
        self::assertCount(2, $this->transport->requests, 'no 401 first');
        // A token for the whole storage at / (the challenge of earlier drafts) is not sent where the deeper scope applies.
        $this->legacy = true;
        $client->read(self::STORAGE . 'elsewhere');
        self::assertSame(self::STORAGE, $this->exchanges[1]['resource']);
        self::assertSame('Bearer tok-1', $client->read(self::STORAGE . 'data/a.txt')->body);
        self::assertSame('secret', $client->read(self::STORAGE . 'elsewhere')->body);
        self::assertSame('Bearer tok-2', $this->transport->last()->headers->first('authorization'));
    }

    /** @return array<string, array{0: array<string, mixed>}> the cases of discovery.json, {A} and {B} two origins */
    public static function discoveryCases(): array
    {
        $f = json_decode(strtr(Fixtures::text('discovery.json'), ['{A}' => 'https://storage.example', '{B}' => 'https://other.example']), true, 512, JSON_THROW_ON_ERROR);
        $out = [];
        foreach ($f['cases'] as $case) {
            $out[$case['name']] = [$case + ['tokenResponse' => $f['tokenResponse']]];
        }
        return $out;
    }

    /**
     * Each case of `conformance/fixtures/discovery.json` through the authenticator, against a fake server that answers
     * as the fixture describes: the outcome, the one token request, what is never fetched, and where the token goes next.
     *
     * @param array<string, mixed> $case
     */
    #[DataProvider('discoveryCases')]
    public function testDiscoveryFixture(array $case): void
    {
        $expected = $case['expected'];
        $then = $expected['then'] ?? [];
        $tokenRequests = [];
        $transport = new FakeTransport(function (HttpRequest $r) use ($case, $then, &$tokenRequests): HttpResponse {
            if ($r->method === 'POST') {
                parse_str((string) $r->body, $form);
                $tokenRequests[] = ['endpoint' => $r->url, 'resource' => $form['resource'] ?? null];
                return $r->url === 'https://storage.example/as/token'
                    ? FakeTransport::response($r, 200, ['Content-Type' => 'application/json'], $case['tokenResponse']) : FakeTransport::response($r, 404);
            }
            if ($this->later && in_array($r->url, array_column($then, 'request'), true)) {
                return FakeTransport::response($r, 200, ['Content-Type' => 'text/plain'], 'ok');
            }
            if ($r->url === $case['request']) {
                return $r->headers->first('authorization') === 'Bearer token-1'
                    ? FakeTransport::response($r, 200, ['Content-Type' => 'text/plain'], 'ok') : FakeTransport::response($r, 401, $case['challenge']);
            }
            $document = $case['documents'][$r->url] ?? null;
            return $document === null ? FakeTransport::response($r, 404) : FakeTransport::response($r, $document['status'], $document['headers'], $document['body']);
        });
        $auth = new TokenExchangeAuthenticator(SelfSignedCredentials::didKey(SigningKey::generateP256()), transport: $transport);
        $client = new LwsClient(authenticator: $auth, transport: $transport);
        try {
            self::assertSame('ok', $client->read($case['request'])->body);
            $outcome = 'ok';
        } catch (AuthenticationException) {
            $outcome = 'AuthenticationError';
        } catch (UnauthorizedException) {
            $outcome = 'UnauthorizedError';
        }
        self::assertSame($expected['outcome'], $outcome);
        self::assertSame($expected['tokenRequest'] === null ? [] : [$expected['tokenRequest']], $tokenRequests);
        $fetched = array_map(static fn (HttpRequest $r): string => $r->url, $transport->requests);
        foreach ($expected['notFetched'] as $url) {
            self::assertNotContains($url, $fetched);
        }
        $this->later = true;
        foreach ($then as $t) {
            $transport->requests = [];
            self::assertSame('ok', $client->read($t['request'])->body);
            self::assertCount(1, $transport->requests);
            self::assertSame($t['sendsToken'] ? 'Bearer token-1' : null, $transport->last()->headers->first('authorization'), $t['request']);
        }
    }

    public function testAUrlOutsideTheScopeGetsTheTokenAfterItsOwn401(): void
    {
        // The storage /storage_1 with its root /storage_1/, and service endpoints outside both on the same origin.
        $this->override = function (HttpRequest $r): ?HttpResponse {
            $auth = $r->headers->first('authorization');
            if ($r->url === self::STORAGE . 'storage_1' && $auth === null) {
                return FakeTransport::response($r, 200, ['Content-Type' => 'application/lws+cid'], self::description(self::STORAGE . 'storage_1', self::STORAGE . 'storage_1/'));
            }
            if (!str_starts_with($r->url, self::STORAGE . 'services/')) {
                return null;
            }
            return $auth === null ? $this->challenge($r, self::STORAGE . 'storage_1') : FakeTransport::response($r, 200, [], $auth);
        };
        $client = $this->client();
        self::assertSame('Bearer tok-1', $client->read(self::STORAGE . 'services/inbox')->body);
        // Another URL outside the scope: no token up front; its 401 passes the checks and reuses the cached token.
        self::assertSame('Bearer tok-1', $client->read(self::STORAGE . 'services/other')->body);
        self::assertCount(1, $this->exchanges);
        $other = array_filter($this->transport->requests, static fn (HttpRequest $r): bool => $r->url === self::STORAGE . 'services/other');
        self::assertSame([null, 'Bearer tok-1'], array_values(array_map(static fn (HttpRequest $r): ?string => $r->headers->first('authorization'), $other)));
    }

    public function testPostBodyIsReplayedOnceAfterThe401(): void
    {
        $client = $this->client();
        $created = $client->createText(self::STORAGE . 'c/', 'Hello');
        self::assertSame(self::STORAGE . 'c/new', $created->location);
        $posts = array_values(array_filter($this->transport->requests, static fn (HttpRequest $r): bool => $r->url === self::STORAGE . 'c/'));
        self::assertCount(2, $posts);
        self::assertSame(['Hello', 'Hello'], [$posts[0]->body, $posts[1]->body]);
    }

    public function testInvalidTokenIsDroppedAndExchangedAgainOnce(): void
    {
        $client = $this->client();
        $client->read(self::STORAGE . 'a');
        $this->valid = [];   // the storage forgets the token
        $client->read(self::STORAGE . 'a');
        self::assertCount(2, $this->exchanges);
        self::assertSame('Bearer tok-2', $this->transport->last()->headers->first('authorization'));
        // A storage that refuses every token: one retry, then the 401 surfaces.
        $this->override = fn (HttpRequest $r): ?HttpResponse => $r->url === self::STORAGE . 'a' ? $this->challenge($r) : null;
        try {
            $client->read(self::STORAGE . 'a');
            self::fail('No 401');
        } catch (UnauthorizedException $e) {
            self::assertSame(self::PRM . 'a', $e->challenges()[0]->resourceMetadata());
            self::assertCount(3, $this->exchanges);
        }
    }

    public function testTokensAreRefreshedBeforeTheyExpire(): void
    {
        $client = $this->client();
        $client->read(self::STORAGE . 'a');
        $this->now += 3600 - 31;
        $client->read(self::STORAGE . 'a');
        self::assertCount(1, $this->exchanges);
        $this->now += 2;   // inside the 30 s refresh margin: not sent, so the storage challenges and the client exchanges anew
        $client->read(self::STORAGE . 'a');
        self::assertCount(2, $this->exchanges);
    }

    public function testTheChallengeOfEarlierDrafts(): void
    {
        // as_uri and realm, without resource_metadata: the realm is the token's resource and its one scope.
        $this->legacy = true;
        $this->challengeRealm = self::STORAGE . 'alice/';
        $this->override = function (HttpRequest $r): ?HttpResponse {
            $auth = $r->headers->first('authorization');
            return str_starts_with($r->url, self::STORAGE . 'alice/') && $auth !== null && $auth === 'Bearer ' . ($this->valid[self::STORAGE . 'alice/'] ?? '')
                ? FakeTransport::response($r, 200, [], 'alice') : null;
        };
        $client = $this->client();
        self::assertSame('alice', $client->read(self::STORAGE . 'alice/notes')->body);
        self::assertSame([
            'GET https://storage.example/alice/notes',
            'GET https://as.example/.well-known/lws-configuration',
            'POST https://as.example/token',
            'GET https://storage.example/alice/notes',
        ], $this->transport->log());
        self::assertSame(self::STORAGE . 'alice/', $this->exchanges[0]['resource']);
        $client->read(self::STORAGE . 'alice/x');
        self::assertSame('Bearer tok-1', $this->transport->last()->headers->first('authorization'));
        try {
            $client->read(self::STORAGE . 'bob/x');
            self::fail('Followed a realm that does not contain the request');
        } catch (AuthenticationException) {
            self::assertNull($this->transport->last()->headers->first('authorization'), 'no token outside the realm');
        }
    }

    public function testRealmMustContainTheRequest(): void
    {
        $client = $this->client();
        $this->legacy = true;
        $this->challengeRealm = self::STORAGE . 'alice/';
        try {
            $client->read(self::STORAGE . 'bob/x');
            self::fail('Accepted a realm that does not contain the request');
        } catch (AuthenticationException $e) {
            self::assertStringContainsString('not within the challenge realm', $e->getMessage());
        }
        self::assertSame(['GET https://storage.example/bob/x'], $this->transport->log(), 'nothing is sent to the authorization server');
    }

    public function testADecoyChallengeDoesNotEvictAWorkingToken(): void
    {
        $client = $this->client();
        $client->read(self::STORAGE . 'a');
        $decoys = [
            // A link to a storage whose root is on another origin.
            fn (HttpRequest $r): HttpResponse => $this->challenge($r, self::STORAGE . 'vault/'),
            // Metadata on another origin.
            static fn (HttpRequest $r): HttpResponse => FakeTransport::response($r, 401, ['WWW-Authenticate' => 'Bearer resource_metadata="https://evil.example/md"',
                'Link' => '<https://storage.example/>; rel="https://www.w3.org/ns/lws#storage"']),
            // Metadata for another resource.
            static fn (HttpRequest $r): HttpResponse => FakeTransport::response($r, 401, ['WWW-Authenticate' => 'Bearer resource_metadata="' . self::PRM . 'a"',
                'Link' => '<https://storage.example/>; rel="https://www.w3.org/ns/lws#storage"']),
            // A realm of the drafts before 19 October 2026 that does not contain the resource.
            static fn (HttpRequest $r): HttpResponse => FakeTransport::response($r, 401, ['WWW-Authenticate' => 'Bearer as_uri="https://evil.example", realm="https://evil.example/"']),
        ];
        foreach ($decoys as $decoy) {
            $this->override = static fn (HttpRequest $r): ?HttpResponse => match ($r->url) {
                self::STORAGE . 'decoy' => $decoy($r),
                self::STORAGE . 'vault/' => FakeTransport::response($r, 200, ['Content-Type' => 'application/lws+cid'], self::description(self::STORAGE . 'vault/', 'https://evil.example/vault/')),
                default => null,
            };
            try {
                $client->read(self::STORAGE . 'decoy');
                self::fail('Followed a decoy challenge');
            } catch (AuthenticationException) {
                self::addToAssertionCount(1);
            }
            $client->read(self::STORAGE . 'a');
            self::assertSame('Bearer tok-1', $this->transport->last()->headers->first('authorization'));
            self::assertCount(1, $this->exchanges);
        }
        self::assertNotContains('https://evil.example/md', array_map(static fn (HttpRequest $r): string => $r->url, $this->transport->requests));
    }

    public function testAuthorizationServerMustUseHttps(): void
    {
        $this->asUri = 'http://as.example';
        try {
            $this->client()->read(self::STORAGE . 'a');
            self::fail('Used an insecure authorization server');
        } catch (AuthenticationException $e) {
            self::assertStringContainsString('insecure', $e->getMessage());
        }
        // allowInsecureHttp, and loopback hosts, may use http (the metadata then fails here, past the check).
        foreach ([[true, 'http://as.example'], [false, 'http://127.0.0.1:9']] as [$allow, $as]) {
            $this->asUri = $as;
            try {
                $this->client(allowInsecureHttp: $allow)->read(self::STORAGE . 'a');
                self::fail('No failure');
            } catch (AuthenticationException $e) {
                self::assertStringNotContainsString('insecure', $e->getMessage());
                self::assertStringContainsString('lws-configuration', (string) $this->transport->last()->url);
            }
        }
        // The first usable authorization server of the metadata is the issuer.
        $this->asUri = self::AS;
        $this->authorizationServers = ['http://as.example', 'as.example', self::AS];
        self::assertSame('secret', $this->client()->read(self::STORAGE . 'a')->body);
        $this->authorizationServers = null;
        // The challenge of earlier drafts.
        $this->legacy = true;
        $this->asUri = 'http://as.example';
        try {
            $this->client()->read(self::STORAGE . 'a');
            self::fail('Used an insecure authorization server');
        } catch (AuthenticationException $e) {
            self::assertStringContainsString('insecure', $e->getMessage());
            self::assertCount(1, $this->transport->requests);
        }
        // An https issuer with an http token endpoint.
        $this->legacy = false;
        $this->asUri = self::AS;
        $this->metadata['token_endpoint'] = 'http://as.example/token';
        $this->expectException(AuthenticationException::class);
        $this->client()->read(self::STORAGE . 'a');
    }

    public function testAuthorizationServerFilter(): void
    {
        $seen = [];
        $client = $this->client(filter: static function (string $issuer, string $storage) use (&$seen): bool {
            $seen[] = [$issuer, $storage];
            return $issuer === 'https://trusted.example';
        });
        try {
            $client->read(self::STORAGE . 'a');
            self::fail('The filter was ignored');
        } catch (AuthenticationException $e) {
            self::assertSame([[self::AS, self::STORAGE]], $seen);
            self::assertStringContainsString('rejected by the authorization server filter', $e->getMessage());
            self::assertSame([], array_filter($this->transport->requests, static fn (HttpRequest $r): bool => str_starts_with($r->url, self::AS)),
                'nothing is sent to the authorization server');
        }
    }

    public function testMetadataAndTokenRequestsNeverFollowRedirects(): void
    {
        $this->override = static fn (HttpRequest $r): ?HttpResponse => $r->url === self::AS . '/.well-known/lws-configuration'
            ? FakeTransport::response($r, 302, ['Location' => 'https://evil.example/md']) : null;
        try {
            $this->client()->read(self::STORAGE . 'a');
            self::fail('Followed a metadata redirect');
        } catch (AuthenticationException $e) {
            self::assertSame(302, $e->status);
            self::assertStringContainsString('Refusing the redirect to https://evil.example/md', $e->getMessage());
        }
        self::assertSame([], $this->exchanges);
        $this->override = static fn (HttpRequest $r): ?HttpResponse => $r->url === self::AS . '/token'
            ? FakeTransport::response($r, 307, ['Location' => 'https://evil.example/token']) : null;
        try {
            $this->client()->read(self::STORAGE . 'a');
            self::fail('Followed a token redirect');
        } catch (AuthenticationException $e) {
            self::assertSame(307, $e->status);
        }
        self::assertNotContains('https://evil.example/token', array_map(static fn (HttpRequest $r): string => $r->url, $this->transport->requests));
        // A transport that answers from another URL than the one requested has followed a redirect.
        $this->override = static fn (HttpRequest $r): ?HttpResponse => $r->url === self::AS . '/.well-known/lws-configuration'
            ? new HttpResponse('https://evil.example/md', 200) : null;
        $this->expectException(AuthenticationException::class);
        $this->client()->read(self::STORAGE . 'a');
    }

    public function testMetadataProblems(): void
    {
        foreach ([
            ['issuer' => 'https://other.example', 'token_endpoint' => self::AS . '/token'],
            ['token_endpoint' => self::AS . '/token'],
            ['issuer' => self::AS],
            ['issuer' => self::AS, 'token_endpoint' => self::AS . '/token', 'subject_token_types_supported' => [TokenType::SAML2]],
        ] as $md) {
            $this->metadata = $md;
            try {
                $this->client()->read(self::STORAGE . 'a');
                self::fail('Accepted metadata ' . json_encode($md));
            } catch (AuthenticationException) {
                self::assertSame([], $this->exchanges);
            }
        }
        // The issuer may differ by one trailing slash.
        $this->metadata = ['issuer' => self::AS . '/', 'token_endpoint' => '/token'];
        self::assertSame('secret', $this->client()->read(self::STORAGE . 'a')->body);
    }

    public function testTokenEndpointErrors(): void
    {
        $this->override = static fn (HttpRequest $r): ?HttpResponse => $r->url === self::AS . '/token'
            ? FakeTransport::response($r, 400, ['Content-Type' => 'application/json'], ['error' => 'invalid_grant', 'error_description' => 'bad signature']) : null;
        try {
            $this->client()->read(self::STORAGE . 'a');
            self::fail('No error');
        } catch (AuthenticationException $e) {
            self::assertSame(['invalid_grant', 'bad signature', 400], [$e->oauthError, $e->oauthErrorDescription, $e->status]);
        }
        foreach ([['access_token' => 't', 'token_type' => 'DPoP'], ['token_type' => 'Bearer'], 'not json'] as $body) {
            $this->override = static fn (HttpRequest $r): ?HttpResponse => $r->url === self::AS . '/token'
                ? FakeTransport::response($r, 200, ['Content-Type' => 'application/json'], $body) : null;
            try {
                $this->client()->read(self::STORAGE . 'a');
                self::fail('Accepted ' . json_encode($body));
            } catch (AuthenticationException $e) {
                self::assertSame(200, $e->status);
            }
        }
    }

    public function testNoUsableChallengeSurfacesThe401(): void
    {
        $this->override = static fn (HttpRequest $r): HttpResponse => FakeTransport::response($r, 401, ['WWW-Authenticate' => 'Bearer realm="x", DPoP algs="ES256"']);
        try {
            $this->client()->read(self::STORAGE . 'a');
            self::fail('No 401');
        } catch (UnauthorizedException $e) {
            self::assertCount(2, $e->challenges());
            self::assertCount(1, $this->transport->requests);
        }
    }

    public function testRedirectHopsAreAuthorizedForTheirOwnUrl(): void
    {
        $client = $this->client();
        $client->read(self::STORAGE . 'a');
        $this->override = static fn (HttpRequest $r): ?HttpResponse => $r->url === self::STORAGE . 'moved'
            ? FakeTransport::response($r, 302, ['Location' => 'https://other.example/landing']) : null;
        self::assertSame('anonymous', $client->read(self::STORAGE . 'moved')->body);
        $requests = $this->transport->requests;
        self::assertSame('Bearer tok-1', $requests[count($requests) - 2]->headers->first('authorization'));
    }

    public function testBearerTokenAuthenticator(): void
    {
        $t = new FakeTransport(static fn (HttpRequest $r): HttpResponse => FakeTransport::response($r, 200, [], (string) ($r->headers->first('authorization') ?? '-')));
        $client = new LwsClient(authenticator: new BearerTokenAuthenticator('abc', realm: self::STORAGE . 'alice/'), transport: $t);
        self::assertSame('Bearer abc', $client->read(self::STORAGE . 'alice/x')->body);
        self::assertSame('-', $client->read(self::STORAGE . 'bob/x')->body);
        $n = 0;
        $supplier = static function () use (&$n): ?string {
            $n++;
            return $n === 1 ? null : "t$n";
        };
        $dynamic = new LwsClient(authenticator: new BearerTokenAuthenticator($supplier), transport: $t);
        self::assertSame(['-', 'Bearer t2'], [$dynamic->read(self::STORAGE)->body, $dynamic->read(self::STORAGE)->body]);
        self::assertStringNotContainsString('abc', print_r(new BearerTokenAuthenticator('abc'), true));
    }

    public function testOpenIdAndSamlCredentials(): void
    {
        $this->client();   // sets up the transport (the storage and the authorization server)
        $seen = null;
        $openid = new OpenIdCredentials(static function (CredentialContext $c) use (&$seen): string {
            $seen = [$c->issuer, $c->storage, $c->metadata->issuer];
            return 'id.token.here';
        });
        $client = new LwsClient(authenticator: new TokenExchangeAuthenticator($openid, transport: $this->transport), transport: $this->transport);
        $client->read(self::STORAGE . 'a');
        self::assertSame([self::AS, self::STORAGE, self::AS], $seen);
        self::assertSame(['id.token.here', TokenType::ID_TOKEN], [$this->exchanges[0]['subject_token'], $this->exchanges[0]['subject_token_type']]);
        $saml = SamlCredentials::fromXml('<saml:Assertion>é</saml:Assertion>');
        self::assertSame(TokenType::SAML2, $saml->tokenType());
        $client = new LwsClient(authenticator: new TokenExchangeAuthenticator($saml, transport: $this->transport), transport: $this->transport);
        $this->valid = [];
        $client->read(self::STORAGE . 'a');
        self::assertSame(rtrim(strtr(base64_encode('<saml:Assertion>é</saml:Assertion>'), '+/', '-_'), '='), $this->exchanges[1]['subject_token']);
        self::assertSame(TokenType::SAML2, $this->exchanges[1]['subject_token_type']);
        self::assertSame('abc', SamlCredentials::fromEncoded('abc')->subjectToken(new CredentialContext(self::AS, self::STORAGE,
            new \Ebremer\Lws\Auth\AuthorizationServerMetadata(self::AS, self::AS . '/token'))));
    }

    public function testSelfSignedCredentialsCacheAndOptions(): void
    {
        $now = 1_800_000_000.0;
        $key = SigningKey::generateEd25519();
        $creds = SelfSignedCredentials::forAgent('https://id.example/alice', $key, 'https://id.example/alice#key-1')
            ->withLifetime(120)->withClock(static function () use (&$now): float {
                return $now;
            });
        $context = static fn (string $issuer): CredentialContext => new CredentialContext($issuer, self::STORAGE,
            new \Ebremer\Lws\Auth\AuthorizationServerMetadata($issuer, $issuer . '/token'));
        $a = $creds->subjectToken($context(self::AS));
        self::assertSame($a, $creds->subjectToken($context(self::AS)), 'reused for the same audience');
        self::assertNotSame($a, $creds->subjectToken($context('https://as2.example')));
        $now += 61;   // 120 s lifetime, reused until 60 s before expiry
        self::assertNotSame($a, $creds->subjectToken($context(self::AS)));
        $header = Jwt::decodeHeader($a);
        $claims = Jwt::decodeClaims($a);
        self::assertSame(['EdDSA', 'https://id.example/alice#key-1'], [$header['alg'], $header['kid']]);
        self::assertSame(['https://id.example/alice', 120], [$claims['sub'], $claims['exp'] - $claims['iat']]);
        self::assertTrue(Jwt::verify($a, $creds->publicKey()));
        self::assertSame('EdDSA', $creds->algorithm());
        self::assertSame(TokenType::JWT, $creds->tokenType());
        self::assertStringNotContainsString($key->jwk()['d'], print_r($creds, true));
        $this->expectException(\InvalidArgumentException::class);
        SelfSignedCredentials::didKey(SigningKey::generate('ES384'));
    }
}
