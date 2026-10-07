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
use Ebremer\Lws\TokenType;
use PHPUnit\Framework\TestCase;

/**
 * The LWS authorization flow against a fake storage and authorization server: `401 → metadata → token exchange
 * → retry`, proactive reuse, refresh, and every check that keeps credentials from the wrong servers.
 */
final class AuthFlowTest extends TestCase
{
    private const STORAGE = 'https://storage.example/';
    private const AS = 'https://as.example';

    /** @var list<array<string, string>> token requests received */
    private array $exchanges = [];
    private int $issued = 0;
    /** @var array<string, string> the token each realm accepts */
    private array $valid = [];
    private float $now = 1_800_000_000.0;
    /** @var array<string, mixed> */
    private array $metadata = [];
    private string $challengeRealm = self::STORAGE;
    private string $asUri = self::AS;
    private FakeTransport $transport;
    private TokenExchangeAuthenticator $auth;
    /** @var \Closure(HttpRequest): ?HttpResponse|null */
    private ?\Closure $override = null;

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
        $expected = $this->valid[self::STORAGE] ?? null;
        if ($expected !== null && $r->headers->first('authorization') === "Bearer $expected") {
            return FakeTransport::response($r, $r->method === 'POST' ? 201 : 200, $r->method === 'POST' ? ['Location' => '/c/new'] : [], 'secret');
        }
        return FakeTransport::response($r, 401, ['WWW-Authenticate' => "Bearer as_uri=\"{$this->asUri}\", realm=\"{$this->challengeRealm}\", error=\"invalid_token\""]);
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
            'GET https://as.example/.well-known/lws-configuration',
            'POST https://as.example/token',
            'GET https://storage.example/notes/a.txt',
        ], $this->transport->log());
        [$form] = $this->exchanges;
        self::assertSame(['urn:ietf:params:oauth:grant-type:token-exchange', self::STORAGE, TokenType::JWT],
            [$form['grant_type'], $form['resource'], $form['subject_token_type']]);
        $requests = $this->transport->requests;
        self::assertSame('application/x-www-form-urlencoded', $requests[2]->headers->first('content-type'));
        self::assertSame('Bearer tok-1', $requests[3]->headers->first('authorization'));
        // The subject token: a self-signed JWT for the authorization server.
        $jwt = $form['subject_token'];
        self::assertTrue(Jwt::verify($jwt, $key->publicKey));
        $claims = Jwt::decodeClaims($jwt);
        $did = DidKey::did($key->publicKey);
        self::assertSame([$did, $did, $did, [self::AS]], [$claims['sub'], $claims['iss'], $claims['client_id'], $claims['aud']]);
        self::assertSame(300, $claims['exp'] - $claims['iat']);
        self::assertSame(['ES256', 'JWT', DidKey::keyId($key->publicKey)], array_values(Jwt::decodeHeader($jwt)));
        self::assertMatchesRegularExpression('/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/', $claims['jti']);
        // Proactive: the next request inside the realm carries the token at once; the metadata is cached.
        $this->transport->requests = [];
        $client->read(self::STORAGE . 'other/b.txt');
        self::assertSame(['GET https://storage.example/other/b.txt'], $this->transport->log());
        self::assertSame('Bearer tok-1', $this->transport->last()->headers->first('authorization'));
        self::assertSame('tok-1', $this->auth->accessToken(self::AS, self::STORAGE)->value);
        // Never outside the realm.
        self::assertSame('anonymous', $client->read('https://other.example/x')->body);
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
        $this->override = static fn (HttpRequest $r): ?HttpResponse => str_starts_with($r->url, self::STORAGE)
            ? FakeTransport::response($r, 401, ['WWW-Authenticate' => 'Bearer as_uri="https://as.example", realm="https://storage.example/"']) : null;
        try {
            $client->read(self::STORAGE . 'a');
            self::fail('No 401');
        } catch (UnauthorizedException $e) {
            self::assertSame('https://as.example', $e->challenges()[0]->asUri());
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

    public function testRealmMustContainTheRequest(): void
    {
        $client = $this->client();
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
        // A resource whose 401 names a realm that does not contain it.
        $this->override = static fn (HttpRequest $r): ?HttpResponse => $r->url === self::STORAGE . 'decoy'
            ? FakeTransport::response($r, 401, ['WWW-Authenticate' => 'Bearer as_uri="https://evil.example", realm="https://evil.example/"']) : null;
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
        // An https issuer with an http token endpoint.
        $this->asUri = self::AS;
        $this->metadata['token_endpoint'] = 'http://as.example/token';
        $this->expectException(AuthenticationException::class);
        $this->client()->read(self::STORAGE . 'a');
    }

    public function testAuthorizationServerFilter(): void
    {
        $seen = [];
        $client = $this->client(filter: static function (string $as, string $realm) use (&$seen): bool {
            $seen = [$as, $realm];
            return false;
        });
        try {
            $client->read(self::STORAGE . 'a');
            self::fail('The filter was ignored');
        } catch (AuthenticationException) {
            self::assertSame([self::AS, self::STORAGE], $seen);
            self::assertCount(1, $this->transport->requests);
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
            $seen = [$c->issuer, $c->realm, $c->metadata->issuer];
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
