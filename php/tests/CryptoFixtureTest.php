<?php
// SPDX-License-Identifier: MIT
declare(strict_types=1);

namespace Ebremer\Lws\Tests;

use Ebremer\Lws\Auth\ControlledIdentifierDocument;
use Ebremer\Lws\Auth\DidKey;
use Ebremer\Lws\Auth\Jwt;
use Ebremer\Lws\Auth\SigningKey;
use Ebremer\Lws\Auth\VerificationKey;
use Ebremer\Lws\Exception\SignatureVerificationException;
use Ebremer\Lws\Http\Headers;
use Ebremer\Lws\Http\SfInnerList;
use Ebremer\Lws\Http\StructuredFields;
use Ebremer\Lws\Json\Json;
use Ebremer\Lws\Model\StorageDescription;
use Ebremer\Lws\Notification\WebhookVerifier;
use Ebremer\Lws\Tests\Support\Fixtures;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/** The shared cryptographic fixtures: did:key, JWT credentials, test keys and the RFC 9421 webhook vectors. */
final class CryptoFixtureTest extends TestCase
{
    /** @return array<string, array{0: array<string, mixed>}> */
    public static function didKeyVectors(): array
    {
        return Fixtures::cases('did-key.json', 'vectors');
    }

    /** @param array<string, mixed> $v */
    #[DataProvider('didKeyVectors')]
    public function testDidKeyDerivation(array $v): void
    {
        $key = VerificationKey::fromJwk($v['publicJwk']);
        self::assertSame($v['did'], DidKey::did($key));
        self::assertSame($v['kid'], DidKey::keyId($key));
        self::assertSame($v['kid'], DidKey::keyIdForDid($v['did']));
        self::assertSame($v['did'], DidKey::didFromJwk($v['publicJwk']));
        self::assertTrue(DidKey::publicKey($v['kid'])->equals($key));
        self::assertEquals($v['publicJwk'], DidKey::publicKey($v['did'])->jwk());
    }

    public function testDidKeyErrorsAndBase58(): void
    {
        self::assertSame('', DidKey::encode(''));
        self::assertSame('11', DidKey::encode("\x00\x00"));
        self::assertSame("\x00\x00\x01\x02", DidKey::decode(DidKey::encode("\x00\x00\x01\x02")));
        self::assertNull(DidKey::decode('0OIl'));
        foreach (['did:web:x', 'did:key:z0', 'did:key:z' . DidKey::encode("\x12\x34abc")] as $bad) {
            try {
                DidKey::publicKey($bad);
                self::fail("Decoded $bad");
            } catch (\InvalidArgumentException) {
                self::addToAssertionCount(1);
            }
        }
        // A P-256 point that is not on the curve.
        try {
            DidKey::publicKey('did:key:z' . DidKey::encode("\x80\x24\x02" . str_repeat("\xff", 32)));
            self::fail('Decoded an invalid point');
        } catch (\InvalidArgumentException) {
            self::addToAssertionCount(1);
        }
        $this->expectException(\InvalidArgumentException::class);
        DidKey::did(SigningKey::generate('ES384')->publicKey);
    }

    /** @return array<string, array{0: array<string, mixed>}> */
    public static function jwtVectors(): array
    {
        return Fixtures::cases('jwt.json', 'vectors');
    }

    /** @param array<string, mixed> $v */
    #[DataProvider('jwtVectors')]
    public function testJwtCredentialsVerify(array $v): void
    {
        $key = VerificationKey::fromJwk($v['publicJwk']);
        $jwt = $v['jwt'];
        self::assertTrue(Jwt::verify($jwt, $key));
        self::assertEquals($v['header'], Jwt::decodeHeader($jwt));
        self::assertEquals($v['claims'], Jwt::decodeClaims($jwt));
        self::assertSame($v['claims']['exp'], Jwt::expiration($jwt)?->getTimestamp());
        $tampered = substr($jwt, 0, -4) . ($jwt[strlen($jwt) - 4] === 'A' ? 'B' : 'A') . substr($jwt, -3);
        self::assertFalse(Jwt::verify($tampered, $key));
        // The kid in the header is the did:key of the key, so the signing key is implied by the token.
        self::assertSame(DidKey::keyId($key), $v['header']['kid']);
        self::assertFalse(Jwt::verify('a.b', $key));
        self::assertNull(Jwt::expiration('not a jwt'));
    }

    /** @return array<string, array{0: string}> */
    public static function keyFiles(): array
    {
        return ['p256' => ['keys/p256.json'], 'ed25519' => ['keys/ed25519.json'], 'p256-unlisted' => ['keys/p256-unlisted.json']];
    }

    #[DataProvider('keyFiles')]
    public function testTestKeysImportAndSign(string $file): void
    {
        $f = Fixtures::load($file);
        $key = SigningKey::fromJwk($f['privateJwk']);
        self::assertEquals($f['publicJwk'], $key->publicKey->jwk());
        self::assertEquals($f['privateJwk'], $key->jwk());
        $signature = $key->sign('signature input');
        self::assertSame(64, strlen($signature));
        $public = VerificationKey::fromJwk($f['publicJwk']);
        self::assertTrue($public->verify($signature, 'signature input'));
        self::assertFalse($public->verify($signature, 'other input'));
        self::assertStringNotContainsString($f['privateJwk']['d'], print_r($key, true));
        $this->expectException(\InvalidArgumentException::class);
        SigningKey::fromJwk($f['publicJwk']);
    }

    public function testGeneratedKeysRoundTrip(): void
    {
        foreach ([SigningKey::generateP256(), SigningKey::generateEd25519(), SigningKey::generate('ES384')] as $key) {
            $again = SigningKey::fromJwk($key->jwk());
            self::assertTrue($again->publicKey->equals($key->publicKey));
            self::assertTrue($key->publicKey->verify($again->sign('x'), 'x'));
            self::assertSame($key->algorithm(), $again->algorithm());
        }
        self::assertSame(96, strlen(SigningKey::generate('ES384')->sign('x')));
        $mismatched = SigningKey::generateP256()->jwk();
        $mismatched['x'] = SigningKey::generateP256()->jwk()['x'];
        foreach ([
            static fn () => SigningKey::fromJwk($mismatched),
            static fn () => SigningKey::generate('RS256'),
            static fn () => VerificationKey::fromJwk(['kty' => 'RSA', 'crv' => 'x']),
            static fn () => VerificationKey::fromJwk(['kty' => 'EC', 'crv' => 'P-256', 'x' => 'AAAA', 'y' => 'AAAA']),
            static fn () => VerificationKey::fromJwk(['kty' => 'OKP', 'crv' => 'X25519', 'x' => 'AAAA']),
            static fn () => VerificationKey::fromJwk(['kty' => 'EC', 'crv' => 'P-256', 'x' => '!!', 'y' => 'AAAA']),
        ] as $bad) {
            try {
                $bad();
                self::fail('Accepted an invalid key');
            } catch (\InvalidArgumentException) {
                self::addToAssertionCount(1);
            }
        }
    }

    public function testControlledIdentifierDocument(): void
    {
        $key = SigningKey::generateEd25519();
        $doc = ControlledIdentifierDocument::create('https://id.example/alice', $key->jwk(), 'key-1');
        $method = $doc['authentication'][0];
        self::assertSame(['https://www.w3.org/ns/cid/v1'], $doc['@context']);
        self::assertSame('https://id.example/alice#key-1', $method['id']);
        self::assertSame('EdDSA', $method['publicKeyJwk']['alg']);
        self::assertArrayNotHasKey('d', $method['publicKeyJwk']);
        self::assertSame('did:key:z6Mk#z6Mk', ControlledIdentifierDocument::create('did:key:z6Mk', $key->publicKey, 'did:key:z6Mk#z6Mk')['authentication'][0]['id']);
    }

    /** @return array{0: array<string, mixed>, 1: Headers, 2: string, 3: StorageDescription} */
    private static function vector(string $file): array
    {
        $v = Fixtures::load('webhook/' . $file);
        $description = StorageDescription::parse(Json::decode(Fixtures::text('webhook/storage-description.json')), 'https://storage.example/');
        return [$v, new Headers($v['headers']), $v['body'], $description];
    }

    /** @return array<string, array{0: string}> */
    public static function webhookVectors(): array
    {
        $out = [];
        foreach (Fixtures::load('webhook/index.json')['vectors'] as $file) {
            $out[$file] = [$file];
        }
        return $out;
    }

    #[DataProvider('webhookVectors')]
    public function testWebhookVector(string $file): void
    {
        [$v, $headers, $body, $description] = self::vector($file);
        $fetches = new \ArrayObject();
        $verifier = new WebhookVerifier(
            storageDescriptionResolver: function (string $url) use ($description, $fetches): StorageDescription {
                $fetches->append($url);
                self::assertSame('https://storage.example/', $url);
                return $description;
            },
            clock: static fn (): int => $v['now'],
        );
        $expected = $v['expected'];
        if (isset($v['signatureBase'])) {
            $covered = StructuredFields::parseDictionary((string) $headers->first('signature-input'))['sig1'];
            self::assertInstanceOf(SfInnerList::class, $covered);
            self::assertSame($v['signatureBase'], WebhookVerifier::signatureBase($v['method'], $v['url'], $headers, $covered));
        }
        if (($expected['valid'] ?? false) !== true) {
            $this->expectException(SignatureVerificationException::class);
            $verifier->verify($v['method'], $v['url'], $headers, $body);
            return;
        }
        $verified = $verifier->verify($v['method'], $v['url'], $headers, $body);
        self::assertSame($expected['keyid'], $verified->keyId);
        self::assertSame('https://storage.example/', $verified->storage);
        $n = $expected['notification'];
        self::assertSame($n['storage'], $verified->notification->storage);
        self::assertCount(count($n['activities']), $verified->notification->activities);
        foreach ($n['activities'] as $i => $x) {
            $a = $verified->notification->activities[$i];
            self::assertSame($x['types'], $a->types);
            self::assertSame($x['objectId'], $a->object->id);
            self::assertSame($x['target'] ?? null, $a->target);
        }
        self::assertCount(1, $fetches);
        // The description is cached: a second delivery does not fetch it again.
        $verifier->verify($v['method'], $v['url'], $headers, $body);
        self::assertCount(1, $fetches);
    }

    public function testWebhookTrustedStoragesAreEnforcedEvenWhenEmpty(): void
    {
        [$v, $headers, $body, $description] = self::vector('p256-valid.json');
        $make = static fn (string ...$trusted): WebhookVerifier => new WebhookVerifier(
            storageDescriptionResolver: static fn (): StorageDescription => $description, trustedStorages: array_values($trusted), clock: static fn (): int => $v['now']);
        foreach ([[], ['https://other.example/']] as $trusted) {
            try {
                $make(...$trusted)->verify('POST', $v['url'], $headers, $body);
                self::fail('Accepted an untrusted storage');
            } catch (SignatureVerificationException) {
                self::addToAssertionCount(1);
            }
        }
        // Compared as URLs: case and the default port do not matter.
        self::assertSame('https://storage.example/', $make('HTTPS://Storage.Example:443/')->verify('POST', $v['url'], $headers, $body)->storage);
        $any = new WebhookVerifier(storageDescriptionResolver: static fn (): StorageDescription => $description, clock: static fn (): int => $v['now']);
        self::assertSame('ecdsa-p256-sha256', $any->verify('POST', $v['url'], $headers->toList(), $body)->algorithm);
    }

    public function testWebhookKeyRotationRefetchesOnce(): void
    {
        [$v, $headers, $body, $current] = self::vector('p256-valid.json');
        // A stale description whose key is the unlisted key (as if the storage rotated keys since).
        $doc = Fixtures::load('webhook/storage-description.json');
        $doc['verificationMethod'][0]['publicKeyJwk'] = Fixtures::load('keys/p256-unlisted.json')['publicJwk'];
        $stale = StorageDescription::parse($doc, 'https://storage.example/');
        $fetches = 0;
        $answers = [$stale, $current];
        $verifier = new WebhookVerifier(storageDescriptionResolver: function () use (&$fetches, $answers): StorageDescription {
            return $answers[$fetches++];
        }, clock: static fn (): int => $v['now']);
        // The first fetch is stale and was not cached before: the failure is final.
        try {
            $verifier->verify('POST', $v['url'], $headers, $body);
            self::fail('Verified with a stale key');
        } catch (SignatureVerificationException) {
            self::assertSame(1, $fetches);
        }
        // Now the stale description is cached: verification fails with it, refetches once and succeeds.
        $verifier->verify('POST', $v['url'], $headers, $body);
        self::assertSame(2, $fetches);
    }

    public function testWebhookVerifierRejectsBadInput(): void
    {
        [$v, $headers, $body, $description] = self::vector('p256-valid.json');
        $verifier = new WebhookVerifier(storageDescriptionResolver: static fn (): StorageDescription => $description, clock: static fn (): int => $v['now']);
        foreach ([
            [$headers->without('content-digest'), $body],
            [$headers->without('signature'), $body],
            [$headers->with('signature-input', 'sig1=('), $body],
            [$headers->with('content-digest', 'md5=:AAAA:'), $body],
            [$headers, $body . ' '],
        ] as [$h, $b]) {
            try {
                $verifier->verify('POST', $v['url'], $h, $b);
                self::fail('Verified an invalid delivery');
            } catch (SignatureVerificationException) {
                self::addToAssertionCount(1);
            }
        }
        // A different inbox URL changes the signature base.
        try {
            $verifier->verify('POST', 'https://elsewhere.example/inbox', $headers, $body);
            self::fail('Verified for another inbox');
        } catch (SignatureVerificationException) {
            self::addToAssertionCount(1);
        }
        $this->expectException(\InvalidArgumentException::class);
        $verifier->verify('POST', '/inbox', $headers, $body);
    }

    public function testHeadersFromServerVariables(): void
    {
        [$v, $headers, $body, $description] = self::vector('p256-valid.json');
        $server = ['REQUEST_METHOD' => 'POST', 'HTTP_HOST' => 'x', 'argv' => [], 'CONTENT_TYPE' => (string) $headers->first('content-type')];
        foreach ($headers->toList() as [$name, $value]) {
            $server['HTTP_' . strtoupper(str_replace('-', '_', $name))] = $value;
        }
        $fields = WebhookVerifier::headersFromServer($server);
        self::assertCount(1, array_filter($fields, static fn (array $f): bool => $f[0] === 'content-type'));
        $verifier = new WebhookVerifier(storageDescriptionResolver: static fn (): StorageDescription => $description, clock: static fn (): int => $v['now']);
        self::assertSame($v['expected']['keyid'], $verifier->verify('POST', $v['url'], $fields, $body)->keyId);
    }
}
