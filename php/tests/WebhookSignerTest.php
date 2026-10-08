<?php
// SPDX-License-Identifier: MIT
declare(strict_types=1);

namespace Ebremer\Lws\Tests;

use Ebremer\Lws\Auth\SigningKey;
use Ebremer\Lws\Exception\SignatureVerificationException;
use Ebremer\Lws\Json\Json;
use Ebremer\Lws\Model\StorageDescription;
use Ebremer\Lws\Notification\WebhookSigner;
use Ebremer\Lws\Notification\WebhookVerifier;
use Ebremer\Lws\Tests\Support\Fixtures;
use PHPUnit\Framework\TestCase;

/** Signing webhook deliveries, checked against the RFC 9421 vectors and the verifier. */
final class WebhookSignerTest extends TestCase
{
    private static function description(): StorageDescription
    {
        return StorageDescription::parse(Json::decode(Fixtures::text('webhook/storage-description.json')), 'https://storage.example/');
    }

    /** @param array<string, mixed> $v */
    private static function verifier(array $v, ?StorageDescription $description = null): WebhookVerifier
    {
        $description ??= self::description();
        return new WebhookVerifier(
            storageDescriptionResolver: static fn (): StorageDescription => $description,
            clock: static fn (): int => $v['now'],
        );
    }

    public function testEd25519VectorIsReproduced(): void
    {
        // Ed25519 signatures are deterministic, so the vector comes out byte for byte.
        $v = Fixtures::load('webhook/ed25519-valid.json');
        $key = SigningKey::fromJwk(Fixtures::load('keys/ed25519.json')['privateJwk']);
        $signer = new WebhookSigner($key, 'https://storage.example/#key-ed25519', 'sha-512');
        self::assertSame('ed25519', $signer->algorithm);
        self::assertSame($v['headers'], $signer->sign($v['url'], $v['body'], created: 1790000000));
    }

    public function testP256SignatureVerifies(): void
    {
        $v = Fixtures::load('webhook/p256-valid.json');
        $key = SigningKey::fromJwk(Fixtures::load('keys/p256.json')['privateJwk']);
        $signer = new WebhookSigner($key, 'https://storage.example/#key-p256', clock: static fn (): int => 1790000000);
        $headers = $signer->sign($v['url'], $v['body']);
        // Everything but the (randomized) ECDSA signature is the vector's.
        self::assertSame(array_diff_key($v['headers'], ['signature' => true]), array_diff_key($headers, ['signature' => true]));
        $verified = self::verifier($v)->verify('POST', $v['url'], $headers, $v['body']);
        self::assertSame('https://storage.example/#key-p256', $verified->keyId);
        self::assertSame('ecdsa-p256-sha256', $verified->algorithm);
        self::assertSame('sig1', $verified->label);
    }

    public function testP384SignatureVerifies(): void
    {
        $key = SigningKey::generate('ES384');
        $doc = Fixtures::load('webhook/storage-description.json');
        $doc['verificationMethod'][] = [
            'id' => 'https://storage.example/#key-p384',
            'type' => 'JsonWebKey',
            'controller' => 'https://storage.example/',
            'publicKeyJwk' => $key->publicKey->jwk(),
        ];
        $doc['authentication'][] = 'https://storage.example/#key-p384';
        $description = StorageDescription::parse($doc, 'https://storage.example/');
        $v = Fixtures::load('webhook/p256-valid.json');
        $signer = new WebhookSigner($key, 'https://storage.example/#key-p384', label: 'lws');
        $headers = $signer->sign($v['url'], $v['body'], created: $v['now']);
        self::assertStringStartsWith('lws=(', $headers['signature-input']);
        self::assertStringContainsString(';alg="ecdsa-p384-sha384"', $headers['signature-input']);
        self::assertSame('ecdsa-p384-sha384', self::verifier($v, $description)->verify('POST', $v['url'], $headers, $v['body'])->algorithm);
    }

    public function testTamperingIsDetected(): void
    {
        $v = Fixtures::load('webhook/p256-valid.json');
        $key = SigningKey::fromJwk(Fixtures::load('keys/p256.json')['privateJwk']);
        $headers = (new WebhookSigner($key, 'https://storage.example/#key-p256'))->sign($v['url'], $v['body'], created: $v['now']);
        $verifier = self::verifier($v);
        foreach ([
            ['POST', $v['url'], $headers, $v['body'] . ' '],
            ['POST', 'https://elsewhere.example/hooks/lws', $headers, $v['body']],
            ['PUT', $v['url'], $headers, $v['body']],
            ['POST', $v['url'], ['content-type' => 'application/json'] + $headers, $v['body']],
        ] as [$method, $url, $h, $body]) {
            try {
                $verifier->verify($method, $url, $h, $body);
                self::fail('Verified a tampered delivery');
            } catch (SignatureVerificationException) {
                self::addToAssertionCount(1);
            }
        }
    }

    public function testContentDigest(): void
    {
        self::assertSame('sha-256=:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=:', WebhookSigner::contentDigest(''));
        $v = Fixtures::load('webhook/ed25519-valid.json');
        self::assertSame($v['headers']['content-digest'], WebhookSigner::contentDigest($v['body'], 'sha-512'));
        $this->expectException(\InvalidArgumentException::class);
        WebhookSigner::contentDigest('', 'md5');
    }

    public function testInvalidArgumentsAreRefused(): void
    {
        $key = SigningKey::generateP256();
        foreach ([
            static fn () => new WebhookSigner($key, 'https://storage.example/'),
            static fn () => new WebhookSigner($key, 'https://storage.example/#'),
            static fn () => new WebhookSigner($key, '/storage/#key'),
            static fn () => new WebhookSigner($key, 'urn:example:storage#key'),
            static fn () => new WebhookSigner($key, 'https://storage.example/#key', 'sha-1'),
            static fn () => new WebhookSigner($key, 'https://storage.example/#key', label: 'Sig'),
            static fn () => (new WebhookSigner($key, 'https://storage.example/#key'))->sign('/inbox', '{}'),
            static fn () => (new WebhookSigner($key, 'https://storage.example/#key'))->sign('https://app.example/inbox', '{}', "text/plain\n"),
        ] as $i => $make) {
            try {
                $make();
                self::fail("Case $i was accepted");
            } catch (\InvalidArgumentException) {
                self::addToAssertionCount(1);
            }
        }
    }
}
