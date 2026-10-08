<?php
// SPDX-License-Identifier: MIT
declare(strict_types=1);

namespace Ebremer\Lws\Tests;

use Ebremer\Lws\Auth\Jwt;
use Ebremer\Lws\Auth\SigningKey;
use Ebremer\Lws\Auth\VerificationKey;
use Ebremer\Lws\Internal\Base64Url;
use Ebremer\Lws\Internal\Rsa;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * RSA verification: RS256/384/512 and PS256/384/512.
 *
 * The vectors are RFC 7515 A.2 (RS256) and RFC 7520 §4.2 (PS384), and signatures made with OpenSSL and Python's
 * cryptography, including PSS with 2057- and 2052-bit moduli, whose encoded messages are a byte shorter than the
 * modulus or have unused top bits. They are PHP's own, not in conformance/fixtures, which every language reads.
 */
final class RsaVerificationTest extends TestCase
{
    /** @return array<string, array{0: array{jwk: array<string, string>, alg: string, jws: string}}> */
    public static function vectors(): array
    {
        /** @var array<string, array{jwk: array<string, string>, alg: string, jws: string}> $vectors */
        $vectors = json_decode((string) file_get_contents(__DIR__ . '/Support/rsa-jws.json'), true, 512, JSON_THROW_ON_ERROR);
        return array_map(static fn (array $v): array => [$v], $vectors);
    }

    /** @param array{jwk: array<string, string>, alg: string, jws: string} $v */
    #[DataProvider('vectors')]
    public function testVerifies(array $v): void
    {
        $key = VerificationKey::fromJwk($v['jwk']);
        self::assertSame('RSA', $key->keyType());
        self::assertTrue($key->supports($v['alg']));
        self::assertTrue(Jwt::verify($v['jws'], $key), $v['alg']);
        // Bound to its algorithm: the same key and signature under another hash or padding fail.
        [$header, $payload, $signature] = explode('.', $v['jws']);
        foreach (array_keys(Rsa::ALGORITHMS) as $other) {
            if ($other !== $v['alg']) {
                $relabelled = Base64Url::encode((string) json_encode(['alg' => $other])) . '.' . $payload . '.' . $signature;
                self::assertFalse(Jwt::verify($relabelled, $key), "$other accepted a {$v['alg']} signature");
            }
        }
        // Any altered byte fails.
        $bytes = (string) Base64Url::decode($signature);
        foreach ([0, intdiv(strlen($bytes), 2), strlen($bytes) - 1] as $i) {
            $altered = $bytes;
            $altered[$i] = chr(ord($altered[$i]) ^ 0x01);
            self::assertFalse(Jwt::verify("$header.$payload." . Base64Url::encode($altered), $key));
        }
        self::assertFalse(Jwt::verify("$header.$payload." . Base64Url::encode(substr($bytes, 1)), $key));
        self::assertFalse(Jwt::verify("$header." . Base64Url::encode('{"iss":"mallory"}') . ".$signature", $key));
        // The JWK round-trips.
        self::assertTrue(VerificationKey::fromJwk($key->jwk())->equals($key));
    }

    public function testAlgorithmFromJwk(): void
    {
        $v = self::vectors()['rfc7515-a2-rs256'][0];
        $pinned = VerificationKey::fromJwk($v['jwk'] + ['alg' => 'RS256', 'use' => 'sig']);
        self::assertSame('RS256', $pinned->algorithm());
        self::assertTrue($pinned->supports('RS256'));
        self::assertFalse($pinned->supports('PS256'));
        self::assertSame('RS256', $pinned->jwk()['alg']);
        self::assertTrue(Jwt::verify($v['jws'], $pinned));
        self::assertFalse(Jwt::verify($v['jws'], VerificationKey::fromJwk($v['jwk'] + ['alg' => 'RS512'])));
        $any = VerificationKey::fromJwk($v['jwk']);
        self::assertSame('RS256', $any->algorithm());
        foreach (array_keys(Rsa::ALGORITHMS) as $alg) {
            self::assertTrue($any->supports($alg));
        }
        foreach (['ES256', 'EdDSA', 'HS256', 'none'] as $alg) {
            self::assertFalse($any->supports($alg));
        }
        self::assertSame('RSA-2048 public key', (string) $any);
    }

    public function testRefusedKeys(): void
    {
        $v = self::vectors()['rfc7515-a2-rs256'][0]['jwk'];
        $cases = [
            'an encryption key' => $v + ['alg' => 'RSA-OAEP'],
            'an unknown algorithm' => $v + ['alg' => 'RS1'],
            'no modulus' => ['kty' => 'RSA', 'e' => 'AQAB'],
            'no exponent' => ['kty' => 'RSA', 'n' => $v['n']],
            'a 1024-bit modulus' => ['kty' => 'RSA', 'n' => Base64Url::encode(str_repeat("\xff", 128)), 'e' => 'AQAB'],
            'an even exponent' => ['kty' => 'RSA', 'n' => $v['n'], 'e' => Base64Url::encode("\x01\x00\x00")],
            'an exponent of one' => ['kty' => 'RSA', 'n' => $v['n'], 'e' => 'AQ'],
            'a modulus that is not base64url' => ['kty' => 'RSA', 'n' => 'not base64url!', 'e' => 'AQAB'],
        ];
        foreach ($cases as $name => $jwk) {
            try {
                VerificationKey::fromJwk($jwk);
                self::fail("Accepted $name");
            } catch (\InvalidArgumentException) {
                self::addToAssertionCount(1);
            }
        }
        // RSA keys verify only.
        $this->expectException(\InvalidArgumentException::class);
        SigningKey::fromJwk($v + ['d' => 'AQAB']);
    }

    public function testNoCompressedForm(): void
    {
        $this->expectException(\LogicException::class);
        VerificationKey::fromJwk(self::vectors()['rfc7515-a2-rs256'][0]['jwk'])->compressed();
    }

    /** EMSA-PSS-VERIFY refuses encodings that are wrong in each of its checks. */
    public function testPssEncodingChecks(): void
    {
        $message = 'message';
        $hash = 'sha256';
        $emBits = 2047;
        $emLen = 256;
        $salt = str_repeat("\x5a", 32);
        $h = hash($hash, str_repeat("\x00", 8) . hash($hash, $message, true) . $salt, true);
        $db = str_repeat("\x00", $emLen - 32 - 32 - 2) . "\x01" . $salt;
        $maskedDb = $db ^ Rsa::mgf1($h, $emLen - 32 - 1, $hash);
        $maskedDb[0] = chr(ord($maskedDb[0]) & 0x7f);
        $em = $maskedDb . $h . "\xbc";
        self::assertTrue(Rsa::emsaPssVerify($message, $em, $emBits, $hash));
        self::assertFalse(Rsa::emsaPssVerify('other message', $em, $emBits, $hash));
        self::assertFalse(Rsa::emsaPssVerify($message, substr($em, 0, -1) . "\xbd", $emBits, $hash));
        $topBit = $em;
        $topBit[0] = chr(ord($topBit[0]) | 0x80);
        self::assertFalse(Rsa::emsaPssVerify($message, $topBit, $emBits, $hash));
        self::assertFalse(Rsa::emsaPssVerify($message, "\x01" . $em, $emBits + 8, $hash));
        self::assertFalse(Rsa::emsaPssVerify($message, substr($em, 1), $emBits, $hash));
        // A salt of another length moves the 0x01 separator.
        $short = str_repeat("\x5a", 20);
        $h2 = hash($hash, str_repeat("\x00", 8) . hash($hash, $message, true) . $short, true);
        $db2 = str_repeat("\x00", $emLen - 20 - 32 - 2) . "\x01" . $short;
        $masked2 = $db2 ^ Rsa::mgf1($h2, $emLen - 32 - 1, $hash);
        $masked2[0] = chr(ord($masked2[0]) & 0x7f);
        self::assertFalse(Rsa::emsaPssVerify($message, $masked2 . $h2 . "\xbc", $emBits, $hash));
    }

    public function testPem(): void
    {
        $v = self::vectors()['rfc7520-4.2-ps384'][0]['jwk'];
        $pem = Rsa::publicKeyPem((string) Base64Url::decode($v['n']), (string) Base64Url::decode($v['e']));
        $key = openssl_pkey_get_public($pem);
        self::assertNotFalse($key);
        $details = openssl_pkey_get_details($key);
        self::assertIsArray($details);
        self::assertSame(OPENSSL_KEYTYPE_RSA, $details['type']);
        self::assertSame(2048, $details['bits']);
        self::assertSame(Base64Url::decode($v['n']), $details['rsa']['n']);
    }
}
