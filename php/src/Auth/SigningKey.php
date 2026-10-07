<?php
// SPDX-License-Identifier: MIT
declare(strict_types=1);

namespace Ebremer\Lws\Auth;

use Ebremer\Lws\Internal\Base64Url;
use Ebremer\Lws\Internal\Ec;
use Ebremer\Lws\Json\Json;

/**
 * A private key that signs: P-256 (`ES256`, required by the self-signed suite), P-384 (`ES384`) or Ed25519
 * (`EdDSA`). ECDSA signatures are JOSE's raw `r‖s`.
 *
 * ```php
 * $key = SigningKey::generateP256();
 * $jwk = $key->jwk();                 // store it: ['kty' => 'EC', 'crv' => 'P-256', 'x' => …, 'y' => …, 'd' => …]
 * $again = SigningKey::fromJwk($jwk);
 * ```
 */
final class SigningKey implements \Stringable
{
    public readonly VerificationKey $publicKey;

    private function __construct(VerificationKey $publicKey, #[\SensitiveParameter] private readonly string $d)
    {
        $this->publicKey = $publicKey;
    }

    /** A new P-256 key. */
    public static function generateP256(): self
    {
        return self::generateEc('P-256');
    }

    /** A new Ed25519 key. */
    public static function generateEd25519(): self
    {
        $seed = random_bytes(SODIUM_CRYPTO_SIGN_SEEDBYTES);
        $pair = sodium_crypto_sign_seed_keypair($seed);
        return new self(new VerificationKey('Ed25519', sodium_crypto_sign_publickey($pair)), $seed);
    }

    /**
     * A new key for a JOSE algorithm: `ES256`, `ES384` or `EdDSA`.
     *
     * @throws \InvalidArgumentException for another algorithm
     */
    public static function generate(string $algorithm): self
    {
        return match ($algorithm) {
            'ES256' => self::generateP256(),
            'ES384' => self::generateEc('P-384'),
            'EdDSA', 'Ed25519' => self::generateEd25519(),
            default => throw new \InvalidArgumentException("Unsupported algorithm: $algorithm"),
        };
    }

    private static function generateEc(string $curve): self
    {
        $key = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => Ec::opensslCurve($curve)]);
        $details = $key === false ? false : openssl_pkey_get_details($key);
        if (!is_array($details) || !isset($details['ec']['d'])) {
            // Without a usable openssl.cnf: a random scalar below the group order, from which OpenSSL derives the point.
            while (openssl_error_string() !== false) {
            }
            $size = Ec::size($curve);
            do {
                $d = random_bytes($size);
                $k = self::fromScalar($curve, $d);
            } while ($k === null);
            return $k;
        }
        $size = Ec::size($curve);
        $public = new VerificationKey($curve, Ec::pad($details['ec']['x'], $size), Ec::pad($details['ec']['y'], $size));
        return new self($public, Ec::pad($details['ec']['d'], $size));
    }

    private static function fromScalar(string $curve, #[\SensitiveParameter] string $d): ?self
    {
        if (!Ec::isValidScalar($curve, $d)) {
            return null;
        }
        $key = @openssl_pkey_get_private(Ec::privateKeyPem($curve, $d));
        $details = $key === false ? false : openssl_pkey_get_details($key);
        while (openssl_error_string() !== false) {
        }
        if (!is_array($details) || !isset($details['ec']['x'], $details['ec']['y'])) {
            return null;
        }
        $size = Ec::size($curve);
        return new self(new VerificationKey($curve, Ec::pad($details['ec']['x'], $size), Ec::pad($details['ec']['y'], $size)), $d);
    }

    /**
     * Imports a private JWK (`EC` P-256 or P-384, `OKP` Ed25519, with `d`). Its public members must match `d`.
     *
     * @param array<array-key, mixed>|\stdClass $jwk
     * @throws \InvalidArgumentException for a public, unsupported, invalid or inconsistent key
     */
    public static function fromJwk(#[\SensitiveParameter] array|\stdClass $jwk): self
    {
        $j = Json::members($jwk) ?? [];
        if (!is_string($j['d'] ?? null)) {
            throw new \InvalidArgumentException("The JWK has no private key member 'd'");
        }
        $public = VerificationKey::fromJwk($j);
        if ($public->curve === 'Ed25519') {
            $seed = VerificationKey::member($j, 'd', SODIUM_CRYPTO_SIGN_SEEDBYTES);
            if ($seed === '') {
                throw new \InvalidArgumentException("JWK member 'd' is empty");
            }
            $derived = sodium_crypto_sign_publickey(sodium_crypto_sign_seed_keypair($seed));
            if (!hash_equals($derived, $public->x)) {
                throw new \InvalidArgumentException("The JWK's 'x' does not match its 'd'");
            }
            return new self($public, $seed);
        }
        $d = VerificationKey::member($j, 'd', Ec::size($public->curve));
        $k = self::fromScalar($public->curve, $d)
            ?? throw new \InvalidArgumentException("Invalid {$public->curve} private key");
        if (!$k->publicKey->equals($public)) {
            throw new \InvalidArgumentException("The JWK's 'x' and 'y' do not match its 'd'");
        }
        return $k;
    }

    /** The JOSE algorithm: `ES256`, `ES384` or `EdDSA`. */
    public function algorithm(): string
    {
        return $this->publicKey->algorithm();
    }

    /** @return array<string, string> the private JWK (public members and `d`) */
    public function jwk(): array
    {
        return $this->publicKey->jwk() + ['d' => Base64Url::encode($this->d)];
    }

    /**
     * Signs `data`: raw `r‖s` (64 bytes for P-256, 96 for P-384) or a 64-byte Ed25519 signature.
     *
     * @throws \RuntimeException when OpenSSL fails
     */
    public function sign(string $data): string
    {
        if ($this->publicKey->curve === 'Ed25519' && $this->d !== '') {
            $pair = sodium_crypto_sign_seed_keypair($this->d);
            return sodium_crypto_sign_detached($data, sodium_crypto_sign_secretkey($pair));
        }
        $key = openssl_pkey_get_private(Ec::privateKeyPem($this->publicKey->curve, $this->d));
        $der = '';
        if ($key === false || !openssl_sign($data, $der, $key, $this->publicKey->curve === 'P-256' ? OPENSSL_ALGO_SHA256 : OPENSSL_ALGO_SHA384)) {
            $error = openssl_error_string();
            throw new \RuntimeException('Signing failed: ' . ($error === false ? 'OpenSSL error' : $error));
        }
        return Ec::derToRaw($der, Ec::size($this->publicKey->curve)) ?? throw new \RuntimeException('OpenSSL returned an invalid signature');
    }

    public function __toString(): string
    {
        return $this->algorithm() . ' private key';
    }

    /** @return array<string, string> without the private key */
    public function __debugInfo(): array
    {
        return ['algorithm' => $this->algorithm(), 'publicKey' => (string) json_encode($this->publicKey->jwk())];
    }
}
