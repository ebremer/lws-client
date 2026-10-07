<?php
// SPDX-License-Identifier: MIT
declare(strict_types=1);

namespace Ebremer\Lws\Auth;

use Ebremer\Lws\Internal\Base64Url;
use Ebremer\Lws\Internal\Ec;
use Ebremer\Lws\Json\Json;

/**
 * A public key that verifies signatures: P-256 (`ES256`), P-384 (`ES384`) or Ed25519 (`EdDSA`). ECDSA signatures
 * are JOSE's raw `r‖s`, never DER.
 */
final class VerificationKey implements \Stringable
{
    /**
     * @param string $curve `P-256`, `P-384` or `Ed25519`
     * @param string $x the x coordinate (EC) or the public key (Ed25519), raw bytes
     * @param ?string $y the y coordinate (EC), raw bytes
     * @internal use {@see fromJwk()}
     */
    public function __construct(public readonly string $curve, public readonly string $x, public readonly ?string $y = null)
    {
    }

    /**
     * Imports a public JWK (`EC` P-256 or P-384, `OKP` Ed25519); private members are ignored.
     *
     * @param array<array-key, mixed>|\stdClass $jwk
     * @throws \InvalidArgumentException for an unsupported or invalid key
     */
    public static function fromJwk(array|\stdClass $jwk): self
    {
        $j = Json::members($jwk) ?? [];
        $kty = $j['kty'] ?? null;
        $crv = $j['crv'] ?? null;
        if (!is_string($kty)) {
            throw new \InvalidArgumentException("JWK member 'kty' is missing");
        }
        if (!is_string($crv)) {
            throw new \InvalidArgumentException("JWK member 'crv' is missing");
        }
        if ($kty === 'EC') {
            if ($crv !== 'P-256' && $crv !== 'P-384') {
                throw new \InvalidArgumentException("Unsupported EC curve: $crv");
            }
            $size = Ec::size($crv);
            $key = new self($crv, self::member($j, 'x', $size), self::member($j, 'y', $size));
            if (@openssl_pkey_get_public(Ec::publicKeyPem($crv, $key->x, (string) $key->y)) === false) {
                while (openssl_error_string() !== false) {
                }
                throw new \InvalidArgumentException("Invalid $crv public key: the point is not on the curve");
            }
            return $key;
        }
        if ($kty === 'OKP') {
            if ($crv !== 'Ed25519') {
                throw new \InvalidArgumentException("Unsupported OKP curve: $crv");
            }
            return new self('Ed25519', self::member($j, 'x', SODIUM_CRYPTO_SIGN_PUBLICKEYBYTES));
        }
        throw new \InvalidArgumentException("Unsupported JWK kty: $kty");
    }

    /**
     * A base64url JWK member of exactly `size` bytes (shorter values are left-padded).
     *
     * @param array<array-key, mixed> $jwk
     * @internal
     */
    public static function member(array $jwk, string $name, int $size): string
    {
        $v = $jwk[$name] ?? null;
        if (!is_string($v)) {
            throw new \InvalidArgumentException("JWK member '$name' is missing");
        }
        $bytes = Base64Url::decode($v);
        if ($bytes === null) {
            throw new \InvalidArgumentException("JWK member '$name' is not base64url");
        }
        if ($bytes === '' || strlen($bytes) > $size) {
            throw new \InvalidArgumentException("JWK member '$name' has the wrong length");
        }
        return str_pad($bytes, $size, "\x00", STR_PAD_LEFT);
    }

    /** The JOSE algorithm: `ES256`, `ES384` or `EdDSA`. */
    public function algorithm(): string
    {
        return match ($this->curve) {
            'P-256' => 'ES256',
            'P-384' => 'ES384',
            default => 'EdDSA',
        };
    }

    /** The JWK `kty`: `EC` or `OKP`. */
    public function keyType(): string
    {
        return $this->curve === 'Ed25519' ? 'OKP' : 'EC';
    }

    /** @return array<string, string> the public JWK */
    public function jwk(): array
    {
        $j = ['kty' => $this->keyType(), 'crv' => $this->curve, 'x' => Base64Url::encode($this->x)];
        if ($this->y !== null) {
            $j['y'] = Base64Url::encode($this->y);
        }
        return $j;
    }

    /** The compressed point (`02|03 ‖ x`) of an EC key, or the raw key of an Ed25519 one. */
    public function compressed(): string
    {
        if ($this->y === null) {
            return $this->x;
        }
        return (ord($this->y[strlen($this->y) - 1]) & 1 ? "\x03" : "\x02") . $this->x;
    }

    /** Verifies a signature (raw `r‖s` for ECDSA) over `data`. */
    public function verify(string $signature, string $data): bool
    {
        if ($this->y === null) {
            return strlen($signature) === SODIUM_CRYPTO_SIGN_BYTES && $this->x !== ''
                && sodium_crypto_sign_verify_detached($signature, $data, $this->x);
        }
        $size = Ec::size($this->curve);
        if (strlen($signature) !== 2 * $size || trim($signature, "\x00") === '') {
            return false;
        }
        $key = @openssl_pkey_get_public(Ec::publicKeyPem($this->curve, $this->x, $this->y));
        if ($key === false) {
            while (openssl_error_string() !== false) {
            }
            return false;
        }
        $ok = openssl_verify($data, Ec::rawToDer($signature), $key, $this->curve === 'P-256' ? OPENSSL_ALGO_SHA256 : OPENSSL_ALGO_SHA384);
        while (openssl_error_string() !== false) {
        }
        return $ok === 1;
    }

    /** Whether two keys are the same public key. */
    public function equals(VerificationKey $other): bool
    {
        return $this->curve === $other->curve && hash_equals($this->x, $other->x) && $this->y === $other->y;
    }

    public function __toString(): string
    {
        return $this->algorithm() . ' public key';
    }
}
