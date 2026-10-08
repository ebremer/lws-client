<?php
// SPDX-License-Identifier: MIT
declare(strict_types=1);

namespace Ebremer\Lws\Auth;

use Ebremer\Lws\Internal\Base64Url;
use Ebremer\Lws\Internal\Ec;
use Ebremer\Lws\Internal\Rsa;
use Ebremer\Lws\Json\Json;

/**
 * A public key that verifies signatures: P-256 (`ES256`), P-384 (`ES384`), Ed25519 (`EdDSA`) or RSA of at least
 * 2048 bits (`RS256`, `RS384`, `RS512`, `PS256`, `PS384`, `PS512`; verification only, as OpenID Providers sign with
 * it). ECDSA signatures are JOSE's raw `r‖s`, never DER.
 */
final class VerificationKey implements \Stringable
{
    /**
     * @param string $curve `P-256`, `P-384`, `Ed25519` or, for an RSA key, `RSA`
     * @param string $x the x coordinate (EC), the public key (Ed25519) or the modulus (RSA), raw bytes
     * @param ?string $y the y coordinate (EC) or the public exponent (RSA), raw bytes
     * @param ?string $rsaAlgorithm the one algorithm an RSA key is for, when its JWK names one
     * @internal use {@see fromJwk()}
     */
    public function __construct(
        public readonly string $curve,
        public readonly string $x,
        public readonly ?string $y = null,
        public readonly ?string $rsaAlgorithm = null,
    ) {
    }

    /**
     * Imports a public JWK (`EC` P-256 or P-384, `OKP` Ed25519, `RSA`); private members are ignored.
     *
     * An RSA key must have at least 2048 bits (RFC 7518 §3.3); one whose `alg` is not an RSA signature algorithm,
     * such as an encryption key, is refused.
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
        if ($kty === 'RSA') {
            return self::rsaFromJwk($j);
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
     * An RSA public key from its JWK members.
     *
     * @param array<array-key, mixed> $j
     */
    private static function rsaFromJwk(array $j): self
    {
        $n = self::bytes($j, 'n');
        $e = self::bytes($j, 'e');
        $bits = Rsa::bits($n);
        if ($bits < Rsa::MIN_BITS || $bits > Rsa::MAX_BITS) {
            throw new \InvalidArgumentException("Unsupported RSA key size: $bits bits");
        }
        $e = ltrim($e, "\x00");
        if ($e === '' || strlen($e) > 8 || (ord($e[strlen($e) - 1]) & 1) === 0 || $e === "\x01") {
            throw new \InvalidArgumentException('Invalid RSA public exponent');
        }
        $alg = $j['alg'] ?? null;
        if ($alg !== null && (!is_string($alg) || !isset(Rsa::ALGORITHMS[$alg]))) {
            throw new \InvalidArgumentException('Not an RSA signature key: alg ' . (is_string($alg) ? $alg : '?'));
        }
        return new self('RSA', ltrim($n, "\x00"), $e, $alg);
    }

    /**
     * A base64url JWK member of any length.
     *
     * @param array<array-key, mixed> $jwk
     */
    private static function bytes(array $jwk, string $name): string
    {
        $v = $jwk[$name] ?? null;
        if (!is_string($v)) {
            throw new \InvalidArgumentException("JWK member '$name' is missing");
        }
        $bytes = Base64Url::decode($v);
        if ($bytes === null || $bytes === '') {
            throw new \InvalidArgumentException("JWK member '$name' is not base64url");
        }
        return $bytes;
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

    /**
     * The JOSE algorithm: `ES256`, `ES384` or `EdDSA`; for an RSA key, the one its JWK named, or `RS256`.
     *
     * An RSA key whose JWK named none verifies any RSA algorithm; see {@see supports()}.
     */
    public function algorithm(): string
    {
        return match ($this->curve) {
            'P-256' => 'ES256',
            'P-384' => 'ES384',
            'RSA' => $this->rsaAlgorithm ?? 'RS256',
            default => 'EdDSA',
        };
    }

    /** Whether the key verifies signatures of a JWS algorithm. */
    public function supports(string $algorithm): bool
    {
        if ($this->curve === 'RSA' && $this->rsaAlgorithm === null) {
            return isset(Rsa::ALGORITHMS[$algorithm]);
        }
        return $algorithm === $this->algorithm();
    }

    /** The JWK `kty`: `EC`, `OKP` or `RSA`. */
    public function keyType(): string
    {
        return match ($this->curve) {
            'Ed25519' => 'OKP',
            'RSA' => 'RSA',
            default => 'EC',
        };
    }

    /** @return array<string, string> the public JWK */
    public function jwk(): array
    {
        if ($this->curve === 'RSA') {
            $j = ['kty' => 'RSA', 'n' => Base64Url::encode($this->x), 'e' => Base64Url::encode((string) $this->y)];
            return $this->rsaAlgorithm === null ? $j : $j + ['alg' => $this->rsaAlgorithm];
        }
        $j = ['kty' => $this->keyType(), 'crv' => $this->curve, 'x' => Base64Url::encode($this->x)];
        if ($this->y !== null) {
            $j['y'] = Base64Url::encode($this->y);
        }
        return $j;
    }

    /**
     * The compressed point (`02|03 ‖ x`) of an EC key, or the raw key of an Ed25519 one.
     *
     * @throws \LogicException for an RSA key, which has none
     */
    public function compressed(): string
    {
        if ($this->curve === 'RSA') {
            throw new \LogicException('An RSA key has no compressed form');
        }
        if ($this->y === null) {
            return $this->x;
        }
        return (ord($this->y[strlen($this->y) - 1]) & 1 ? "\x03" : "\x02") . $this->x;
    }

    /**
     * Verifies a signature (raw `r‖s` for ECDSA) over `data`.
     *
     * @param ?string $algorithm the JWS algorithm, for an RSA key; {@see algorithm()} by default
     */
    public function verify(string $signature, string $data, ?string $algorithm = null): bool
    {
        if ($this->curve === 'RSA') {
            $algorithm ??= $this->algorithm();
            return $this->supports($algorithm) && Rsa::verify($this->x, (string) $this->y, $algorithm, $signature, $data);
        }
        if ($algorithm !== null && $algorithm !== $this->algorithm()) {
            return false;
        }
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
        return $this->curve === 'RSA' ? sprintf('RSA-%d public key', Rsa::bits($this->x)) : $this->algorithm() . ' public key';
    }
}
