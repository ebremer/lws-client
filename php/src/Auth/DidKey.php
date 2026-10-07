<?php
// SPDX-License-Identifier: MIT
declare(strict_types=1);

namespace Ebremer\Lws\Auth;

use Ebremer\Lws\Internal\Ec;

/**
 * `did:key` identifiers for P-256 (`did:key:zDn…`) and Ed25519 (`did:key:z6Mk…`) keys: multibase base58btc of the
 * multicodec prefix (`0x80 0x24` p256-pub, `0xed 0x01` ed25519-pub) and the (compressed) public key.
 */
final class DidKey
{
    private const ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
    private const P256 = "\x80\x24";
    private const ED25519 = "\xed\x01";

    private function __construct()
    {
    }

    /**
     * The `did:key` of a public key.
     *
     * @throws \InvalidArgumentException for a P-384 key
     */
    public static function did(VerificationKey $key): string
    {
        $prefix = match ($key->curve) {
            'P-256' => self::P256,
            'Ed25519' => self::ED25519,
            default => throw new \InvalidArgumentException('did:key supports P-256 and Ed25519 keys, not ' . $key->curve),
        };
        return 'did:key:z' . self::encode($prefix . $key->compressed());
    }

    /**
     * The `did:key` of a public JWK.
     *
     * @param array<array-key, mixed>|\stdClass $jwk
     */
    public static function didFromJwk(array|\stdClass $jwk): string
    {
        return self::did(VerificationKey::fromJwk($jwk));
    }

    /** The key id of a key's `did:key`: `did:key:z…#z…`. */
    public static function keyId(VerificationKey $key): string
    {
        return self::keyIdForDid(self::did($key));
    }

    /**
     * The key id of a `did:key` (the DID, `#` and its method-specific identifier).
     *
     * @throws \InvalidArgumentException when it is not a did:key
     */
    public static function keyIdForDid(string $did): string
    {
        if (!str_starts_with($did, 'did:key:z')) {
            throw new \InvalidArgumentException("Not a did:key: $did");
        }
        $base = explode('#', $did, 2)[0];
        return $base . '#' . substr($base, strlen('did:key:'));
    }

    /**
     * The public key a `did:key` (or its key id) encodes.
     *
     * @throws \InvalidArgumentException when it is not a P-256 or Ed25519 did:key
     */
    public static function publicKey(string $did): VerificationKey
    {
        $base = explode('#', $did, 2)[0];
        if (!str_starts_with($base, 'did:key:z')) {
            throw new \InvalidArgumentException("Not a base58btc did:key: $did");
        }
        $bytes = self::decode(substr($base, strlen('did:key:z')));
        if ($bytes === null) {
            throw new \InvalidArgumentException("Not a base58btc did:key: $did");
        }
        if (str_starts_with($bytes, self::P256) && strlen($bytes) === 35) {
            $xy = Ec::decompress('P-256', substr($bytes, 2))
                ?? throw new \InvalidArgumentException('Invalid P-256 point in did:key');
            return new VerificationKey('P-256', $xy[0], $xy[1]);
        }
        if (str_starts_with($bytes, self::ED25519) && strlen($bytes) === 34) {
            return new VerificationKey('Ed25519', substr($bytes, 2));
        }
        throw new \InvalidArgumentException("Unsupported did:key key type: $did");
    }

    /** base58btc encoding (Bitcoin alphabet). */
    public static function encode(string $bytes): string
    {
        $digits = [];
        $n = strlen($bytes);
        for ($i = 0; $i < $n; $i++) {
            $carry = ord($bytes[$i]);
            foreach ($digits as $k => $d) {
                $carry += $d << 8;
                $digits[$k] = $carry % 58;
                $carry = intdiv($carry, 58);
            }
            while ($carry > 0) {
                $digits[] = $carry % 58;
                $carry = intdiv($carry, 58);
            }
        }
        $out = str_repeat('1', strspn($bytes, "\x00"));
        for ($k = count($digits) - 1; $k >= 0; $k--) {
            $out .= self::ALPHABET[$digits[$k]];
        }
        return $out;
    }

    /** base58btc decoding, or null for a character outside the alphabet. */
    public static function decode(string $text): ?string
    {
        $bytes = [];
        $n = strlen($text);
        for ($i = 0; $i < $n; $i++) {
            $v = strpos(self::ALPHABET, $text[$i]);
            if ($v === false) {
                return null;
            }
            $carry = $v;
            foreach ($bytes as $k => $b) {
                $carry += $b * 58;
                $bytes[$k] = $carry & 0xff;
                $carry >>= 8;
            }
            while ($carry > 0) {
                $bytes[] = $carry & 0xff;
                $carry >>= 8;
            }
        }
        $out = str_repeat("\x00", strspn($text, '1'));
        for ($k = count($bytes) - 1; $k >= 0; $k--) {
            $out .= chr($bytes[$k]);
        }
        return $out;
    }
}
