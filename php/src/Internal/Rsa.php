<?php
// SPDX-License-Identifier: MIT
declare(strict_types=1);

namespace Ebremer\Lws\Internal;

/**
 * RSA signature verification for JWS (RFC 7518 §3.3, §3.5): RSASSA-PKCS1-v1_5 through ext-openssl, and RSASSA-PSS,
 * which ext-openssl cannot verify, as the raw RSA operation through ext-openssl followed by EMSA-PSS-VERIFY
 * (RFC 8017 §9.1.2) here.
 *
 * @internal
 */
final class Rsa
{
    /** The smallest modulus JWA allows, in bits (RFC 7518 §3.3). */
    public const MIN_BITS = 2048;

    /** The largest modulus accepted, in bits: larger keys only cost time. */
    public const MAX_BITS = 16384;

    /** JWS algorithm → [PSS?, hash, ext-openssl digest]. */
    public const ALGORITHMS = [
        'RS256' => [false, 'sha256', OPENSSL_ALGO_SHA256],
        'RS384' => [false, 'sha384', OPENSSL_ALGO_SHA384],
        'RS512' => [false, 'sha512', OPENSSL_ALGO_SHA512],
        'PS256' => [true, 'sha256', OPENSSL_ALGO_SHA256],
        'PS384' => [true, 'sha384', OPENSSL_ALGO_SHA384],
        'PS512' => [true, 'sha512', OPENSSL_ALGO_SHA512],
    ];

    /** The DER `rsaEncryption` AlgorithmIdentifier: OID 1.2.840.113549.1.1.1 and NULL parameters. */
    private const ALGORITHM_IDENTIFIER = '300d06092a864886f70d0101010500';

    private function __construct()
    {
    }

    /** The size of a modulus in bits (big-endian, leading zero bytes ignored). */
    public static function bits(string $n): int
    {
        $n = ltrim($n, "\x00");
        return $n === '' ? 0 : (strlen($n) - 1) * 8 + strlen(decbin(ord($n[0])));
    }

    /** The PEM SubjectPublicKeyInfo of a public key, for ext-openssl. */
    public static function publicKeyPem(string $n, string $e): string
    {
        $key = self::der(0x30, self::integer($n) . self::integer($e));
        $spki = self::der(0x30, (string) hex2bin(self::ALGORITHM_IDENTIFIER) . self::der(0x03, "\x00" . $key));
        return "-----BEGIN PUBLIC KEY-----\n" . chunk_split(base64_encode($spki), 64, "\n") . "-----END PUBLIC KEY-----\n";
    }

    /**
     * Verifies a JWS signature with an RSA public key.
     *
     * @param string $algorithm one of {@see ALGORITHMS}
     */
    public static function verify(string $n, string $e, string $algorithm, string $signature, string $data): bool
    {
        [$pss, $hash, $digest] = self::ALGORITHMS[$algorithm] ?? throw new \InvalidArgumentException("Not an RSA algorithm: $algorithm");
        $n = ltrim($n, "\x00");
        // RFC 8017 §8.1.2 and §8.2.2 step 1: the signature is exactly as long as the modulus.
        if (strlen($signature) !== strlen($n)) {
            return false;
        }
        $key = @openssl_pkey_get_public(self::publicKeyPem($n, $e));
        if ($key === false) {
            self::clearErrors();
            return false;
        }
        if (!$pss) {
            $ok = openssl_verify($data, $signature, $key, $digest);
            self::clearErrors();
            return $ok === 1;
        }
        // RSAVP1: the signature to the power e, modulo n; it fails for a signature not below n.
        $em = '';
        $ok = @openssl_public_decrypt($signature, $em, $key, OPENSSL_NO_PADDING);
        self::clearErrors();
        return $ok && self::emsaPssVerify($data, $em, self::bits($n) - 1, $hash);
    }

    /**
     * EMSA-PSS-VERIFY (RFC 8017 §9.1.2), with MGF1 over the same hash and a salt as long as the hash, as JWA has it.
     *
     * @param string $em the encoded message, as many bytes as the modulus
     * @param int $emBits the modulus size in bits, less one
     */
    public static function emsaPssVerify(string $message, string $em, int $emBits, string $hash): bool
    {
        $mHash = hash($hash, $message, true);
        $hLen = strlen($mHash);
        $sLen = $hLen;
        $emLen = intdiv($emBits + 7, 8);
        // I2OSP(m, emLen): when the modulus is one bit longer than a whole number of bytes, the first is zero.
        if (strlen($em) === $emLen + 1) {
            if ($em[0] !== "\x00") {
                return false;
            }
            $em = substr($em, 1);
        }
        if (strlen($em) !== $emLen || $emLen < $hLen + $sLen + 2 || $em[$emLen - 1] !== "\xbc") {
            return false;
        }
        $maskedDb = substr($em, 0, $emLen - $hLen - 1);
        $h = substr($em, $emLen - $hLen - 1, $hLen);
        $unused = 8 * $emLen - $emBits;
        $topMask = $unused === 0 ? 0xff : 0xff >> $unused;
        if ((ord($maskedDb[0]) & ~$topMask & 0xff) !== 0) {
            return false;
        }
        $db = $maskedDb ^ self::mgf1($h, $emLen - $hLen - 1, $hash);
        $db[0] = chr(ord($db[0]) & $topMask);
        $padding = $emLen - $hLen - $sLen - 2;
        if (strspn($db, "\x00", 0, $padding) !== $padding || $db[$padding] !== "\x01") {
            return false;
        }
        $salt = substr($db, -$sLen);
        return hash_equals($h, hash($hash, str_repeat("\x00", 8) . $mHash . $salt, true));
    }

    /** MGF1 (RFC 8017 §B.2.1): a mask of `length` bytes from a seed. */
    public static function mgf1(string $seed, int $length, string $hash): string
    {
        $mask = '';
        for ($counter = 0; strlen($mask) < $length; $counter++) {
            $mask .= hash($hash, $seed . pack('N', $counter), true);
        }
        return substr($mask, 0, $length);
    }

    /** A DER INTEGER of a non-negative big-endian number. */
    private static function integer(string $bytes): string
    {
        $bytes = ltrim($bytes, "\x00");
        if ($bytes === '' || ord($bytes[0]) & 0x80) {
            $bytes = "\x00" . $bytes;
        }
        return self::der(0x02, $bytes);
    }

    /** A DER TLV. */
    private static function der(int $tag, string $value): string
    {
        $length = strlen($value);
        if ($length < 0x80) {
            return chr($tag) . chr($length) . $value;
        }
        $bytes = ltrim(pack('N', $length), "\x00");
        return chr($tag) . chr(0x80 | strlen($bytes)) . $bytes . $value;
    }

    private static function clearErrors(): void
    {
        while (openssl_error_string() !== false) {
        }
    }
}
