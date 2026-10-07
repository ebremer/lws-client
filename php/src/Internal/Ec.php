<?php
// SPDX-License-Identifier: MIT
declare(strict_types=1);

namespace Ebremer\Lws\Internal;

/**
 * DER encodings for ext-openssl: EC public keys (SubjectPublicKeyInfo), SEC 1 private keys and the conversion
 * between DER ECDSA signatures and JOSE's raw `r‖s`.
 *
 * @internal
 */
final class Ec
{
    /** Curve name → [coordinate size, OpenSSL curve name, SPKI prefix (uncompressed), SPKI prefix (compressed), OID]. */
    private const CURVES = [
        'P-256' => [32, 'prime256v1', '3059301306072a8648ce3d020106082a8648ce3d030107034200', '3039301306072a8648ce3d020106082a8648ce3d030107032200', '06082a8648ce3d030107'],
        'P-384' => [48, 'secp384r1', '3076301006072a8648ce3d020106052b81040022036200', '3046301006072a8648ce3d020106052b81040022033200', '06052b81040022'],
    ];

    private const ORDERS = [
        'P-256' => 'ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551',
        'P-384' => 'ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973',
    ];

    /** Whether a big-endian scalar of the curve's size is a valid private key: 0 < d < n. */
    public static function isValidScalar(string $curve, #[\SensitiveParameter] string $d): bool
    {
        return strlen($d) === self::size($curve) && trim($d, "\x00") !== '' && strcmp($d, self::bin(self::ORDERS[$curve])) < 0;
    }

    /** @return positive-int the coordinate size in bytes */
    public static function size(string $curve): int
    {
        return self::CURVES[$curve][0] ?? throw new \InvalidArgumentException("Unsupported EC curve: $curve");
    }

    public static function opensslCurve(string $curve): string
    {
        return self::CURVES[$curve][1] ?? throw new \InvalidArgumentException("Unsupported EC curve: $curve");
    }

    /** The PEM public key of an uncompressed point. */
    public static function publicKeyPem(string $curve, string $x, string $y): string
    {
        $der = self::bin(self::CURVES[$curve][2]) . "\x04" . $x . $y;
        return self::pem('PUBLIC KEY', $der);
    }

    /**
     * Decompresses a point (`02|03 ‖ x`), or returns null when it is not on the curve.
     *
     * @return array{0: string, 1: string}|null x and y
     */
    public static function decompress(string $curve, string $compressed): ?array
    {
        $size = self::size($curve);
        if (strlen($compressed) !== $size + 1 || ($compressed[0] !== "\x02" && $compressed[0] !== "\x03")) {
            return null;
        }
        $der = self::bin(self::CURVES[$curve][3]) . $compressed;
        $key = @openssl_pkey_get_public(self::pem('PUBLIC KEY', $der));
        if ($key === false) {
            while (openssl_error_string() !== false) {
            }
            return null;
        }
        $details = openssl_pkey_get_details($key);
        if (!is_array($details) || !isset($details['ec']['x'], $details['ec']['y'])) {
            return null;
        }
        return [self::pad($details['ec']['x'], $size), self::pad($details['ec']['y'], $size)];
    }

    /** The PEM of a SEC 1 private key holding only `d` (OpenSSL derives the public point). */
    public static function privateKeyPem(string $curve, #[\SensitiveParameter] string $d): string
    {
        $oid = self::bin(self::CURVES[$curve][4]);
        $body = "\x02\x01\x01" . "\x04" . chr(strlen($d)) . $d . "\xa0" . chr(strlen($oid)) . $oid;
        return self::pem('EC PRIVATE KEY', "\x30" . chr(strlen($body)) . $body);
    }

    private static function bin(string $hex): string
    {
        $b = hex2bin($hex);
        if ($b === false) {
            throw new \LogicException("Invalid hex constant: $hex");
        }
        return $b;
    }

    private static function pem(string $label, string $der): string
    {
        return "-----BEGIN $label-----\n" . chunk_split(base64_encode($der), 64, "\n") . "-----END $label-----\n";
    }

    /** Left-pads a big-endian integer to `size` bytes (dropping extra leading zero bytes). */
    public static function pad(string $bytes, int $size): string
    {
        $b = ltrim($bytes, "\x00");
        return strlen($b) > $size ? $b : str_repeat("\x00", $size - strlen($b)) . $b;
    }

    /** A DER ECDSA signature as raw `r‖s`, or null when it is not one. */
    public static function derToRaw(string $der, int $size): ?string
    {
        $i = 0;
        if (($der[$i++] ?? '') !== "\x30" || self::length($der, $i) !== strlen($der) - $i) {
            return null;
        }
        $parts = [];
        for ($k = 0; $k < 2; $k++) {
            if (($der[$i++] ?? '') !== "\x02") {
                return null;
            }
            $len = self::length($der, $i);
            if ($len === null || $len < 1 || $i + $len > strlen($der)) {
                return null;
            }
            $v = ltrim(substr($der, $i, $len), "\x00");
            if (strlen($v) > $size) {
                return null;
            }
            $parts[] = str_pad($v, $size, "\x00", STR_PAD_LEFT);
            $i += $len;
        }
        return $i === strlen($der) ? $parts[0] . $parts[1] : null;
    }

    /** Raw `r‖s` as a DER ECDSA signature. */
    public static function rawToDer(string $raw): string
    {
        $half = intdiv(strlen($raw), 2);
        $body = '';
        foreach ([substr($raw, 0, $half), substr($raw, $half)] as $v) {
            $v = ltrim($v, "\x00");
            if ($v === '' || ord($v[0]) >= 0x80) {
                $v = "\x00" . $v;
            }
            $body .= "\x02" . self::encodeLength(strlen($v)) . $v;
        }
        return "\x30" . self::encodeLength(strlen($body)) . $body;
    }

    private static function length(string $der, int &$i): ?int
    {
        if (!isset($der[$i])) {
            return null;
        }
        $b = ord($der[$i++]);
        if ($b < 0x80) {
            return $b;
        }
        $n = $b & 0x7f;
        if ($n < 1 || $n > 2 || $i + $n > strlen($der)) {
            return null;
        }
        $len = 0;
        for ($k = 0; $k < $n; $k++) {
            $len = ($len << 8) | ord($der[$i++]);
        }
        return $len;
    }

    private static function encodeLength(int $len): string
    {
        return $len < 0x80 ? chr($len) : "\x81" . chr($len);
    }
}
