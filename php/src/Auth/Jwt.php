<?php
// SPDX-License-Identifier: MIT
declare(strict_types=1);

namespace Ebremer\Lws\Auth;

use Ebremer\Lws\Internal\Base64Url;
use Ebremer\Lws\Internal\JsonAccess;
use Ebremer\Lws\Json\Json;

/** Compact JWS/JWT signing, verification and (unverified) decoding. */
final class Jwt
{
    private function __construct()
    {
    }

    /**
     * Signs a JWT; the header's `alg` is set from the key.
     *
     * @param array<string, mixed> $header
     * @param array<string, mixed> $claims
     */
    public static function sign(array $header, array $claims, SigningKey $key): string
    {
        $header = ['alg' => $key->algorithm()] + $header;
        $header['alg'] = $key->algorithm();
        $input = Base64Url::encode(Json::encode($header)) . '.' . Base64Url::encode(Json::encode(Json::object($claims)));
        return $input . '.' . Base64Url::encode($key->sign($input));
    }

    /** Whether a JWT is signed by `key` (its header's `alg` must be the key's algorithm). */
    public static function verify(string $jwt, VerificationKey $key): bool
    {
        $parts = explode('.', $jwt);
        if (count($parts) !== 3) {
            return false;
        }
        try {
            $header = self::decodeHeader($jwt);
        } catch (\InvalidArgumentException) {
            return false;
        }
        $signature = Base64Url::decode($parts[2]);
        if (($header['alg'] ?? null) !== $key->algorithm() || $signature === null) {
            return false;
        }
        return $key->verify($signature, $parts[0] . '.' . $parts[1]);
    }

    /**
     * The header, without verifying anything.
     *
     * @return array<array-key, mixed>
     * @throws \InvalidArgumentException when it is not a JWT
     */
    public static function decodeHeader(string $jwt): array
    {
        return self::part($jwt, 0);
    }

    /**
     * The claims, without verifying anything.
     *
     * @return array<array-key, mixed>
     * @throws \InvalidArgumentException when it is not a JWT
     */
    public static function decodeClaims(string $jwt): array
    {
        return self::part($jwt, 1);
    }

    /** The `exp` claim of a JWT (unverified), or null when it is not a JWT or has none. */
    public static function expiration(string $token): ?\DateTimeImmutable
    {
        try {
            $exp = JsonAccess::int(self::decodeClaims($token), 'exp');
        } catch (\InvalidArgumentException) {
            return null;
        }
        return $exp === null ? null : (new \DateTimeImmutable('@' . $exp));
    }

    /** @return array<array-key, mixed> */
    private static function part(string $jwt, int $index): array
    {
        $parts = explode('.', $jwt);
        if (count($parts) < 2) {
            throw new \InvalidArgumentException('Not a JWT');
        }
        $bytes = Base64Url::decode($parts[$index]);
        if ($bytes === null) {
            throw new \InvalidArgumentException('Not a JWT: invalid base64url');
        }
        try {
            $value = Json::decode($bytes);
        } catch (\JsonException) {
            throw new \InvalidArgumentException('Not a JWT: a part is not JSON');
        }
        $members = Json::members($value);
        if ($members === null && !$value instanceof \stdClass) {
            throw new \InvalidArgumentException('Not a JWT: a part is not a JSON object');
        }
        return $members ?? [];
    }
}
