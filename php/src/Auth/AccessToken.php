<?php
// SPDX-License-Identifier: MIT
declare(strict_types=1);

namespace Ebremer\Lws\Auth;

use Ebremer\Lws\Exception\AuthenticationException;
use Ebremer\Lws\Internal\JsonAccess;

/** An access token issued by an authorization server. */
final class AccessToken implements \Stringable
{
    /** The lifetime assumed when neither `expires_in` nor a JWT `exp` is available, in seconds. */
    public const DEFAULT_LIFETIME = 300;

    /** @param float $expiresAt when it expires, in seconds since the epoch */
    public function __construct(
        #[\SensitiveParameter] public readonly string $value,
        public readonly float $expiresAt,
        public readonly string $tokenType = 'Bearer',
        public readonly ?string $scope = null,
    ) {
    }

    /**
     * Parses a token endpoint success response (RFC 6749 section 5.1). The expiry is `expires_in`, else the token's
     * JWT `exp` claim, else {@see DEFAULT_LIFETIME}.
     *
     * @param array<array-key, mixed> $json
     * @throws AuthenticationException without a token, or with a token type other than Bearer
     */
    public static function fromTokenResponse(array $json, float $now): self
    {
        $token = JsonAccess::str($json, 'access_token');
        if ($token === null || $token === '') {
            throw new AuthenticationException('The token response has no access_token');
        }
        $type = JsonAccess::str($json, 'token_type');
        if ($type === null || strcasecmp($type, 'bearer') !== 0) {
            throw new AuthenticationException('Unsupported token_type: ' . ($type ?? 'none'));
        }
        $expiresIn = $json['expires_in'] ?? null;
        if (is_int($expiresIn) || is_float($expiresIn)) {
            $expires = $now + $expiresIn;
        } else {
            $exp = Jwt::expiration($token);
            $expires = $exp !== null ? (float) $exp->getTimestamp() : $now + self::DEFAULT_LIFETIME;
        }
        return new self($token, $expires, 'Bearer', JsonAccess::str($json, 'scope'));
    }

    /** Whether the token is still usable at `now`, keeping `margin` seconds in reserve. */
    public function isValid(float $now, float $margin = 0): bool
    {
        return $now + $margin < $this->expiresAt;
    }

    public function __toString(): string
    {
        return "AccessToken({$this->tokenType}, expires " . gmdate('Y-m-d\TH:i:s\Z', (int) $this->expiresAt) . ')';
    }

    /** @return array<string, mixed> without the token */
    public function __debugInfo(): array
    {
        return ['tokenType' => $this->tokenType, 'expiresAt' => $this->expiresAt, 'scope' => $this->scope];
    }
}
