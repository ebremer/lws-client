<?php
// SPDX-License-Identifier: MIT
declare(strict_types=1);

namespace Ebremer\Lws\Auth;

use Ebremer\Lws\TokenType;

/**
 * Self-signed identity authentication suite (`lws10-authn-ssi-cid`, `did:key` subjects included): the agent signs
 * its own JWT credential (`urn:ietf:params:oauth:token-type:jwt`) with `sub = iss = client_id = agent`,
 * `aud = [authorization server]`, `iat`, `exp` and a random `jti`. Supports `ES256` (P-256) and `EdDSA` (Ed25519).
 * Tokens are reused per audience until 60 seconds before they expire.
 *
 * ```php
 * $me = SelfSignedCredentials::didKey(SigningKey::generateP256());   // agent = did:key:zDn…
 * ```
 */
final class SelfSignedCredentials implements CredentialProvider
{
    private const REUSE_MARGIN = 60;

    /** @var \Closure(): float */
    private readonly \Closure $clock;
    /** @var array<string, array{0: string, 1: float}> audience → token and expiry */
    private array $cache = [];

    /**
     * @param string $agent the agent identifier (`sub`, `iss` and `client_id`)
     * @param ?string $keyId the `kid` of the JWT header
     * @param int $lifetime how long minted tokens live, in seconds
     * @param ?\Closure(): (int|float) $clock the time in seconds since the epoch (default: the system clock)
     */
    private function __construct(
        public readonly string $agent,
        private readonly SigningKey $key,
        public readonly ?string $keyId,
        public readonly int $lifetime = 300,
        ?\Closure $clock = null,
    ) {
        $this->clock = $clock === null ? static fn (): float => microtime(true) : static fn (): float => (float) $clock();
    }

    /**
     * Credentials for an agent whose controlled identifier document (at `agent`) lists the key under
     * `authentication`; `keyId` identifies that verification method.
     */
    public static function forAgent(string $agent, SigningKey $key, ?string $keyId): self
    {
        return new self($agent, $key, $keyId);
    }

    /**
     * Credentials for a `did:key` agent derived from a P-256 or Ed25519 key.
     *
     * @throws \InvalidArgumentException for a P-384 key
     */
    public static function didKey(SigningKey $key): self
    {
        return new self(DidKey::did($key->publicKey), $key, DidKey::keyId($key->publicKey));
    }

    /** A copy whose tokens live for `lifetime` seconds. */
    public function withLifetime(int $lifetime): self
    {
        return new self($this->agent, $this->key, $this->keyId, $lifetime, $this->clock);
    }

    /** @param \Closure(): (int|float) $clock a copy using another clock (for tests) */
    public function withClock(\Closure $clock): self
    {
        return new self($this->agent, $this->key, $this->keyId, $this->lifetime, $clock);
    }

    /** The JOSE algorithm: `ES256` or `EdDSA`. */
    public function algorithm(): string
    {
        return $this->key->algorithm();
    }

    public function publicKey(): VerificationKey
    {
        return $this->key->publicKey;
    }

    public function tokenType(): string
    {
        return TokenType::JWT;
    }

    public function subjectToken(CredentialContext $context): string
    {
        $audience = $context->metadata->issuer;
        $now = ($this->clock)();
        $cached = $this->cache[$audience] ?? null;
        if ($cached !== null && $now + self::REUSE_MARGIN < $cached[1]) {
            return $cached[0];
        }
        $token = $this->createToken($audience);
        $this->cache[$audience] = [$token, $now + $this->lifetime];
        return $token;
    }

    /** Creates and signs a new credential for `audience`. */
    public function createToken(string $audience): string
    {
        $iat = (int) floor(($this->clock)());
        $header = ['alg' => $this->key->algorithm(), 'typ' => 'JWT'];
        if ($this->keyId !== null) {
            $header['kid'] = $this->keyId;
        }
        $claims = [
            'sub' => $this->agent,
            'iss' => $this->agent,
            'client_id' => $this->agent,
            'aud' => [$audience],
            'iat' => $iat,
            'exp' => $iat + $this->lifetime,
            'jti' => self::uuid(),
        ];
        return Jwt::sign($header, $claims, $this->key);
    }

    private static function uuid(): string
    {
        $b = random_bytes(16);
        $b[6] = chr((ord($b[6]) & 0x0f) | 0x40);
        $b[8] = chr((ord($b[8]) & 0x3f) | 0x80);
        return vsprintf('%s%s-%s-%s-%s-%s%s%s', str_split(bin2hex($b), 4));
    }

    /** @return array<string, mixed> without the key */
    public function __debugInfo(): array
    {
        return ['agent' => $this->agent, 'keyId' => $this->keyId, 'algorithm' => $this->algorithm(), 'lifetime' => $this->lifetime];
    }
}
