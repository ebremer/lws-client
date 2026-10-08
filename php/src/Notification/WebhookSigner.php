<?php
// SPDX-License-Identifier: MIT
declare(strict_types=1);

namespace Ebremer\Lws\Notification;

use Ebremer\Lws\Auth\SigningKey;
use Ebremer\Lws\Auth\VerificationKey;
use Ebremer\Lws\Exception\SignatureVerificationException;
use Ebremer\Lws\Http\Headers;
use Ebremer\Lws\Http\SfBytes;
use Ebremer\Lws\Http\SfInnerList;
use Ebremer\Lws\Http\SfItem;
use Ebremer\Lws\Http\StructuredFields;
use Ebremer\Lws\Internal\Url;
use Ebremer\Lws\MediaType;

/**
 * Signs webhook deliveries, the storage's side of {@see WebhookVerifier} (lws10-notifications-webhook): an RFC 9530
 * `Content-Digest` of the body, and an RFC 9421 signature over `@method`, `@scheme`, `@authority`, `@path`,
 * `content-type` and `content-digest`, with `created`, `keyid` and `alg`.
 *
 * ```php
 * $signer = new WebhookSigner($key, 'https://storage.example/#' . $kid);
 * $headers = $signer->sign('https://app.example/inbox', $body);   // content-type, content-digest, signature-input, signature
 * ```
 *
 * The key ID must be the ID of a verification method of the storage description, referenced from `authentication`:
 * the storage URI with the method's fragment. The storage publishes the key's public JWK there.
 */
final class WebhookSigner
{
    /** The components every signature covers, in order. */
    public const COMPONENTS = WebhookVerifier::REQUIRED_COMPONENTS;

    /** The digest algorithms, by their RFC 9530 names. */
    private const DIGESTS = ['sha-256' => 'sha256', 'sha-512' => 'sha512'];

    /** The RFC 9421 algorithm of the key. */
    public readonly string $algorithm;

    /** @var \Closure(): int */
    private readonly \Closure $clock;

    /**
     * @param SigningKey $key a P-256, P-384 or Ed25519 key
     * @param string $keyId the verification method's ID: an absolute http(s) URL with a fragment
     * @param string $digest the digest algorithm, `sha-256` or `sha-512`
     * @param string $label the signature label
     * @param ?\Closure(): (int|float) $clock the time in seconds since the epoch (default: the system clock)
     * @throws \InvalidArgumentException for a key ID, digest or label that cannot be used
     */
    public function __construct(
        private readonly SigningKey $key,
        public readonly string $keyId,
        private readonly string $digest = 'sha-256',
        private readonly string $label = 'sig1',
        ?\Closure $clock = null,
    ) {
        $hash = strpos($keyId, '#');
        if ($hash === false || $hash === strlen($keyId) - 1 || !Url::isHttp(substr($keyId, 0, $hash))) {
            throw new \InvalidArgumentException("The key ID must be an absolute http(s) URL with a fragment: $keyId");
        }
        if (!isset(self::DIGESTS[$digest])) {
            throw new \InvalidArgumentException("Unsupported digest algorithm $digest (sha-256, sha-512)");
        }
        if (preg_match('/^[a-z*][a-z0-9_\-.*]*$/', $label) !== 1) {
            throw new \InvalidArgumentException("Not a structured field key: $label");
        }
        $this->algorithm = self::algorithmOf($key->publicKey);
        $this->clock = $clock === null ? static fn (): int => time() : static fn (): int => (int) floor($clock());
    }

    /**
     * The headers that sign a delivery.
     *
     * @param string $url the inbox URL, as it was registered
     * @param string $body the body bytes, exactly as they will be sent
     * @param string $contentType the body's media type, as it will be sent
     * @param string $method the request method
     * @param ?int $created when the signature was made (default: now)
     * @return array<string, string> `content-type`, `content-digest`, `signature-input` and `signature`
     * @throws \InvalidArgumentException when the inbox URL is not absolute or the content type is not printable ASCII
     */
    public function sign(string $url, string $body, string $contentType = MediaType::LWS_JSON, string $method = 'POST', ?int $created = null): array
    {
        if (!Url::isHttp($url)) {
            throw new \InvalidArgumentException("The inbox URL must be an absolute http(s) URL: $url");
        }
        if (preg_match('/^[\x20-\x7e]+$/', $contentType) !== 1) {
            throw new \InvalidArgumentException('The content type must be printable ASCII');
        }
        $headers = [
            'content-type' => $contentType,
            'content-digest' => self::contentDigest($body, $this->digest),
        ];
        $covered = new SfInnerList(
            array_map(static fn (string $c): SfItem => new SfItem($c), self::COMPONENTS),
            ['created' => $created ?? ($this->clock)(), 'keyid' => $this->keyId, 'alg' => $this->algorithm],
        );
        try {
            $base = WebhookVerifier::signatureBase($method, $url, new Headers($headers), $covered);
        } catch (SignatureVerificationException $e) {
            // Only a key ID with characters a structured field string cannot hold gets here.
            throw new \InvalidArgumentException($e->getMessage(), 0, $e);
        }
        $headers['signature-input'] = StructuredFields::serializeDictionary([$this->label => $covered]);
        $headers['signature'] = StructuredFields::serializeDictionary([$this->label => new SfItem(new SfBytes($this->key->sign($base)))]);
        return $headers;
    }

    /**
     * The `Content-Digest` field value of a body (RFC 9530).
     *
     * @param string $algorithm `sha-256` or `sha-512`
     * @throws \InvalidArgumentException for another algorithm
     */
    public static function contentDigest(string $body, string $algorithm = 'sha-256'): string
    {
        $hash = self::DIGESTS[$algorithm] ?? throw new \InvalidArgumentException("Unsupported digest algorithm $algorithm (sha-256, sha-512)");
        return StructuredFields::serializeDictionary([$algorithm => new SfItem(new SfBytes(hash($hash, $body, true)))]);
    }

    /**
     * The RFC 9421 algorithm a key signs with: `ecdsa-p256-sha256`, `ecdsa-p384-sha384` or `ed25519`.
     *
     * @throws \InvalidArgumentException for an RSA key
     */
    public static function algorithmOf(VerificationKey $key): string
    {
        return match ($key->curve) {
            'P-256' => 'ecdsa-p256-sha256',
            'P-384' => 'ecdsa-p384-sha384',
            'Ed25519' => 'ed25519',
            default => throw new \InvalidArgumentException("A {$key->curve} key does not sign webhooks"),
        };
    }
}
