<?php
// SPDX-License-Identifier: MIT
declare(strict_types=1);

namespace Ebremer\Lws\Notification;

use Ebremer\Lws\Auth\VerificationKey;
use Ebremer\Lws\Exception\LwsException;
use Ebremer\Lws\Exception\ProtocolException;
use Ebremer\Lws\Exception\SignatureVerificationException;
use Ebremer\Lws\Http\Headers;
use Ebremer\Lws\Http\SfBytes;
use Ebremer\Lws\Http\SfInnerList;
use Ebremer\Lws\Http\SfItem;
use Ebremer\Lws\Http\StructuredFieldException;
use Ebremer\Lws\Http\StructuredFields;
use Ebremer\Lws\Internal\Url;
use Ebremer\Lws\LwsClient;
use Ebremer\Lws\Model\StorageDescription;
use Psr\Http\Message\ServerRequestInterface;

/**
 * Verifies signed webhook deliveries (RFC 9421 HTTP Message Signatures, RFC 9530 `Content-Digest`): the digest of
 * the body, the signature over `@method`, `@scheme`, `@authority`, `@path`, `content-type` and `content-digest`
 * with a key the storage lists in its description under `authentication`, the signature's age, and the
 * notification's storage.
 *
 * ```php
 * $verifier = new WebhookVerifier(client: $client, trustedStorages: ['https://storage.example/']);
 * $verified = $verifier->verifyGlobals('https://app.example/inbox');   // in the inbox script
 * foreach ($verified->notification->activities as $a) { … }
 * ```
 *
 * Pass the inbox URL as it was registered, not the one a proxy forwarded to. Storage descriptions are cached
 * (10 minutes by default); a signature that fails with a cached description is retried once with a fresh one, in
 * case the storage rotated its keys.
 */
final class WebhookVerifier
{
    /** The components a signature must cover. */
    public const REQUIRED_COMPONENTS = ['@method', '@scheme', '@authority', '@path', 'content-type', 'content-digest'];

    /** @var \Closure(string): StorageDescription */
    private readonly \Closure $descriptions;
    /** @var \Closure(): float */
    private readonly \Closure $clock;
    /** @var array<string, true>|null */
    private readonly ?array $trusted;
    /** @var array<string, array{0: StorageDescription, 1: float}> */
    private array $cache = [];

    /**
     * @param ?LwsClient $client the client that retrieves storage descriptions (default: an anonymous one)
     * @param ?\Closure(string): StorageDescription $storageDescriptionResolver retrieves a storage description instead
     * @param ?list<string> $trustedStorages accept deliveries from these storages only (compared as URLs); an empty
     *     list trusts none, null trusts any
     * @param int $maxAge the oldest acceptable signature, in seconds
     * @param int $clockSkew how far in the future a signature may be created, in seconds
     * @param int $keyCacheTtl how long storage descriptions are cached, in seconds
     * @param ?\Closure(): (int|float) $clock the time in seconds since the epoch (default: the system clock)
     */
    public function __construct(
        ?LwsClient $client = null,
        ?\Closure $storageDescriptionResolver = null,
        ?array $trustedStorages = null,
        private readonly int $maxAge = 300,
        private readonly int $clockSkew = 300,
        private readonly int $keyCacheTtl = 600,
        ?\Closure $clock = null,
    ) {
        if ($storageDescriptionResolver !== null) {
            $this->descriptions = $storageDescriptionResolver;
        } else {
            $c = $client ?? new LwsClient();
            $this->descriptions = static fn (string $url): StorageDescription => $c->getStorageDescription($url);
        }
        $this->clock = $clock === null ? static fn (): float => microtime(true) : static fn (): float => (float) $clock();
        $this->trusted = $trustedStorages === null ? null
            : array_fill_keys(array_map(Url::canonical(...), $trustedStorages), true);
    }

    /**
     * Verifies a delivery.
     *
     * @param string $method the request method
     * @param string $url the inbox URL as registered
     * @param Headers|iterable<array-key, mixed> $headers the request headers
     * @param string $body the raw body bytes
     * @throws SignatureVerificationException when the delivery does not verify
     * @throws \InvalidArgumentException when the inbox URL is not absolute
     */
    public function verify(string $method, string $url, Headers|iterable $headers, string $body): VerifiedNotification
    {
        if (!Url::isHttp($url)) {
            throw new \InvalidArgumentException("The inbox URL must be an absolute http(s) URL: $url");
        }
        $headers = Headers::of($headers);
        self::checkDigest(self::field($headers, 'content-digest'), $body);
        $inputs = self::dictionary(self::field($headers, 'signature-input'), 'Signature-Input');
        $signatures = self::dictionary(self::field($headers, 'signature'), 'Signature');
        $label = null;
        $covered = null;
        foreach ($inputs as $key => $member) {
            if ($member instanceof SfInnerList && is_string($member->params['keyid'] ?? null) && isset($signatures[$key])) {
                $label = (string) $key;
                $covered = $member;
                break;
            }
        }
        if ($label === null || $covered === null) {
            throw self::fail('No signature with a keyid in Signature-Input and Signature');
        }
        $sigItem = $signatures[$label];
        if (!$sigItem instanceof SfItem || !$sigItem->value instanceof SfBytes) {
            throw self::fail("Signature $label is not a byte sequence");
        }
        $signature = $sigItem->value->bytes;
        $components = [];
        foreach ($covered->items as $item) {
            if (!is_string($item->value)) {
                throw self::fail('A covered component is not a string');
            }
            if ($item->params !== []) {
                throw self::fail("Unsupported component parameters on {$item->value}");
            }
            if (isset($components[$item->value])) {
                throw self::fail("Duplicate covered component {$item->value}");
            }
            $components[$item->value] = true;
        }
        foreach (self::REQUIRED_COMPONENTS as $r) {
            if (!isset($components[$r])) {
                throw self::fail("Required component not covered: $r");
            }
        }
        $params = $covered->params;
        $created = $params['created'] ?? null;
        if (!is_int($created)) {
            throw self::fail("The signature parameters lack an integer 'created'");
        }
        $now = (int) floor(($this->clock)());
        if ($created < $now - $this->maxAge) {
            throw self::fail("Signature too old (created $created)");
        }
        if ($created > $now + $this->clockSkew) {
            throw self::fail("Signature created in the future (created $created)");
        }
        if (array_key_exists('expires', $params) && (!is_int($params['expires']) || $params['expires'] < $now)) {
            throw self::fail('Signature expired');
        }
        $keyid = $params['keyid'] ?? null;
        if (!is_string($keyid)) {
            throw self::fail('The signature has no keyid');
        }
        $alg = is_string($params['alg'] ?? null) ? $params['alg'] : null;
        $hash = strpos($keyid, '#');
        if ($hash === false || $hash === 0 || $hash === strlen($keyid) - 1) {
            throw self::fail("keyid is not a URL with a fragment: $keyid");
        }
        $storageId = substr($keyid, 0, $hash);
        if (!Url::isHttp($storageId)) {
            throw self::fail("keyid is not an absolute http(s) URL: $keyid");
        }
        if ($this->trusted !== null && !isset($this->trusted[Url::canonical($storageId)])) {
            throw self::fail("Storage $storageId is not trusted");
        }
        $base = self::signatureBase($method, $url, $headers, $covered);
        $cacheKey = Url::canonical($storageId);
        $cached = $this->cache[$cacheKey] ?? null;
        if ($cached !== null && $cached[1] + $this->keyCacheTtl > ($this->clock)()) {
            try {
                $algorithm = self::verifyWith($cached[0], $storageId, $keyid, $alg, $base, $signature);
            } catch (SignatureVerificationException) {
                // The key may have rotated: fetch the description again, once.
                $algorithm = self::verifyWith($this->fetch($storageId), $storageId, $keyid, $alg, $base, $signature);
            }
        } else {
            $algorithm = self::verifyWith($this->fetch($storageId), $storageId, $keyid, $alg, $base, $signature);
        }
        try {
            $notification = Notification::parse($body);
        } catch (ProtocolException $e) {
            throw self::fail("The signed body is not a valid notification: {$e->getMessage()}");
        }
        if (Url::canonical($notification->storage) !== Url::canonical($storageId)) {
            throw self::fail("Notification storage {$notification->storage} does not match the signing storage $storageId");
        }
        return new VerifiedNotification($notification, $keyid, $storageId, $label, $algorithm);
    }

    /**
     * Verifies the delivery of the current PHP request (`$_SERVER` and `php://input`).
     *
     * @throws SignatureVerificationException when the delivery does not verify
     */
    public function verifyGlobals(string $inboxUrl): VerifiedNotification
    {
        $method = is_string($_SERVER['REQUEST_METHOD'] ?? null) ? $_SERVER['REQUEST_METHOD'] : 'POST';
        return $this->verify($method, $inboxUrl, self::requestHeaders(), (string) file_get_contents('php://input'));
    }

    /**
     * The headers of the current PHP request: `getallheaders()` where the SAPI has it, else
     * {@see headersFromServer()} of `$_SERVER`.
     *
     * @return list<array{0: string, 1: string}>
     */
    private static function requestHeaders(): array
    {
        if (!function_exists('getallheaders')) {
            return self::headersFromServer($_SERVER);
        }
        $headers = [];
        foreach (getallheaders() as $name => $value) {
            $headers[] = [(string) $name, (string) $value];
        }
        return $headers;
    }

    /**
     * Request headers from a `$_SERVER`-style array: the `HTTP_*`, `CONTENT_TYPE` and `CONTENT_LENGTH` members,
     * each field once (some SAPIs set both `CONTENT_TYPE` and `HTTP_CONTENT_TYPE`).
     *
     * @param array<array-key, mixed> $server
     * @return list<array{0: string, 1: string}>
     */
    public static function headersFromServer(array $server): array
    {
        $headers = [];
        $seen = [];
        foreach ($server as $k => $v) {
            $k = (string) $k;
            if (!is_string($v) || !(str_starts_with($k, 'HTTP_') || $k === 'CONTENT_TYPE' || $k === 'CONTENT_LENGTH')) {
                continue;
            }
            $name = strtolower(str_replace('_', '-', str_starts_with($k, 'HTTP_') ? substr($k, 5) : $k));
            if (!isset($seen[$name])) {
                $seen[$name] = true;
                $headers[] = [$name, $v];
            }
        }
        return $headers;
    }

    /**
     * Verifies a PSR-7 server request (needs `psr/http-message`); `inboxUrl` defaults to the request URI.
     *
     * @throws SignatureVerificationException when the delivery does not verify
     */
    public function verifyServerRequest(ServerRequestInterface $request, ?string $inboxUrl = null): VerifiedNotification
    {
        $headers = [];
        foreach ($request->getHeaders() as $name => $values) {
            foreach ($values as $v) {
                $headers[] = [(string) $name, $v];
            }
        }
        return $this->verify($request->getMethod(), $inboxUrl ?? (string) $request->getUri(), $headers, (string) $request->getBody());
    }

    /**
     * The RFC 9421 signature base of a request for the covered components.
     *
     * @throws SignatureVerificationException for an unsupported or missing component
     */
    public static function signatureBase(string $method, string $url, Headers $headers, SfInnerList $covered): string
    {
        $s = '';
        foreach ($covered->items as $item) {
            if (!is_string($item->value)) {
                throw self::fail('A covered component is not a string');
            }
            try {
                $name = StructuredFields::serializeBareItem($item->value);
            } catch (StructuredFieldException) {
                $name = '"' . $item->value . '"';
            }
            $s .= $name . ': ' . self::componentValue($item->value, $method, $url, $headers) . "\n";
        }
        try {
            return $s . '"@signature-params": ' . StructuredFields::serializeInnerList($covered);
        } catch (StructuredFieldException $e) {
            throw self::fail("The signature parameters cannot be serialized: {$e->getMessage()}");
        }
    }

    private static function componentValue(string $name, string $method, string $url, Headers $headers): string
    {
        switch ($name) {
            case '@method':
                return strtoupper($method);
            case '@scheme':
                return Url::scheme($url);
            case '@authority':
                $host = Url::host($url);
                $h = str_contains($host, ':') ? "[$host]" : $host;
                $port = Url::port($url);
                return $port === null || $port === (Url::scheme($url) === 'https' ? 443 : 80) ? $h : "$h:$port";
            case '@path':
                return Url::path($url);
            case '@query':
                $q = Url::query($url);
                return $q === '' ? '?' : $q;
            case '@target-uri':
                return Url::withoutFragment($url);
            case '@request-target':
                return Url::path($url) . Url::query($url);
        }
        if (str_starts_with($name, '@')) {
            throw self::fail("Unsupported derived component $name");
        }
        $values = $headers->all($name);
        if ($values === []) {
            throw self::fail("Covered header field missing: $name");
        }
        return implode(', ', array_map(static fn (string $v): string => trim($v, " \t"), $values));
    }

    private static function verifyWith(StorageDescription $description, string $storageId, string $keyid, ?string $alg, string $base, string $signature): string
    {
        if (Url::canonical($description->id) !== Url::canonical($storageId)) {
            throw self::fail("Storage description id {$description->id} does not match the keyid storage $storageId");
        }
        $method = $description->verificationMethod($keyid) ?? throw self::fail("Verification method $keyid not found in the storage description");
        if (!$description->isAuthenticationMethod($method)) {
            throw self::fail("Verification method $keyid is not referenced from authentication");
        }
        $jwk = $method->publicKeyJwk ?? throw self::fail("Verification method $keyid has no publicKeyJwk");
        try {
            $key = VerificationKey::fromJwk($jwk);
        } catch (\InvalidArgumentException $e) {
            throw self::fail("Unusable verification key $keyid: {$e->getMessage()}");
        }
        $keyAlgorithm = match ($key->curve) {
            'P-256' => 'ecdsa-p256-sha256',
            'P-384' => 'ecdsa-p384-sha384',
            default => 'ed25519',
        };
        if ($alg !== null && $alg !== $keyAlgorithm) {
            throw self::fail("alg $alg does not match the key type ($keyAlgorithm)");
        }
        if (!$key->verify($signature, $base)) {
            throw self::fail('The signature does not verify');
        }
        return $keyAlgorithm;
    }

    private function fetch(string $storageId): StorageDescription
    {
        try {
            $description = ($this->descriptions)($storageId);
        } catch (LwsException $e) {
            throw self::fail("Cannot retrieve the storage description $storageId: {$e->getMessage()}");
        }
        $this->cache[Url::canonical($storageId)] = [$description, ($this->clock)()];
        return $description;
    }

    private static function checkDigest(string $header, string $body): void
    {
        $digests = self::dictionary($header, 'Content-Digest');
        $any = false;
        foreach (['sha-256' => 'sha256', 'sha-512' => 'sha512'] as $name => $algo) {
            if (!isset($digests[$name])) {
                continue;
            }
            $any = true;
            $member = $digests[$name];
            if (!$member instanceof SfItem || !$member->value instanceof SfBytes) {
                throw self::fail("Malformed $name digest");
            }
            if (!hash_equals(hash($algo, $body, true), $member->value->bytes)) {
                throw self::fail("Content-Digest $name mismatch");
            }
        }
        if (!$any) {
            throw self::fail('Content-Digest has no supported algorithm (sha-256, sha-512)');
        }
    }

    private static function field(Headers $headers, string $name): string
    {
        $values = $headers->all($name);
        if ($values === []) {
            throw self::fail("Missing $name header");
        }
        return implode(', ', $values);
    }

    /** @return array<string, SfItem|SfInnerList> */
    private static function dictionary(string $value, string $what): array
    {
        try {
            return StructuredFields::parseDictionary($value);
        } catch (StructuredFieldException $e) {
            throw self::fail("Malformed $what: {$e->getMessage()}");
        }
    }

    private static function fail(string $message): SignatureVerificationException
    {
        return new SignatureVerificationException($message);
    }
}
