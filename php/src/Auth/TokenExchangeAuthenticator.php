<?php
// SPDX-License-Identifier: MIT
declare(strict_types=1);

namespace Ebremer\Lws\Auth;

use Ebremer\Lws\Exception\AuthenticationException;
use Ebremer\Lws\Exception\ProtocolException;
use Ebremer\Lws\Http\AuthChallenge;
use Ebremer\Lws\Http\CurlTransport;
use Ebremer\Lws\Http\Headers;
use Ebremer\Lws\Http\HttpRequest;
use Ebremer\Lws\Http\HttpResponse;
use Ebremer\Lws\Http\HttpTransport;
use Ebremer\Lws\Http\Link;
use Ebremer\Lws\Http\LinkHeader;
use Ebremer\Lws\Internal\HeaderLists;
use Ebremer\Lws\Internal\JsonAccess;
use Ebremer\Lws\Internal\Url;
use Ebremer\Lws\Json\Json;
use Ebremer\Lws\LinkRelation;
use Ebremer\Lws\LwsClient;
use Ebremer\Lws\MediaType;
use Ebremer\Lws\Model\StorageDescription;
use Ebremer\Lws\Vocabulary;

/**
 * The LWS authorization flow (OAuth 2.0 token exchange, RFC 8693):
 *
 * 1. a request is answered `401` with `WWW-Authenticate: Bearer resource_metadata="…"` and a `Link` to the
 *    storage that holds the resource;
 * 2. before asking for a token the client checks what the `401` told it against the URL requested: the metadata
 *    URL is on its origin, the protected resource metadata (RFC 9728) describes that very URL, and the storage's
 *    description puts its root on that origin too;
 * 3. the first authorization server of the metadata that uses HTTPS (loopback hosts excepted) and passes the
 *    optional filter is the issuer; its metadata is read from `/.well-known/lws-configuration` and its `issuer`
 *    checked;
 * 4. the {@see CredentialProvider}'s subject token is exchanged for an access token with `resource = storage`;
 * 5. the request is sent again with the token, even when its URL lies outside the storage and its root, as it has
 *    just passed the checks; later the token is sent at once (until 30 seconds before it expires) to every URL
 *    inside the storage or its root, and nowhere else: a URL outside them gets it only after its own `401` passes
 *    the checks.
 *
 * None of the metadata, storage description and token requests follows a redirect. The challenge of the drafts
 * before 19 October 2026, `Bearer as_uri="…", realm="…"`, is still followed: the request URL must lie inside the
 * realm, which is then the token's storage and the one place it is sent to.
 *
 * ```php
 * $auth = new TokenExchangeAuthenticator(SelfSignedCredentials::didKey(SigningKey::generateP256()));
 * $client = new LwsClient(authenticator: $auth);
 * ```
 */
final class TokenExchangeAuthenticator implements Authenticator
{
    private readonly HttpTransport $transport;
    /** @var \Closure(): float */
    private readonly \Closure $clock;
    /** @var array<string, array{storage: string, scopes: list<string>, token: AccessToken}> (issuer, storage) → token */
    private array $tokens = [];
    /** @var array<string, AuthorizationServerMetadata> issuer → metadata */
    private array $metadata = [];
    /** @var array<string, StorageDescription> storage → description */
    private array $descriptions = [];
    /** @var ?array{url: string, key: string} the request whose challenge was just answered, and its token's key */
    private ?array $retry = null;

    /**
     * @param bool $allowInsecureHttp allow plain-HTTP authorization servers beyond loopback hosts (testing only)
     * @param ?\Closure(string, string): bool $authorizationServerFilter decides whether to trust an authorization server
     *     (its issuer, first argument) for a storage (second) before any credential is sent to it. A malicious storage
     *     can name any server: self-signed tokens are audience-bound to it, but static OpenID or SAML tokens may
     *     not be, so use this filter or audience-restricted tokens.
     * @param ?HttpTransport $transport for metadata, storage description and token requests (default: a
     *     {@see CurlTransport}); it must not follow redirects
     * @param float $refreshMargin refresh tokens this long before they expire, in seconds
     * @param float $timeout the time limit of each metadata, storage description and token request, in seconds
     * @param ?string $userAgent the `User-Agent` of those requests
     * @param ?\Closure(): (int|float) $clock the time in seconds since the epoch (default: the system clock)
     */
    public function __construct(
        public readonly CredentialProvider $credentials,
        private readonly bool $allowInsecureHttp = false,
        private readonly ?\Closure $authorizationServerFilter = null,
        ?HttpTransport $transport = null,
        private readonly float $refreshMargin = 30.0,
        private readonly float $timeout = 30.0,
        private readonly ?string $userAgent = LwsClient::DEFAULT_USER_AGENT,
        ?\Closure $clock = null,
    ) {
        $this->transport = $transport ?? new CurlTransport();
        $this->clock = $clock === null ? static fn (): float => microtime(true) : static fn (): float => (float) $clock();
    }

    /**
     * Adds the cached token whose scope (its storage, and the storage root) contains the URL, the longest scope
     * winning; the retry of a request whose challenge was just answered gets the token the challenge led to.
     */
    public function authorize(AuthRequest $request): AuthRequest
    {
        $now = ($this->clock)();
        $retry = $this->retry;
        $this->retry = null;
        if ($retry !== null && $retry['url'] === Url::withoutFragment($request->url)) {
            $token = $this->tokens[$retry['key']]['token'] ?? null;
            if ($token !== null && $token->isValid($now, $this->refreshMargin)) {
                return $request->withBearerToken($token->value);
            }
        }
        $best = null;
        $depth = -1;
        foreach ($this->tokens as $e) {
            if (!$e['token']->isValid($now, $this->refreshMargin)) {
                continue;
            }
            foreach ($e['scopes'] as $scope) {
                $d = strlen(rtrim(Url::path($scope), '/'));
                if ($d > $depth && Url::contains($scope, $request->url)) {
                    [$best, $depth] = [$e['token'], $d];
                }
            }
        }
        return $best === null ? $request : $request->withBearerToken($best->value);
    }

    /**
     * @throws AuthenticationException when a discovery check fails (the metadata is on another origin, cannot be read
     *     or describes another URL; the 401 links to no storage; the storage root is on another origin), the request
     *     URL is outside the realm of a challenge of the drafts before 19 October 2026, no authorization server is
     *     usable, or the token exchange failed. A cached token stays in use when the challenge is refused.
     */
    public function handleChallenge(AuthRequest $request, AuthResponse $response): bool
    {
        $url = Url::withoutFragment($request->url);
        $current = null;
        $legacy = null;
        foreach ($response->challenges() as $c) {
            if (!$c->isScheme('Bearer')) {
                continue;
            }
            if ($c->resourceMetadata() !== null) {
                $current = $c;
                break;
            }
            if ($legacy === null && $c->asUri() !== null && $c->realm() !== null) {
                $legacy = $c;
            }
        }
        if ($current !== null) {
            [$issuer, $storage, $scopes] = $this->discover($url, $current, $response);
        } elseif ($legacy !== null) {
            [$issuer, $storage, $scopes] = $this->discoverFromRealm($url, $legacy);
        } else {
            return false;
        }
        // Every check, the authorization server's metadata included, comes before the cached token the request
        // carried is touched: a decoy challenge must not evict a working token.
        $md = $this->serverMetadata($issuer);
        $key = self::key($issuer, $storage);
        $cached = $this->tokens[$key] ?? null;
        $sent = $request->headers->first('Authorization');
        if ($cached !== null && (($sent !== null && hash_equals('Bearer ' . $cached['token']->value, $sent))
            || !$cached['token']->isValid(($this->clock)(), $this->refreshMargin))) {
            unset($this->tokens[$key]);
            $cached = null;
        }
        if ($cached === null) {
            $this->exchange($issuer, $storage, $scopes, $md);
        } else {
            $this->tokens[$key]['scopes'] = array_values(array_unique([...$cached['scopes'], ...$scopes]));
        }
        // The URL has passed the checks: its retry carries the token, inside the token's scope or not.
        $this->retry = ['url' => $url, 'key' => $key];
        return true;
    }

    /**
     * A valid access token for a storage, performing the token exchange when needed.
     *
     * @throws AuthenticationException when the exchange fails
     * @throws \InvalidArgumentException when `issuer` or `storage` is not an absolute http(s) URL
     */
    public function accessToken(string $issuer, string $storage): AccessToken
    {
        $cached = $this->tokens[self::key($issuer, $storage)] ?? null;
        if ($cached !== null && $cached['token']->isValid(($this->clock)(), $this->refreshMargin)) {
            return $cached['token'];
        }
        Url::requireHttp($issuer, 'issuer');
        Url::requireHttp($storage, 'storage');
        $this->requireSecure($issuer, 'authorization server');
        return $this->exchange($issuer, $storage, [$storage], $this->serverMetadata($issuer));
    }

    /** Forgets every cached token, metadata document and storage description. */
    public function clear(): void
    {
        $this->tokens = [];
        $this->metadata = [];
        $this->descriptions = [];
        $this->retry = null;
    }

    /**
     * The checks of a challenge with `resource_metadata`, in order: the metadata's origin, the storage link, the
     * metadata's resource, the storage root's origin, then the first usable authorization server.
     *
     * @return array{0: string, 1: string, 2: list<string>} the issuer, the storage and the token's scopes
     */
    private function discover(string $url, AuthChallenge $challenge, AuthResponse $response): array
    {
        $text = (string) $challenge->resourceMetadata();
        $metadataUrl = Url::resolve($text, $url);
        if ($metadataUrl === null || !Url::isHttp($metadataUrl) || !Url::sameOrigin($metadataUrl, $url)) {
            throw new AuthenticationException("The protected resource metadata $text is not on the origin of the request URL $url");
        }
        $storage = Link::first(LinkHeader::parse($response->headers->all('link'), $url), LinkRelation::STORAGE)->href
            ?? throw new AuthenticationException("The 401 response of $url has no link to its storage (rel=\"" . LinkRelation::STORAGE . '")');
        $prm = $this->protectedResourceMetadata($metadataUrl);
        if (!$prm->describes($url)) {
            throw new AuthenticationException("The protected resource metadata $metadataUrl describes {$prm->resource}, not the request URL $url");
        }
        try {
            $root = $this->storageDescription($storage)->storageRoot();
        } catch (ProtocolException $e) {
            throw new AuthenticationException("The storage $storage cannot be checked: {$e->getMessage()}", null, null, null, $e);
        }
        if (!Url::sameOrigin($root, $url)) {
            throw new AuthenticationException("The storage $storage has its root $root on another origin than the request URL $url");
        }
        $refused = [];
        foreach ($prm->authorizationServers as $issuer) {
            $reason = $this->refusal($issuer, $storage);
            if ($reason === null) {
                return [$issuer, $storage, [$storage, $root]];
            }
            $refused[] = "$issuer ($reason)";
        }
        throw new AuthenticationException("No authorization server of $metadataUrl can be used: " . implode(', ', $refused));
    }

    /**
     * The checks of the challenge of the drafts before 19 October 2026: the realm contains the request URL, and
     * `as_uri` is usable.
     *
     * @return array{0: string, 1: string, 2: list<string>} the issuer, the storage (the realm) and the token's scopes
     */
    private function discoverFromRealm(string $url, AuthChallenge $challenge): array
    {
        $issuer = (string) $challenge->asUri();
        $realm = (string) $challenge->realm();
        if (!Url::isHttp($issuer)) {
            throw new AuthenticationException("The challenge as_uri is not an absolute URL: $issuer");
        }
        if (!Url::isHttp($realm)) {
            throw new AuthenticationException("The challenge realm is not an absolute URL: $realm");
        }
        if (!Url::contains($realm, $url)) {
            throw new AuthenticationException("Request URL $url is not within the challenge realm $realm");
        }
        $reason = $this->refusal($issuer, $realm);
        if ($reason !== null) {
            throw new AuthenticationException("Refusing the authorization server $issuer: $reason");
        }
        return [$issuer, $realm, [$realm]];
    }

    /** Why an authorization server cannot be used for a storage, or null when it can. */
    private function refusal(string $issuer, string $storage): ?string
    {
        if (!Url::isHttp($issuer)) {
            return 'not an absolute http(s) URL';
        }
        if (!$this->isSecure($issuer)) {
            return 'insecure, HTTPS required';
        }
        if ($this->authorizationServerFilter !== null && !($this->authorizationServerFilter)($issuer, $storage)) {
            return 'rejected by the authorization server filter';
        }
        return null;
    }

    /** @param list<string> $scopes */
    private function exchange(string $issuer, string $storage, array $scopes, AuthorizationServerMetadata $md): AccessToken
    {
        $this->requireSecure($md->tokenEndpoint, 'token endpoint');
        $type = $this->credentials->tokenType();
        if (!$md->supportsSubjectTokenType($type)) {
            throw new AuthenticationException("Authorization server $issuer does not accept subject tokens of type $type"
                . ' (supported: ' . implode(', ', $md->subjectTokenTypesSupported) . ')');
        }
        $subjectToken = $this->credentials->subjectToken(new CredentialContext($issuer, $storage, $md));
        $form = http_build_query([
            'grant_type' => Vocabulary::GRANT_TYPE_TOKEN_EXCHANGE,
            'resource' => $storage,
            'subject_token' => $subjectToken,
            'subject_token_type' => $type,
        ], '', '&', PHP_QUERY_RFC1738);
        $r = $this->send(new HttpRequest('POST', $md->tokenEndpoint,
            new Headers(['Content-Type' => MediaType::FORM, 'Accept' => MediaType::JSON]), $form), 'token endpoint');
        $json = null;
        if (trim($r->body) !== '') {
            try {
                $json = Json::members(Json::decode($r->body));
            } catch (\JsonException) {
                $json = null;
            }
        }
        if (intdiv($r->status, 100) !== 2) {
            $error = $json === null ? null : JsonAccess::str($json, 'error');
            $description = $json === null ? null : JsonAccess::str($json, 'error_description');
            throw new AuthenticationException("Token exchange at {$md->tokenEndpoint} failed with HTTP {$r->status}"
                . ($error === null ? '' : ": $error") . ($description === null ? '' : " ($description)"), $error, $description, $r->status);
        }
        if ($json === null) {
            throw new AuthenticationException('The token endpoint returned no JSON object', null, null, $r->status);
        }
        try {
            $token = AccessToken::fromTokenResponse($json, ($this->clock)());
        } catch (AuthenticationException $e) {
            throw new AuthenticationException($e->getMessage(), null, null, $r->status, $e);
        }
        $this->tokens[self::key($issuer, $storage)] = ['storage' => $storage, 'scopes' => array_values(array_unique($scopes)), 'token' => $token];
        return $token;
    }

    /** The protected resource metadata (RFC 9728) at a URL; not cached, as it describes one resource. */
    private function protectedResourceMetadata(string $url): ProtectedResourceMetadata
    {
        $r = $this->send(new HttpRequest('GET', $url, new Headers(['Accept' => MediaType::JSON])), 'protected resource metadata');
        if ($r->status !== 200) {
            throw new AuthenticationException("Cannot read the protected resource metadata $url: HTTP {$r->status}", null, null, $r->status);
        }
        if (!HeaderLists::isJson($r->headers->first('content-type') ?? MediaType::JSON)) {
            throw new AuthenticationException("The protected resource metadata $url is not JSON", null, null, $r->status);
        }
        try {
            return ProtectedResourceMetadata::parse(JsonAccess::parse($r->body, 'The protected resource metadata'));
        } catch (ProtocolException $e) {
            throw new AuthenticationException("Invalid protected resource metadata at $url: {$e->getMessage()}", null, null, $r->status, $e);
        }
    }

    /** The description of a storage, read without credentials and cached for the authenticator's lifetime. */
    private function storageDescription(string $storage): StorageDescription
    {
        if (isset($this->descriptions[$storage])) {
            return $this->descriptions[$storage];
        }
        if (!Url::isHttp($storage)) {
            throw new AuthenticationException("The storage $storage is not an http(s) URL");
        }
        $r = $this->send(new HttpRequest('GET', $storage, new Headers(['Accept' => LwsClient::ACCEPT_DESCRIPTION])), 'storage description');
        if ($r->status !== 200) {
            throw new AuthenticationException("Cannot read the storage description $storage: HTTP {$r->status}", null, null, $r->status);
        }
        $ct = $r->headers->first('content-type');
        if ($ct !== null && !HeaderLists::isJson($ct) && HeaderLists::essence($ct) !== MediaType::LWS_CID) {
            throw new AuthenticationException("The storage description $storage has the unexpected media type $ct", null, null, $r->status);
        }
        try {
            $description = StorageDescription::parse(JsonAccess::parse($r->body, 'The storage description'), $storage);
        } catch (ProtocolException $e) {
            throw new AuthenticationException("Invalid storage description at $storage: {$e->getMessage()}", null, null, $r->status, $e);
        }
        return $this->descriptions[$storage] = $description;
    }

    private function serverMetadata(string $issuer): AuthorizationServerMetadata
    {
        if (isset($this->metadata[$issuer])) {
            return $this->metadata[$issuer];
        }
        $url = AuthorizationServerMetadata::metadataUrl($issuer);
        $r = $this->send(new HttpRequest('GET', $url, new Headers(['Accept' => MediaType::JSON])), 'authorization server metadata');
        if ($r->status !== 200) {
            throw new AuthenticationException("Cannot read the authorization server metadata $url: HTTP {$r->status}", null, null, $r->status);
        }
        if (!HeaderLists::isJson($r->headers->first('content-type') ?? MediaType::JSON)) {
            throw new AuthenticationException("The authorization server metadata $url is not JSON", null, null, $r->status);
        }
        try {
            $md = AuthorizationServerMetadata::parse(JsonAccess::parse($r->body, 'The authorization server metadata'), $url);
        } catch (ProtocolException $e) {
            throw new AuthenticationException("Invalid authorization server metadata at $url: {$e->getMessage()}", null, null, $r->status, $e);
        }
        $same = Url::equalsIgnoringTrailingSlash($md->issuer, $issuer)
            || (Url::isHttp($md->issuer) && Url::equalsIgnoringTrailingSlash(Url::canonical($md->issuer), Url::canonical($issuer)));
        if (!$same) {
            throw new AuthenticationException("The authorization server metadata issuer {$md->issuer} does not match the issuer $issuer", null, null, $r->status);
        }
        return $this->metadata[$issuer] = $md;
    }

    /**
     * Sends a metadata, storage description or token request; a redirect is refused, since it would carry credentials
     * to another URL, or have the client trust a document from somewhere else.
     */
    private function send(HttpRequest $request, string $what): HttpResponse
    {
        $headers = $this->userAgent === null ? $request->headers : $request->headers->with('User-Agent', $this->userAgent);
        $response = $this->transport->send(new HttpRequest($request->method, $request->url, $headers, $request->body, $this->timeout));
        if (($response->status >= 300 && $response->status < 400) || $response->url !== $request->url) {
            $location = $response->headers->first('location');
            throw new AuthenticationException('Refusing the redirect' . ($location === null ? '' : " to $location")
                . " of the $what request {$request->url} (HTTP {$response->status}): discovery and token requests follow no redirect",
                null, null, $response->status);
        }
        return $response;
    }

    private function isSecure(string $url): bool
    {
        $scheme = Url::scheme($url);
        return $scheme === 'https' || ($scheme === 'http' && ($this->allowInsecureHttp || Url::isLoopback($url)));
    }

    private function requireSecure(string $url, string $what): void
    {
        if (!$this->isSecure($url)) {
            throw new AuthenticationException("Refusing to use the insecure $what $url (HTTPS required)");
        }
    }

    private static function key(string $issuer, string $storage): string
    {
        return $issuer . ' ' . $storage;
    }

    /** @return array<string, mixed> without tokens */
    public function __debugInfo(): array
    {
        return ['credentials' => $this->credentials, 'storages' => array_column($this->tokens, 'storage')];
    }
}
