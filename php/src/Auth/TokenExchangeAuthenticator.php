<?php
// SPDX-License-Identifier: MIT
declare(strict_types=1);

namespace Ebremer\Lws\Auth;

use Ebremer\Lws\Exception\AuthenticationException;
use Ebremer\Lws\Exception\ProtocolException;
use Ebremer\Lws\Http\CurlTransport;
use Ebremer\Lws\Http\Headers;
use Ebremer\Lws\Http\HttpRequest;
use Ebremer\Lws\Http\HttpResponse;
use Ebremer\Lws\Http\HttpTransport;
use Ebremer\Lws\Internal\HeaderLists;
use Ebremer\Lws\Internal\JsonAccess;
use Ebremer\Lws\Internal\Url;
use Ebremer\Lws\Json\Json;
use Ebremer\Lws\LwsClient;
use Ebremer\Lws\MediaType;
use Ebremer\Lws\Vocabulary;

/**
 * The LWS authorization flow (OAuth 2.0 token exchange, RFC 8693):
 *
 * 1. a request is answered `401` with `WWW-Authenticate: Bearer as_uri="…", realm="…"`;
 * 2. the request URL must lie inside the realm, the authorization server must use HTTPS (loopback hosts
 *    excepted) and pass the optional filter;
 * 3. the authorization server metadata is read from `/.well-known/lws-configuration` (never following a
 *    redirect) and its `issuer` checked;
 * 4. the {@see CredentialProvider}'s subject token is exchanged for an access token with `resource = realm`;
 * 5. the request is sent again with the token, and the token is reused (until 30 seconds before it expires) for
 *    every URL inside the realm, and never sent outside it.
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
    /** @var array<string, array{realm: string, token: AccessToken}> (as_uri, realm) → token */
    private array $tokens = [];
    /** @var array<string, AuthorizationServerMetadata> as_uri → metadata */
    private array $metadata = [];

    /**
     * @param bool $allowInsecureHttp allow plain-HTTP authorization servers beyond loopback hosts (testing only)
     * @param ?\Closure(string, string): bool $authorizationServerFilter decides whether to trust an authorization server
     *     (`as_uri`, first argument) for a realm (second) before any credential is sent to it. A malicious storage
     *     can name any server: self-signed tokens are audience-bound to it, but static OpenID or SAML tokens may
     *     not be, so use this filter or audience-restricted tokens.
     * @param ?HttpTransport $transport for metadata and token requests (default: a {@see CurlTransport}); it must not
     *     follow redirects
     * @param float $refreshMargin refresh tokens this long before they expire, in seconds
     * @param float $timeout the time limit of each metadata and token request, in seconds
     * @param ?string $userAgent the `User-Agent` of metadata and token requests
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

    public function authorize(AuthRequest $request): AuthRequest
    {
        $now = ($this->clock)();
        $best = null;
        foreach ($this->tokens as $e) {
            if ($e['token']->isValid($now, $this->refreshMargin) && Url::contains($e['realm'], $request->url)
                && ($best === null || strlen(Url::path($e['realm'])) > strlen(Url::path($best['realm'])))) {
                $best = $e;
            }
        }
        return $best === null ? $request : $request->withBearerToken($best['token']->value);
    }

    /**
     * @throws AuthenticationException when the request URL is outside the challenge realm, the authorization
     *     server is insecure or rejected, or the token exchange failed. A cached token stays in use when the
     *     challenge is refused.
     */
    public function handleChallenge(AuthRequest $request, AuthResponse $response): bool
    {
        $challenge = null;
        foreach ($response->challenges() as $c) {
            if ($c->isScheme('Bearer') && $c->asUri() !== null && $c->realm() !== null) {
                $challenge = $c;
                break;
            }
        }
        if ($challenge === null) {
            return false;
        }
        $asText = (string) $challenge->asUri();
        $realmText = (string) $challenge->realm();
        $asUri = Url::isHttp($asText) ? $asText : throw new AuthenticationException("The challenge as_uri is not an absolute URL: $asText");
        $realm = Url::isHttp($realmText) ? $realmText : throw new AuthenticationException("The challenge realm is not an absolute URL: $realmText");
        // Every check comes before the cached token the request carried is touched: a decoy challenge must not
        // evict a working token.
        if (!Url::contains($realm, $request->url)) {
            throw new AuthenticationException("Request URL {$request->url} is not within the challenge realm $realmText");
        }
        $this->requireSecure($asUri, 'authorization server');
        if ($this->authorizationServerFilter !== null && !($this->authorizationServerFilter)($asUri, $realm)) {
            throw new AuthenticationException("Authorization server $asText was rejected by the authorization server filter");
        }
        $sent = $request->headers->first('Authorization');
        if ($sent !== null) {
            foreach ($this->tokens as $k => $e) {
                if (hash_equals('Bearer ' . $e['token']->value, $sent)) {
                    unset($this->tokens[$k]);
                }
            }
        }
        $cached = $this->tokens[self::key($asText, $realmText)] ?? null;
        if ($cached === null || !$cached['token']->isValid(($this->clock)(), $this->refreshMargin)) {
            $this->exchange($asText, $realmText);
        }
        return true;
    }

    /**
     * A valid access token for a realm, performing the token exchange when needed.
     *
     * @throws AuthenticationException when the exchange fails
     * @throws \InvalidArgumentException when `asUri` or `realm` is not an absolute http(s) URL
     */
    public function accessToken(string $asUri, string $realm): AccessToken
    {
        $cached = $this->tokens[self::key($asUri, $realm)] ?? null;
        if ($cached !== null && $cached['token']->isValid(($this->clock)(), $this->refreshMargin)) {
            return $cached['token'];
        }
        Url::requireHttp($asUri, 'asUri');
        Url::requireHttp($realm, 'realm');
        $this->requireSecure($asUri, 'authorization server');
        return $this->exchange($asUri, $realm);
    }

    /** Forgets every cached token and metadata document. */
    public function clear(): void
    {
        $this->tokens = [];
        $this->metadata = [];
    }

    private function exchange(string $asUri, string $realm): AccessToken
    {
        $md = $this->serverMetadata($asUri);
        $this->requireSecure($md->tokenEndpoint, 'token endpoint');
        $type = $this->credentials->tokenType();
        if (!$md->supportsSubjectTokenType($type)) {
            throw new AuthenticationException("Authorization server $asUri does not accept subject tokens of type $type"
                . ' (supported: ' . implode(', ', $md->subjectTokenTypesSupported) . ')');
        }
        $subjectToken = $this->credentials->subjectToken(new CredentialContext($asUri, $realm, $md));
        $form = http_build_query([
            'grant_type' => Vocabulary::GRANT_TYPE_TOKEN_EXCHANGE,
            'resource' => $realm,
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
        $this->tokens[self::key($asUri, $realm)] = ['realm' => $realm, 'token' => $token];
        return $token;
    }

    private function serverMetadata(string $asUri): AuthorizationServerMetadata
    {
        if (isset($this->metadata[$asUri])) {
            return $this->metadata[$asUri];
        }
        $url = AuthorizationServerMetadata::metadataUrl($asUri);
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
        $same = Url::equalsIgnoringTrailingSlash($md->issuer, $asUri)
            || (Url::isHttp($md->issuer) && Url::equalsIgnoringTrailingSlash(Url::canonical($md->issuer), Url::canonical($asUri)));
        if (!$same) {
            throw new AuthenticationException("The authorization server metadata issuer {$md->issuer} does not match as_uri $asUri", null, null, $r->status);
        }
        return $this->metadata[$asUri] = $md;
    }

    /** Sends a metadata or token request; a redirect is refused, since it would carry credentials to another URL. */
    private function send(HttpRequest $request, string $what): HttpResponse
    {
        $headers = $this->userAgent === null ? $request->headers : $request->headers->with('User-Agent', $this->userAgent);
        $response = $this->transport->send(new HttpRequest($request->method, $request->url, $headers, $request->body, $this->timeout));
        if (($response->status >= 300 && $response->status < 400) || $response->url !== $request->url) {
            $location = $response->headers->first('location');
            throw new AuthenticationException('Refusing the redirect' . ($location === null ? '' : " to $location")
                . " of the $what request {$request->url} (HTTP {$response->status}): it would carry credentials to another URL",
                null, null, $response->status);
        }
        return $response;
    }

    private function requireSecure(string $url, string $what): void
    {
        $scheme = Url::scheme($url);
        if ($scheme === 'https' || ($scheme === 'http' && ($this->allowInsecureHttp || Url::isLoopback($url)))) {
            return;
        }
        throw new AuthenticationException("Refusing to use the insecure $what $url (HTTPS required)");
    }

    private static function key(string $asUri, string $realm): string
    {
        return $asUri . ' ' . $realm;
    }

    /** @return array<string, mixed> without tokens */
    public function __debugInfo(): array
    {
        return ['credentials' => $this->credentials, 'realms' => array_column($this->tokens, 'realm')];
    }
}
