<?php
// SPDX-License-Identifier: MIT
declare(strict_types=1);

namespace Ebremer\Lws;

use Ebremer\Lws\Access\AccessGrant;
use Ebremer\Lws\Access\AccessRequest;
use Ebremer\Lws\Auth\Authenticator;
use Ebremer\Lws\Auth\AuthRequest;
use Ebremer\Lws\Auth\AuthResponse;
use Ebremer\Lws\Exception\HttpException;
use Ebremer\Lws\Exception\LwsException;
use Ebremer\Lws\Exception\MethodNotAllowedException;
use Ebremer\Lws\Exception\ProtocolException;
use Ebremer\Lws\Http\CurlTransport;
use Ebremer\Lws\Http\Headers;
use Ebremer\Lws\Http\HttpRequest;
use Ebremer\Lws\Http\HttpResponse;
use Ebremer\Lws\Http\HttpTransport;
use Ebremer\Lws\Http\Link;
use Ebremer\Lws\Http\LinkHeader;
use Ebremer\Lws\Http\Slug;
use Ebremer\Lws\Internal\Answer;
use Ebremer\Lws\Internal\Dates;
use Ebremer\Lws\Internal\HeaderLists;
use Ebremer\Lws\Internal\JsonAccess;
use Ebremer\Lws\Internal\Url;
use Ebremer\Lws\Json\Json;
use Ebremer\Lws\Json\JsonPatch;
use Ebremer\Lws\Model\ByteRange;
use Ebremer\Lws\Model\ContainedResource;
use Ebremer\Lws\Model\ContainerPage;
use Ebremer\Lws\Model\CreateResult;
use Ebremer\Lws\Model\Linkset;
use Ebremer\Lws\Model\LinksetDocument;
use Ebremer\Lws\Model\ReadResult;
use Ebremer\Lws\Model\ResourceMetadata;
use Ebremer\Lws\Model\Service;
use Ebremer\Lws\Model\StorageDescription;
use Ebremer\Lws\Model\TypeIndexPage;
use Ebremer\Lws\Model\TypeQuery;
use Ebremer\Lws\Model\UpdateResult;
use Ebremer\Lws\Notification\Subscription;
use Ebremer\Lws\Notification\WebhookSubscriptionRequest;

/**
 * Client for the W3C Linked Web Storage (LWS) Protocol 1.0.
 *
 * ```php
 * $me = SelfSignedCredentials::didKey(SigningKey::generateP256());
 * $client = new LwsClient(authenticator: new TokenExchangeAuthenticator($me));
 * $storage = $client->discoverStorage('https://storage.example/root/');
 * $note = $client->createText($storage->storageRoot(), 'Hello', slug: 'hello.txt');
 * foreach ($client->listContainer($storage->storageRoot()) as $item) {
 *     echo $item->id, "\n";
 * }
 * ```
 *
 * Every operation takes, besides its own options, `headers` (extra request headers, `['Name' => 'value']`) and
 * `timeout` (seconds) as named arguments. Errors are {@see LwsException}s: {@see Exception\NotFoundException},
 * {@see Exception\PreconditionFailedException}, {@see Exception\ConflictException}, … for error statuses,
 * {@see Exception\AuthenticationException}, {@see Exception\ProtocolException} and
 * {@see Exception\TransportException}. Arguments that are not absolute http(s) URLs raise
 * `\InvalidArgumentException` before any request is sent.
 *
 * Redirects are followed by the client itself (at most `maxRedirects`), authorizing every hop afresh for its own
 * URL, so that an access token never leaves its realm. `POST` is never sent twice, except for the single retry
 * after a `401` that the authenticator handled (when nothing was created). Instances are immutable.
 */
final class LwsClient
{
    public const VERSION = '0.1.0';
    public const DEFAULT_USER_AGENT = 'lws-client-php/' . self::VERSION;

    private const ACCEPT_DESCRIPTION = MediaType::LWS_CID . ', ' . MediaType::LD_JSON . ';q=0.9, ' . MediaType::JSON . ';q=0.8';
    private const ACCEPT_LINKSET = MediaType::LINKSET_JSON . ', ' . MediaType::JSON . ';q=0.5';
    private const REDIRECTS = [301, 302, 303, 307, 308];
    private const SAFE_METHODS = ['GET', 'HEAD', 'OPTIONS', 'QUERY'];

    public readonly HttpTransport $transport;
    public readonly Headers $defaultHeaders;

    /**
     * @param ?Authenticator $authenticator how requests are authenticated (null: anonymous)
     * @param ?HttpTransport $transport the HTTP engine (default: a {@see CurlTransport}); it must not follow redirects
     * @param ?string $userAgent the `User-Agent` (null: none)
     * @param Headers|iterable<array-key, mixed> $defaultHeaders headers sent with every request
     * @param ?float $timeout the time limit of each request, in seconds (null: the transport's)
     * @param int $maxRedirects how many redirects a request may follow
     */
    public function __construct(
        public readonly ?Authenticator $authenticator = null,
        ?HttpTransport $transport = null,
        public readonly ?string $userAgent = self::DEFAULT_USER_AGENT,
        Headers|iterable $defaultHeaders = [],
        public readonly ?float $timeout = 30.0,
        public readonly int $maxRedirects = 10,
    ) {
        $this->transport = $transport ?? new CurlTransport();
        $this->defaultHeaders = Headers::of($defaultHeaders);
    }

    /** A client with another authenticator, sharing this client's transport and options. */
    public function withAuthenticator(?Authenticator $authenticator): self
    {
        return new self($authenticator, $this->transport, $this->userAgent, $this->defaultHeaders, $this->timeout, $this->maxRedirects);
    }

    // ------------------------------------------------------------------------------------------------
    // Discovery

    /**
     * Finds the storage a resource belongs to (its `rel="https://www.w3.org/ns/lws#storage"` link, from a `HEAD`,
     * or a `GET` when `HEAD` is answered 405 or 501) and retrieves the storage description.
     *
     * @param Headers|iterable<array-key, mixed> $headers
     * @throws ProtocolException when the response has no storage link or the description is invalid
     */
    public function discoverStorage(string $resourceUrl, Headers|iterable $headers = [], ?float $timeout = null): StorageDescription
    {
        $url = Url::requireHttp($resourceUrl, 'resourceUrl');
        $r = $this->call('HEAD', $url, null, new Headers(), $headers, $timeout);
        if ($r->status === 405 || $r->status === 501) {
            $r = $this->call('GET', $url, null, new Headers(), $headers, $timeout);
        }
        $storage = self::metadata($r)->storage;
        // A 401 SHOULD carry the storage link too, so that anonymous discovery works.
        if ($storage === null || !(intdiv($r->status, 100) === 2 || $r->status === 401)) {
            self::check($r);
            throw new ProtocolException("The response for $url has no storage link (rel=\"" . LinkRelation::STORAGE . '")');
        }
        return $this->getStorageDescription($storage, $headers, $timeout);
    }

    /**
     * Retrieves and parses a storage description (`application/lws+cid`).
     *
     * @param Headers|iterable<array-key, mixed> $headers
     * @throws ProtocolException when the document is not a storage description
     */
    public function getStorageDescription(string $storageUrl, Headers|iterable $headers = [], ?float $timeout = null): StorageDescription
    {
        $url = Url::requireHttp($storageUrl, 'storageUrl');
        $r = $this->call('GET', $url, null, new Headers(['Accept' => self::ACCEPT_DESCRIPTION]), $headers, $timeout);
        self::check($r);
        $ct = $r->headers->first('content-type');
        if ($ct !== null && !HeaderLists::isJson($ct) && HeaderLists::essence($ct) !== MediaType::LWS_CID) {
            throw new ProtocolException("The storage description has the unexpected media type $ct");
        }
        return StorageDescription::parse(JsonAccess::parse($r->body, 'The storage description'), $r->url);
    }

    // ------------------------------------------------------------------------------------------------
    // Reading

    /**
     * Retrieves a resource's metadata (`HEAD`).
     *
     * @param Headers|iterable<array-key, mixed> $headers
     */
    public function head(string $url, Headers|iterable $headers = [], ?float $timeout = null): ResourceMetadata
    {
        $r = $this->call('HEAD', Url::requireHttp($url, 'url'), null, new Headers(), $headers, $timeout);
        self::check($r);
        return self::metadata($r);
    }

    /**
     * Reads a resource (`GET`). A conditional read answered `304` returns a result whose `notModified` is true
     * instead of throwing; `206` is a normal result.
     *
     * @param ?string $accept the `Accept` header
     * @param ?ByteRange $range the bytes to read
     * @param ?string $ifNoneMatch an ETag: read only when it changed
     * @param ?\DateTimeInterface $ifModifiedSince read only when modified since
     * @param ?string $prefer the `Prefer` header
     * @param Headers|iterable<array-key, mixed> $headers
     */
    public function read(
        string $url,
        ?string $accept = null,
        ?ByteRange $range = null,
        ?string $ifNoneMatch = null,
        ?\DateTimeInterface $ifModifiedSince = null,
        ?string $prefer = null,
        Headers|iterable $headers = [],
        ?float $timeout = null,
    ): ReadResult {
        $h = (new Headers())->with('Accept', $accept)->with('Range', $range?->headerValue())->with('If-None-Match', $ifNoneMatch)
            ->with('If-Modified-Since', $ifModifiedSince === null ? null : Dates::formatHttpDate($ifModifiedSince))->with('Prefer', $prefer);
        return self::resource($this->call('GET', Url::requireHttp($url, 'url'), null, $h, $headers, $timeout));
    }

    /**
     * Reads one page of a container listing (`Accept: application/lws+json`); also takes opaque page URLs.
     *
     * @param Headers|iterable<array-key, mixed> $headers
     * @throws ProtocolException when the response is not an LWS container representation
     */
    public function readContainer(string $url, Headers|iterable $headers = [], ?float $timeout = null): ContainerPage
    {
        $r = $this->call('GET', Url::requireHttp($url, 'url'), null, new Headers(['Accept' => MediaType::LWS_JSON]), $headers, $timeout);
        $page = self::page($r);
        if (!$page->isContainer()) {
            throw new ProtocolException("{$r->url} is not a container (type [" . implode(', ', $page->types) . '])');
        }
        return $page;
    }

    /**
     * Every member of a container, fetched lazily page by page (following `rel="next"`).
     *
     * @param Headers|iterable<array-key, mixed> $headers
     * @return PagedSequence<ContainedResource>
     */
    public function listContainer(string $url, Headers|iterable $headers = [], ?float $timeout = null): PagedSequence
    {
        Url::requireHttp($url, 'url');
        $headers = Headers::of($headers);
        $page = function (string $u) use ($headers, $timeout): array {
            $p = $this->readContainer($u, $headers, $timeout);
            return [$p->items, $p->next];
        };
        return new PagedSequence($url, static fn (): array => $page($url), $page(...));
    }

    // ------------------------------------------------------------------------------------------------
    // Creating

    /**
     * Creates a data resource in a container (`POST`); the server assigns its URL (`location`).
     *
     * @param string $body the content bytes
     * @param ?string $slug the identity hint (sent as `Slug`)
     * @param list<string> $types extra resource types (`Link: <type>; rel="type"`)
     * @param list<Link> $links extra links
     * @param Headers|iterable<array-key, mixed> $headers
     * @throws ProtocolException when the response has no `Location`
     */
    public function create(
        string $containerUrl,
        string $body,
        string $contentType,
        ?string $slug = null,
        array $types = [],
        array $links = [],
        Headers|iterable $headers = [],
        ?float $timeout = null,
    ): CreateResult {
        $u = Url::requireHttp($containerUrl, 'containerUrl');
        $h = self::createHeaders($slug, $types, $links, null)->with('Content-Type', $contentType);
        return self::created($this->call('POST', $u, $body, $h, $headers, $timeout));
    }

    /**
     * Creates a text data resource (UTF-8).
     *
     * @param list<string> $types
     * @param list<Link> $links
     * @param Headers|iterable<array-key, mixed> $headers
     */
    public function createText(
        string $containerUrl,
        string $text,
        string $contentType = 'text/plain',
        ?string $slug = null,
        array $types = [],
        array $links = [],
        Headers|iterable $headers = [],
        ?float $timeout = null,
    ): CreateResult {
        return $this->create($containerUrl, $text, $contentType, $slug, $types, $links, $headers, $timeout);
    }

    /**
     * Creates a JSON data resource (`application/json`) from any value `json_encode()` takes.
     *
     * @param list<string> $types
     * @param list<Link> $links
     * @param Headers|iterable<array-key, mixed> $headers
     * @throws \InvalidArgumentException when the value cannot be encoded as JSON
     */
    public function createJson(
        string $containerUrl,
        mixed $value,
        ?string $slug = null,
        array $types = [],
        array $links = [],
        string $contentType = MediaType::JSON,
        Headers|iterable $headers = [],
        ?float $timeout = null,
    ): CreateResult {
        return $this->create($containerUrl, self::encode($value), $contentType, $slug, $types, $links, $headers, $timeout);
    }

    /**
     * Creates a sub-container (`POST` with `Link: <https://www.w3.org/ns/lws#Container>; rel="type"`, empty body).
     *
     * @param list<string> $types
     * @param list<Link> $links
     * @param Headers|iterable<array-key, mixed> $headers
     */
    public function createContainer(
        string $parentUrl,
        ?string $slug = null,
        array $types = [],
        array $links = [],
        Headers|iterable $headers = [],
        ?float $timeout = null,
    ): CreateResult {
        $u = Url::requireHttp($parentUrl, 'parentUrl');
        return self::created($this->call('POST', $u, '', self::createHeaders($slug, $types, $links, ResourceType::CONTAINER), $headers, $timeout));
    }

    // ------------------------------------------------------------------------------------------------
    // Updating and deleting

    /**
     * Replaces a resource's content (`PUT`); pass `ifMatch` to avoid lost updates.
     *
     * @param ?string $ifMatch the ETag the resource must still have
     * @param ?string $ifNoneMatch `*` to create only when absent
     * @param list<Link> $links links to send (with `setLinkset`, the resource's new links)
     * @param bool $setLinkset send `Prefer: set-linkset`
     * @param Headers|iterable<array-key, mixed> $headers
     */
    public function update(
        string $url,
        string $body,
        string $contentType,
        ?string $ifMatch = null,
        ?string $ifNoneMatch = null,
        array $links = [],
        bool $setLinkset = false,
        Headers|iterable $headers = [],
        ?float $timeout = null,
    ): UpdateResult {
        return $this->updateCore('PUT', $url, $body, $contentType, $ifMatch, $ifNoneMatch, $links, $setLinkset, $headers, $timeout);
    }

    /**
     * Patches a resource (`PATCH`): with a {@see JsonPatch} (`application/json-patch+json`, the LWS baseline), or
     * with bytes in any format the server advertises in `Accept-Patch` (then `contentType` is required).
     *
     * @param list<Link> $links
     * @param Headers|iterable<array-key, mixed> $headers
     * @throws \InvalidArgumentException for bytes without a content type
     */
    public function patch(
        string $url,
        JsonPatch|string $patch,
        ?string $contentType = null,
        ?string $ifMatch = null,
        array $links = [],
        bool $setLinkset = false,
        Headers|iterable $headers = [],
        ?float $timeout = null,
    ): UpdateResult {
        if ($patch instanceof JsonPatch) {
            return $this->updateCore('PATCH', $url, $patch->encode(), $contentType ?? MediaType::JSON_PATCH, $ifMatch, null, $links, $setLinkset, $headers, $timeout);
        }
        if ($contentType === null) {
            throw new \InvalidArgumentException('A patch given as bytes needs its content type');
        }
        return $this->updateCore('PATCH', $url, $patch, $contentType, $ifMatch, null, $links, $setLinkset, $headers, $timeout);
    }

    /**
     * @param list<Link> $links
     * @param Headers|iterable<array-key, mixed> $headers
     */
    private function updateCore(string $method, string $url, string $body, string $contentType, ?string $ifMatch, ?string $ifNoneMatch,
        array $links, bool $setLinkset, Headers|iterable $headers, ?float $timeout): UpdateResult
    {
        $u = Url::requireHttp($url, 'url');
        $h = (new Headers(['Content-Type' => $contentType]))->with('If-Match', $ifMatch)->with('If-None-Match', $ifNoneMatch);
        foreach ($links as $l) {
            $h = $h->withAdded('Link', LinkHeader::format($l));
        }
        if ($setLinkset) {
            $h = $h->with('Prefer', Prefer::SET_LINKSET);
        }
        $r = $this->call($method, $u, $body, $h, $headers, $timeout);
        self::check($r);
        return new UpdateResult($r->status, self::metadata($r), $r->body);
    }

    /**
     * Deletes a resource; a non-empty container needs `recursive` (else {@see Exception\ConflictException}).
     *
     * @param Headers|iterable<array-key, mixed> $headers
     */
    public function delete(string $url, ?string $ifMatch = null, bool $recursive = false, Headers|iterable $headers = [], ?float $timeout = null): void
    {
        $h = (new Headers())->with('If-Match', $ifMatch)->with('Depth', $recursive ? 'infinity' : null);
        self::check($this->call('DELETE', Url::requireHttp($url, 'url'), null, $h, $headers, $timeout));
    }

    // ------------------------------------------------------------------------------------------------
    // Metadata (linksets)

    /**
     * The linkset resource of a resource (`HEAD`, `rel="linkset"`).
     *
     * @param Headers|iterable<array-key, mixed> $headers
     * @throws ProtocolException when the resource has no linkset link
     */
    public function linksetUrl(string $resourceUrl, Headers|iterable $headers = [], ?float $timeout = null): string
    {
        $m = $this->head($resourceUrl, $headers, $timeout);
        return $m->linkset ?? throw new ProtocolException("{$m->url} has no linkset link");
    }

    /**
     * Discovers and reads a resource's linkset (`application/linkset+json`).
     *
     * @param Headers|iterable<array-key, mixed> $headers
     */
    public function readLinkset(string $resourceUrl, Headers|iterable $headers = [], ?float $timeout = null): LinksetDocument
    {
        return $this->readLinksetResource($this->linksetUrl($resourceUrl, $headers, $timeout), $headers, $timeout);
    }

    /**
     * Reads a linkset resource at a known URL.
     *
     * @param Headers|iterable<array-key, mixed> $headers
     */
    public function readLinksetResource(string $linksetUrl, Headers|iterable $headers = [], ?float $timeout = null): LinksetDocument
    {
        $r = $this->call('GET', Url::requireHttp($linksetUrl, 'linksetUrl'), null, new Headers(['Accept' => self::ACCEPT_LINKSET]), $headers, $timeout);
        self::check($r);
        return new LinksetDocument($r->url, Linkset::parse(JsonAccess::parse($r->body, 'The linkset')), self::metadata($r));
    }

    /**
     * Replaces a linkset (`PUT`; only when the server allows it, else {@see MethodNotAllowedException}).
     *
     * @param Headers|iterable<array-key, mixed> $headers
     */
    public function updateLinkset(string $linksetUrl, Linkset $linkset, ?string $ifMatch = null, Headers|iterable $headers = [], ?float $timeout = null): UpdateResult
    {
        return $this->updateCore('PUT', $linksetUrl, $linkset->encode(), MediaType::LINKSET_JSON, $ifMatch, null, [], false, $headers, $timeout);
    }

    /**
     * Patches a linkset with JSON Patch; {@see Json\JsonPointer} escapes relation keys that are URIs.
     *
     * @param Headers|iterable<array-key, mixed> $headers
     */
    public function patchLinkset(string $linksetUrl, JsonPatch $patch, ?string $ifMatch = null, Headers|iterable $headers = [], ?float $timeout = null): UpdateResult
    {
        return $this->patch($linksetUrl, $patch, ifMatch: $ifMatch, headers: $headers, timeout: $timeout);
    }

    // ------------------------------------------------------------------------------------------------
    // Notifications

    /**
     * Creates a webhook subscription at a notification service: its endpoint URL, or the {@see Service} of a
     * storage description (then it must offer `WebhookSubscription`).
     *
     * @param Headers|iterable<array-key, mixed> $headers
     * @throws ProtocolException when the service does not support webhooks, or the response has neither a
     *     subscription URL nor a `Location`
     */
    public function subscribe(string|Service $service, WebhookSubscriptionRequest $request, Headers|iterable $headers = [], ?float $timeout = null): Subscription
    {
        if ($service instanceof Service) {
            $types = $service->subscriptionTypes();
            if ($types !== [] && !in_array(SubscriptionType::WEBHOOK, $types, true)) {
                throw new ProtocolException("The notification service {$service->serviceEndpoint} does not support " . SubscriptionType::WEBHOOK);
            }
            $service = $service->serviceEndpoint;
        }
        $u = Url::requireHttp($service, 'serviceUrl');
        $r = $this->call('POST', $u, Json::encode($request->toJson()), self::jsonHeaders(), $headers, $timeout);
        self::check($r);
        $location = $r->headers->first('location');
        $location = $location === null ? null : Url::resolve($location, $r->url);
        if (trim($r->body) === '') {
            if ($location === null) {
                throw new ProtocolException('The subscription response has neither a body nor a Location');
            }
            return Subscription::parse(['type' => SubscriptionType::WEBHOOK], $r->url, $location);
        }
        return Subscription::parse(JsonAccess::parse($r->body, 'The subscription'), $r->url, $location);
    }

    /**
     * The subscriber's subscriptions: the container listing of the notification service.
     *
     * @param Headers|iterable<array-key, mixed> $headers
     * @return PagedSequence<ContainedResource>
     */
    public function listSubscriptions(string $serviceUrl, Headers|iterable $headers = [], ?float $timeout = null): PagedSequence
    {
        return $this->listContainer($serviceUrl, $headers, $timeout);
    }

    /**
     * Retrieves a subscription's current state.
     *
     * @param Headers|iterable<array-key, mixed> $headers
     */
    public function getSubscription(string $url, Headers|iterable $headers = [], ?float $timeout = null): Subscription
    {
        $r = $this->call('GET', Url::requireHttp($url, 'url'), null, new Headers(['Accept' => MediaType::LWS_JSON]), $headers, $timeout);
        self::check($r);
        return Subscription::parse(JsonAccess::parse($r->body, 'The subscription'), $r->url, $r->url);
    }

    /**
     * Cancels a subscription (`DELETE`).
     *
     * @param Headers|iterable<array-key, mixed> $headers
     */
    public function unsubscribe(string $url, Headers|iterable $headers = [], ?float $timeout = null): void
    {
        $this->delete($url, headers: $headers, timeout: $timeout);
    }

    // ------------------------------------------------------------------------------------------------
    // Access requests and grants

    /**
     * Submits an access request; returns its URL (`Location`).
     *
     * @param Headers|iterable<array-key, mixed> $headers
     */
    public function requestAccess(string $serviceUrl, AccessRequest $request, Headers|iterable $headers = [], ?float $timeout = null): string
    {
        return $this->postForLocation($serviceUrl, $request->toJson(), $headers, $timeout);
    }

    /**
     * The access requests: the container listing of the service.
     *
     * @param Headers|iterable<array-key, mixed> $headers
     * @return PagedSequence<ContainedResource>
     */
    public function listAccessRequests(string $serviceUrl, Headers|iterable $headers = [], ?float $timeout = null): PagedSequence
    {
        return $this->listContainer($serviceUrl, $headers, $timeout);
    }

    /**
     * Retrieves an access request (its `raw` is the document as sent).
     *
     * @param Headers|iterable<array-key, mixed> $headers
     */
    public function getAccessRequest(string $url, Headers|iterable $headers = [], ?float $timeout = null): AccessRequest
    {
        return AccessRequest::parse($this->getJson($url, $headers, $timeout));
    }

    /**
     * Cancels (deletes) an access request.
     *
     * @param Headers|iterable<array-key, mixed> $headers
     */
    public function cancelAccessRequest(string $url, Headers|iterable $headers = [], ?float $timeout = null): void
    {
        $this->delete($url, headers: $headers, timeout: $timeout);
    }

    /**
     * Creates an access grant (as storage controller); returns its URL (`Location`).
     *
     * @param Headers|iterable<array-key, mixed> $headers
     */
    public function grantAccess(string $serviceUrl, AccessGrant $grant, Headers|iterable $headers = [], ?float $timeout = null): string
    {
        return $this->postForLocation($serviceUrl, $grant->toJson(), $headers, $timeout);
    }

    /**
     * The access grants: the container listing of the service.
     *
     * @param Headers|iterable<array-key, mixed> $headers
     * @return PagedSequence<ContainedResource>
     */
    public function listAccessGrants(string $serviceUrl, Headers|iterable $headers = [], ?float $timeout = null): PagedSequence
    {
        return $this->listContainer($serviceUrl, $headers, $timeout);
    }

    /**
     * Retrieves an access grant (its `raw` is the document as sent).
     *
     * @param Headers|iterable<array-key, mixed> $headers
     */
    public function getAccessGrant(string $url, Headers|iterable $headers = [], ?float $timeout = null): AccessGrant
    {
        return AccessGrant::parse($this->getJson($url, $headers, $timeout));
    }

    /**
     * Revokes (deletes) an access grant.
     *
     * @param Headers|iterable<array-key, mixed> $headers
     */
    public function revokeAccessGrant(string $url, Headers|iterable $headers = [], ?float $timeout = null): void
    {
        $this->delete($url, headers: $headers, timeout: $timeout);
    }

    // ------------------------------------------------------------------------------------------------
    // Type index and type search

    /**
     * Reads a type index page (the service endpoint, or an opaque page URL).
     *
     * @param Headers|iterable<array-key, mixed> $headers
     */
    public function readTypeIndex(string $url, Headers|iterable $headers = [], ?float $timeout = null): TypeIndexPage
    {
        $r = $this->call('GET', Url::requireHttp($url, 'url'), null, new Headers(['Accept' => MediaType::LWS_JSON]), $headers, $timeout);
        self::check($r);
        self::requireLwsJson($r);
        return TypeIndexPage::parse(JsonAccess::parse($r->body, 'The type index'), self::metadata($r));
    }

    /**
     * Every type IRI of a type index, fetched lazily page by page.
     *
     * @param Headers|iterable<array-key, mixed> $headers
     * @return PagedSequence<string>
     */
    public function listTypes(string $serviceUrl, Headers|iterable $headers = [], ?float $timeout = null): PagedSequence
    {
        Url::requireHttp($serviceUrl, 'serviceUrl');
        $headers = Headers::of($headers);
        $page = function (string $u) use ($headers, $timeout): array {
            $p = $this->readTypeIndex($u, $headers, $timeout);
            return [$p->types, $p->next];
        };
        return new PagedSequence($serviceUrl, static fn (): array => $page($serviceUrl), $page(...));
    }

    /**
     * Runs a type search (HTTP `QUERY`, RFC 10008, with an `application/lws-query+json` filter) and returns the
     * first page. The page's `id` is the page URL when the body has none.
     *
     * @param Headers|iterable<array-key, mixed> $headers
     */
    public function searchTypes(string $serviceUrl, TypeQuery $query, Headers|iterable $headers = [], ?float $timeout = null): ContainerPage
    {
        $u = Url::requireHttp($serviceUrl, 'serviceUrl');
        $h = new Headers(['Content-Type' => MediaType::LWS_QUERY_JSON, 'Accept' => MediaType::LWS_JSON]);
        return self::page($this->call('QUERY', $u, $query->encode(), $h, $headers, $timeout));
    }

    /**
     * Every search result: the first page by `QUERY`, further pages by `GET` of the opaque `next` links.
     *
     * @param Headers|iterable<array-key, mixed> $headers
     * @return PagedSequence<ContainedResource>
     */
    public function searchAll(string $serviceUrl, TypeQuery $query, Headers|iterable $headers = [], ?float $timeout = null): PagedSequence
    {
        Url::requireHttp($serviceUrl, 'serviceUrl');
        $headers = Headers::of($headers);
        $query = clone $query;
        return new PagedSequence(
            $serviceUrl,
            function () use ($serviceUrl, $query, $headers, $timeout): array {
                $p = $this->searchTypes($serviceUrl, $query, $headers, $timeout);
                return [$p->items, $p->next];
            },
            function (string $u) use ($headers, $timeout): array {
                $p = self::page($this->call('GET', Url::requireHttp($u, 'url'), null, new Headers(['Accept' => MediaType::LWS_JSON]), $headers, $timeout));
                return [$p->items, $p->next];
            },
        );
    }

    /**
     * The query formats a search service accepts (`OPTIONS`, `Accept-Query`).
     *
     * @param Headers|iterable<array-key, mixed> $headers
     * @return list<string>
     */
    public function acceptedQueryFormats(string $serviceUrl, Headers|iterable $headers = [], ?float $timeout = null): array
    {
        $r = $this->call('OPTIONS', Url::requireHttp($serviceUrl, 'serviceUrl'), null, new Headers(), $headers, $timeout);
        self::check($r);
        return array_map(HeaderLists::unquote(...), HeaderLists::split($r->headers->all('accept-query')));
    }

    // ------------------------------------------------------------------------------------------------
    // Low-level access

    /**
     * Sends any request through the client's pipeline (authentication, redirects). An error status throws the
     * matching exception; `304` yields a not-modified result.
     *
     * @param Headers|iterable<array-key, mixed> $headers
     */
    public function request(string $method, string $url, ?string $body = null, ?string $contentType = null, Headers|iterable $headers = [], ?float $timeout = null): ReadResult
    {
        if (preg_match('/^[!#$%&\'*+\-.^_`|~0-9A-Za-z]+$/', $method) !== 1) {
            throw new \InvalidArgumentException("Invalid method: $method");
        }
        $h = (new Headers())->with('Content-Type', $contentType);
        return self::resource($this->call($method, Url::requireHttp($url, 'url'), $body, $h, $headers, $timeout));
    }

    // ------------------------------------------------------------------------------------------------
    // The request pipeline

    /**
     * Sends a request: authenticating, retrying once after a handled 401, following redirects. The response
     * carries the URL of the hop that produced it.
     *
     * @param Headers|iterable<array-key, mixed> $callHeaders
     */
    private function call(string $method, string $url, ?string $body, Headers $headers, Headers|iterable $callHeaders, ?float $timeout): Answer
    {
        $headers = $headers->merge(Headers::of($callHeaders));
        $timeout ??= $this->timeout;
        $userAuth = $headers->has('Authorization') || $this->defaultHeaders->has('Authorization');
        $hops = 0;
        while (true) {
            $attempt = $this->prepare($method, $url, $headers, $userAuth);
            $response = $this->dispatch($attempt, $body, $timeout);
            if ($response->status === 401 && $this->authenticator !== null
                && $this->authenticator->handleChallenge($attempt, new AuthResponse($url, 401, $response->headers))) {
                $attempt = $this->prepare($method, $url, $headers, $userAuth);
                $response = $this->dispatch($attempt, $body, $timeout);
            }
            $answer = new Answer($method, $url, $response->status, $response->headers, $response->body);
            $location = $response->headers->first('location');
            if (!in_array($response->status, self::REDIRECTS, true) || $location === null) {
                return $answer;
            }
            $target = Url::resolve($location, $url);
            if ($target === null || !Url::isHttp($target)) {
                return $answer;
            }
            $safe = in_array($method, self::SAFE_METHODS, true);
            if ($response->status === 303 && $safe) {
                // See Other: retrieve the result with GET (HEAD stays HEAD), without a body.
                if ($method !== 'HEAD') {
                    $method = 'GET';
                }
                $body = null;
                foreach ($headers->names() as $name) {
                    if (str_starts_with(strtolower($name), 'content-')) {
                        $headers = $headers->without($name);
                    }
                }
            } elseif (!(($safe && ($response->status === 301 || $response->status === 302)) || $response->status === 307 || $response->status === 308)) {
                return $answer;
            }
            if (++$hops > $this->maxRedirects) {
                throw new ProtocolException("Too many redirects (more than {$this->maxRedirects}) at $url");
            }
            // An Authorization header the caller set explicitly survives same-origin redirects only; the
            // authenticator's tokens are evaluated afresh for the new URL.
            if ($userAuth && !Url::sameOrigin($url, $target)) {
                $userAuth = false;
            }
            $url = Url::withoutFragment($target);
        }
    }

    private function prepare(string $method, string $url, Headers $callHeaders, bool $keepUserAuthorization): AuthRequest
    {
        $h = $this->defaultHeaders;
        if ($this->userAgent !== null && !$h->has('User-Agent') && !$callHeaders->has('User-Agent')) {
            $h = $h->with('User-Agent', $this->userAgent);
        }
        $h = $h->merge($callHeaders);
        if (!$keepUserAuthorization) {
            $h = $h->without('Authorization');
        }
        $request = new AuthRequest($method, $url, $h);
        return $this->authenticator === null ? $request : $this->authenticator->authorize($request);
    }

    private function dispatch(AuthRequest $attempt, ?string $body, ?float $timeout): HttpResponse
    {
        return $this->transport->send(new HttpRequest($attempt->method, Url::withoutFragment($attempt->url), $attempt->headers, $body, $timeout));
    }

    // ------------------------------------------------------------------------------------------------
    // Internals of the operations

    private static function check(Answer $r): void
    {
        if (intdiv($r->status, 100) !== 2) {
            throw HttpException::fromResponse($r->status, $r->method, $r->url, $r->headers, $r->body);
        }
    }

    private static function metadata(Answer $r): ResourceMetadata
    {
        return new ResourceMetadata($r->url, $r->status, $r->headers);
    }

    private static function jsonHeaders(): Headers
    {
        return new Headers(['Content-Type' => MediaType::LWS_JSON, 'Accept' => MediaType::LWS_JSON]);
    }

    private static function resource(Answer $r): ReadResult
    {
        if ($r->status === 304) {
            return new ReadResult(self::metadata($r), '', true);
        }
        self::check($r);
        return new ReadResult(self::metadata($r), $r->body, false);
    }

    private static function page(Answer $r): ContainerPage
    {
        self::check($r);
        self::requireLwsJson($r);
        return ContainerPage::parse(JsonAccess::parse($r->body, 'The container representation'), self::metadata($r));
    }

    private static function requireLwsJson(Answer $r): void
    {
        $essence = HeaderLists::essence($r->headers->first('content-type'));
        if ($essence !== null && $essence !== MediaType::LWS_JSON && $essence !== MediaType::LD_JSON && $essence !== MediaType::JSON) {
            throw new ProtocolException("Unexpected media type $essence for an LWS JSON representation at {$r->url}");
        }
    }

    private static function created(Answer $r): CreateResult
    {
        self::check($r);
        $location = $r->headers->first('location')
            ?? throw new ProtocolException("The create response (HTTP {$r->status}) from {$r->url} has no Location header");
        $resolved = Url::resolve($location, $r->url) ?? throw new ProtocolException("Invalid Location header: $location");
        return new CreateResult($resolved, self::metadata($r), $r->body);
    }

    /**
     * @param list<string> $types
     * @param list<Link> $links
     */
    private static function createHeaders(?string $slug, array $types, array $links, ?string $containerType): Headers
    {
        $h = new Headers();
        if ($containerType !== null) {
            $h = $h->withAdded('Link', LinkHeader::format($containerType, LinkRelation::TYPE));
        }
        foreach ($types as $t) {
            $h = $h->withAdded('Link', LinkHeader::format($t, LinkRelation::TYPE));
        }
        foreach ($links as $l) {
            $h = $h->withAdded('Link', LinkHeader::format($l));
        }
        return $slug === null ? $h : $h->with(Slug::HEADER, Slug::encode($slug));
    }

    /**
     * @param array<array-key, mixed> $document
     * @param Headers|iterable<array-key, mixed> $headers
     */
    private function postForLocation(string $serviceUrl, array $document, Headers|iterable $headers, ?float $timeout): string
    {
        $u = Url::requireHttp($serviceUrl, 'serviceUrl');
        return self::created($this->call('POST', $u, Json::encode($document), self::jsonHeaders(), $headers, $timeout))->location;
    }

    /** @param Headers|iterable<array-key, mixed> $headers */
    private function getJson(string $url, Headers|iterable $headers, ?float $timeout): mixed
    {
        $r = $this->call('GET', Url::requireHttp($url, 'url'), null, new Headers(['Accept' => MediaType::LWS_JSON]), $headers, $timeout);
        self::check($r);
        return JsonAccess::parse($r->body, "The response of {$r->url}");
    }

    private static function encode(mixed $value): string
    {
        try {
            return Json::encode($value);
        } catch (\JsonException $e) {
            throw new \InvalidArgumentException('The value cannot be encoded as JSON: ' . $e->getMessage(), 0, $e);
        }
    }
}
