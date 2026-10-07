<?php
// SPDX-License-Identifier: MIT
//
// The PHP adapter of the lws-client driver.
//
// Runs the operations of driver/PROTOCOL.md with the LwsClient of the ebremer/lws-client package (../../../php),
// speaking the line-delimited JSON protocol lws-driver/1 on stdin and stdout:
//
//   php driver/adapters/php/adapter.php
//
// It loads the library through Composer's autoloader when the repository has one (composer install), and
// otherwise from the sources directly, so it needs nothing but PHP 8.2+ with curl, openssl and sodium.
declare(strict_types=1);

namespace Ebremer\Lws\DriverAdapter;

use Ebremer\Lws\Access\AccessGrant;
use Ebremer\Lws\Access\AccessRequest;
use Ebremer\Lws\Auth\Authenticator;
use Ebremer\Lws\Auth\BearerTokenAuthenticator;
use Ebremer\Lws\Auth\OpenIdCredentials;
use Ebremer\Lws\Auth\SelfSignedCredentials;
use Ebremer\Lws\Auth\SigningKey;
use Ebremer\Lws\Auth\TokenExchangeAuthenticator;
use Ebremer\Lws\Exception\AuthenticationException;
use Ebremer\Lws\Exception\BadRequestException;
use Ebremer\Lws\Exception\ConflictException;
use Ebremer\Lws\Exception\ForbiddenException;
use Ebremer\Lws\Exception\GoneException;
use Ebremer\Lws\Exception\HttpException;
use Ebremer\Lws\Exception\InsufficientStorageException;
use Ebremer\Lws\Exception\MethodNotAllowedException;
use Ebremer\Lws\Exception\NotAcceptableException;
use Ebremer\Lws\Exception\NotFoundException;
use Ebremer\Lws\Exception\NotImplementedException;
use Ebremer\Lws\Exception\PreconditionFailedException;
use Ebremer\Lws\Exception\ProtocolException;
use Ebremer\Lws\Exception\SignatureVerificationException;
use Ebremer\Lws\Exception\TransportException;
use Ebremer\Lws\Exception\UnauthorizedException;
use Ebremer\Lws\Exception\UnprocessableContentException;
use Ebremer\Lws\Exception\UnsupportedMediaTypeException;
use Ebremer\Lws\Http\Link;
use Ebremer\Lws\Http\ProblemDetails;
use Ebremer\Lws\Json\Json;
use Ebremer\Lws\Json\JsonPatch;
use Ebremer\Lws\LwsClient;
use Ebremer\Lws\Model\ByteRange;
use Ebremer\Lws\Model\ContainedResource;
use Ebremer\Lws\Model\ContainerPage;
use Ebremer\Lws\Model\CreateResult;
use Ebremer\Lws\Model\Linkset;
use Ebremer\Lws\Model\ReadResult;
use Ebremer\Lws\Model\ResourceMetadata;
use Ebremer\Lws\Model\Service;
use Ebremer\Lws\Model\StorageDescription;
use Ebremer\Lws\Model\TypeQuery;
use Ebremer\Lws\Model\UpdateResult;
use Ebremer\Lws\Notification\Subscription;
use Ebremer\Lws\Notification\WebhookSubscriptionRequest;
use Ebremer\Lws\Notification\WebhookVerifier;

const PROTOCOL = 'lws-driver/1';

/** An error the adapter reports itself: `InvalidArguments` or `Unsupported`. */
final class AdapterError extends \RuntimeException
{
    public function __construct(public readonly string $kind, string $message)
    {
        parent::__construct($message);
    }

    public static function invalid(string $message): self
    {
        return new self('InvalidArguments', $message);
    }
}

// ---------------------------------------------------------------------------------------------
// Arguments

/** The arguments of a request: a JSON object's members. */
final class Args
{
    /** @param array<array-key, mixed> $members */
    public function __construct(private readonly array $members)
    {
    }

    public static function of(mixed $value, string $what): self
    {
        if ($value === null || $value === []) {
            return new self([]);
        }
        $m = Json::members($value);
        if ($m === null && !$value instanceof \stdClass) {
            throw AdapterError::invalid("$what must be an object");
        }
        return new self($m ?? []);
    }

    public function has(string $name): bool
    {
        return ($this->members[$name] ?? null) !== null;
    }

    public function raw(string $name): mixed
    {
        return $this->members[$name] ?? null;
    }

    public function str(string $name): string
    {
        return $this->optStr($name) ?? throw AdapterError::invalid("missing argument '$name'");
    }

    public function optStr(string $name): ?string
    {
        $v = $this->members[$name] ?? null;
        if ($v !== null && !is_string($v)) {
            throw AdapterError::invalid("argument '$name' must be a string");
        }
        return $v;
    }

    /** A request target: an absolute URL. A relative one is malformed (PROTOCOL.md section 3). */
    public function url(string $name): string
    {
        $v = $this->str($name);
        if (preg_match('/^[A-Za-z][A-Za-z0-9+.\-]*:/', $v) !== 1) {
            throw AdapterError::invalid("argument '$name' must be an absolute URL, not '$v'");
        }
        return $v;
    }

    public function optBool(string $name): ?bool
    {
        $v = $this->members[$name] ?? null;
        if ($v !== null && !is_bool($v)) {
            throw AdapterError::invalid("argument '$name' must be a boolean");
        }
        return $v;
    }

    /** An integer of at least `minimum`; a JSON number without a fraction (`2.0`) counts. */
    public function optInt(string $name, int $minimum = 0): ?int
    {
        $v = $this->members[$name] ?? null;
        if ($v === null) {
            return null;
        }
        if (is_float($v) && floor($v) === $v && abs($v) < 9.0e18) {
            $v = (int) $v;
        }
        if (!is_int($v) || $v < $minimum) {
            throw AdapterError::invalid("argument '$name' must be " . ($minimum === 0 ? 'a non-negative integer' : "an integer of at least $minimum"));
        }
        return $v;
    }

    /** @return array<array-key, mixed>|\stdClass */
    public function object(string $name): array|\stdClass
    {
        return $this->optObject($name) ?? throw AdapterError::invalid("missing argument '$name'");
    }

    /** @return array<array-key, mixed>|\stdClass|null the object as decoded (empty objects stay `\stdClass`) */
    public function optObject(string $name): array|\stdClass|null
    {
        $v = $this->members[$name] ?? null;
        if ($v === null) {
            return null;
        }
        if (!$v instanceof \stdClass && !Json::isObject($v)) {
            throw AdapterError::invalid("argument '$name' must be an object");
        }
        return $v;
    }

    /** @return list<mixed>|null */
    public function optList(string $name): ?array
    {
        $v = $this->members[$name] ?? null;
        if ($v !== null && !Json::isList($v)) {
            throw AdapterError::invalid("argument '$name' must be an array");
        }
        return $v;
    }

    /** @return list<string>|null */
    public function optStrings(string $name): ?array
    {
        $v = $this->optList($name);
        if ($v !== null && count(array_filter($v, 'is_string')) !== count($v)) {
            throw AdapterError::invalid("argument '$name' must be an array of strings");
        }
        /** @var list<string>|null $v */
        return $v;
    }

    /** @return list<string> */
    public function strings(string $name): array
    {
        return $this->optStrings($name) ?? throw AdapterError::invalid("missing argument '$name'");
    }

    public function limit(): int
    {
        return $this->optInt('limit') ?? 1000;
    }
}

/**
 * A `body` argument as bytes, with the content type it implies.
 *
 * @return array{0: string, 1: string}
 */
function body_of(mixed $body, ?string $contentType): array
{
    if ($body === null) {
        return ['', $contentType ?? 'application/octet-stream'];
    }
    $b = Json::members($body);
    if ($b === null) {
        throw AdapterError::invalid("argument 'body' must be an object");
    }
    if (is_string($b['text'] ?? null)) {
        return [$b['text'], $contentType ?? 'text/plain'];
    }
    if (is_string($b['base64'] ?? null)) {
        $data = preg_match('/^[A-Za-z0-9+\/]*={0,2}$/', $b['base64']) === 1 ? base64_decode($b['base64'], true) : false;
        if ($data === false || strlen($b['base64']) % 4 !== 0) {
            throw AdapterError::invalid("argument 'body': invalid base64");
        }
        return [$data, $contentType ?? 'application/octet-stream'];
    }
    if (array_key_exists('json', $b)) {
        try {
            return [Json::encode($b['json']), $contentType ?? 'application/json'];
        } catch (\JsonException $e) {
            throw AdapterError::invalid("argument 'body': {$e->getMessage()}");
        }
    }
    throw AdapterError::invalid("argument 'body' must have text, base64 or json");
}

/** Rebuilds an RFC 6902 operations array with the library's JsonPatch builder. */
function patch_of(mixed $operations): JsonPatch
{
    if (!Json::isList($operations)) {
        throw AdapterError::invalid("argument 'patch' must be an array of operations");
    }
    $patch = new JsonPatch();
    foreach ($operations as $raw) {
        $op = Json::members($raw);
        if ($op === null || !is_string($op['op'] ?? null)) {
            throw AdapterError::invalid('a patch operation must be an object with an op');
        }
        $name = $op['op'];
        $pointer = static function (string $member) use ($op, $name): string {
            $v = $op[$member] ?? null;
            return is_string($v) ? $v : throw AdapterError::invalid("a '$name' patch operation needs a string '$member'");
        };
        $value = static function () use ($op, $name): mixed {
            return array_key_exists('value', $op) ? $op['value'] : throw AdapterError::invalid("a '$name' patch operation needs a 'value'");
        };
        match ($name) {
            'add' => $patch->add($pointer('path'), $value()),
            'remove' => $patch->remove($pointer('path')),
            'replace' => $patch->replace($pointer('path'), $value()),
            'move' => $patch->move($pointer('from'), $pointer('path')),
            'copy' => $patch->copy($pointer('from'), $pointer('path')),
            'test' => $patch->test($pointer('path'), $value()),
            default => throw AdapterError::invalid("unknown patch operation '$name'"),
        };
    }
    return $patch;
}

/** Rebuilds an application/lws-query+json document with the library's TypeQuery builder. */
function query_of(mixed $query): TypeQuery
{
    $members = Json::members($query) ?? [];
    $q = TypeQuery::create();
    foreach ($members as $key => $groups) {
        $key = (string) $key;
        if (!Json::isList($groups)) {
            throw AdapterError::invalid("query member '$key' must be a list of groups");
        }
        try {
            $clause = $q->relation($key);
            foreach ($groups as $g) {
                if (is_string($g)) {
                    $clause->allOf($g);
                } elseif (Json::isList($g) && count(array_filter($g, 'is_string')) === count($g)) {
                    $clause->anyOf(...$g);
                } else {
                    throw AdapterError::invalid("a group of query member '$key' must be an IRI or a list of IRIs");
                }
            }
        } catch (\InvalidArgumentException $e) {
            throw AdapterError::invalid("query member '$key': {$e->getMessage()}");
        }
    }
    return $q;
}

/**
 * @param list<mixed>|null $links
 * @return list<Link>
 */
function links_of(?array $links): array
{
    $out = [];
    foreach ($links ?? [] as $l) {
        $m = Json::members($l);
        if ($m === null || !is_string($m['href'] ?? null) || !is_string($m['rel'] ?? null)) {
            throw AdapterError::invalid("argument 'links' must be an array of {href, rel} objects");
        }
        $out[] = new Link($m['href'], $m['rel']);
    }
    return $out;
}

/**
 * The headers of a notification delivery: name → list of values (or a single value).
 *
 * @return list<array{0: string, 1: string}>
 */
function headers_of(Args $args): array
{
    $pairs = [];
    foreach (Json::members($args->object('headers')) ?? [] as $name => $values) {
        $values = is_string($values) ? [$values] : $values;
        if (!Json::isList($values) || count(array_filter($values, 'is_string')) !== count($values)) {
            throw AdapterError::invalid("header '$name' must be a list of strings");
        }
        foreach ($values as $v) {
            $pairs[] = [(string) $name, $v];
        }
    }
    return $pairs;
}

// ---------------------------------------------------------------------------------------------
// Results

/**
 * An object of the given members, leaving out the absent (null) ones.
 *
 * @param array<string, mixed> $values
 * @return array<string, mixed>
 */
function members(array $values): array
{
    return array_filter($values, static fn (mixed $v): bool => $v !== null);
}

function is_textual(string $contentType): bool
{
    $e = strtolower(trim(explode(';', $contentType, 2)[0]));
    return str_starts_with($e, 'text/') || $e === 'application/json' || $e === 'application/xml'
        || str_ends_with($e, '+json') || str_ends_with($e, '+xml');
}

/** @return array<string, string> */
function body_result(ReadResult $r): array
{
    if ($r->contentType !== null && is_textual($r->contentType)) {
        return ['text' => $r->text()];
    }
    return ['base64' => base64_encode($r->body)];
}

/** @return array<string, mixed> */
function metadata_result(ResourceMetadata $m): array
{
    return members([
        'url' => $m->url,
        'status' => $m->status,
        'etag' => $m->etag,
        'lastModified' => $m->lastModified,
        'contentType' => $m->contentType,
        'contentLength' => $m->contentLength,
        'links' => array_map(static fn (Link $l): array => ['href' => $l->href, 'rel' => $l->rel, 'params' => Json::object($l->params)], $m->links),
        'linkset' => $m->linkset,
        'parent' => $m->parent,
        'storage' => $m->storage,
        'types' => $m->types,
        'allow' => $m->allow,
        'acceptPatch' => $m->acceptPatch,
    ]);
}

/** @return array<string, mixed> */
function item_result(ContainedResource $i): array
{
    return members(['id' => $i->id, 'types' => $i->types, 'format' => $i->format, 'size' => $i->size, 'modified' => $i->modifiedRaw]);
}

/** @return array<string, mixed> */
function page_result(ContainerPage $p): array
{
    return members([
        'id' => $p->id,
        'types' => $p->types,
        'totalItems' => $p->totalItems,
        'items' => array_map(item_result(...), $p->items),
        'first' => $p->first,
        'next' => $p->next,
        'prev' => $p->prev,
        'last' => $p->last,
        'metadata' => metadata_result($p->metadata),
    ]);
}

/** @return array<string, mixed> */
function update_result(UpdateResult $u): array
{
    return members(['status' => $u->status, 'etag' => $u->etag, 'metadata' => metadata_result($u->metadata)]);
}

/** @return array<string, mixed> */
function created_result(CreateResult $c): array
{
    return ['location' => $c->location, 'metadata' => metadata_result($c->metadata)];
}

/** @return array<string, mixed> */
function service_result(Service $s): array
{
    return members([
        'id' => $s->id,
        'types' => $s->types,
        'serviceEndpoint' => $s->serviceEndpoint,
        'subscriptionType' => array_key_exists('subscriptionType', $s->raw) ? $s->subscriptionTypes() : null,
    ]);
}

/** @return array<string, mixed> */
function storage_result(StorageDescription $s): array
{
    try {
        $root = $s->storageRoot();
    } catch (ProtocolException) {
        $root = null;
    }
    return members([
        'id' => $s->id,
        'types' => $s->types,
        'storageRoot' => $root,
        'services' => array_map(service_result(...), $s->services),
        'verificationMethods' => array_map(static fn ($vm): array => members(['id' => $vm->id, 'type' => $vm->type, 'controller' => $vm->controller]),
            $s->verificationMethods),
        'raw' => Json::object($s->raw),
    ]);
}

/** @return array<string, mixed> */
function subscription_result(Subscription $s): array
{
    return members(['subscription' => $s->url, 'types' => $s->types, 'expires' => $s->expiresRaw, 'raw' => Json::object($s->raw)]);
}

/**
 * Pulls at most `limit + 1` items: the first `limit`, and whether there was one more.
 *
 * @template T
 * @param iterable<T> $sequence
 * @return array{0: list<T>, 1: bool}
 */
function take(iterable $sequence, int $limit): array
{
    $items = [];
    foreach ($sequence as $item) {
        if (count($items) === $limit) {
            return [$items, true];
        }
        $items[] = $item;
    }
    return [$items, false];
}

/**
 * @param iterable<ContainedResource> $sequence
 * @return array<string, mixed>
 */
function listing(iterable $sequence, int $limit): array
{
    [$items, $truncated] = take($sequence, $limit);
    return ['items' => array_map(item_result(...), $items), 'truncated' => $truncated];
}

// ---------------------------------------------------------------------------------------------
// Errors

const HTTP_KINDS = [
    BadRequestException::class => 'BadRequestError',
    UnauthorizedException::class => 'UnauthorizedError',
    ForbiddenException::class => 'ForbiddenError',
    NotFoundException::class => 'NotFoundError',
    MethodNotAllowedException::class => 'MethodNotAllowedError',
    NotAcceptableException::class => 'NotAcceptableError',
    ConflictException::class => 'ConflictError',
    GoneException::class => 'GoneError',
    PreconditionFailedException::class => 'PreconditionFailedError',
    UnsupportedMediaTypeException::class => 'UnsupportedMediaTypeError',
    UnprocessableContentException::class => 'UnprocessableContentError',
    NotImplementedException::class => 'NotImplementedError',
    InsufficientStorageException::class => 'InsufficientStorageError',
];

/** @return array<array-key, mixed>|\stdClass the problem object: the standard members present, and the extensions */
function problem_result(ProblemDetails $p): array|\stdClass
{
    return Json::object([...$p->extensions, ...members(['type' => $p->type, 'title' => $p->title, 'status' => $p->status,
        'detail' => $p->detail, 'instance' => $p->instance])]);
}

/** @return array<string, mixed> */
function error_result(\Throwable $e): array
{
    if ($e instanceof AdapterError) {
        return ['kind' => $e->kind, 'message' => $e->getMessage()];
    }
    if ($e instanceof HttpException) {
        $error = ['kind' => HTTP_KINDS[$e::class] ?? 'HttpError', 'status' => $e->status, 'message' => $e->getMessage()];
        if ($e->problem !== null) {
            $error['problem'] = problem_result($e->problem);
        }
        if ($e instanceof MethodNotAllowedException) {
            $error['allow'] = $e->allow();
        }
        if ($e instanceof UnsupportedMediaTypeException) {
            $error['acceptPatch'] = $e->acceptPatch();
        }
        return $error;
    }
    if ($e instanceof AuthenticationException) {
        return members(['kind' => 'AuthenticationError', 'status' => $e->status, 'message' => $e->getMessage(),
            'oauthError' => $e->oauthError, 'oauthErrorDescription' => $e->oauthErrorDescription]);
    }
    if ($e instanceof SignatureVerificationException) {
        return ['kind' => 'SignatureVerificationError', 'message' => $e->getMessage()];
    }
    if ($e instanceof ProtocolException) {
        return ['kind' => 'ProtocolError', 'message' => $e->getMessage()];
    }
    if ($e instanceof TransportException) {
        return ['kind' => 'TransportError', 'message' => $e->getMessage()];
    }
    if ($e instanceof \InvalidArgumentException) {
        return ['kind' => 'InvalidArguments', 'message' => $e->getMessage()];
    }
    $message = $e::class . ': ' . $e->getMessage() . "\n" . $e->getTraceAsString();
    fwrite(STDERR, $message . "\n");
    return ['kind' => 'InternalError', 'message' => $message];
}

// ---------------------------------------------------------------------------------------------
// The operations

final class Adapter
{
    private LwsClient $client;
    /** @var array<string, \Closure(Args): array<string, mixed>> */
    public readonly array $operations;

    public function __construct()
    {
        $this->client = new LwsClient();
        $this->operations = [
            'configure' => $this->configure(...),
            'discover_storage' => fn (Args $a): array => storage_result($this->client->discoverStorage($a->url('url'))),
            'get_storage_description' => fn (Args $a): array => storage_result($this->client->getStorageDescription($a->url('url'))),
            'head' => fn (Args $a): array => metadata_result($this->client->head($a->url('url'))),
            'read' => $this->read(...),
            'read_container' => fn (Args $a): array => page_result($this->client->readContainer($a->url('url'))),
            'list_container' => fn (Args $a): array => listing($this->client->listContainer($a->url('url')), $a->limit()),
            'create' => $this->create(...),
            'create_container' => fn (Args $a): array => created_result($this->client->createContainer($a->url('parent'), slug: $a->optStr('slug'))),
            'update' => $this->update(...),
            'patch' => fn (Args $a): array => update_result($this->client->patch($a->url('url'), patch_of($a->raw('patch')), ifMatch: $a->optStr('ifMatch'))),
            'delete' => function (Args $a): array {
                $this->client->delete($a->url('url'), ifMatch: $a->optStr('ifMatch'), recursive: $a->optBool('recursive') ?? false);
                return [];
            },
            'linkset_url' => fn (Args $a): array => ['linkset' => $this->client->linksetUrl($a->url('url'))],
            'read_linkset' => $this->readLinkset(...),
            'update_linkset' => $this->updateLinkset(...),
            'patch_linkset' => fn (Args $a): array => update_result($this->client->patchLinkset($a->url('linksetUrl'), patch_of($a->raw('patch')), ifMatch: $a->optStr('ifMatch'))),
            'subscribe' => $this->subscribe(...),
            'list_subscriptions' => fn (Args $a): array => listing($this->client->listSubscriptions($a->url('serviceUrl')), $a->limit()),
            'get_subscription' => fn (Args $a): array => subscription_result($this->client->getSubscription($a->url('url'))),
            'unsubscribe' => function (Args $a): array {
                $this->client->unsubscribe($a->url('url'));
                return [];
            },
            'verify_notification' => $this->verifyNotification(...),
            'request_access' => function (Args $a): array {
                $url = $a->url('serviceUrl');
                return ['location' => $this->client->requestAccess($url, self::document(AccessRequest::class, $a, 'request'))];
            },
            'get_access_request' => fn (Args $a): array => ['document' => Json::object($this->client->getAccessRequest($a->url('url'))->document())],
            'list_access_requests' => fn (Args $a): array => listing($this->client->listAccessRequests($a->url('serviceUrl')), $a->limit()),
            'cancel_access_request' => function (Args $a): array {
                $this->client->cancelAccessRequest($a->url('url'));
                return [];
            },
            'grant_access' => function (Args $a): array {
                $url = $a->url('serviceUrl');
                return ['location' => $this->client->grantAccess($url, self::document(AccessGrant::class, $a, 'grant'))];
            },
            'get_access_grant' => fn (Args $a): array => ['document' => Json::object($this->client->getAccessGrant($a->url('url'))->document())],
            'list_access_grants' => fn (Args $a): array => listing($this->client->listAccessGrants($a->url('serviceUrl')), $a->limit()),
            'revoke_access_grant' => function (Args $a): array {
                $this->client->revokeAccessGrant($a->url('url'));
                return [];
            },
            'read_type_index' => function (Args $a): array {
                $p = $this->client->readTypeIndex($a->url('url'));
                return members(['totalItems' => $p->totalItems, 'types' => $p->types, 'first' => $p->first, 'next' => $p->next, 'prev' => $p->prev, 'last' => $p->last]);
            },
            'list_types' => function (Args $a): array {
                [$types, $truncated] = take($this->client->listTypes($a->url('serviceUrl')), $a->limit());
                return ['types' => $types, 'truncated' => $truncated];
            },
            'search_types' => function (Args $a): array {
                $url = $a->url('serviceUrl');
                return page_result($this->client->searchTypes($url, query_of($a->object('query'))));
            },
            'search_all' => function (Args $a): array {
                $url = $a->url('serviceUrl');
                return listing($this->client->searchAll($url, query_of($a->object('query'))), $a->limit());
            },
            'accepted_query_formats' => fn (Args $a): array => ['formats' => $this->client->acceptedQueryFormats($a->url('serviceUrl'))],
            'shutdown' => static fn (Args $a): array => [],
        ];
    }

    /** @return array<string, mixed> */
    private function configure(Args $args): array
    {
        $auth = Args::of($args->raw('auth') ?? ['type' => 'none'], "argument 'auth'");
        $allowInsecureHttp = $args->optBool('allowInsecureHttp') ?? false;
        $result = ['library' => LwsClient::DEFAULT_USER_AGENT];
        $exchange = static fn ($credentials): TokenExchangeAuthenticator => new TokenExchangeAuthenticator($credentials, allowInsecureHttp: $allowInsecureHttp);
        $authenticator = null;
        switch ($auth->optStr('type')) {
            case 'none':
                break;
            case 'bearer':
                $authenticator = new BearerTokenAuthenticator($auth->str('token'), $auth->optStr('realm'));
                break;
            case 'openid':
                $authenticator = $exchange(new OpenIdCredentials($auth->str('idToken')));
                break;
            case 'selfSigned':
                $agent = $auth->str('agent');
                $jwk = $auth->object('privateJwk');
                $kid = $auth->optStr('kid') ?? (Json::members($jwk)['kid'] ?? null);
                if (!is_string($kid)) {
                    throw AdapterError::invalid("selfSigned needs 'kid', or a 'kid' in the private JWK");
                }
                try {
                    $key = SigningKey::fromJwk($jwk);
                } catch (\InvalidArgumentException $e) {
                    throw AdapterError::invalid("argument 'privateJwk' is not a usable private key: {$e->getMessage()}");
                }
                $authenticator = $exchange(SelfSignedCredentials::forAgent($agent, $key, $kid));
                $result += ['agent' => $agent, 'kid' => $kid];
                break;
            case 'didKey':
                $algorithm = $auth->optStr('algorithm') ?? 'ES256';
                if ($algorithm !== 'ES256' && $algorithm !== 'EdDSA') {
                    throw AdapterError::invalid("unknown algorithm '$algorithm'");
                }
                $didKey = SelfSignedCredentials::didKey(SigningKey::generate($algorithm));
                $authenticator = $exchange($didKey);
                $result += ['agent' => $didKey->agent, 'kid' => $didKey->keyId];
                break;
            default:
                throw AdapterError::invalid("unknown auth type '" . json_encode($auth->raw('type')) . "'");
        }
        $headers = $args->optObject('headers');
        $defaultHeaders = [];
        foreach (Json::members($headers) ?? [] as $name => $value) {
            if (!is_string($value)) {
                throw AdapterError::invalid("argument 'headers' must map header names to strings");
            }
            $defaultHeaders[] = [(string) $name, $value];
        }
        $timeout = $args->optInt('timeoutSeconds', 1);
        $this->client = new LwsClient(
            authenticator: $authenticator instanceof Authenticator ? $authenticator : null,
            userAgent: $args->optStr('userAgent') ?? LwsClient::DEFAULT_USER_AGENT,
            defaultHeaders: $defaultHeaders,
            timeout: $timeout === null ? 30.0 : (float) $timeout,
        );
        return $result;
    }

    /** @return array<string, mixed> */
    private function read(Args $args): array
    {
        $url = $args->url('url');
        $start = $args->optInt('rangeStart');
        $end = $args->optInt('rangeEnd');
        if ($start === null && $end !== null) {
            throw AdapterError::invalid('rangeEnd needs rangeStart');
        }
        $r = $this->client->read($url, accept: $args->optStr('accept'), range: $start === null ? null : ByteRange::of($start, $end),
            ifNoneMatch: $args->optStr('ifNoneMatch'), prefer: $args->optStr('prefer'));
        return members(['metadata' => metadata_result($r->metadata), 'notModified' => $r->notModified, 'contentRange' => $r->contentRange,
            'body' => body_result($r)]);
    }

    /** @return array<string, mixed> */
    private function create(Args $args): array
    {
        $container = $args->url('container');
        [$data, $contentType] = body_of($args->raw('body'), $args->optStr('contentType'));
        return created_result($this->client->create($container, $data, $contentType, slug: $args->optStr('slug'),
            types: $args->optStrings('types') ?? [], links: links_of($args->optList('links'))));
    }

    /** @return array<string, mixed> */
    private function update(Args $args): array
    {
        $url = $args->url('url');
        if (!$args->has('body')) {
            throw AdapterError::invalid("missing argument 'body'");
        }
        [$data, $contentType] = body_of($args->raw('body'), $args->optStr('contentType'));
        return update_result($this->client->update($url, $data, $contentType, ifMatch: $args->optStr('ifMatch'), ifNoneMatch: $args->optStr('ifNoneMatch')));
    }

    /** @return array<string, mixed> */
    private function readLinkset(Args $args): array
    {
        $doc = $this->client->readLinkset($args->url('url'));
        return members(['url' => $doc->url, 'etag' => $doc->etag, 'linkset' => $doc->linkset->toJson(), 'allow' => $doc->allow, 'acceptPatch' => $doc->acceptPatch]);
    }

    /** @return array<string, mixed> */
    private function updateLinkset(Args $args): array
    {
        $url = $args->url('linksetUrl');
        try {
            $linkset = Linkset::parse($args->object('linkset'));
        } catch (ProtocolException $e) {
            throw AdapterError::invalid("argument 'linkset': {$e->getMessage()}");
        }
        return update_result($this->client->updateLinkset($url, $linkset, ifMatch: $args->optStr('ifMatch')));
    }

    /** @return array<string, mixed> */
    private function subscribe(Args $args): array
    {
        $url = $args->url('serviceUrl');
        try {
            $request = new WebhookSubscriptionRequest($args->strings('topics'), $args->str('inbox'), $args->optStr('expires'));
        } catch (\InvalidArgumentException $e) {
            throw AdapterError::invalid($e->getMessage());
        }
        return subscription_result($this->client->subscribe($url, $request));
    }

    /** @return array<string, mixed> */
    private function verifyNotification(Args $args): array
    {
        $method = $args->str('method');
        $url = $args->str('url');
        $headers = headers_of($args);
        $encoded = $args->str('bodyBase64');
        $body = preg_match('/^[A-Za-z0-9+\/]*={0,2}$/', $encoded) === 1 && strlen($encoded) % 4 === 0 ? base64_decode($encoded, true) : false;
        if ($body === false) {
            throw AdapterError::invalid("argument 'bodyBase64' is not base64");
        }
        $trusted = $args->optStrings('trustedStorages');
        if ($trusted === []) {
            // Section 4.2: the driver leaves trustedStorages out to accept any storage.
            throw AdapterError::invalid("argument 'trustedStorages' must not be empty; leave it out to accept any storage");
        }
        $verified = (new WebhookVerifier(client: $this->client, trustedStorages: $trusted))->verify($method, $url, $headers, $body);
        $activities = [];
        foreach ($verified->notification->activities as $a) {
            $activities[] = members(['id' => $a->id, 'types' => $a->types, 'object' => $a->object->id, 'objectTypes' => $a->object->types]);
        }
        return ['storage' => $verified->storage, 'keyid' => $verified->keyId, 'activities' => $activities, 'raw' => Json::object($verified->notification->raw)];
    }

    /**
     * @template T of AccessRequest|AccessGrant
     * @param class-string<T> $class
     * @return T
     */
    private static function document(string $class, Args $args, string $name): AccessRequest|AccessGrant
    {
        try {
            return $class::parse($args->object($name));
        } catch (ProtocolException|\InvalidArgumentException $e) {
            throw AdapterError::invalid("argument '$name': {$e->getMessage()}");
        }
    }
}

// ---------------------------------------------------------------------------------------------
// The protocol loop

/** @param array<string, mixed> $message */
function write(array $message): void
{
    $flags = JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_PRESERVE_ZERO_FRACTION | JSON_INVALID_UTF8_SUBSTITUTE;
    $line = json_encode($message, $flags);
    if ($line === false) {
        // A result that cannot be serialized (a non-finite number, say) is a bug: report it.
        $line = (string) json_encode(['id' => $message['id'] ?? null, 'ok' => false,
            'error' => ['kind' => 'InternalError', 'message' => 'the result is not serializable: ' . json_last_error_msg()]], $flags);
    }
    fwrite(STDOUT, $line . "\n");
    fflush(STDOUT);
}

function serve(Adapter $adapter): void
{
    write(['hello' => ['protocol' => PROTOCOL, 'language' => 'php', 'library' => LwsClient::DEFAULT_USER_AGENT, 'operations' => array_keys($adapter->operations)]]);
    while (($raw = fgets(STDIN)) !== false) {
        $line = trim($raw);
        if ($line === '') {
            continue;
        }
        try {
            $request = Json::members(Json::decode($line));
        } catch (\JsonException) {
            write(['id' => null, 'ok' => false, 'error' => error_result(AdapterError::invalid('the request is not JSON'))]);
            continue;
        }
        if ($request === null) {
            write(['id' => null, 'ok' => false, 'error' => error_result(AdapterError::invalid('the request is not a JSON object'))]);
            continue;
        }
        $id = $request['id'] ?? null;
        $op = $request['op'] ?? null;
        $operation = is_string($op) ? ($adapter->operations[$op] ?? null) : null;
        if ($operation === null) {
            write(['id' => $id, 'ok' => false, 'error' => ['kind' => 'Unsupported', 'message' => 'unknown operation ' . json_encode($op)]]);
            continue;
        }
        try {
            $result = $operation(Args::of($request['args'] ?? null, 'args'));
            write(['id' => $id, 'ok' => true, 'result' => $result === [] ? new \stdClass() : $result]);
        } catch (\Throwable $e) {
            write(['id' => $id, 'ok' => false, 'error' => error_result($e)]);
        }
        if ($op === 'shutdown') {
            break;
        }
    }
}

// The library: Composer's autoloader when the repository has one, else the sources (php/src, or src next to this
// script in a deployed bundle).
(static function (): void {
    $root = dirname(__DIR__, 3);
    if (is_file("$root/vendor/autoload.php")) {
        require "$root/vendor/autoload.php";
        return;
    }
    $src = is_dir(__DIR__ . '/src') ? __DIR__ . '/src' : "$root/php/src";
    spl_autoload_register(static function (string $class) use ($src): void {
        if (str_starts_with($class, 'Ebremer\\Lws\\')) {
            $file = $src . '/' . str_replace('\\', '/', substr($class, strlen('Ebremer\\Lws\\'))) . '.php';
            if (is_file($file)) {
                require $file;
            }
        }
    });
})();

// stdout carries protocol messages only: PHP's own warnings and notices go to stderr.
ini_set('display_errors', 'stderr');
error_reporting(E_ALL);
serve(new Adapter());
