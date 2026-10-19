# LWS Client for PHP

A client for the [W3C Linked Web Storage (LWS) Protocol 1.0](https://www.w3.org/TR/lws10-core/) and its companion
specifications, as they stood on 2026-10-19 (the Working Draft of 19 October 2026, `w3c/lws-protocol` 9a08ff6):
discovery, resources and containers, linkset metadata, moving resources between containers, OAuth 2.0 token exchange
after RFC 9728 discovery with the OpenID Connect / SAML 2.0 / self-signed (controlled identifier, `did:key`)
authentication suites, webhook notifications with RFC 9421 signature verification (and signing, for servers), access
requests and grants, and the type index / type search services.

* PHP 8.2 or later, with the bundled extensions ext-curl, ext-openssl and ext-sodium; no Composer dependencies
* Operation options are named arguments (`slug:`, `ifMatch:`, `recursive:`, `headers:`, `timeout:`); listings are
  lazy `foreach`-able sequences; models are final classes with `readonly` properties; errors are one exception
  hierarchy under `LwsException`
* ext-curl underneath, behind a pluggable `HttpTransport`; `Psr18Transport` runs it on any PSR-18 client (Guzzle,
  Symfony HttpClient, …)
* ES256 (P-256) through ext-openssl, EdDSA (Ed25519) through ext-sodium; RSA verification only (RS256/384/512, and
  PS256/384/512 with EMSA-PSS in PHP), for ID Tokens of OpenID Providers that sign with RSA
* Composer package `ebremer/lws-client`, namespace `Ebremer\Lws`
* MIT licensed (see [`../LICENSE`](../LICENSE))

## Install

The package is this repository. Packagist and Composer's VCS repositories read the manifest at the root of a
repository, so [`composer.json`](../composer.json) is there and maps `Ebremer\Lws\` to `php/src/`:

```sh
composer require ebremer/lws-client
```

Or, before it is on Packagist, from the repository:

```json
{
    "repositories": [{"type": "vcs", "url": "https://github.com/ebremer/lws-client"}],
    "require": {"ebremer/lws-client": "dev-main"}
}
```

## Quickstart

```php
<?php
require 'vendor/autoload.php';

use Ebremer\Lws\Auth\SelfSignedCredentials;
use Ebremer\Lws\Auth\SigningKey;
use Ebremer\Lws\Auth\TokenExchangeAuthenticator;
use Ebremer\Lws\Exception\PreconditionFailedException;
use Ebremer\Lws\Json\JsonPatch;
use Ebremer\Lws\LwsClient;

// A did:key agent signs its own credential; the client exchanges it for access tokens on demand.
$me = SelfSignedCredentials::didKey(SigningKey::generateP256());
$client = new LwsClient(authenticator: new TokenExchangeAuthenticator($me));

$storage = $client->discoverStorage('https://storage.example/root/');
$root = $storage->storageRoot();

$note = $client->createText($root, 'Hello, LWS!', slug: 'hello.txt')->location;
$r = $client->read($note);
echo $r->text(), ' ', $r->etag, "\n";

// Optimistic concurrency: the update fails if someone changed the note since it was read.
try {
    $client->update($note, 'Hello again', 'text/plain', ifMatch: $r->etag);
} catch (PreconditionFailedException $e) {
    echo "Changed meanwhile ({$e->status})\n";
}

$profile = $client->createJson($root, ['name' => 'Alice', 'age' => 30], slug: 'profile.json')->location;
$client->patch($profile, (new JsonPatch())->replace('/age', 31)->add('/city', 'Boston'));

foreach ($client->listContainer($root) as $item) {   // follows rel="next" pages lazily
    echo $item->id, ' ', $item->format, "\n";
}
$client->delete($note);
```

[`examples/`](examples) has this as a program ([`quickstart.php`](examples/quickstart.php)), plus
[`self_signed_auth.php`](examples/self_signed_auth.php) (did:key and HTTPS agents, the controlled identifier
document to publish) and [`webhook_receiver.php`](examples/webhook_receiver.php) (an inbox that verifies signed
notifications).

## API at a glance

| Area | Methods of `LwsClient` |
|---|---|
| Discovery | `discoverStorage`, `getStorageDescription` |
| Reading | `head`, `read` (`accept:`, `range: ByteRange::of(0, 1023)`, `ifNoneMatch:`, `ifModifiedSince:`, `prefer:`), `readContainer`, `listContainer` |
| Creating | `create`, `createText`, `createJson`, `createContainer` (`slug:`, `types:`, `links:`) |
| Updating | `update` (`ifMatch:`, `ifNoneMatch:`, `links:`, `setLinkset:`), `patch` (a `JsonPatch`, or bytes and a content type), `delete` (`ifMatch:`, `recursive:`) |
| Linksets | `linksetUrl`, `readLinkset`, `readLinksetResource`, `updateLinkset`, `patchLinkset` |
| Moving | `move` (`ifMatch:`), where `getStorageDescription(...)->moveCapability()` allows it |
| Notifications | `subscribe`, `listSubscriptions`, `getSubscription`, `unsubscribe`; `WebhookVerifier`, and `WebhookSigner` for servers |
| Access | `requestAccess`, `listAccessRequests`, `getAccessRequest`, `cancelAccessRequest`, `grantAccess`, `listAccessGrants`, `getAccessGrant`, `revokeAccessGrant` |
| Type index and search | `readTypeIndex`, `listTypes`, `searchTypes` (HTTP `QUERY`), `searchAll`, `acceptedQueryFormats` |
| Anything else | `request($method, $url, body:, contentType:)` through the same authentication and redirect pipeline |

Every operation also takes `headers:` (extra request headers, `['Name' => 'value']`) and `timeout:` (seconds).
Every URL in a result is an absolute string. A conditional read answered `304` is a result whose `notModified` is
true, not an exception. Listings (`listContainer`, `listTypes`, `searchAll`, …) are `PagedSequence`s: nothing is
fetched until the `foreach`, pages are fetched as it advances, each `foreach` starts over, and `toArray()` /
`take($n)` collect them.

The contract's `Resource` is `ReadResult` here, as `resource` is a reserved word in PHP.

### JSON

`Json::decode()` turns JSON objects into associative arrays, except an empty object `{}` and an object whose keys
are `"0"`, `"1"`, … in order, which stay `\stdClass`: so the documents the models keep (`raw`, linksets, access
requests) encode back to the same JSON. Values you send (`createJson`, JSON Patch values) are anything
`json_encode()` takes; write `new \stdClass()` for `{}`, since `[]` is an empty array.

`JsonPatch::apply($document)` applies a patch to a decoded document (RFC 6902), atomically: it returns the patched
copy, or throws `JsonPatchException` (a failed `test`, a missing location) and changes nothing. Servers use it to
honour `PATCH`; `conformance/fixtures/json-patch-apply.json` holds its cases.

## Moving resources

```php
$move = $client->discoverStorage($root)->moveCapability();   // null: this storage moves nothing
if ($move !== null && $move->movesDataResources()) {
    $moved = $client->move($note, $archive);
    $note = $moved->location;   // the storage may have given it a new URL
}
```

`move` reads the resource's linkset and sends a JSON Patch that `test`s and `replace`s its `up` link, conditionally on
the linkset's ETag (`ifMatch:` overrides it). Unless the capability says `preservesIdentifier: true`, take the
resource's URL from the result: `location` and `linkset` are where the resource and its linkset are now, and
`identifierPreserved` says whether the URL stayed. A storage that refuses the move (no capability, a destination
that is not a container, a container moved into itself) answers `409`, a `ConflictException`. `LinksetDocument::movePatch()`
and `MoveResult::fromResponse()` are its two halves. Notifications report moves as `Move` activities
(`$activity->isMove()`, with `origin` and `target`).

## Errors

```
LwsException (\RuntimeException)
├── HttpException                 any error status: $status, $method, $url, $headers, $problem (RFC 9457), $body
│   ├── BadRequestException            400
│   ├── UnauthorizedException          401   challenges()
│   ├── ForbiddenException             403
│   ├── NotFoundException              404
│   ├── MethodNotAllowedException      405   allow()
│   ├── NotAcceptableException         406
│   ├── ConflictException              409
│   ├── GoneException                  410
│   ├── PreconditionFailedException    412
│   ├── UnsupportedMediaTypeException  415   acceptPatch(), acceptQuery()
│   ├── UnprocessableContentException  422
│   ├── NotImplementedException        501
│   └── InsufficientStorageException   507
├── AuthenticationException       a discovery check or the token exchange failed: $oauthError, $oauthErrorDescription, $status
├── ProtocolException             the server broke the specification (no Location, wrong media type, bad JSON)
├── SignatureVerificationException  a webhook delivery that does not verify
└── TransportException            no response: refused, TLS, isTimeout()
```

They are in `Ebremer\Lws\Exception`. Arguments the caller gets wrong (a relative URL, an IRI that is not absolute
in a `TypeQuery`, a header value with a line break) raise PHP's own `\InvalidArgumentException`, before any request
is sent.

## Authentication

`TokenExchangeAuthenticator` runs the LWS flow. A `401` carries `WWW-Authenticate: Bearer resource_metadata="…"` and
a `Link` to the storage that holds the resource. Before it asks for a token, the authenticator checks what the `401`
said against the URL it requested: the metadata URL is on that origin, the protected resource metadata (RFC 9728)
describes that very URL, and the storage's description (read without credentials, and cached until `clear()`) puts
the storage root on that origin too. A `401` that fails a check gets no token, and does not cost the client the
token it has. The first authorization server of the metadata that uses HTTPS (loopback hosts excepted) and passes
the filter is used: its metadata is read and its `issuer` checked, a subject token is exchanged for an access token
with `resource` = the storage, and the request is sent once more with it. None of these requests follows a redirect.
Tokens are cached per authorization server and storage, and sent at once to every URL inside the storage or its root
until 30 seconds before they expire, never anywhere else, redirects included: a URL outside them gets the token only
after its own `401` passes the checks. A server still on the drafts before 19 October 2026 (`Bearer as_uri="…",
realm="…"`) is followed too: the request must lie inside the realm, which is then the token's storage and scope.

| Suite | Credentials |
|---|---|
| Self-signed, `did:key` | `SelfSignedCredentials::didKey(SigningKey::generateP256())` (or `generateEd25519()`) |
| Self-signed, HTTPS agent | `SelfSignedCredentials::forAgent($agentUrl, $key, $kid)`; publish `ControlledIdentifierDocument::create($agentUrl, $key->publicKey, $kid)` at the agent URL |
| OpenID Connect | `new OpenIdCredentials($idToken)`, or a closure that returns one per authorization server |
| SAML 2.0 | `SamlCredentials::fromXml($assertion)` (base64url-encodes it), `SamlCredentials::fromEncoded()` |
| A known token | `new BearerTokenAuthenticator($token, realm: 'https://storage.example/')` |

Keys round-trip as JWKs: `$key->jwk()` and `SigningKey::fromJwk($jwk)`. Options of the flow:
`allowInsecureHttp:` (testing only), `authorizationServerFilter:` (a `fn (string $issuer, string $storage): bool`
that decides which servers may receive your credentials), `refreshMargin:`, `timeout:`, `transport:`.
`accessToken($issuer, $storage)` gets a token without a request first. Keys, tokens and credentials are kept out of
`var_dump()` and `print_r()`, and are `#[\SensitiveParameter]`s.

## Webhooks

```php
// inbox.php, at the URL you subscribed with
$verifier = new WebhookVerifier(trustedStorages: ['https://storage.example/']);
try {
    $verified = $verifier->verifyGlobals('https://app.example/inbox.php');
    foreach ($verified->notification->activities as $activity) {
        error_log(implode(',', $activity->types) . ' ' . $activity->object->id);
    }
    http_response_code(204);
} catch (SignatureVerificationException $e) {
    http_response_code(401);
}
```

`verifyGlobals()` reads the current request; `verifyServerRequest()` takes a PSR-7 request; `verify($method, $url,
$headers, $body)` takes the parts. Pass the inbox URL as it was registered, not the one a proxy forwarded to. The
verifier checks the RFC 9530 digest, the RFC 9421 signature and its age, that the key is one the storage lists
under `authentication`, and that the notification comes from that storage; storage descriptions are cached, and
fetched again once when a signature fails, in case the storage rotated its keys.

A storage that delivers notifications signs them with `WebhookSigner`, the other side of the verifier:

```php
// $key: a P-256, P-384 or Ed25519 SigningKey; its public JWK is a verification method of the storage
// description, with the ID https://storage.example/#{$kid}, referenced from `authentication`.
$signer = new WebhookSigner($key, 'https://storage.example/#' . $kid);
$headers = $signer->sign($inboxUrl, $body);   // content-type, content-digest, signature-input, signature
```

The signature covers `@method`, `@scheme`, `@authority`, `@path`, `content-type` and `content-digest`, with
`created`, `keyid` and `alg`. Send the body bytes you signed, to the inbox URL you signed for, with those headers.

## Transports

The client follows redirects itself, authorizing each hop for its own URL, so a transport must not follow them.

* `CurlTransport` (the default): one reused curl handle (keep-alive), no redirects, no cookies, http and https only.
  `new CurlTransport(connectTimeout: 5, curlOptions: [CURLOPT_CAINFO => '/path/ca.pem'])`.
* `Psr18Transport`: any PSR-18 client with PSR-17 factories, e.g.
  `new Psr18Transport(new \GuzzleHttp\Client(), $factory, $factory)` (Guzzle's `sendRequest` follows no redirects).
* Your own: implement `HttpTransport::send(HttpRequest): HttpResponse`.

## Build and test

From the repository root, where `composer.json` is:

```sh
composer install
composer test                                        # PHPUnit: fixtures, HTTP, auth flow, webhook vectors
composer analyse                                     # PHPStan, level 8
node testing/mock-server/server.mjs --port 8787 &
LWS_TEST_SERVER=http://localhost:8787 composer test  # adds the cross-language interop scenario
php php/examples/quickstart.php http://localhost:8787/root/
```

The driver adapter is [`../driver/adapters/php/adapter.php`](../driver/adapters/php/adapter.php):
`node driver/adapters/check.mjs -- php driver/adapters/php/adapter.php`.

## License

[MIT](../LICENSE).
