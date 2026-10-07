// SPDX-License-Identifier: MIT
import { callout, code, table } from "../../lib.mjs";
import { sample } from "../../samples.mjs";

const s = (topic) => code(sample("php", topic).lang, sample("php", topic).code);

export default {
  path: "languages/php.html",
  title: "PHP",
  description: "The LWS client for PHP 8.2+: installation with Composer, configuration with named arguments, lazy PagedSequence listings, the LwsException hierarchy, ext-curl or any PSR-18 client, and build instructions.",
  body: `
<h1><span class="lang-badge lang-php">PHP</span> PHP</h1>
<div class="badges">
  <span class="badge accent">lws-client 0.1.0 (Composer)</span>
  <span class="badge">PHP 8.2+</span>
  <span class="badge">namespace Ebremer\\Lws</span>
  <span class="badge">no Composer dependencies (ext-curl, ext-openssl, ext-sodium; PSR-18 optional)</span>
</div>
<p class="lead">A PHP client for any PHP 8.2+ application, from a plain script to a framework. Calls are synchronous,
options are named arguments (<code>slug:</code>, <code>ifMatch:</code>, <code>recursive:</code>), listings are lazy
<code>PagedSequence</code>s for <code>foreach</code>, models are final classes with <code>readonly</code> properties, and errors are
one exception hierarchy under <code>LwsException</code>. It needs only the extensions most PHP builds bundle.</p>
<div id="toc" class="toc"></div>

<h2 id="install">Install</h2>
${s("install")}
<p>The package's manifest is the repository's root <code>composer.json</code> (Packagist and Composer's VCS repositories read the
manifest only there); the sources are in <code>php/src</code>, autoloaded as <code>Ebremer\\Lws\\</code> (PSR-4).</p>

<h2 id="first">First program</h2>
${s("first-program")}
<p>This is a complete script: save it next to your project's <code>vendor/</code> directory and run it with <code>php</code>.</p>

<h2 id="configure">Configure the client</h2>
${s("client-config")}
<p><code>LwsClient</code> is immutable: create one and pass it around. <code>withAuthenticator($a)</code> returns a client with a
different authenticator over the same transport. The client follows redirects itself and authorizes each hop afresh, so its
<code>HttpTransport</code> must not follow redirects. The default <code>CurlTransport</code> keeps one curl handle (so connections are
reused), follows no redirects, stores no cookies and speaks http and https only; its constructor takes extra
<code>CURLOPT_*</code> options (a CA bundle, a proxy). <code>Psr18Transport</code> runs the client on any PSR-18 client (Guzzle,
Symfony HttpClient's <code>Psr18Client</code>, …) with PSR-17 factories; that client must not follow redirects either. A transport of
your own implements one method, <code>send(HttpRequest $request): HttpResponse</code>.</p>

<h2 id="idioms">PHP idioms</h2>
${table(
  ["Aspect", "How the PHP client does it"],
  [
    ["Calls", "Synchronous, like PHP itself. The <code>timeout</code> option (seconds, per request) bounds each exchange; running out of time throws <code>TransportException</code>, whose <code>isTimeout()</code> is true"],
    ["Options", "PHP 8 named arguments on every operation: <code>create($c, $body, 'text/plain', slug: 'a.txt', types: […])</code>, <code>update($url, $body, $type, ifMatch: $etag)</code>, <code>delete($url, recursive: true)</code>, <code>read($url, range: ByteRange::of(0, 1023))</code>. Every operation also takes <code>headers:</code> and <code>timeout:</code>"],
    ["Pagination", "<code>listContainer</code>, <code>listTypes</code>, <code>searchAll</code>, <code>listSubscriptions</code>… return a lazy <code>PagedSequence</code> (an <code>IteratorAggregate</code>): <code>foreach</code>, <code>toArray()</code> or <code>take($n)</code>. Pages are fetched as the iteration advances, and each <code>foreach</code> starts again from the first page"],
    ["Bodies", "PHP strings, which are bytes: always replayable for the retry after a <code>401</code>. <code>createText</code> and <code>createJson($c, $value)</code> for any value <code>json_encode()</code> takes; <code>ReadResult::text()</code> (by the response charset) and <code>json()</code>"],
    ["JSON", "<code>Json::decode()</code> turns objects into associative arrays, except <code>{}</code> and objects with keys <code>\"0\"</code>, <code>\"1\"</code>…, which stay <code>\\stdClass</code>, so documents (linksets, access documents, <code>raw</code>) round-trip unchanged. Write <code>new \\stdClass()</code> for <code>{}</code> in values you send"],
    ["Models", "Final classes with <code>public readonly</code> properties (<code>$meta->etag</code>, <code>$page->items</code>); computed values are methods (<code>storageRoot()</code>, <code>isContainer()</code>). URLs are strings, absolute in every result"],
    ["Errors", "<code>LwsException</code> (a <code>RuntimeException</code>): <code>HttpException</code> with a subclass per status (<code>NotFoundException</code>, <code>ConflictException</code>, <code>PreconditionFailedException</code>, …), <code>AuthenticationException</code>, <code>ProtocolException</code>, <code>SignatureVerificationException</code>, <code>TransportException</code>. Caller mistakes are PHP's own <code>\\InvalidArgumentException</code>, thrown before any request"],
    ["Crypto", "ext-openssl for P-256 and P-384 ECDSA (JOSE's raw <code>r‖s</code>, converted from OpenSSL's DER), ext-sodium for Ed25519, <code>hash()</code> for SHA-256 and SHA-512"],
    ["Secrets", "Keys, tokens and credentials are hidden from <code>var_dump</code> and <code>print_r</code> (<code>__debugInfo</code>), and marked <code>#[\\SensitiveParameter]</code> so stack traces leave them out"],
  ],
)}

<h2 id="types">Types</h2>
${table(
  ["Namespace", "Types"],
  [
    ["<code>Ebremer\\Lws</code>", "<code>LwsClient</code>, <code>PagedSequence</code>, <code>Vocabulary</code> (namespaces, type matching), and the constants <code>LinkRelation</code>, <code>ResourceType</code>, <code>MediaType</code>, <code>ServiceType</code>, <code>SubscriptionType</code>, <code>TokenType</code>, <code>AccessAction</code>, <code>ConstraintOperand</code>, <code>ConstraintOperator</code>, <code>Prefer</code>, <code>ActivityType</code>"],
    ["<code>…\\Model</code>", "<code>ResourceMetadata</code>, <code>ReadResult</code>, <code>CreateResult</code>, <code>UpdateResult</code>, <code>ByteRange</code>, <code>ContainerPage</code>, <code>ContainedResource</code>, <code>StorageDescription</code>, <code>Service</code>, <code>Capability</code>, <code>VerificationMethod</code>, <code>Linkset</code>, <code>LinkContext</code>, <code>LinkTarget</code>, <code>LinksetDocument</code>, <code>TypeIndexPage</code>, <code>TypeQuery</code>"],
    ["<code>…\\Auth</code>", "<code>Authenticator</code>, <code>AuthRequest</code>, <code>AuthResponse</code>, <code>TokenExchangeAuthenticator</code>, <code>BearerTokenAuthenticator</code>, <code>CredentialProvider</code>, <code>CredentialContext</code>, <code>OpenIdCredentials</code>, <code>SamlCredentials</code>, <code>SelfSignedCredentials</code>, <code>SigningKey</code>, <code>VerificationKey</code>, <code>Jwt</code>, <code>DidKey</code>, <code>ControlledIdentifierDocument</code>, <code>AuthorizationServerMetadata</code>, <code>AccessToken</code>"],
    ["<code>…\\Notification</code>", "<code>WebhookSubscriptionRequest</code>, <code>Subscription</code>, <code>Notification</code>, <code>Activity</code>, <code>ActivityObject</code>, <code>WebhookVerifier</code>, <code>VerifiedNotification</code>"],
    ["<code>…\\Access</code>", "<code>AccessRequest</code>, <code>AccessGrant</code>, <code>AccessPolicy</code>, <code>AccessTarget</code>, <code>Constraint</code>"],
    ["<code>…\\Http</code>", "<code>HttpTransport</code>, <code>CurlTransport</code>, <code>Psr18Transport</code>, <code>HttpRequest</code>, <code>HttpResponse</code>, <code>Headers</code>, <code>Link</code>, <code>LinkHeader</code>, <code>WwwAuthenticate</code>, <code>AuthChallenge</code>, <code>StructuredFields</code>, <code>ProblemDetails</code>, <code>Slug</code>"],
    ["<code>…\\Json</code>", "<code>Json</code>, <code>JsonPatch</code>, <code>JsonPointer</code>"],
    ["<code>…\\Exception</code>", "<code>LwsException</code>, <code>HttpException</code> and its status subclasses, <code>AuthenticationException</code>, <code>ProtocolException</code>, <code>SignatureVerificationException</code>, <code>TransportException</code>"],
  ],
)}
<p>The fragments on this site leave out their <code>use</code> statements; the complete programs show them.</p>

<h2 id="notes">Notes and deviations</h2>
<ul>
  <li>The contract's <code>Resource</code> is <code>ReadResult</code>, because <code>resource</code> is a soft-reserved word in PHP.
  <code>Link::typeLink($iri)</code> builds a <code>rel="type"</code> link, since <code>type()</code> is the accessor of the
  <code>type</code> attribute. A subscription's URL (the contract's <code>subscription</code>) is <code>Subscription::$url</code>.</li>
  <li>The contract's error classes are exception classes named <code>…Exception</code> (<code>NotFoundException</code>,
  <code>ProtocolException</code>); the 501 one is <code>NotImplementedException</code>, which clashes with nothing in PHP.</li>
  <li>Request and response bodies are strings: there is no streaming read or upload, so every body can be replayed for
  the single retry after a <code>401</code>. Read large resources in pieces with <code>range:</code>.</li>
  <li><code>JsonPatch</code>, <code>TypeQuery</code> and <code>Linkset</code> are fluent builders that change in place:
  <code>$doc->linkset->add(…)</code>, then <code>updateLinkset($doc->url, $doc->linkset)</code>. <code>TypeQuery</code>'s builders throw
  <code>\\InvalidArgumentException</code> for an IRI that is not absolute or an empty OR group.</li>
  <li><code>WebhookVerifier::verifyGlobals($inboxUrl)</code> verifies the delivery of the current request (<code>$_SERVER</code> and
  <code>php://input</code>), so a plain PHP script can be the inbox; <code>verifyServerRequest($request, $inboxUrl)</code> takes a PSR-7
  request, and <code>verify($method, $url, $headers, $body)</code> the parts. Pass the inbox URL as registered, not the one a proxy
  forwarded to.</li>
  <li>The token cache lives in the <code>TokenExchangeAuthenticator</code>, so it lasts as long as the PHP process: one request under
  PHP-FPM, or the whole run of a CLI worker.</li>
  <li>Extras: <code>request($method, $url, body:, contentType:)</code> sends any method through the authentication and redirect
  pipeline; <code>readLinksetResource($url)</code> reads a linkset at a known URL.</li>
</ul>

<h2 id="build">Build, test and examples</h2>
${code("bash", `
composer install                                        # at the repository root: PHPUnit, PHPStan, PSR test doubles
composer test                                           # unit, fixture and HTTP tests (PHPUnit, php/phpunit.xml.dist)
composer analyse                                        # PHPStan, level 8
node testing/mock-server/server.mjs --port 8787 &
LWS_TEST_SERVER=http://localhost:8787 composer test     # adds the cross-language interop scenario

# Examples (php/examples/): quickstart.php, self_signed_auth.php, webhook_receiver.php
php php/examples/quickstart.php http://localhost:8787/root/`)}
${callout("note", "Source", ' <a href="https://github.com/ebremer/lws-client/tree/main/php">php/</a> in the repository, with its own <a href="https://github.com/ebremer/lws-client/blob/main/php/README.md">README</a> and <a href="https://github.com/ebremer/lws-client/tree/main/php/examples">examples</a>.')}
`,
};
