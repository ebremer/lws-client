// SPDX-License-Identifier: MIT
import { callout, table } from "../lib.mjs";

const c = (s) => `<code>${s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")}</code>`;
const H = ["Concept", "Java", "TypeScript", "C++", "Rust", "Go", "Python", "C#"];

/** rows: [concept, java, ts, cpp, rust, go, python, csharp] — cells are code unless they start with "~" (plain text). */
function group(rows) {
  return table(
    H,
    rows.map(([concept, ...cells]) => [concept, ...cells.map((x) => (x.startsWith("~") ? x.slice(1) : c(x)))]),
  );
}

export default {
  path: "api-reference.html",
  title: "API cross-reference",
  wide: true,
  description: "The same LWS concept in Java, TypeScript, C++, Rust, Go, Python and C#: a side-by-side reference of every class, method and option in the seven clients.",
  body: `
<h1>API cross-reference</h1>
<p class="lead">All seven clients implement one <a href="https://github.com/ebremer/lws-client/blob/main/design/client-api.md">API
contract</a>. This page maps each concept to its name in every language. Arguments are abbreviated: <code>url</code>
is a URL (Java <code>URI</code>, C# <code>Uri</code>, Rust <code>impl IntoUrl</code>, otherwise a string). Go methods also take a leading
<code>ctx</code>, Rust request builders are awaited, and C# methods are awaited and take an optional trailing
<code>CancellationToken</code>.</p>
<div id="toc" class="toc"></div>

<h2 id="client">Client and configuration</h2>
${group([
  ["Client", "LwsClient.builder()…build()", "new LwsClient({…})", "lws::Client(ClientOptions)", "Client::builder()…build()?", "lws.NewClient(opts...)", "LwsClient(…) / AsyncLwsClient(…)", "new LwsClient(new LwsClientOptions { … })"],
  ["Concurrency model", "~blocking, plus <code>*Async</code> → <code>CompletableFuture</code>", "~<code>Promise</code> / <code>async</code>", "~blocking (thread-safe)", "~<code>async</code> (tokio)", "~blocking + <code>context.Context</code>", "~sync and <code>asyncio</code> clients", "~<code>async</code> / <code>await</code> (<code>Task</code>, <code>CancellationToken</code>)"],
  ["Authenticator", ".authenticator(a)", "{ authenticator }", "options.authenticator", ".authenticator(a)", "lws.WithAuthenticator(a)", "authenticator=a", "Authenticator = a"],
  ["HTTP engine", ".httpClient(HttpClient)", "{ fetch }", "options.transport (HttpTransport)", ".http_client(reqwest::Client)", "lws.WithHTTPClient(*http.Client)", "http_client=httpx.Client", "HttpClient = … / HttpMessageHandler = …"],
  ["User-Agent / headers", ".userAgent(s) .header(k, v)", "{ userAgent, headers }", "options.user_agent / default_headers", ".user_agent(s) .default_header(k, v)", "lws.WithUserAgent(s) lws.WithHeader(k, v)", "user_agent=, default_headers=", "UserAgent = s, DefaultHeaders = {…}"],
  ["Timeout", ".timeout(Duration)", "{ timeoutMs }", "options.timeout", ".timeout(Duration)", "lws.WithTimeout(d)", "timeout=seconds", "Timeout = TimeSpan"],
  ["Per-call options", "ReadOptions / CreateOptions / UpdateOptions / DeleteOptions", "{ headers, signal, … }", "ReadOptions{…} / CreateOptions{…} / …", "~request-builder methods", "~variadic <code>CallOption</code>s", "~keyword arguments", "ReadOptions / CreateOptions / UpdateOptions / DeleteOptions"],
])}

<h2 id="discovery">Discovery</h2>
${group([
  ["Discover from any URL", "discoverStorage(url)", "discoverStorage(url)", "discover_storage(url)", "discover_storage(url)", "DiscoverStorage(ctx, url)", "discover_storage(url)", "DiscoverStorageAsync(url)"],
  ["Fetch description", "getStorageDescription(url)", "getStorageDescription(url)", "get_storage_description(url)", "get_storage_description(url)", "GetStorageDescription(ctx, url)", "get_storage_description(url)", "GetStorageDescriptionAsync(url)"],
  ["Storage root", "storageRoot()", "storageRoot()", "storage_root()", "storage_root()?", "StorageRoot()", "storage_root()", "GetStorageRoot()"],
  ["Find services", "service(t) / services(t)", "service(t) / services(t)", "service(t) / services_of(t)", "service(t) / services_of(t)", "Service(t) / ServicesOfType(t)", "service(t) / find_services(t)", "GetService(t) / GetServices(t)"],
  ["Well-known services", "notificationService() … → Optional<Service>", "notificationService() … → Service | undefined", "notification_service() … → const Service*", "notification_service() … → Option<&Service>", "NotificationService() … → (Service, bool)", "notification_service() … → endpoint URL | None", "NotificationService … → Service?"],
  ["Capability", "capability(t)", "capability(t)", "capability(t)", "capability(t)", "Capability(t)", "capability(t)", "GetCapability(t)"],
])}

<h2 id="reading">Reading</h2>
${group([
  ["Metadata only", "head(url)", "head(url)", "head(url)", "head(url)", "Head(ctx, url)", "head(url)", "HeadAsync(url)"],
  ["Read", "read(url, ReadOptions)", "read(url, { … })", "read(url, ReadOptions{…})", "read(url).…", "Read(ctx, url, opts...)", "read(url, …)", "ReadAsync(url, ReadOptions)"],
  ["Body", "text() / body() / json() / json(Class)", "text() / bytes() / json() / blob()", "text() / body / json()", "text()? / body / json::<T>()?", "Text() / Body / JSON(&v)", "text / content / json()", "GetText() / Body / GetJson() / GetJson<T>()"],
  ["Stream body", "readStream(url) → ResourceStream", "read(url).body (ReadableStream)", "~— (use byte ranges)", "read(url).send_streaming()", "ReadStream(ctx, url)", "stream(url) (context manager)", "ReadStreamAsync(url) → ResourceStream"],
  ["Conditional read", "ReadOptions.ifNoneMatch(etag)", "{ ifNoneMatch }", "{.if_none_match = …}", ".if_none_match(etag)", "lws.IfNoneMatch(etag)", "if_none_match=", "new ReadOptions { IfNoneMatch = etag }"],
  ["304 result", "notModified()", "notModified", "not_modified", "not_modified", "NotModified", "not_modified", "NotModified"],
  ["Byte range", "range(start, end) / suffixRange(n)", "{ range: { start, end } | { suffix } }", "byte_range(first, last)", ".range(start, Some(end))", "lws.ByteRange(start, end)", "range=(start, end)", "Range = new RangeHeaderValue(from, to)"],
  ["Read a container page", "readContainer(url)", "readContainer(url)", "read_container(url)", "read_container(url)", "ReadContainer(ctx, url)", "read_container(url)", "ReadContainerAsync(url)"],
  ["Iterate all members", "listContainer(url) → Stream", "listContainer(url) → AsyncGenerator", "list_container(url) → ContainerRange", "list_container(url) → LwsStream", "ListContainer(ctx, url) → iter.Seq2", "list_container(url) → Iterator", "ListContainerAsync(url) → IAsyncEnumerable"],
])}

<h2 id="writing">Writing</h2>
${group([
  ["Create", "create(url, Body, type, CreateOptions)", "create(url, body, type, { … })", "create(url, body, type, {…})", "create(url, body, type).…", "Create(ctx, url, io.Reader, type, opts...)", "create(url, body, type, …)", "CreateAsync(url, bytes | Stream, type, CreateOptions)"],
  ["Create JSON / text", "createJson(url, value, opts)", "createJson / createText", "create_json(url, json, opts)", "create_json(url, &value)", "CreateJSON(ctx, url, v, opts...)", "create_json / create_text", "CreateJsonAsync / CreateTextAsync"],
  ["Create container", "createContainer(url, opts)", "createContainer(url, opts)", "create_container(url, opts)", "create_container(url)", "CreateContainer(ctx, url, opts...)", "create_container(url, …)", "CreateContainerAsync(url, opts)"],
  ["Slug / types / links", "CreateOptions.builder().slug().type().link()", "{ slug, types, links }", "{.slug, .types, .links}", ".slug() .resource_type() .link()", "lws.Slug() lws.Types() lws.Links()", "slug=, types=, links=", "new CreateOptions { Slug, Types, Links }"],
  ["Replace (PUT)", "update(url, Body, type, UpdateOptions)", "update(url, body, type, { … })", "update(url, body, type, {…})", "update(url, body, type).…", "Update(ctx, url, r, type, opts...)", "update(url, body, type, …)", "UpdateAsync(url, bytes | Stream, type, UpdateOptions)"],
  ["If-Match", "UpdateOptions.ifMatch(etag)", "{ ifMatch }", "{.if_match = …}", ".if_match(etag)", "lws.IfMatch(etag)", "if_match=", "new UpdateOptions { IfMatch = etag }"],
  ["Prefer: set-linkset", "builder().setLinkset(true).link(…)", "{ setLinkset: true, links }", "{.links, .set_linkset = true}", ".set_linkset(true).link(…)", "lws.SetLinkset() lws.Links(…)", "set_linkset=True, links=", "{ SetLinkset = true, Links = […] }"],
  ["JSON Patch", "patch(url, JsonPatch, opts)", "patch(url, JsonPatch | ops)", "patch(url, JsonPatch, opts)", "patch(url, &JsonPatch)", "Patch(ctx, url, JSONPatch, opts...)", "patch(url, JsonPatch)", "PatchAsync(url, JsonPatch, opts)"],
  ["Other patch format", "patch(url, Body, type, opts)", "patch(url, { body, contentType })", "patch(url, body, type, opts)", "patch_with(url, body, type)", "PatchRaw(ctx, url, r, type)", "patch(url, body, content_type=)", "PatchAsync(url, bytes, type, opts)"],
  ["Patch builder", "JsonPatch.builder().add().remove()….build()", "new JsonPatch().add().remove()…", "lws::JsonPatch{}.add().remove()…", "JsonPatch::new().add().remove()… (move_value)", "lws.JSONPatch{}.Add().Remove()…", "JsonPatch().add().remove()…", "new JsonPatch().Add().Remove()… (immutable)"],
  ["JSON Pointer", "JsonPointer.of(segments...)", "JsonPointer.from([segments])", "JsonPointer::from_segments({…})", "JsonPointer::from_segments([…])", "lws.JSONPointer(segments...)", "JsonPointer.from_segments(*segments)", "JsonPointer.Of(segments...)"],
  ["Delete", "delete(url, DeleteOptions)", "delete(url, { … })", "remove(url, {…})", "delete(url).…", "Delete(ctx, url, opts...)", "delete(url, …)", "DeleteAsync(url, DeleteOptions)"],
  ["Recursive delete", "DeleteOptions.recursive()", "{ recursive: true }", "{.recursive = true}", ".recursive(true)", "lws.Recursive()", "recursive=True", "new DeleteOptions { Recursive = true }"],
])}

<h2 id="metadata">Metadata (linksets)</h2>
${group([
  ["Linkset URL", "linksetUrl(url)", "linksetUrl(url)", "linkset_url(url)", "linkset_url(url)", "LinksetURL(ctx, url)", "linkset_url(url)", "LinksetUrlAsync(url)"],
  ["Read for a resource", "readLinkset(url)", "readLinkset(url)", "read_linkset(url)", "read_linkset(url)", "ReadLinkset(ctx, url)", "read_linkset(url)", "ReadLinksetAsync(url)"],
  ["Read by linkset URL", "readLinksetResource(url)", "~—", "~—", "read_linkset_document(url)", "ReadLinksetAt(ctx, url)", "read_linkset_at(url)", "ReadLinksetResourceAsync(url)"],
  ["Replace (PUT)", "updateLinkset(url, Linkset, opts)", "updateLinkset(url, linkset, opts)", "update_linkset(url, linkset, opts)", "update_linkset(url, &linkset)", "UpdateLinkset(ctx, url, *Linkset, opts...)", "update_linkset(url, linkset, …)", "UpdateLinksetAsync(url, Linkset, opts)"],
  ["Patch", "patchLinkset(url, JsonPatch, opts)", "patchLinkset(url, patch, opts)", "patch_linkset(url, patch, opts)", "patch_linkset(url, &patch)", "PatchLinkset(ctx, url, patch, opts...)", "patch_linkset(url, patch, …)", "PatchLinksetAsync(url, JsonPatch, opts)"],
  ["Model helpers", "links() targets(rel) add(…) remove(…) (immutable)", "links() targets(rel) add() remove() clone()", "links() targets(rel) add() remove()", "links() targets(rel) add() remove()", "Links() Targets(rel) Add() Remove()", "links() targets(rel) add() remove() copy()", "GetLinks() GetTargets(rel) Add(…) Remove(…) (immutable)"],
])}

<h2 id="auth">Authentication</h2>
${group([
  ["Authenticator interface", "Authenticator (authorize, handleChallenge)", "Authenticator (authorize, handleChallenge)", "lws::Authenticator (authorize, handle_challenge)", "Authenticator trait (BoxFuture methods)", "Authenticator (Authorize, HandleChallenge)", "Authenticator (authorize, handle_challenge)", "IAuthenticator (AuthorizeAsync, HandleChallengeAsync)"],
  ["Token exchange", "TokenExchangeAuthenticator.of(c) / .builder(c)", "new TokenExchangeAuthenticator(c, opts)", "TokenExchangeAuthenticator(c, TokenExchangeOptions)", "TokenExchangeAuthenticator::new(c) / ::builder(c)", "NewTokenExchangeAuthenticator(c, *TokenExchangeOptions)", "TokenExchangeAuthenticator(c, …)", "new TokenExchangeAuthenticator(c, TokenExchangeOptions)"],
  ["Static bearer token", "BearerTokenAuthenticator.of(token, realm)", "new BearerTokenAuthenticator(token, { realm })", "BearerTokenAuthenticator(token, realm)", "BearerTokenAuthenticator::new(t).with_realm(u)", "NewBearerTokenAuthenticator(token, realm)", "BearerTokenAuthenticator(token, realm=)", "new BearerTokenAuthenticator(token, realm)"],
  ["OpenID Connect", "OpenIdCredentials.of(t) / .from(supplier)", "new OpenIdCredentials(t | fn)", "OpenIdCredentials(t | supplier)", "OpenIdCredentials::new(t) / ::from_fn(f)", "NewOpenIDCredentials(t) / NewOpenIDCredentialsFunc(f)", "OpenIdCredentials(t | callable)", "new OpenIdCredentials(t | callback)"],
  ["SAML 2.0", "SamlCredentials.ofXml(xml) / .ofEncoded(b64)", "new SamlCredentials(assertion | fn)", "SamlCredentials::from_xml(xml) / SamlCredentials(b64)", "SamlCredentials::from_xml(xml) / ::new(b64)", "NewSAMLCredentials(EncodeSAMLAssertion(xml))", "SamlCredentials(xml | b64 | callable)", "SamlCredentials.FromXml(xml) / .FromEncoded(b64)"],
  ["Self-signed did:key", "SelfSignedCredentials.didKey(KeyPair)", "SelfSignedCredentials.didKey(pair)", "SelfSignedCredentials::did_key(PrivateKey)", "SelfSignedCredentials::did_key(SigningKey)", "NewDIDKeyCredentials(signer, opts)", "SelfSignedCredentials.did_key(SigningKey)", "SelfSignedCredentials.DidKey(SigningKey)"],
  ["Self-signed HTTPS agent", "SelfSignedCredentials.forAgent(uri, key, kid)", "SelfSignedCredentials.forAgent(agent, pair, kid)", "SelfSignedCredentials::for_agent(uri, key, kid)", "SelfSignedCredentials::for_agent(agent, key, kid)", "NewSelfSignedCredentials(agent, signer, kid, opts)", "SelfSignedCredentials.for_agent(agent, key, kid)", "SelfSignedCredentials.ForAgent(uri, key, kid)"],
  ["Generate keys", "KeyPairs.generateP256() / generateEd25519()", 'generateKeyPair("ES256" | "EdDSA")', "PrivateKey::generate(KeyAlgorithm::ES256 | EdDSA)", "SigningKey::generate_p256() / generate_ed25519()", "GenerateP256Key() / GenerateEd25519Key()", 'SigningKey.generate("ES256" | "EdDSA")', "SigningKey.GenerateP256() / GenerateEd25519()"],
  ["Export / import JWK", "Jwk.fromKeyPair / Jwk.toPrivateKey", "exportPrivateJwk / importKeyPair", "private_jwk() / PrivateKey::from_jwk", "to_jwk() / SigningKey::from_jwk", "JWKFromPrivateKey / ParseJWK(…).PrivateKey()", "private_jwk() / SigningKey.from_jwk", "key.ToJwk() / SigningKey.FromJwk"],
  ["did:key ⇄ key", "DidKey.fromPublicKey / DidKey.toPublicKey", "didKeyFromJwk / jwkFromDidKey", "did_key_from_public_jwk", "key.did_key() / VerifyingKey::from_did_key", "DIDKeyFromPublicKey / PublicKeyFromDIDKey", "did_key_from_jwk / did_key_to_jwk", "DidKey.FromPublicKey / DidKey.ToPublicKey"],
  ["CID document", "ControlledIdentifiers.document(…)", "controlledIdentifierDocument(…)", "controlled_identifier_document(…)", "crypto::controlled_identifier_document(…)", "NewControlledIdentifierDocument(…)", "controlled_identifier_document(…)", "ControlledIdentifierDocument.Create(…)"],
])}

<h2 id="notifications">Notifications</h2>
${group([
  ["Subscribe", "subscribe(url | StorageDescription, WebhookSubscriptionRequest)", "subscribe(service, { topics, inbox, expires })", "subscribe(url | StorageDescription, WebhookSubscriptionRequest)", "subscribe(url, &req) / subscribe_storage(&sd, &req)", "Subscribe(ctx, url, req) / SubscribeWebhook(ctx, sd, req)", "subscribe(service, topics, inbox, expires=)", "SubscribeAsync(url | Service, WebhookSubscriptionRequest)"],
  ["List / get / cancel", "listSubscriptions / getSubscription / unsubscribe", "listSubscriptions / getSubscription / unsubscribe", "list_subscriptions / get_subscription / unsubscribe", "list_subscriptions / get_subscription / unsubscribe", "ListSubscriptions / GetSubscription / Unsubscribe", "list_subscriptions / get_subscription / unsubscribe", "ListSubscriptionsAsync / GetSubscriptionAsync / UnsubscribeAsync"],
  ["Parse a notification", "Notification.parse(json)", "parseNotification(body)", "parse_notification(body)", "parse_notification(bytes)", "ParseNotification(data)", "parse_notification(body)", "Notification.Parse(json)"],
  ["Verify deliveries", "WebhookVerifier.builder()…build().verify(m, inbox, headers, body)", "new WebhookVerifier({…}).verify(request, { inboxUrl })", "WebhookVerifier(client, opts).verify(m, url, headers, body)", "WebhookVerifier::builder()…build().verify(…).await", "NewWebhookVerifier(opts).Verify / VerifyRequest / Handler", "WebhookVerifier(client=…).verify(…) / AsyncWebhookVerifier", "new WebhookVerifier(opts).VerifyAsync(m, inbox, headers, body)"],
])}

<h2 id="access">Access requests and grants</h2>
${group([
  ["Request access", "requestAccess(url, AccessRequest)", "requestAccess(service, request)", "request_access(url, AccessRequest)", "request_access(url, &request)", "RequestAccess(ctx, url, *AccessRequest)", "request_access(service, request)", "RequestAccessAsync(url, AccessRequest)"],
  ["List / get / cancel", "listAccessRequests / getAccessRequest / cancelAccessRequest", "listAccessRequests / getAccessRequest / cancelAccessRequest", "list_access_requests / get_access_request / cancel_access_request", "list_access_requests / get_access_request / cancel_access_request", "ListAccessRequests / GetAccessRequest / CancelAccessRequest", "list_access_requests / get_access_request / cancel_access_request", "ListAccessRequestsAsync / GetAccessRequestAsync / CancelAccessRequestAsync"],
  ["Grant / list / get / revoke", "grantAccess / listAccessGrants / getAccessGrant / revokeAccessGrant", "grantAccess / listAccessGrants / getAccessGrant / revokeAccessGrant", "grant_access / list_access_grants / get_access_grant / revoke_access_grant", "grant_access / list_access_grants / get_access_grant / revoke_access_grant", "GrantAccess / ListAccessGrants / GetAccessGrant / RevokeAccessGrant", "grant_access / list_access_grants / get_access_grant / revoke_access_grant", "GrantAccessAsync / ListAccessGrantsAsync / GetAccessGrantAsync / RevokeAccessGrantAsync"],
  ["Build a request", "AccessRequest.builder().storage().access(policy)", "new AccessRequest({ storage, access })", "AccessRequest{.storage, .access}", "AccessRequest::builder(storage).policy(p).build()?", "NewAccessRequest(storage, policies...)", "AccessRequest(storage=, access=[…])", "new AccessRequest(storage, [policy], inbox)"],
  ["Build a policy", "AccessPolicy.builder().actions().assignee().target()", "{ actions, assignee, target, constraints }", "AccessPolicy{.actions, .assignee, .target}", "AccessPolicy::builder(assignee).action().target_resources()", "NewAccessPolicy(assignee, actions...).WithTarget()", "AccessPolicy(actions=, assignee=, target=)", "new AccessPolicy(actions, assignee, target, constraints)"],
  ["Constraints", "Constraint.purpose / client / format / type / notBefore / notAfter", "Constraints.purpose / client / format / type / notBefore / notAfter", "Constraint::purpose / client / format / type / not_before / not_after", "Constraint::purpose / client / format / resource_type / not_before / not_after", "PurposeConstraint / ClientConstraint / FormatConstraint / TypeConstraint / NotBefore / NotAfter", "Constraint.purpose / client / format / resource_type / not_before / not_after", "Constraint.Purpose / Client / Format / Type / NotBefore / NotAfter"],
])}

<h2 id="types">Type index and search</h2>
${group([
  ["Read an index page", "readTypeIndex(url)", "readTypeIndex(url)", "read_type_index(url)", "read_type_index(url)", "ReadTypeIndex(ctx, url)", "read_type_index(url)", "ReadTypeIndexAsync(url)"],
  ["Iterate all types", "listTypes(url) → Stream<String>", "listTypes(service) → AsyncGenerator<string>", "list_types(url) → TypeRange", "list_types(url) → LwsStream<String>", "ListTypes(ctx, url) → iter.Seq2[string, error]", "list_types(service) → Iterator[str]", "ListTypesAsync(url) → IAsyncEnumerable<string>"],
  ["Search (one page, QUERY)", "searchTypes(url, TypeQuery)", "searchTypes(service, query)", "search_types(url, query)", "search_types(url, &query)", "SearchTypes(ctx, url, *TypeQuery)", "search_types(service, query)", "SearchTypesAsync(url, TypeQuery)"],
  ["Search (all pages)", "searchAll(url, query)", "searchAll(service, query)", "search_all(url, query)", "search_all(url, &query)", "SearchAll(ctx, url, q)", "search_all(service, query)", "SearchAllAsync(url, query)"],
  ["Query builder", "TypeQuery.builder().allOf().anyOf().relationAllOf()", "new TypeQuery().allOf().anyOf().relation(r).allOf()", "TypeQuery{}.all_of({…}).any_of({…}).relation_all_of(r, {…})", "TypeQuery::new().all_of([…]).any_of([…]).relation(r).all_of([…])", "NewTypeQuery().AllOf().AnyOf().RelationAllOf(r, …)", "TypeQuery().all_of().any_of().relation(r).all_of()", "new TypeQuery().AllOf().AnyOf().Relation(r).AllOf()"],
  ["Accepted formats", "acceptedQueryFormats(url)", "acceptedQueryFormats(service)", "accepted_query_formats(url)", "accepted_query_formats(url)", "AcceptedQueryFormats(ctx, url)", "accepted_query_formats(service)", "AcceptedQueryFormatsAsync(url)"],
])}

<h2 id="parsers">HTTP primitives</h2>
${group([
  ["Link header (RFC 8288)", "LinkHeader.parse / LinkHeader.format", "parseLinkHeader / formatLink", "parse_link_header / Link::to_header", "headers::parse_link_headers", "ParseLinkHeader / FormatLinks", "parse_link_header / serialize_links", "LinkHeader.Parse / LinkHeader.Format"],
  ["WWW-Authenticate", "WwwAuthenticate.parse", "parseWwwAuthenticate", "parse_www_authenticate", "headers::parse_www_authenticate", "ParseChallenges", "parse_www_authenticate", "WwwAuthenticate.Parse"],
  ["Structured fields (RFC 8941)", "StructuredFields.parseDictionary", "parseDictionary / serializeDictionary", "sf::parse_dictionary / sf::serialize", "headers::structured", "ParseSFDictionary", "structured_fields module", "StructuredFields.ParseDictionary / SerializeDictionary"],
  ["Problem details (RFC 9457)", "ProblemDetails", "parseProblemDetails", "ProblemDetails::from_response", "headers::ProblemDetails", "ParseProblemDetails", "ProblemDetails", "ProblemDetails.Parse / FromJson"],
  ["Constants", "Lws.Rel / Lws.Type / Lws.MediaType / …", "Rel / LwsType / MediaType / ServiceType / …", "lws::rel / types / media / service / …", "constants::{rel, types, media_type, …}", "RelStorage / TypeContainer / MediaLWSJSON / …", "Rel / Types / MediaType / ServiceType / …", "Lws.Rel / Lws.Types / Lws.MediaType / Lws.ServiceType / …"],
])}
${callout("note", "Where names differ", " Keywords and built-ins force a few renames. C++ uses <code>remove</code> (not <code>delete</code>) and <code>Constraint::op</code>. Rust uses <code>JsonPatch::move_value</code> and <code>Constraint::resource_type</code>. Python uses <code>NotImplementedByServerError</code>, <code>links_for</code> and <code>find_services</code>. Java uses <code>LwsProtocolException</code> and <code>HttpStatusException</code>. C# uses <code>HttpNotImplementedException</code>, <code>Subscription.Url</code> and <code>GetStorageRoot()</code>. Each <a href=\"languages/java.html\">language guide</a> lists its deviations.")}
`,
};
