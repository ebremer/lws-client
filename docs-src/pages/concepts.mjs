// SPDX-License-Identifier: MIT
import { callout, code, table } from "../lib.mjs";

const resourceModel = `
<figure class="diagram">
<svg viewBox="0 0 760 236" role="img" aria-labelledby="rm-title">
  <title id="rm-title">LWS resource model: a storage description points to the storage root container, which contains containers and data resources, each with a linkset.</title>
  <defs><marker id="rm-arrow" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse"><path class="arrowhead" d="M0 0L10 5L0 10z"/></marker></defs>
  <rect class="box-accent" x="8" y="62" width="176" height="84" rx="8"/>
  <text class="label" x="22" y="88">Storage description</text>
  <text class="sublabel" x="22" y="108">application/lws+cid</text>
  <text class="sublabel" x="22" y="126">service, capability</text>
  <rect class="box" x="268" y="76" width="140" height="56" rx="8"/>
  <text class="label" x="282" y="100">Storage root</text>
  <text class="sublabel" x="282" y="119">Container /root/</text>
  <rect class="box" x="448" y="14" width="140" height="56" rx="8"/>
  <text class="label" x="462" y="38">notes/</text>
  <text class="sublabel" x="462" y="57">Container</text>
  <rect class="box" x="448" y="138" width="140" height="56" rx="8"/>
  <text class="label" x="462" y="162">profile.json</text>
  <text class="sublabel" x="462" y="181">DataResource</text>
  <rect class="box" x="616" y="14" width="136" height="56" rx="8"/>
  <text class="label" x="630" y="38">shopping.txt</text>
  <text class="sublabel" x="630" y="57">DataResource</text>
  <rect class="box" x="616" y="138" width="136" height="56" rx="8" stroke-dasharray="5 4"/>
  <text class="label" x="630" y="162">profile.json.meta</text>
  <text class="sublabel" x="630" y="181">linkset+json</text>
  <path class="edge" d="M184 104H266" marker-end="url(#rm-arrow)"/>
  <text class="edge-label" x="225" y="96" text-anchor="middle">StorageRoot</text>
  <path class="edge" d="M408 96C430 96 426 42 446 42" marker-end="url(#rm-arrow)"/>
  <path class="edge" d="M408 112C430 112 426 166 446 166" marker-end="url(#rm-arrow)"/>
  <text class="edge-label" x="438" y="108" text-anchor="middle">items</text>
  <path class="edge" d="M588 42H614" marker-end="url(#rm-arrow)"/>
  <path class="edge" d="M588 166H614" stroke-dasharray="4 4" marker-end="url(#rm-arrow)"/>
  <text class="edge-label" x="602" y="214" text-anchor="middle">rel="linkset"</text>
</svg>
<figcaption>A storage is described by a storage description; its root container lists members in <code>items</code>. Every member links back to its parent with <code>rel="up"</code> and to its metadata with <code>rel="linkset"</code>.</figcaption>
</figure>`;

const authSequence = `
<figure class="diagram">
<svg viewBox="0 0 760 392" role="img" aria-labelledby="auth-title">
  <title id="auth-title">LWS authorization sequence: 401 challenge, authorization server metadata discovery, OAuth 2.0 token exchange, and a retried request with a bearer token.</title>
  <defs><marker id="seq-arrow" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse"><path class="arrowhead" d="M0 0L10 5L0 10z"/></marker></defs>
  <rect class="box-accent" x="40" y="10" width="160" height="38" rx="8"/><text class="label" x="120" y="34" text-anchor="middle">LWS client</text>
  <rect class="box" x="300" y="10" width="160" height="38" rx="8"/><text class="label" x="380" y="34" text-anchor="middle">Storage server</text>
  <rect class="box" x="560" y="10" width="160" height="38" rx="8"/><text class="label" x="640" y="34" text-anchor="middle">Authorization server</text>
  <path class="edge" d="M120 48V384M380 48V384M640 48V384" stroke-dasharray="3 5"/>
  <path class="edge" d="M120 84H378" marker-end="url(#seq-arrow)"/><text class="edge-label" x="250" y="76" text-anchor="middle">GET /root/notes/</text>
  <path class="edge" d="M380 122H122" marker-end="url(#seq-arrow)"/><text class="edge-label" x="250" y="114" text-anchor="middle">401 · Bearer as_uri, realm</text>
  <path class="edge" d="M120 164H638" marker-end="url(#seq-arrow)"/><text class="edge-label" x="510" y="156" text-anchor="middle">GET /.well-known/lws-configuration</text>
  <path class="edge" d="M640 202H122" marker-end="url(#seq-arrow)"/><text class="edge-label" x="510" y="194" text-anchor="middle">issuer · token_endpoint</text>
  <path class="edge" d="M120 244H638" marker-end="url(#seq-arrow)"/><text class="edge-label" x="510" y="236" text-anchor="middle">POST token (token-exchange, subject_token)</text>
  <path class="edge" d="M640 282H122" marker-end="url(#seq-arrow)"/><text class="edge-label" x="510" y="274" text-anchor="middle">access_token (aud = realm)</text>
  <path class="edge" d="M120 324H378" marker-end="url(#seq-arrow)"/><text class="edge-label" x="250" y="316" text-anchor="middle">GET + Authorization: Bearer</text>
  <path class="edge" d="M380 362H122" marker-end="url(#seq-arrow)"/><text class="edge-label" x="250" y="354" text-anchor="middle">200 OK</text>
</svg>
<figcaption>Every client runs this flow automatically when configured with a <code>TokenExchangeAuthenticator</code>. Tokens are cached per authorization server and realm and reused proactively.</figcaption>
</figure>`;

export default {
  path: "concepts.html",
  title: "LWS concepts",
  description: "The Linked Web Storage model in one page: storages, storage descriptions, containers, data resources, linksets, authentication, notifications, access grants and type indexes.",
  body: `
<h1>LWS concepts</h1>
<p class="lead">Linked Web Storage (LWS) is the W3C Working Group's standard for giving applications secure,
permissioned access to data that users keep in a storage of their choosing. It grew out of the Solid
Protocol. This page summarises the model the clients implement.</p>
<div id="toc" class="toc"></div>

<h2 id="storage">Storages and storage descriptions</h2>
<p>A <dfn>storage</dfn> is a hierarchy of HTTP resources managed under LWS rules. Every storage is
identified by a URI. Dereferencing it yields a <dfn>storage description</dfn>: a
<a href="https://www.w3.org/TR/cid-1.0/">W3C Controlled Identifier</a> document served as
<code>application/lws+cid</code>. It lists <code>service</code> entries (one of which is always the
<code>StorageRoot</code>), optional <code>capability</code> entries, and keys the storage uses to sign
webhooks.</p>
${code("json", `
{
  "@context": ["https://www.w3.org/ns/cid/v1", "https://www.w3.org/ns/lws/v1"],
  "id": "https://storage.example/",
  "type": "Storage",
  "service": [
    { "type": "StorageRoot", "serviceEndpoint": "https://storage.example/root/" },
    { "type": "NotificationService", "serviceEndpoint": "https://storage.example/notifications/",
      "subscriptionType": ["WebhookSubscription"] },
    { "type": "TypeIndexService", "serviceEndpoint": "https://storage.example/types/index" },
    { "type": "TypeSearchService", "serviceEndpoint": "https://storage.example/types/search" }
  ]
}`, { title: "GET https://storage.example/  →  application/lws+cid" })}
<p>Clients never guess URLs. Every response to <code>GET</code>/<code>HEAD</code> on a storage resource
carries <code>Link: &lt;storage&gt;; rel="https://www.w3.org/ns/lws#storage"</code>, so
<a href="discovery.html">discovery</a> can start from any resource URL.</p>

<h2 id="resources">Containers and data resources</h2>
${resourceModel}
<dl class="defs">
  <dt>Container</dt><dd>A resource that enumerates other resources. Its representation
  (<code>application/lws+json</code>) has <code>id</code>, <code>type: "Container"</code>,
  <code>totalItems</code> and <code>items</code>. Large listings are paginated with
  <code>first</code>/<code>next</code>/<code>prev</code>/<code>last</code> links.</dd>
  <dt>Data resource</dt><dd>Any data-bearing resource: a document, image, JSON object, RDF graph and so on.</dd>
  <dt>Containment</dt><dd>Expressed through metadata, not URL structure: <code>rel="up"</code> links to
  the parent, and the parent lists the child in <code>items</code>. The server assigns URIs, and
  clients must not infer containment from paths.</dd>
  <dt>Linkset</dt><dd>Every resource has an auxiliary <code>application/linkset+json</code>
  (RFC 9264) resource holding its metadata links, discovered via <code>rel="linkset"</code> and
  updated with JSON Patch.</dd>
</dl>

<h2 id="operations">Operations and their HTTP binding</h2>
${table(
  ["Operation", "HTTP", "Success", "Notes"],
  [
    ["Read", "<code>GET</code> / <code>HEAD</code>", "<code>200</code>, <code>206</code>, <code>304</code>", "ETag on every response; range and conditional requests"],
    ["List", "<code>GET</code> container", "<code>200</code>", "<code>application/lws+json</code>; link-based pagination"],
    ["Create", "<code>POST</code> container", "<code>201</code> + <code>Location</code>", "Container via <code>Link: &lt;…lws#Container&gt;; rel=\"type\"</code>; name hint via <code>Slug</code>"],
    ["Replace", "<code>PUT</code>", "<code>200</code> / <code>204</code>", "<code>If-Match</code> to avoid lost updates (<code>412</code>)"],
    ["Patch", "<code>PATCH</code>", "<code>200</code> / <code>204</code>", "JSON Patch (<code>application/json-patch+json</code>) is the baseline format"],
    ["Delete", "<code>DELETE</code>", "<code>204</code>", "Non-empty container → <code>409</code> unless <code>Depth: infinity</code>"],
  ],
)}
${callout("tip", "Baseline patch format", " The 2026-10-05 editor's draft made JSON Patch (RFC 6902) the mandatory PATCH format for resources and linksets, replacing JSON Merge Patch. Every client ships a <code>JsonPatch</code> builder.")}

<h2 id="media-types">Media types</h2>
${table(
  ["Media type", "Used for"],
  [
    ["<code>application/lws+cid</code>", "Storage descriptions"],
    ["<code>application/lws+json</code>", "Container listings, subscriptions, notifications, access requests/grants, type index and search results (equivalent to <code>application/ld+json</code> and <code>application/json</code> for containers)"],
    ["<code>application/linkset+json</code>", "Linkset (metadata) resources"],
    ["<code>application/json-patch+json</code>", "PATCH bodies"],
    ["<code>application/lws-query+json</code>", "Type search filters sent with the HTTP <code>QUERY</code> method"],
  ],
)}

<h2 id="auth">Authentication and authorization</h2>
<p>LWS separates <em>who you are</em> from <em>what you may do</em>. An identity provider issues an
<dfn>authentication credential</dfn> (an OpenID Connect ID token, a SAML assertion or a self-signed
JWT). The client exchanges it at the storage's authorization server for a short-lived OAuth 2.0
access token (RFC 8693 token exchange), then presents that token as a <code>Bearer</code> token.</p>
${authSequence}
<p>Three authentication suites are defined. Each is a credential provider in every client:</p>
${table(
  ["Suite", "Credential", "Token type"],
  [
    ["OpenID Connect", "ID token from an OpenID provider listed in the agent's CID document", "<code>urn:ietf:params:oauth:token-type:id_token</code>"],
    ["SAML 2.0", "Signed SAML assertion (base64url)", "<code>urn:ietf:params:oauth:token-type:saml2</code>"],
    ["Self-signed (CID / did:key)", "JWT signed by the agent's own key; <code>sub = iss = client_id</code>", "<code>urn:ietf:params:oauth:token-type:jwt</code>"],
  ],
)}
<p>See <a href="authentication.html">Authentication</a> for configuration, key management and security notes.</p>

<h2 id="notifications">Notifications</h2>
<p>A storage may advertise a <code>NotificationService</code>. Subscribers <code>POST</code> a
<code>WebhookSubscription</code> naming <code>topic</code> resources and an <code>inbox</code>. A
subscription to a container is recursive. The server then <code>POST</code>s notification envelopes
wrapping Activity Streams 2.0 <code>Create</code>, <code>Update</code> and <code>Delete</code>
activities to the inbox, signed with HTTP Message Signatures (RFC 9421). The clients include a
verifier that checks the <code>Content-Digest</code>, the signature, the signing key's storage
description and the notification's storage. See <a href="notifications.html">Notifications</a>.</p>

<h2 id="access">Access requests and grants</h2>
<p>Agents ask for access by posting an <code>AccessRequest</code> to the storage's
<code>AccessRequestService</code>. A storage controller records decisions as <code>AccessGrant</code>s.
Both use an ODRL-based profile: actions (<code>read</code>, <code>modify</code>, <code>create</code>,
<code>delete</code>), an assignee, targets and constraints (purpose, client, format, type, date-time).
See <a href="access.html">Access requests &amp; grants</a>.</p>

<h2 id="index">Type index and search</h2>
<p>Instead of crawling containers, clients can ask a <code>TypeIndexService</code> which resource types
exist, and query a <code>TypeSearchService</code> using the HTTP <code>QUERY</code> method with a
conjunctive-normal-form filter such as
<code>{"type": [["schema:Person", "foaf:Person"], "lws:DataResource"]}</code>. Results are always
filtered to what the caller may read. See <a href="type-index.html">Type index &amp; search</a>.</p>

<h2 id="glossary">Glossary</h2>
<dl class="defs">
  <dt>Agent</dt><dd>A person, social entity or software identified by a URI.</dd>
  <dt>Storage controller</dt><dd>An agent that controls every resource in a storage.</dd>
  <dt>Realm</dt><dd>The URI in a <code>WWW-Authenticate</code> challenge that scopes a token. It becomes
  the token's audience, and the client only sends the token to URLs inside it.</dd>
  <dt>Authorization server (AS)</dt><dd>Issues access tokens. Its metadata lives at
  <code>/.well-known/lws-configuration</code>.</dd>
  <dt>Subscription / inbox</dt><dd>A registration for change notifications and the URL they are delivered to.</dd>
</dl>
`,
};
