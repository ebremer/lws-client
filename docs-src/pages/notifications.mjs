// SPDX-License-Identifier: MIT
import { callout, code, table, tabs } from "../lib.mjs";
import { S } from "../samples.mjs";

export default {
  path: "notifications.html",
  title: "Notifications & webhooks",
  description: "Subscribe to changes in a Linked Web Storage with webhooks and verify every signed delivery (RFC 9421 HTTP Message Signatures, RFC 9530 Content-Digest).",
  body: `
<h1>Notifications &amp; webhooks</h1>
<p class="lead">A storage that advertises a <code>NotificationService</code> can POST change notifications to an
inbox you control. The clients manage subscriptions, and verify each delivery's signature against
the key the storage publishes before you act on it.</p>
<div id="toc" class="toc"></div>

<h2 id="subscribe">Managing subscriptions</h2>
<p>A subscription names one or more <code>topic</code> resources and an <code>inbox</code> URL. Subscribing to a container is
recursive: you receive events for everything below it that you are allowed to read, both when you
subscribe and when each event is delivered. The service's <code>subscriptionType</code> must include
<code>WebhookSubscription</code>. The storage-description overloads check this for you.</p>
${tabs(S.subscribe)}
${code("http", `
POST /notifications/ HTTP/1.1
Content-Type: application/lws+json
Authorization: Bearer eyJ…

{"@context":["https://www.w3.org/ns/lws/v1"],"type":"WebhookSubscription",
 "topic":["https://storage.example/root/notes/"],"inbox":"https://my-app.example/hooks/lws",
 "expires":"2026-12-31T00:00:00Z"}`, { title: "On the wire" })}

<h2 id="model">The notification model</h2>
${code("json", `
{
  "@context": ["https://www.w3.org/ns/lws/v1", "https://www.w3.org/ns/activitystreams"],
  "type": "Notification",
  "storage": "https://storage.example/",
  "activity": [{
    "id": "urn:uuid:a1b2c3d4-…",
    "type": ["Create"],
    "object": { "id": "https://storage.example/root/notes/meeting.txt", "type": ["DataResource"] },
    "target": "https://storage.example/root/notes/",
    "published": "2026-09-21T11:33:20Z"
  }]
}`)}
${table(
  ["Field", "Meaning"],
  [
    ["<code>storage</code>", "The storage the events belong to (checked against the signing key)"],
    ["<code>activities</code>", "Always a list, even when the server sent a single object (servers may batch)"],
    ["<code>types</code>", "<code>Create</code>, <code>Update</code> (content or metadata) or <code>Delete</code>; helpers <code>isCreate()</code>, <code>isUpdate()</code>, <code>isDelete()</code>"],
    ["<code>object</code>", "The resource's <code>id</code> and types"],
    ["<code>target</code> / <code>origin</code>", "Container a resource was added to (Create) or removed from (Delete)"],
    ["<code>actor</code>, <code>published</code>", "Who acted (optional) and when"],
  ],
)}
<p><code>parseNotification</code> parses a body you have already verified, or trust for another reason.</p>

<h2 id="verify">Receiving and verifying deliveries</h2>
<p>Anyone can POST to your inbox, so verify every delivery before you trust it. The verifier is
framework-agnostic: it takes the method, the <strong>registered inbox URL</strong>, the headers and the raw
body bytes. Most languages also ship a small adapter for their standard server:</p>
${table(
  ["Language", "Adapter"],
  [
    ["Java", "<code>HttpExchangeWebhooks.verify(verifier, exchange, inbox)</code> for <code>com.sun.net.httpserver</code> (optional module)"],
    ["TypeScript", "<code>verifier.verify(request)</code> for Fetch <code>Request</code>s; <code>createWebhookHandler</code> from <code>lws-client/node</code> for <code>node:http</code>"],
    ["C++", "<code>verifier.verify(method, url, headers, body)</code>, callable from any server"],
    ["Rust", "<code>verify_request(&amp;inbox, &amp;http::Request)</code> for any <code>http</code>-based framework"],
    ["Go", "<code>verifier.Handler(inbox, fn)</code> as an <code>http.Handler</code>, or <code>VerifyRequest(r, inbox)</code>"],
    ["Python", "<code>WebhookVerifier.verify(…)</code>; <code>AsyncWebhookVerifier.verify_asgi(scope, receive, inbox)</code> for ASGI"],
    ["C#", "<code>verifier.VerifyAsync(context.Request, inbox)</code> for <code>System.Net.HttpListener</code>; ASP.NET Core and others pass the method, inbox, <code>HeaderMap.From(…)</code> and body"],
  ],
)}
${tabs(S.webhook)}
${callout("warn", "Use the URL you registered", " Verify against the inbox URL you gave the storage, not one rebuilt from the <code>Host</code> header. Behind a reverse proxy, that is your public URL. The signature covers <code>@scheme</code>, <code>@authority</code> and <code>@path</code>, and this is what stops a delivery meant for someone else from being replayed at you.")}

<h2 id="checks">What the verifier checks</h2>
<ol class="steps">
  <li><code>Content-Digest</code> (RFC 9530) matches the body: every <code>sha-256</code>/<code>sha-512</code> value present must match.</li>
  <li><code>Signature-Input</code> covers at least <code>@method</code>, <code>@scheme</code>, <code>@authority</code>, <code>@path</code>,
  <code>content-type</code> and <code>content-digest</code>, and carries <code>created</code> and <code>keyid</code>.</li>
  <li><code>created</code> is within the allowed window (default 300 s either way), and <code>expires</code>, if present, has not passed.</li>
  <li>The <code>keyid</code> is a URL with a fragment. Without the fragment it names the storage, which must be in
  <code>trustedStorages</code> when you set it.</li>
  <li>The storage description is fetched (and cached). Its <code>id</code> must equal that storage, the
  verification method must exist, and it must be referenced from <code>authentication</code>.</li>
  <li>The RFC 9421 signature base is rebuilt and verified with the published JWK (<code>ecdsa-p256-sha256</code>
  or <code>ed25519</code>). A matching <code>alg</code> parameter is required when present. On failure with a cached key,
  the description is fetched once more to handle key rotation.</li>
  <li>The body is parsed, and its <code>storage</code> must equal the signing key's storage, so one storage cannot
  speak for another.</li>
</ol>
<p>All seven verifiers pass the same <a href="testing.html#fixtures">13 shared test vectors</a>. They include tampered
bodies, recomputed digests, wrong hosts, replays, missing components, unauthorised keys, storage spoofing and
algorithm confusion.</p>

<h2 id="delivery">Delivery semantics</h2>
<ul>
  <li>Answer with any <code>2xx</code> to acknowledge. Servers may retry failed deliveries and deactivate a
  subscription after repeated failures.</li>
  <li>Retries can deliver the same activity twice, so de-duplicate on the activity <code>id</code>.</li>
  <li>Use a unique, hard-to-guess inbox URL per subscription. It limits correlation, and lets you
  revoke a single feed.</li>
</ul>
`,
};
