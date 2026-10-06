// SPDX-License-Identifier: MIT
import { callout, code, table, tabs } from "../lib.mjs";
import { S } from "../samples.mjs";

export default {
  path: "discovery.html",
  title: "Storage discovery",
  description: "Find a Linked Web Storage storage description from any resource URL and look up its root container, services and capabilities.",
  body: `
<h1>Storage discovery</h1>
<p class="lead">LWS clients never hard-code paths. Starting from any URL inside a storage, the client
follows a link to the <em>storage description</em>, which names the root container and every
optional service.</p>
<div id="toc" class="toc"></div>

<h2 id="how">How discovery works</h2>
<ol class="steps">
  <li><code>discoverStorage(url)</code> sends <code>HEAD url</code>, falling back to <code>GET</code> when a server rejects
  <code>HEAD</code> with 405 or 501.</li>
  <li>It reads <code>Link: &lt;…&gt;; rel="https://www.w3.org/ns/lws#storage"</code>. Every <code>GET</code>/<code>HEAD</code>
  response carries it, and servers should also send it on <code>401</code>.</li>
  <li>It fetches that URL with <code>Accept: application/lws+cid</code> and validates the document:
  <code>type</code> must include <code>Storage</code>.</li>
</ol>
${code("http", `
HEAD /root/notes/ HTTP/1.1
Host: storage.example

HTTP/1.1 200 OK
Link: <https://storage.example/>; rel="https://www.w3.org/ns/lws#storage"
Link: </root/>; rel="up"
Link: <https://www.w3.org/ns/lws#Container>; rel="type"`)}

<h2 id="usage">Usage</h2>
${tabs(S.discover)}

<h2 id="services">Services</h2>
<p>Every client has typed accessors for the services defined by the LWS documents. You can also look
up any service type, including extension services, by name. The <code>type</code> values may be short
terms (<code>StorageRoot</code>) or full IRIs; matching treats both forms as equal.</p>
${table(
  ["Service type", "Accessor (concept name)", "Used by"],
  [
    ["<code>StorageRoot</code> (required)", "<code>storageRoot()</code>", "Root container for all resources"],
    ["<code>NotificationService</code>", "<code>notificationService()</code>", '<a href="notifications.html">Notifications</a> (<code>subscriptionType</code> lists supported channels)'],
    ["<code>AccessRequestService</code>", "<code>accessRequestService()</code>", '<a href="access.html">Access requests</a>'],
    ["<code>AccessGrantService</code>", "<code>accessGrantService()</code>", '<a href="access.html">Access grants</a>'],
    ["<code>TypeIndexService</code>", "<code>typeIndexService()</code>", '<a href="type-index.html">Type index</a>'],
    ["<code>TypeSearchService</code>", "<code>typeSearchService()</code>", '<a href="type-index.html#search">Type search</a>'],
    ["any other", "<code>service(type)</code> / <code>services(type)</code>", "Extension services (raw JSON preserved)"],
  ],
)}
${callout("note", "Endpoints are absolute", " The clients resolve <code>serviceEndpoint</code> values and every other URL against the response URL, so you can pass them straight to other calls.")}

<h2 id="capabilities">Capabilities</h2>
<p><code>capability</code> entries describe optional features, such as additional patch formats or resumable uploads.
The LWS core spec defines their shape (an optional <code>id</code>, a required <code>type</code>, extra properties) but
not their vocabulary. The clients keep every property and let you look capabilities up by type. Because
<code>PATCH</code> formats are also advertised per resource in <code>Accept-Patch</code>, check that header before you
send a non-baseline format.</p>

<h2 id="keys">Signing keys</h2>
<p>A storage that signs webhooks publishes its keys as <code>verificationMethod</code> entries referenced from
<code>authentication</code>, following the Controlled Identifier data model. The webhook verifier reads them
for you; see <a href="notifications.html#verify">verifying deliveries</a>.</p>
`,
};
