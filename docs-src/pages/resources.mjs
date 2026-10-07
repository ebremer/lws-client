// SPDX-License-Identifier: MIT
import { callout, code, table, tabs } from "../lib.mjs";
import { S } from "../samples.mjs";

export default {
  path: "resources.html",
  title: "Reading & writing resources",
  description: "Create containers and data resources, read with conditional and range requests, replace with PUT, patch with JSON Patch and delete with the LWS clients.",
  body: `
<h1>Reading &amp; writing resources</h1>
<p class="lead">LWS maps its four abstract operations (create, read, update, delete) onto plain HTTP.
The clients add typed metadata, automatic URL resolution and error mapping, so you work with
resources rather than raw requests.</p>
<div id="toc" class="toc"></div>
${callout("note", "About the samples", " Fragments assume <code>client</code> (an authenticated client), <code>container</code> (a container URL), <code>url</code> (a resource URL) and <code>etag</code> are in scope. See <a href=\"getting-started.html#first-program\">Getting started</a> for a complete program.")}

<h2 id="create">Create</h2>
<p>Resources are always created inside an existing container with <code>POST</code>. The server assigns the final
URL and returns it in <code>Location</code>, which the clients surface (absolute) as the create result's
<code>location</code>. A container is created by sending <code>Link: &lt;https://www.w3.org/ns/lws#Container&gt;; rel="type"</code>
with an empty body, which <code>createContainer</code> does for you.</p>
${tabs(S.create)}
${table(
  ["Option", "Wire effect"],
  [
    ["<code>slug</code>", "<code>Slug</code> header: a <em>hint</em> for the new name (percent-encoded). The server may change it to keep names unique."],
    ["<code>types</code>", "Extra <code>Link: &lt;iri&gt;; rel=\"type\"</code> headers. Type index and search use them."],
    ["<code>links</code>", "Any other user-managed metadata, sent as <code>Link</code> headers and stored in the resource's linkset."],
  ],
)}
${callout("warn", "POST is not idempotent", " The clients never retry a <code>POST</code> automatically. The one exception is the single retry after a <code>401</code> authentication challenge, when nothing was created.")}

<h2 id="read">Read</h2>
<p><code>read</code> performs a <code>GET</code> and returns the body together with the parsed metadata: ETag,
<code>Last-Modified</code>, content type, the <code>up</code>/<code>linkset</code>/<code>type</code>/storage links, and
<code>Allow</code>/<code>Accept-Patch</code>. <code>head</code> returns the same metadata without a body.</p>
${tabs(S.read)}

<h3 id="streaming">Streaming large bodies</h3>
<p>Where the platform supports it, the clients can hand you the body as a stream instead of buffering it.
Streamed uploads cannot be replayed after a <code>401</code>, so the JS, Python, Go and C# clients first send a
<code>HEAD</code> to obtain a token. Java bodies are always replayable. C++ bodies are buffered strings and Swift
bodies are buffered <code>Data</code>, so use range requests to process large resources in pieces.</p>
${tabs(S.stream)}

<h2 id="conditional">Conditional requests</h2>
<p>Every LWS response to <code>GET</code>/<code>HEAD</code> carries an ETag. Echo it back verbatim, quotes included:</p>
<ul>
  <li><code>ifNoneMatch</code> on a read revalidates a cached copy. A <code>304</code> is returned as a normal
  result flagged <code>notModified</code>, not as an error.</li>
  <li><code>ifMatch</code> on update, patch or delete prevents lost updates. A mismatch raises the
  <em>precondition failed</em> error (<code>412</code>).</li>
</ul>
${tabs(S.conditional)}

<h3 id="range">Byte ranges</h3>
<p>Servers must support range requests for data resources. A <code>206 Partial Content</code> is a normal
success, and the clients expose <code>Content-Range</code>.</p>
${tabs(S.range)}

<h2 id="update">Replace (PUT)</h2>
<p><code>update</code> replaces the whole representation, and the media type should match the existing one.
Content updates leave the linkset untouched unless you ask for a combined update with
<code>setLinkset</code>. That option sends <code>Prefer: set-linkset</code> plus your <code>Link</code> headers, and the server
applies both atomically. Servers that don't support it ignore the preference or answer <code>501</code>.</p>
${tabs(S.update)}

<h2 id="patch">Partial updates (PATCH)</h2>
<p>JSON Patch (RFC 6902, <code>application/json-patch+json</code>) is the baseline format every LWS server
supports. It replaced JSON Merge Patch in the 2026-10-05 draft. Every client includes a <code>JsonPatch</code>
builder with <code>add</code>, <code>remove</code>, <code>replace</code>, <code>move</code>, <code>copy</code> and <code>test</code>.
A server may accept other formats, such as SPARQL Update for RDF, but only send them when
<code>Accept-Patch</code> lists them. Otherwise expect <code>415</code>.</p>
${tabs(S.patch)}

<h2 id="delete">Delete</h2>
<p>Deleting a resource also removes its linkset and its entry in the parent container. A non-empty
container can only be deleted recursively, which sends <code>Depth: infinity</code>. Without it the server
answers <code>409 Conflict</code>.</p>
${tabs(S.delete)}

<h2 id="status-codes">Status codes at a glance</h2>
${table(
  ["Operation", "Success", "Typical failures"],
  [
    ["create", "<code>201</code> + <code>Location</code>", "<code>404</code> container missing · <code>403</code> · <code>409</code> · <code>507</code> quota"],
    ["read / head", "<code>200</code>, <code>206</code>, <code>304</code>", "<code>404</code> · <code>403</code> · <code>401</code>"],
    ["update", "<code>200</code> / <code>204</code>", "<code>412</code> stale ETag · <code>404</code> (no create-by-PUT) · <code>405</code> on containers"],
    ["patch", "<code>200</code> / <code>204</code>", "<code>415</code> unsupported format · <code>409</code>/<code>422</code> patch failed · <code>412</code>"],
    ["delete", "<code>204</code>", "<code>409</code> non-empty container · <code>412</code> · <code>405</code> storage root"],
  ],
)}
<p>See <a href="errors.html">Errors</a> for how each status maps to a typed error in every language.</p>
${code("http", `
POST /root/notes/ HTTP/1.1
Content-Type: text/plain
Slug: shopping.txt

milk

HTTP/1.1 201 Created
Location: /root/notes/shopping.txt
Link: </root/notes/shopping.txt.meta>; rel="linkset"; type="application/linkset+json"
Link: </root/notes/>; rel="up"
Link: <https://www.w3.org/ns/lws#DataResource>; rel="type"`, { title: "On the wire" })}
`,
};
