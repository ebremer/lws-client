// SPDX-License-Identifier: MIT
import { callout, code, table, tabs } from "../lib.mjs";
import { S } from "../samples.mjs";

export default {
  path: "metadata.html",
  title: "Metadata & linksets",
  description: "Read, patch and replace Linked Web Storage metadata stored in RFC 9264 linkset resources, including JSON Pointer escaping for URI relation types, and move resources between containers by changing their up link.",
  body: `
<h1>Metadata &amp; linksets</h1>
<p class="lead">LWS keeps a resource's metadata as typed links in a dedicated <em>linkset resource</em>
(<code>application/linkset+json</code>, RFC 9264). You find it through <code>rel="linkset"</code> and change it with JSON Patch.</p>
<div id="toc" class="toc"></div>

<h2 id="kinds">Kinds of metadata</h2>
${table(
  ["Kind", "Examples", "Who changes it"],
  [
    ["System managed", "<code>linkset</code>, <code>type</code> (Container/DataResource), <code>format</code>, <code>size</code>, <code>modified</code>", "Server only"],
    ["Core", "<code>items</code>, <code>title</code>, <code>creator</code>", "Client, subject to server restrictions"],
    ["Containment", "<code>up</code>", "Client, only where the storage describes a <code>MoveResource</code> capability: changing it moves the resource (see <a href=\"#move\">Moving resources</a>)"],
    ["User-defined", "<code>describedby</code>, <code>license</code>, extension relation URIs", "Client"],
  ],
)}
${code("json", `
{
  "linkset": [{
    "anchor": "https://storage.example/alice/personalinfo.json",
    "describedby": [{ "href": "https://storage.example/schemas/personal-info.json" }],
    "license": [{ "href": "https://creativecommons.org/licenses/by/4.0/" }]
  }]
}`, { title: "GET /alice/personalinfo.json.meta  (application/linkset+json)" })}

<h2 id="read">Reading a linkset</h2>
<p><code>readLinkset(resourceUrl)</code> discovers the linkset URL with <code>HEAD</code>, fetches it and returns a document
with the linkset URL, its ETag, and the server's <code>Allow</code> and <code>Accept-Patch</code> headers. The
<code>Linkset</code> model keeps unknown members, so a read-modify-write round trip loses nothing.</p>
${tabs(S["read-linkset"])}

<h2 id="patch">Patching a linkset</h2>
<p>JSON Patch is the mandatory linkset update format. Two details catch most people:</p>
<ul>
  <li><strong>Escape relation URIs.</strong> Extension relation types are URIs and contain <code>/</code>, which JSON
  Pointer uses as a separator. Build paths with <code>JsonPointer</code>, which escapes <code>/</code> as <code>~1</code> and
  <code>~</code> as <code>~0</code>. For example, <code>/linkset/0/https:~1~1example.org~1rel~1reviewer/-</code>.</li>
  <li><strong>Add versus append.</strong> <code>add</code> on an existing member <em>replaces</em> it. Append to an
  existing relation with the <code>/-</code> array index, and create a new relation with a one-element array.</li>
</ul>
${tabs(S["patch-linkset"])}
${callout("tip", "Always send If-Match", " Several agents may edit the same metadata. Pass the linkset's ETag so a concurrent change produces <code>412 Precondition Failed</code> instead of a silent overwrite.")}

<h2 id="move">Moving resources</h2>
<p>LWS has no method for a move. A resource moves into another container when the <code>up</code> link in its linkset
changes to that container, and the storage moves it (a container with everything in it) in one step. That only works
where the storage description lists a <code>MoveResource</code> capability. Without one the <code>up</code> link is not
modifiable, and a client must not assume it is. <code>moveCapability()</code> returns the capability, or nothing:</p>
<ul>
  <li><strong><code>appliesTo</code></strong> names what moves: <code>DataResource</code>, <code>Container</code> or both. A capability
  that does not say moves data resources only. <code>movesDataResources()</code> and <code>movesContainers()</code> check it.</li>
  <li><strong><code>preservesIdentifier</code></strong> says whether a moved resource keeps its URL. When it is absent, do not
  assume it does.</li>
</ul>
${code("json", `
"capability": [
  { "type": "MoveResource", "appliesTo": ["DataResource", "Container"], "preservesIdentifier": false }
]`, { title: "In the storage description" })}
<p><code>move(resourceUrl, destinationUrl)</code> reads the resource's linkset first, because JSON Patch addresses the
<code>up</code> link by its position (<code>/linkset/<em>i</em>/up/<em>j</em>/href</code>) and the request should be
conditional on the linkset's ETag. It then sends two operations in one conditional <code>PATCH</code>: a <code>test</code>
that the link still holds the <code>href</code> it read, and a <code>replace</code> of it with the destination.</p>
<p>A storage that keeps identifiers answers <code>204</code> (or <code>200</code> with the linkset), and the resource keeps its
URL. One that does not answers <code>200</code> with the updated linkset, whose <code>anchor</code> is the resource's new URL,
and a <code>Content-Location</code> header with the linkset's new URL. The result reports the outcome: <code>location</code> is
where the resource is now, <code>linkset</code> is where its metadata is, and <code>identifierPreserved</code> says whether the URL
stayed. Unless the capability says <code>preservesIdentifier: true</code>, take the resource's URL from the result.</p>
${code("http", `
PATCH /alice/notes/shoppinglist.txt.meta HTTP/1.1
Content-Type: application/json-patch+json
If-Match: "7f3a"

[
  { "op": "test",    "path": "/linkset/0/up/0/href", "value": "https://storage.example/alice/notes/" },
  { "op": "replace", "path": "/linkset/0/up/0/href", "value": "https://storage.example/alice/archive/" }
]

HTTP/1.1 200 OK
Content-Type: application/linkset+json
Content-Location: /alice/archive/shoppinglist.txt.meta

{ "linkset": [{ "anchor": "/alice/archive/shoppinglist.txt", "up": [{ "href": "/alice/archive/" }] }] }`, { title: "A move in a storage that does not keep identifiers" })}
${tabs(S["move"])}
${callout("warn", "Refused moves", " A storage that does not allow the move answers <code>409 Conflict</code> (<code>ConflictError</code>), as it does for a destination that is not an existing container, or for a container moved into itself or one of its descendants. A move needs permission to delete the resource and to create in the destination (<code>403 Forbidden</code> otherwise). A concurrent change to the linkset is <code>412 Precondition Failed</code>.")}

<h2 id="put">Replacing a linkset</h2>
<p>Servers may also accept <code>PUT</code> of a complete linkset, and advertise it in <code>Allow</code>. Check before
you use it. Servers without <code>PUT</code> support answer <code>405 Method Not Allowed</code>.</p>
${tabs(S["put-linkset"])}

<h2 id="combined">Content and links together</h2>
<p>To change a resource's content and its links in one atomic request, pass <code>links</code> with
<code>setLinkset</code> to <code>update</code> or <code>patch</code>. See <a href="resources.html#update">Replace (PUT)</a>.
Server-managed relations such as <code>linkset</code> and the LWS type are never overridden by client-supplied
links, and neither is <code>up</code>, which only a <a href="#move">move</a> changes.</p>
`,
};
