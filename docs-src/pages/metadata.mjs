// SPDX-License-Identifier: MIT
import { callout, code, table, tabs } from "../lib.mjs";
import { S } from "../samples.mjs";

export default {
  path: "metadata.html",
  title: "Metadata & linksets",
  description: "Read, patch and replace Linked Web Storage metadata stored in RFC 9264 linkset resources, including JSON Pointer escaping for URI relation types.",
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
    ["Core", "<code>up</code>, <code>items</code>, <code>title</code>, <code>creator</code>", "Client, subject to server restrictions"],
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

<h2 id="put">Replacing a linkset</h2>
<p>Servers may also accept <code>PUT</code> of a complete linkset, and advertise it in <code>Allow</code>. Check before
you use it. Servers without <code>PUT</code> support answer <code>405 Method Not Allowed</code>.</p>
${tabs(S["put-linkset"])}

<h2 id="combined">Content and links together</h2>
<p>To change a resource's content and its links in one atomic request, pass <code>links</code> with
<code>setLinkset</code> to <code>update</code> or <code>patch</code>. See <a href="resources.html#update">Replace (PUT)</a>.
Server-managed relations such as <code>up</code>, <code>linkset</code> and the LWS type are never overridden
by client-supplied links.</p>
`,
};
