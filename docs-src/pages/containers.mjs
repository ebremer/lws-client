// SPDX-License-Identifier: MIT
import { callout, code, table, tabs } from "../lib.mjs";
import { S } from "../samples.mjs";

export default {
  path: "containers.html",
  title: "Containers & pagination",
  description: "Read LWS container listings (application/lws+json), iterate lazily across server-issued pages and work with contained resource metadata.",
  body: `
<h1>Containers &amp; pagination</h1>
<p class="lead">A container lists its members in an <code>application/lws+json</code> representation. Large
containers are split into pages linked with <code>first</code>, <code>next</code>, <code>prev</code> and
<code>last</code>. The clients give you one page at a time, or a lazy sequence over all of them.</p>
<div id="toc" class="toc"></div>

<h2 id="representation">The container representation</h2>
${code("json", `
{
  "@context": "https://www.w3.org/ns/lws/v1",
  "id": "/alice/photos/",
  "type": "Container",
  "totalItems": 150,
  "items": [
    { "type": "DataResource", "id": "/alice/photos/vacation.jpg",
      "format": "image/jpeg", "size": 248392, "modified": "2025-11-20T10:30:00Z" },
    { "type": "Container", "id": "albums/" }
  ]
}`, { title: "GET /alice/photos/  (Accept: application/lws+json)" })}
${table(
  ["Field", "Model property", "Notes"],
  [
    ["<code>id</code>", "<code>id</code>", "Resolved to an absolute URL"],
    ["<code>type</code>", "<code>types</code>", "Always a list. <code>Container</code>, <code>lws:Container</code> and the full IRI all match <code>isContainer()</code>"],
    ["<code>totalItems</code>", "<code>totalItems</code>", "All visible members across pages; may be approximate (optional or <code>-1</code> in Go when absent)"],
    ["<code>items</code>", "<code>items</code>", "This page's members as <code>ContainedResource</code>"],
    ["<code>format</code>", "<code>format</code>", "Media type; required for data resources"],
    ["<code>size</code> / <code>modified</code>", "<code>size</code> / <code>modified</code>", "Optional. An unparseable date never fails the listing (the raw string is kept)"],
  ],
)}
${callout("tip", "Relative identifiers", " Servers may return path-relative ids such as <code>/alice/photos/</code> or <code>albums/</code>. The clients always resolve them against the response URL, so every id you receive is absolute and can be passed straight to <code>read</code>.")}

<h2 id="pages">Reading one page</h2>
<p><code>readContainer</code> returns a single page with its pagination links and response metadata. Page URLs are
opaque: follow them, but never construct them.</p>
${tabs(S["read-container"])}
<p>The clients accept the three equivalent container media types (<code>application/lws+json</code>,
<code>application/ld+json</code>, <code>application/json</code>). Any other content type, or a body whose type is
not a container, is reported as a protocol error.</p>

<h2 id="iterate">Iterating every member</h2>
<p><code>listContainer</code> follows <code>rel="next"</code> lazily. A page is only fetched when you iterate past
the previous one, so you can stop early without loading the rest. Each language uses its native
lazy-sequence type:</p>
${table(
  ["Language", "Type returned by listContainer"],
  [
    ["Java", "<code>Stream&lt;ContainedResource&gt;</code> (lazy, spliterator-backed)"],
    ["TypeScript", "<code>AsyncGenerator&lt;ContainedResource&gt;</code> (<code>for await</code>)"],
    ["C++", "<code>lws::ContainerRange</code>, a C++20 input range (<code>for (auto&amp; item : …)</code>, <code>.to_vector()</code>)"],
    ["Rust", "<code>LwsStream&lt;ContainedResource&gt;</code>, a <code>futures::Stream</code> (<code>try_next</code>, <code>try_collect</code>)"],
    ["Go", "<code>iter.Seq2[ContainedResource, error]</code> (<code>for item, err := range …</code>)"],
    ["Python", "<code>Iterator[ContainedResource]</code>; <code>AsyncIterator</code> on <code>AsyncLwsClient</code>"],
  ],
)}
${tabs(S["list-container"])}

<h2 id="visibility">What you can see</h2>
<p>If you can read a container, its listing includes every member you can access. It may also list members
you cannot read. Being able to list a container does not imply access to its members, and access to a
member does not imply you can list its container. Expect <code>403</code> or <code>404</code> when you follow ids from a listing.</p>

<h2 id="other-listings">Other listings use the same model</h2>
<p>Subscriptions, access requests and access grants are exposed as LWS containers too, and type search
results use the same <code>ContainerPage</code> shape. The same pagination helpers
(<code>listSubscriptions</code>, <code>listAccessRequests</code>, <code>searchAll</code>…) work for all of them.</p>
`,
};
