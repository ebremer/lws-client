// SPDX-License-Identifier: MIT
import { callout, code, table, tabs } from "../lib.mjs";
import { S } from "../samples.mjs";

export default {
  path: "type-index.html",
  title: "Type index & search",
  description: "Discover which resource types exist in a Linked Web Storage and find resources by type with the HTTP QUERY method and application/lws-query+json filters.",
  body: `
<h1>Type index &amp; search</h1>
<p class="lead">Instead of crawling containers, ask the storage which types exist with the <code>TypeIndexService</code>.
Then find the matching resources with the <code>TypeSearchService</code>, which takes a conjunctive-normal-form
filter sent with the HTTP <code>QUERY</code> method.</p>
<div id="toc" class="toc"></div>

<h2 id="index">Listing types</h2>
<p><code>listTypes</code> pages through the type index lazily. Types come from <code>rel="type"</code> links you set
when creating or updating resources, plus the intrinsic LWS classes. They are filtered to what you are
allowed to read.</p>
${tabs(S["list-types"])}

<h2 id="search">Searching by type</h2>
<p>A filter is a list of AND-ed groups, where each group is one IRI or an OR-list of IRIs. The builders produce
exactly that:</p>
${table(
  ["Builder call", "Serialised filter", "Meaning"],
  [
    ["<code>allOf(A, B)</code>", "<code>{\"type\": [\"A\", \"B\"]}</code>", "A AND B"],
    ["<code>anyOf(A, B)</code>", "<code>{\"type\": [[\"A\", \"B\"]]}</code>", "A OR B"],
    ["<code>anyOf(A, B)</code> then <code>allOf(C)</code>", "<code>{\"type\": [[\"A\", \"B\"], \"C\"]}</code>", "(A OR B) AND C"],
    ["<code>relation(\"describedby\").allOf(S)</code>", "<code>{\"describedby\": [\"S\"]}</code>", "has a <code>describedby</code> link to S"],
    ["(nothing)", "<code>{}</code>", "every resource you can see"],
  ],
)}
${tabs(S.search)}
${code("http", `
QUERY /types/search HTTP/1.1
Content-Type: application/lws-query+json
Accept: application/lws+json

{"type": [["https://schema.org/Person", "http://xmlns.com/foaf/0.1/Person"], "https://www.w3.org/ns/lws#DataResource"]}`, { title: "On the wire" })}
<p>The first page comes from <code>QUERY</code>. Later pages are opaque links fetched with <code>GET</code>.
<code>searchAll</code> handles both for you. Results use the container page shape, but they are a synthetic,
per-client result set, not a container.</p>

<h2 id="rules">Rules and errors</h2>
<ul>
  <li>Every value must be an absolute IRI, and empty OR-groups are invalid. The client builders reject both before
  sending, because the server would answer <code>400</code>.</li>
  <li>An unknown type, or a relation the server does not index, simply matches nothing. It is never an error,
  and servers never reveal which relations they index.</li>
  <li>Overly complex filters get <code>422</code>, unsupported query formats get <code>415</code> (see
  <code>acceptedQueryFormats</code>), and expired page links get <code>404</code>/<code>410</code>. In that last case,
  restart the search.</li>
  <li>Type derivation may be eventually consistent, so a resource you just created can take a moment to
  show up. Authorization filtering, however, is always current.</li>
</ul>
${callout("tip", "Make resources findable", " Servers are not required to parse resource bodies. Declare types with <code>types</code> (extra <code>rel=\"type\"</code> links) when you create a resource, or add them to its linkset later.")}
`,
};
