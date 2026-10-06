// SPDX-License-Identifier: MIT
import { callout, code, table, tabs } from "../lib.mjs";
import { S } from "../samples.mjs";

export default {
  path: "access.html",
  title: "Access requests & grants",
  description: "Request access to resources in a Linked Web Storage and record access grants using the ODRL-based LWS access profile.",
  body: `
<h1>Access requests &amp; grants</h1>
<p class="lead">An agent asks for access by posting an <code>AccessRequest</code> to the storage's
<code>AccessRequestService</code>. A storage controller records a decision as an <code>AccessGrant</code>, and the server
then adjusts its access policies. Grants are records of what was allowed, not tokens you present.</p>
<div id="toc" class="toc"></div>

<h2 id="model">The access profile</h2>
${code("json", `
{
  "@context": ["https://www.w3.org/ns/lws/v1"],
  "type": ["AccessRequest"],
  "storage": "https://storage.example/",
  "inbox": "https://id.example/agent/inbox/",
  "access": [{
    "type": ["AccessPolicy"],
    "action": ["read", "create"],
    "assignee": "https://id.example/agent",
    "target": { "type": "StorageResource", "value": ["https://storage.example/root/projects/"] },
    "constraint": [
      { "leftOperand": "purpose", "operator": "eq", "rightOperand": "https://purpose.example/collaboration" },
      { "leftOperand": "dateTime", "operator": "lteq", "rightOperand": "2026-12-31T23:59:59Z" }
    ]
  }]
}`)}
${table(
  ["Member", "Meaning"],
  [
    ["<code>action</code>", "<code>read</code> (GET/HEAD), <code>modify</code> (PUT/PATCH), <code>create</code> (POST), <code>delete</code> (DELETE)"],
    ["<code>assignee</code>", "The agent requesting or receiving access; <code>http://xmlns.com/foaf/0.1/Agent</code> means everyone"],
    ["<code>target</code>", "<code>StorageResource</code>, <code>Container</code> or <code>DataResource</code> matcher plus resource URLs"],
    ["<code>constraint</code>", "All must hold. Operands are <code>purpose</code>, <code>client</code>, <code>format</code>, <code>type</code> and <code>dateTime</code>; operators are <code>eq</code>, <code>isAnyOf</code>, <code>gteq</code> and <code>lteq</code>"],
  ],
)}
<h3 id="constraints">Constraint helpers</h3>
${table(
  ["Helper (concept)", "Produces"],
  [
    ["<code>purpose(uri)</code> / <code>purposeAnyOf(uris)</code>", "<code>purpose eq</code> / <code>purpose isAnyOf</code>"],
    ["<code>client(clientId)</code>", "<code>client eq</code>: limit access to one application"],
    ["<code>format(mediaType)</code> / <code>formatAnyOf(types)</code>", "<code>format eq</code> / <code>isAnyOf</code>"],
    ["<code>type(iri)</code> / <code>typeAnyOf(iris)</code>", "<code>type eq</code> / <code>isAnyOf</code> (Rust and Python: <code>resource_type…</code>)"],
    ["<code>notBefore(time)</code> / <code>notAfter(time)</code>", "<code>dateTime gteq</code> / <code>dateTime lteq</code> (an access window)"],
  ],
)}

<h2 id="request">Requesting access</h2>
${tabs(S["access-request"])}

<h2 id="grant">Granting and revoking</h2>
<p>Creating grants is normally reserved to the storage controller. Revoking a grant (<code>DELETE</code>) tells the
server to withdraw the permissions it recorded.</p>
${tabs(S["access-grant"])}
${callout("note", "Notifications", " If a request or grant has an <code>inbox</code>, the server should notify it: the controller about new requests, and the requester when a grant is created. These deliveries use the LWS notification format, so you can verify them with the same <a href=\"notifications.html#verify\">webhook verifier</a>.")}

<h2 id="endpoints">Endpoints</h2>
${table(
  ["Operation", "HTTP", "Client method"],
  [
    ["Create request", "<code>POST {AccessRequestService}</code>", "<code>requestAccess</code> → URL of the request"],
    ["List requests", "<code>GET {AccessRequestService}</code> (an LWS container)", "<code>listAccessRequests</code>"],
    ["Read / cancel request", "<code>GET</code> / <code>DELETE {request}</code>", "<code>getAccessRequest</code> / <code>cancelAccessRequest</code>"],
    ["Create grant", "<code>POST {AccessGrantService}</code>", "<code>grantAccess</code> → URL of the grant"],
    ["List grants", "<code>GET {AccessGrantService}</code>", "<code>listAccessGrants</code>"],
    ["Read / revoke grant", "<code>GET</code> / <code>DELETE {grant}</code>", "<code>getAccessGrant</code> / <code>revokeAccessGrant</code>"],
  ],
)}
`,
};
