// SPDX-License-Identifier: MIT
import { callout, code, table } from "../../lib.mjs";
import { sample } from "../../samples.mjs";

const s = (topic) => code(sample("ts", topic).lang, sample("ts", topic).code);

export default {
  path: "languages/javascript.html",
  title: "JavaScript / TypeScript",
  description: "The zero-dependency LWS client for JavaScript and TypeScript: runs on Node.js, browsers, Deno and Bun with fetch and WebCrypto.",
  body: `
<h1><span class="lang-badge lang-js">TS</span> JavaScript / TypeScript</h1>
<div class="badges">
  <span class="badge accent">lws-client 0.1.0</span>
  <span class="badge">ESM + .d.ts</span>
  <span class="badge">Node 20+ · browsers · Deno · Bun</span>
  <span class="badge">zero runtime dependencies</span>
</div>
<p class="lead">Written in strict TypeScript and compiled to ES modules. The library core only uses web platform
APIs (<code>fetch</code>, WebCrypto, <code>URL</code>, streams), so the same package runs on servers, in browsers and on edge runtimes.</p>
<div id="toc" class="toc"></div>

<h2 id="install">Install</h2>
${s("install")}

<h2 id="first">First program</h2>
${s("first-program")}

<h2 id="configure">Configure the client</h2>
${s("client-config")}

<h2 id="idioms">TypeScript idioms</h2>
${table(
  ["Aspect", "How the JS/TS client does it"],
  [
    ["Calls", "<code>async</code> methods returning <code>Promise</code>s; every operation accepts <code>{ headers, signal }</code> for cancellation with <code>AbortSignal</code>"],
    ["Pagination", "<code>AsyncGenerator</code>s: <code>for await (const item of client.listContainer(url))</code>"],
    ["Options", "Plain option objects (<code>{ slug, types, links }</code>, <code>{ ifMatch }</code>, <code>{ recursive }</code>)"],
    ["Bodies", "Any <code>BodyInit</code>: string, <code>Uint8Array</code>, <code>Blob</code>, <code>ReadableStream</code>; <code>createJson</code>, <code>createText</code>, <code>updateJson</code> helpers"],
    ["Responses", "<code>Resource</code> exposes <code>text()</code>, <code>json()</code>, <code>bytes()</code> and <code>blob()</code> (buffered once, re-readable), plus the raw <code>body</code> stream"],
    ["Errors", "<code>Error</code> subclasses: <code>LwsError</code> → <code>HttpError</code> (with <code>status</code>, <code>problem</code>, <code>headers</code>) → <code>NotFoundError</code>, …"],
    ["Escape hatch", "<code>client.fetch(url, init)</code> sends any request through the authenticator without throwing on error statuses"],
  ],
)}

<h2 id="runtimes">Runtimes and entry points</h2>
${table(
  ["Entry point", "Use"],
  [
    ["<code>lws-client</code>", "Everything: client, models, auth, crypto, webhook verification. No <code>node:</code> imports"],
    ["<code>lws-client/node</code>", "Node helpers: <code>createWebhookHandler</code>, <code>webhookRequestFromIncomingMessage</code>, <code>readBody</code>"],
  ],
)}
<ul>
  <li><strong>Browsers:</strong> calls to another origin need CORS on the storage and authorization server. The
  default <code>User-Agent</code> is not set in browsers, to avoid extra preflights. See <code>examples/browser.html</code>.</li>
  <li><strong>Custom <code>fetch</code>:</strong> pass <code>{ fetch }</code> to add proxies, retries or instrumentation, or to test without a network.</li>
  <li><strong>Ed25519</strong> needs a WebCrypto implementation with Ed25519 support: Node 22+ and current browsers have it.</li>
</ul>

<h2 id="notes">Notes and deviations</h2>
<ul>
  <li><code>links(rel?)</code>, <code>services(type?)</code> and <code>capabilities(type?)</code> are methods, not fields.</li>
  <li>The <code>Linkset</code> model keeps anchors and hrefs exactly as received, so a read-modify-write round trip is lossless.</li>
  <li><code>WebhookVerifier</code> takes a <code>resolveStorageDescription</code> callback (usually
  <code>(id) =&gt; client.getStorageDescription(id)</code>) rather than a client.</li>
  <li>Invalid builder input such as a relative IRI in a <code>TypeQuery</code> throws <code>TypeError</code>.</li>
  <li>Streaming upload bodies trigger a <code>HEAD</code> to obtain a token first, because streams cannot be replayed.</li>
</ul>

<h2 id="build">Build, test and examples</h2>
${code("bash", `
cd js
npm install
npm run build          # dist/ (ESM + .d.ts)
npm run typecheck
npm test               # unit, fixture and in-process HTTP tests (Node 22+)
node ../testing/mock-server/server.mjs --port 8787 &
LWS_TEST_SERVER=http://localhost:8787 npm run test:interop

# Examples: quickstart.mjs, self-signed-auth.mjs, webhook-receiver.mjs, browser.html
LWS_SERVER=http://localhost:8787 node examples/quickstart.mjs`)}
${callout("note", "Source", ' <a href="https://github.com/ebremer/lws-client/tree/main/js">js/</a> in the repository, with its own <a href="https://github.com/ebremer/lws-client/blob/main/js/README.md">README</a>.')}
`,
};
