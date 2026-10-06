// SPDX-License-Identifier: MIT
import { callout, code, table } from "../../lib.mjs";
import { sample } from "../../samples.mjs";

const s = (topic) => code(sample("go", topic).lang, sample("go", topic).code);

export default {
  path: "languages/go.html",
  title: "Go",
  description: "The zero-dependency Go LWS client: context-aware calls, functional options, iter.Seq2 pagination, errors.Is sentinels and an http.Handler webhook verifier.",
  body: `
<h1><span class="lang-badge lang-go">GO</span> Go</h1>
<div class="badges">
  <span class="badge accent">github.com/ebremer/lws-client/go</span>
  <span class="badge">Go 1.23+</span>
  <span class="badge">package lws</span>
  <span class="badge">zero third-party dependencies</span>
</div>
<p class="lead">A single package built on <code>net/http</code>, <code>encoding/json</code> and the standard crypto libraries.
Every network call takes a <code>context.Context</code>, pagination uses range-over-func iterators, and errors work
with <code>errors.Is</code> and <code>errors.As</code>.</p>
<div id="toc" class="toc"></div>

<h2 id="install">Install</h2>
${s("install")}

<h2 id="first">First program</h2>
${s("first-program")}

<h2 id="configure">Configure the client</h2>
${s("client-config")}

<h2 id="idioms">Go idioms</h2>
${table(
  ["Aspect", "How the Go client does it"],
  [
    ["Calls", "Blocking methods with <code>ctx context.Context</code> first; the <code>*lws.Client</code> is safe for concurrent use and shares one in-flight token exchange"],
    ["Pagination", "<code>iter.Seq2[T, error]</code>: <code>for item, err := range client.ListContainer(ctx, url)</code>; <code>ListContainerPages</code> yields whole pages"],
    ["Options", "Client options <code>WithHTTPClient</code>, <code>WithAuthenticator</code>, <code>WithUserAgent</code>, <code>WithHeader</code>, <code>WithTimeout</code>; per-call options <code>Slug</code>, <code>Types</code>, <code>Links</code>, <code>IfMatch</code>, <code>IfNoneMatch</code>, <code>IfModifiedSince</code>, <code>Accept</code>, <code>ByteRange</code>, <code>Prefer</code>, <code>SetLinkset</code>, <code>Recursive</code>, <code>Header</code>"],
    ["Bodies", "Any <code>io.Reader</code>; <code>CreateJSON</code> marshals values; <code>ReadStream</code> returns an <code>io.ReadCloser</code>"],
    ["Absent values", "Zero values and sentinels: <code>TotalItems</code>/<code>Size</code> are <code>-1</code> when missing; times are <code>time.Time</code> (zero if absent) plus the raw string"],
    ["Errors", "<code>*HTTPError</code> (<code>StatusCode</code>, <code>Problem</code>, <code>Header</code>, <code>Challenges</code>) matching sentinels <code>ErrNotFound</code>, <code>ErrConflict</code>, <code>ErrPreconditionFailed</code>…; <code>*AuthenticationError</code>, <code>*ProtocolError</code>, <code>*SignatureVerificationError</code>"],
    ["Webhooks", "<code>verifier.Handler(inbox, fn)</code> is an <code>http.Handler</code>; <code>VerifyRequest(r, inbox)</code> for custom handlers"],
  ],
)}

<h2 id="notes">Notes and deviations</h2>
<ul>
  <li>Per-call options are one variadic <code>CallOption</code> type shared by all methods. Each method documents which options it honours.</li>
  <li><code>SubscribeWebhook(ctx, storage, req)</code> checks <code>subscriptionType</code> before subscribing. <code>Subscribe</code> takes a raw service URL.</li>
  <li>Redirects: the client wraps <code>CheckRedirect</code> to drop <code>Authorization</code> and re-authorize per realm. Plain Go
  would forward the header to the same host on a different port.</li>
  <li>Streaming upload bodies trigger a <code>HEAD</code> to obtain a token first. Self-signed credentials refresh 60 s
  before expiry, or at half the lifetime for short lifetimes.</li>
  <li>Extras: <code>ReadStream</code>, <code>PatchRaw</code>, <code>ReadLinksetAt</code>, <code>ListContainerPages</code>, <code>SearchPage</code>,
  <code>ContentDigest</code>, and JWT/did:key decoding helpers.</li>
</ul>

<h2 id="build">Build, test and examples</h2>
${code("bash", `
cd go
go vet ./...
go test ./...                        # add -race with cgo enabled
node ../testing/mock-server/server.mjs --port 8787 &
LWS_TEST_SERVER=http://localhost:8787 go test -run TestInterop -v .

go run ./examples/quickstart -url http://localhost:8787/root/
go run ./examples/selfsigned -url http://localhost:8787/root/ -key agent.jwk
go run ./examples/webhook    -url http://localhost:8787/root/ -listen 127.0.0.1:9000`)}
${callout("note", "Source", ' <a href="https://github.com/ebremer/lws-client/tree/main/go">go/</a> in the repository, with its own <a href="https://github.com/ebremer/lws-client/blob/main/go/README.md">README</a> and godoc examples.')}
`,
};
