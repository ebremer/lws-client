// SPDX-License-Identifier: MIT
import { callout, code, table } from "../../lib.mjs";
import { sample } from "../../samples.mjs";

const s = (topic) => code(sample("cpp", topic).lang, sample("cpp", topic).code);

export default {
  path: "languages/cpp.html",
  title: "C++",
  description: "The C++20 LWS client: CMake integration, the pluggable HTTP transport, optional libcurl and OpenSSL, lazy ranges and exception types.",
  body: `
<h1><span class="lang-badge lang-cpp">C++</span> C++</h1>
<div class="badges">
  <span class="badge accent">CMake target lws::client</span>
  <span class="badge">C++20 · CMake 3.21+</span>
  <span class="badge">nlohmann/json · optional libcurl &amp; OpenSSL 3</span>
</div>
<p class="lead">A synchronous, exception-based C++20 client with value-semantic models and lazy input ranges.
Its core depends only on nlohmann/json. HTTP goes through a pluggable <code>lws::HttpTransport</code>
(libcurl by default), and cryptography uses OpenSSL 3.</p>
<div id="toc" class="toc"></div>

<h2 id="install">Install</h2>
${s("install")}
${table(
  ["CMake option", "Default", "Meaning"],
  [
    ["<code>LWS_WITH_CURL</code>", "<code>ON</code>", "Build <code>lws::CurlTransport</code> and <code>make_default_transport()</code>"],
    ["<code>LWS_WITH_OPENSSL</code>", "<code>ON</code>", "Keys, self-signed credentials, JWTs and <code>WebhookVerifier</code>"],
    ["<code>LWS_FETCH_DEPS</code>", "<code>ON</code>", "Fall back to <code>FetchContent</code> for nlohmann/json and GoogleTest"],
    ["<code>LWS_BUILD_TESTS</code> / <code>LWS_BUILD_EXAMPLES</code>", "top-level only", "GoogleTest suite / example programs"],
  ],
)}
<p>The generated <code>lws/config.hpp</code> defines <code>LWS_WITH_CURL</code> and <code>LWS_WITH_OPENSSL</code> as 0/1 so your code can check them.</p>

<h2 id="first">First program</h2>
${s("first-program")}

<h2 id="configure">Configure the client</h2>
${s("client-config")}

<h2 id="transport">Bring your own HTTP stack</h2>
<p>Implement <code>lws::HttpTransport::send(const HttpRequest&amp;) → HttpResponse</code> to run the client on Boost.Beast,
cpp-httplib, Qt or anything else. The transport must <em>not</em> follow redirects. The client follows them
itself so that it can re-evaluate credentials per hop. <code>Client::execute</code> sends a raw request through
authentication, the 401 retry and redirect handling without throwing on HTTP errors.
<code>execute_checked</code> does throw.</p>

<h2 id="idioms">C++ idioms</h2>
${table(
  ["Aspect", "How the C++ client does it"],
  [
    ["Calls", "Synchronous member functions; <code>Client</code> is immutable, cheap to copy and thread-safe (token cache guarded internally)"],
    ["Pagination", "<code>PagedRange&lt;T&gt;</code> input ranges (<code>ContainerRange</code>, <code>TypeRange</code>) that fetch pages on demand; <code>.to_vector()</code>"],
    ["Options", "Aggregates with designated initializers: <code>{.slug = \"x\"}</code>, <code>{.if_match = etag}</code>, <code>{.recursive = true}</code>"],
    ["Bodies", "<code>std::string</code> byte buffers (always replayable); no streaming, so use byte ranges for very large resources"],
    ["Models", "Plain structs with <code>std::optional</code>; JSON as <code>nlohmann::json</code>"],
    ["Errors", "<code>lws::Error : std::runtime_error</code> → <code>HttpError</code> → <code>NotFoundError</code>, …; plus <code>AuthenticationError</code>, <code>ProtocolError</code>/<code>ParseError</code>, <code>SignatureVerificationError</code>, <code>TransportError</code>"],
  ],
)}

<h2 id="headers">Headers</h2>
<p>Include everything with <code>&lt;lws/lws.hpp&gt;</code>, or pick from <code>client.hpp</code>, <code>models.hpp</code>, <code>auth.hpp</code>,
<code>crypto.hpp</code>, <code>keys.hpp</code>, <code>webhook.hpp</code>, <code>notifications.hpp</code>, <code>access.hpp</code>,
<code>type_index.hpp</code>, <code>json_patch.hpp</code>, <code>link.hpp</code>, <code>structured_fields.hpp</code>,
<code>errors.hpp</code>, <code>http.hpp</code> and <code>constants.hpp</code>.</p>

<h2 id="notes">Notes and deviations</h2>
<ul>
  <li>The delete operation is <code>remove()</code> because <code>delete</code> is a keyword, and <code>Constraint::op</code> stands in for <code>operator</code>.</li>
  <li><code>services_of(type)</code> looks up services because <code>services</code> is the data member.</li>
  <li>Builder validation (<code>TypeQuery</code>, access documents, subscription requests) throws <code>std::invalid_argument</code>.</li>
  <li>The library has no HTTP server. <code>WebhookVerifier::verify(method, url, headers, body)</code> plugs into the one you use.</li>
  <li>ES384 keys are supported for verification in addition to ES256 and EdDSA.</li>
  <li>When linking static OpenSSL and curl on Windows without vcpkg's toolchain, add <code>ws2_32</code> and <code>crypt32</code> yourself.</li>
</ul>

<h2 id="build">Build, test and examples</h2>
${code("bash", `
cd cpp
cmake --preset debug             # vcpkg manifest mode (needs VCPKG_ROOT)
cmake --build --preset debug
ctest --preset debug             # LWS_TEST_SERVER=http://localhost:8787 adds the interop test

cmake --preset mingw-debug       # MinGW-w64 with the x64-mingw-static triplet
cmake --preset minimal           # core only: no curl, no OpenSSL

# Examples: lws-quickstart, lws-did-key-auth, lws-verify-webhook
./build/debug/examples/lws-did-key-auth http://localhost:8787/root/`)}
${callout("note", "Source", ' <a href="https://github.com/ebremer/lws-client/tree/main/cpp">cpp/</a> in the repository, with its own <a href="https://github.com/ebremer/lws-client/blob/main/cpp/README.md">README</a>.')}
`,
};
