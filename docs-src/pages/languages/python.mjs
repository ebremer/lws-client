// SPDX-License-Identifier: MIT
import { callout, code, table } from "../../lib.mjs";
import { sample } from "../../samples.mjs";

const s = (topic) => code(sample("python", topic).lang, sample("python", topic).code);

export default {
  path: "languages/python.html",
  title: "Python",
  description: "The typed Python LWS client: synchronous and asyncio clients over one sans-I/O core, httpx, frozen dataclasses and an optional cryptography extra.",
  body: `
<h1><span class="lang-badge lang-python">PY</span> Python</h1>
<div class="badges">
  <span class="badge accent">lws-client 0.1.0</span>
  <span class="badge">Python 3.10+</span>
  <span class="badge">httpx · optional cryptography</span>
  <span class="badge">fully typed (py.typed, mypy --strict)</span>
</div>
<p class="lead"><code>LwsClient</code> (synchronous) and <code>AsyncLwsClient</code> (asyncio) share a sans-I/O core. Every
operation, redirect rule and step of the token exchange is written once, so the two clients behave identically.</p>
<div id="toc" class="toc"></div>

<h2 id="install">Install</h2>
${s("install")}

<h2 id="first">First program</h2>
${s("first-program")}

<h2 id="configure">Configure the client</h2>
${s("client-config")}

<h2 id="async">Async usage</h2>
${s("async-usage")}

<h2 id="idioms">Python idioms</h2>
${table(
  ["Aspect", "How the Python client does it"],
  [
    ["Calls", "<code>LwsClient</code> and <code>AsyncLwsClient</code> with identical method names; both are context managers that close their httpx client"],
    ["Pagination", "Generators: <code>list_container</code>, <code>list_types</code>, <code>search_all</code>…; async generators on <code>AsyncLwsClient</code>; <code>container_pages</code> / <code>search_pages</code> yield whole pages"],
    ["Options", "Keyword arguments: <code>slug=</code>, <code>types=</code>, <code>links=</code>, <code>if_match=</code>, <code>if_none_match=</code>, <code>range=(start, end)</code>, <code>recursive=</code>, <code>set_linkset=</code>"],
    ["Bodies", "<code>bytes</code>, <code>str</code> or an iterable of bytes; <code>create_json</code>, <code>create_text</code>, <code>read_json</code>; <code>stream(url)</code> for unbuffered reads"],
    ["Models", "Frozen, slotted dataclasses; <code>is_container</code>/<code>is_data_resource</code>/<code>not_modified</code> are properties; datetimes are aware <code>datetime</code>s plus raw strings"],
    ["Errors", "<code>LwsError</code> → <code>HttpError</code> (<code>status</code>, <code>problem</code>, <code>headers</code>, <code>body_text</code>) → <code>NotFoundError</code>, …; <code>TransportError</code> wraps httpx failures"],
    ["Crypto", "The <code>[crypto]</code> extra (cryptography) is imported lazily, with a clear error if it is missing; ES256, EdDSA and ES384"],
  ],
)}

<h2 id="modules">Modules</h2>
<p>Everything is importable from the package root (<code>from lws_client import …</code>). Submodules:
<code>client</code>, <code>models</code>, <code>linkset</code>, <code>auth</code>, <code>crypto</code>, <code>webhook</code>, <code>notifications</code>,
<code>access</code>, <code>type_index</code>, <code>json_patch</code>, <code>headers</code>, <code>structured_fields</code>,
<code>errors</code> and <code>constants</code>.</p>

<h2 id="notes">Notes and deviations</h2>
<ul>
  <li><code>NotImplementedByServerError</code> (501) avoids shadowing the built-in <code>NotImplementedError</code>.
  <code>GoneError</code> subclasses <code>NotFoundError</code>, since expired page links may answer either status.</li>
  <li><code>links_for(rel)</code> and <code>find_services(type)</code> are the lookups, because <code>links</code> and <code>services</code> are fields.</li>
  <li><code>subscribe(service, topics, inbox, expires=…)</code> takes arguments rather than a request object.</li>
  <li>Invalid builder input raises <code>ValueError</code>. A malformed notification body during webhook verification raises
  <code>SignatureVerificationError</code>, so a handler only needs to catch one exception type.</li>
  <li>Redirects are followed manually, for <code>GET</code>/<code>HEAD</code>/<code>OPTIONS</code>/<code>QUERY</code> only, with credentials re-evaluated per hop.</li>
  <li>Extras: <code>authenticate(url)</code> to obtain a token up front, <code>stream</code>, <code>read_linkset_at</code>, ES384, <code>verify_jwt</code> and <code>did_key_to_jwk</code>.</li>
</ul>

<h2 id="build">Build, test and examples</h2>
${code("bash", `
cd python
python -m venv .venv
.venv/bin/pip install -e ".[dev]"            # Windows: .venv\\Scripts\\pip
.venv/bin/pytest
.venv/bin/mypy                               # strict
.venv/bin/ruff check src tests examples
node ../testing/mock-server/server.mjs --port 8787 &
LWS_TEST_SERVER=http://localhost:8787 .venv/bin/pytest tests/test_interop.py

# Examples: quickstart.py, async_usage.py, self_signed_identity.py, webhook_receiver.py
.venv/bin/python examples/quickstart.py http://localhost:8787/root/`)}
${callout("note", "Source", ' <a href="https://github.com/ebremer/lws-client/tree/main/python">python/</a> in the repository, with its own <a href="https://github.com/ebremer/lws-client/blob/main/python/README.md">README</a>.')}
`,
};
