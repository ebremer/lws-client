// SPDX-License-Identifier: MIT
import { readFileSync } from "node:fs";
import { callout, code, table } from "../lib.mjs";

const LICENSE_TEXT = readFileSync(new URL("../../LICENSE", import.meta.url), "utf8");

export default {
  path: "contributing.html",
  title: "Contributing & license",
  description: "Repository layout, build and test commands for all ten LWS clients, the shared conformance process, documentation workflow and the MIT license.",
  body: `
<h1>Contributing &amp; license</h1>
<p class="lead">The ten clients evolve together. A behaviour change starts in the shared contract and
fixtures, then lands in every language, and the interop scenario keeps them honest.</p>
<div id="toc" class="toc"></div>

<h2 id="layout">Repository layout</h2>
${table(
  ["Path", "Contents"],
  [
    ["<code>design/client-api.md</code>", "The cross-language API contract: concepts, wire behaviour, interpretation decisions"],
    ["<code>conformance/</code>", "Shared JSON fixtures, their generator, and the interop scenario (<code>scenario.md</code>)"],
    ["<code>testing/mock-server/</code>", "Zero-dependency Node.js LWS server used by interop tests"],
    ["<code>java/</code> <code>js/</code> <code>cpp/</code> <code>rust/</code> <code>go/</code> <code>python/</code> <code>csharp/</code> <code>swift/</code> <code>php/</code> <code>kotlin/</code>", "The clients, each with a README, tests and examples (Swift's manifest is the root <code>Package.swift</code>, PHP's the root <code>composer.json</code>)"],
    ["<code>wasm/</code>", "The Rust client as a WebAssembly component, and its WIT interface (<code>wasm/wit/lws.wit</code>)"],
    ["<code>docs-src/</code>", "Sources of this website: page modules, snippet books, layout"],
    ["<code>docs/</code>", "The generated GitHub Pages site (do not edit the HTML by hand)"],
    ["<code>.github/workflows/ci.yml</code>", "CI: builds and tests every client and runs the interop scenario"],
  ],
)}

<h2 id="building">Building and testing each client</h2>
${table(
  ["Language", "Toolchain", "Build and test"],
  [
    ["Java", "JDK 17+ (built with <code>--release 17</code>), Maven 3.9", "<code>cd java &amp;&amp; mvn verify</code>"],
    ["JavaScript", "Node.js 22+ for the test suite (library: 20+)", "<code>cd js &amp;&amp; npm install &amp;&amp; npm run build &amp;&amp; npm test</code>"],
    ["C++", "C++20 compiler, CMake 3.21+, Ninja, vcpkg (or system packages)", "<code>cd cpp &amp;&amp; cmake --preset debug &amp;&amp; cmake --build --preset debug &amp;&amp; ctest --preset debug</code>"],
    ["Rust", "Rust 1.85+", "<code>cd rust &amp;&amp; cargo test &amp;&amp; cargo clippy --all-targets -- -D warnings</code>"],
    ["Go", "Go 1.23+", "<code>cd go &amp;&amp; go vet ./... &amp;&amp; go test ./...</code>"],
    ["Python", "Python 3.10+", "<code>cd python &amp;&amp; python -m venv .venv &amp;&amp; .venv/bin/pip install -e \".[dev]\" &amp;&amp; .venv/bin/pytest</code>"],
    ["C#", ".NET 10 SDK", "<code>dotnet test csharp</code>"],
    ["Swift", "Swift 6.0+ (Xcode 16+ on macOS)", "<code>swift build &amp;&amp; swift test</code> at the repository root"],
    ["PHP", "PHP 8.2+ with ext-curl, ext-openssl, ext-sodium; Composer", "<code>composer install &amp;&amp; composer test &amp;&amp; composer analyse</code> at the repository root"],
    ["Kotlin", "JDK 17+ (built with <code>-Xjdk-release=17</code>); the Gradle wrapper fetches Gradle", "<code>cd kotlin &amp;&amp; ./gradlew build</code>"],
    ["WebAssembly", "Rust 1.87+ with the <code>wasm32-wasip2</code> target; Node.js 22+", "<code>cd wasm &amp;&amp; cargo build --release --target wasm32-wasip2</code>, then test it through its driver adapter (<a href=\"languages/wasm.html#test\">how</a>)"],
  ],
)}
<p>Every suite runs the cross-language interop scenario when <code>LWS_TEST_SERVER</code> points at a running
<a href="testing.html#mock-server">mock server</a>:</p>
${code("bash", `
node testing/mock-server/server.mjs --port 8787 &
export LWS_TEST_SERVER=http://localhost:8787`)}

<h2 id="process">Changing behaviour</h2>
<ol class="steps">
  <li><strong>Contract first.</strong> Update <code>design/client-api.md</code>, and record a <strong>Decision:</strong> whenever
  the LWS drafts leave something open.</li>
  <li><strong>Fixtures next.</strong> Add or adjust the vectors in <code>conformance/fixtures/</code>. Cryptographic fixtures are
  regenerated with <code>node conformance/tools/generate-fixtures.mjs</code>.</li>
  <li><strong>Mock server.</strong> Teach <code>testing/mock-server</code> the server side, with tests.</li>
  <li><strong>All ten clients.</strong> Implement the change idiomatically in each language, run its tests, then run
  the interop scenario.</li>
  <li><strong>Docs.</strong> Update the snippet books and pages, and re-run the sample checks (below).</li>
</ol>

<h2 id="spec-tracking">Tracking the specifications</h2>
<p>The baseline is pinned to a commit of <a href="https://github.com/w3c/lws-protocol">w3c/lws-protocol</a> (currently
<code>ef02548</code>, 2026-10-05). To move it, diff the spec repository from the pinned commit, list the normative
changes in a pull request, then follow the process above and update the <a href="spec-coverage.html">spec coverage</a> page.</p>

<h2 id="conventions">Conventions</h2>
<ul>
  <li>Every source file starts with <code>SPDX-License-Identifier: MIT</code>.</li>
  <li>Keep the canonical concept names from the contract, and adapt only casing and language idioms.</li>
  <li>Return absolute URLs only: resolve every id, <code>Location</code> and link target against the response URL.</li>
  <li>Never auto-retry non-idempotent requests, except the single post-401 authentication retry.</li>
  <li>Each client runs with no network access to third parties in its unit tests. HTTP tests use in-process servers or mock transports.</li>
</ul>

<h2 id="docs">Documentation</h2>
<p>The site is generated with a zero-dependency Node script:</p>
${code("bash", `
node docs-src/build.mjs              # writes docs/*.html from docs-src/pages/**/*.mjs
node docs-src/check-samples.mjs      # compiles / type-checks every code sample (needs the toolchains)`)}
<ul>
  <li>Pages are ES modules in <code>docs-src/pages/</code> that export <code>{ path, title, description, body }</code>. The sidebar
  order lives in <code>docs/assets/site.js</code>.</li>
  <li>Code samples live in per-language snippet books, <code>docs-src/samples/&lt;lang&gt;.txt</code>, one
  <code>@@@ topic</code> section per sample. A page shows all ten languages of a topic with
  <code>tabs(S.topic)</code>.</li>
  <li><code>check-samples.mjs</code> wraps every snippet in a harness and runs the real compilers: <code>tsc</code> against
  <code>js/dist</code>, <code>mypy</code>, <code>go build</code>, <code>javac</code>, <code>cargo check</code>,
  <code>g++ -fsyntax-only</code>, <code>dotnet build</code> (of throwaway projects that reference <code>csharp/</code>),
  <code>swift build</code> (of a throwaway package that depends on the repository), <code>php -l</code> plus PHPStan (level 8,
  against <code>php/src</code>), and Gradle's <code>compileKotlin</code> (of a throwaway build that includes <code>kotlin/</code>).
  Fragments may use the shared names <code>client</code>, <code>storage</code>, <code>container</code>,
  <code>url</code>, <code>etag</code>, <code>credentials</code>, and so on.</li>
  <li>GitHub Pages serves the committed <code>docs/</code> folder (Settings → Pages → <em>Deploy from a branch</em>,
  <code>main</code> / <code>docs</code>). CI fails if <code>docs/</code> is out of date with <code>docs-src/</code>.</li>
</ul>

<h2 id="license">License</h2>
<p>Everything in the repository is released under the <strong>MIT License</strong>: the ten clients, the mock server, the
fixtures, the tools and this documentation. Each package manifest (<code>pom.xml</code>, <code>package.json</code>,
<code>Cargo.toml</code>, <code>pyproject.toml</code>, <code>vcpkg.json</code>, <code>composer.json</code>, the POM of <code>kotlin/build.gradle.kts</code>, and <code>Directory.Build.props</code> for the NuGet package) declares <code>MIT</code>;
SwiftPM manifests have no license field, so <code>Package.swift</code>, like every source file, carries the SPDX header.</p>
${code("text", LICENSE_TEXT, { title: "LICENSE" })}
${callout("note", "Not a W3C publication", " This is an independent implementation of the W3C Linked Web Storage Working Group's drafts. The specifications themselves are published by the W3C under its own document license.")}
`,
};
