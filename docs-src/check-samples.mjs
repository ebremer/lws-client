#!/usr/bin/env node
// SPDX-License-Identifier: MIT
//
// Compiles / type-checks every code sample in docs-src/samples/<lang>.txt against the real
// clients, so the documentation never shows an API that does not exist.
//
//   node docs-src/check-samples.mjs [java] [ts] [cpp] [rust] [go] [python] [csharp] [swift] [php] [kotlin]
//
// Each language is skipped (not failed) when its toolchain or build output is missing:
//   ts      js/dist and js/node_modules (npm install && npm run build in js/)
//   python  python/.venv with the dev extras (mypy), or the interpreter of another such venv in
//           $LWS_DOCS_PYTHON; mypy resolves lws_client from python/src either way
//   go      go on PATH
//   java    java/target/classes (mvn compile) and mvn on PATH (for the Jackson classpath)
//   rust    cargo on PATH
//   cpp     g++ (or $CXX) plus nlohmann/json headers (cpp/vcpkg_installed/*/include, or system)
//           and a generated lws/config.hpp (any cpp/build*/**/generated directory)
//   csharp  dotnet (a .NET 10 SDK) on PATH; the harness projects reference
//           csharp/src/Ebremer.Lws.Client, and every build output (the library's too) goes to
//           <tmpdir>/lws-docs-check/csharp-artifacts, so csharp/**/bin and obj are left alone
//   swift   swift (Swift 6.0+) on PATH; the harness package depends on the repository's root Package.swift,
//           and builds in <tmpdir>/lws-docs-check/swift-build
//   php     php (PHP 8.2+) on PATH lints every sample; with vendor/ at the repository root (composer install),
//           PHPStan (level 8, as for the library) also type-checks them against php/src
//   kotlin  java (a JDK 17+) on PATH or $JAVA_HOME; the harness, a Gradle build that includes kotlin/ (built with
//           kotlin/gradlew), goes to ~/.cache/lws-docs-check/kotlin rather than <tmpdir>, which can be a slow
//           Windows drive under WSL
//
// Harness projects are written to <tmpdir>/lws-docs-check/<lang>.

import { spawnSync } from "node:child_process";
import { existsSync, mkdirSync, readFileSync, readdirSync, rmSync, statSync, writeFileSync } from "node:fs";
import { homedir, tmpdir } from "node:os";
import { delimiter, dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const REPO = resolve(here, "..").replace(/\\/g, "/");
const WORK = join(tmpdir(), "lws-docs-check");
const FULL = new Set(["first-program", "webhook"]);
const SKIP = new Set(["install"]);
// Samples that declare types/functions and therefore live at file scope, not inside a function.
const TOP_LEVEL = new Set(["custom-authenticator"]);
const isWin = process.platform === "win32";

function book(lang) {
  const text = readFileSync(join(here, "samples", `${lang}.txt`), "utf8").replace(/\r\n/g, "\n");
  const out = {};
  let cur = null;
  for (const line of text.split("\n")) {
    const m = /^@@@ (\S+)(?: (\S+))?\s*$/.exec(line);
    if (m) { cur = out[m[1]] = { lines: [] }; continue; }
    if (cur) cur.lines.push(line);
  }
  return Object.fromEntries(Object.entries(out).map(([k, v]) => [k, v.lines.join("\n").trimEnd()]));
}
const indent = (code, pad) => code.split("\n").map((l) => (l ? pad + l : l)).join("\n");
const ident = (topic) => topic.replace(/-/g, "_");
function fresh(name) {
  const dir = join(WORK, name);
  rmSync(dir, { recursive: true, force: true });
  mkdirSync(dir, { recursive: true });
  return dir;
}
function run(cmd, args, opts = {}) {
  const r = spawnSync(cmd, args, { encoding: "utf8", shell: isWin, ...opts });
  return { ok: r.status === 0, out: `${r.stdout ?? ""}${r.stderr ?? ""}`.trim() };
}
const has = (cmd) => run(cmd, ["--version"]).ok;
function findDirs(start, predicate, depth = 6) {
  if (!existsSync(start) || depth < 0) return [];
  const found = predicate(start) ? [start] : [];
  for (const n of readdirSync(start)) {
    const p = join(start, n);
    if (statSync(p).isDirectory()) found.push(...findDirs(p, predicate, depth - 1));
  }
  return found;
}

// ---------------------------------------------------------------------------- TypeScript
function checkTs() {
  const tsc = join(REPO, "js/node_modules/.bin", isWin ? "tsc.cmd" : "tsc");
  if (!existsSync(join(REPO, "js/dist/index.d.ts")) || !existsSync(tsc)) return { skipped: "build js/ first (npm install && npm run build)" };
  const dir = fresh("ts");
  const dts = readFileSync(join(REPO, "js/dist/index.d.ts"), "utf8");
  const names = new Set();
  for (const m of dts.matchAll(/export\s*\{([^}]*)\}/g)) {
    for (const part of m[1].split(",")) {
      const p = part.trim().replace(/^type\s+/, "");
      if (p) names.add(p.split(/\s+as\s+/).pop().trim());
    }
  }
  for (const m of dts.matchAll(/export \* from "([^"]+)"/g)) {
    const sub = readFileSync(join(REPO, "js/dist", m[1].replace(/\.js$/, ".d.ts")), "utf8");
    for (const n of sub.matchAll(/export (?:declare )?(?:const|class|function|interface|type) ([A-Za-z_]\w*)/g)) names.add(n[1]);
  }
  let frag = `import { ${[...names].sort().join(", ")} } from "lws-client";
declare const client: LwsClient; declare const storage: StorageDescription;
declare const container: string; declare const url: string; declare const etag: string;
declare const idToken: string; declare const samlAssertionXml: string; declare const accessToken: string;
declare const apiKey: string; declare const requestUrl: string; declare const credentials: SelfSignedCredentials;
`;
  for (const [topic, code] of Object.entries(book("ts"))) {
    if (SKIP.has(topic)) continue;
    if (FULL.has(topic)) writeFileSync(join(dir, `${topic}.ts`), `${code}\nexport {};\n`);
    else frag += `\nexport async function snippet_${ident(topic)}(): Promise<void> {\n${indent(code, "  ")}\n}\n`;
  }
  writeFileSync(join(dir, "fragments.ts"), frag);
  writeFileSync(join(dir, "tsconfig.json"), JSON.stringify({
    compilerOptions: {
      target: "es2022", module: "esnext", moduleResolution: "bundler", strict: true, noEmit: true, skipLibCheck: true,
      lib: ["es2023", "dom", "dom.iterable"], types: ["node"], typeRoots: [`${REPO}/js/node_modules/@types`],
      paths: { "lws-client": [`${REPO}/js/dist/index.d.ts`], "lws-client/node": [`${REPO}/js/dist/node.d.ts`] },
    },
    include: ["*.ts"],
  }));
  return run(tsc, ["-p", "tsconfig.json"], { cwd: dir });
}

// ---------------------------------------------------------------------------- Python
function checkPython() {
  const py = process.env.LWS_DOCS_PYTHON || join(REPO, "python/.venv", isWin ? "Scripts/python.exe" : "bin/python");
  if (!existsSync(py)) return { skipped: "create python/.venv with the dev extras (or set LWS_DOCS_PYTHON)" };
  const dir = fresh("python");
  let frag = `from __future__ import annotations
from typing import cast
from lws_client import *  # noqa: F403
from lws_client import LwsClient, SelfSignedCredentials, StorageDescription
client = cast(LwsClient, None)
storage = cast(StorageDescription, None)
container = url = etag = id_token = saml_assertion_xml = access_token = api_key = request_url = ""
credentials = cast(SelfSignedCredentials, None)
`;
  for (const [topic, code] of Object.entries(book("python"))) {
    if (SKIP.has(topic)) continue;
    if (FULL.has(topic) || topic === "async-usage") writeFileSync(join(dir, `prog_${ident(topic)}.py`), `${code}\n`);
    else frag += `\n\ndef snippet_${ident(topic)}() -> None:\n${indent(code, "    ")}\n`;
  }
  writeFileSync(join(dir, "fragments.py"), frag);
  const files = readdirSync(dir).filter((f) => f.endsWith(".py"));
  const env = { ...process.env, MYPYPATH: join(REPO, "python/src") };   // this checkout, whatever the venv installed
  return run(py, ["-m", "mypy", "--check-untyped-defs", "--no-incremental", ...files], { cwd: dir, shell: false, env });
}

// ---------------------------------------------------------------------------- Go
function checkGo() {
  if (!run("go", ["version"]).ok) return { skipped: "go not on PATH" };
  const dir = fresh("go");
  writeFileSync(join(dir, "go.mod"), `module docscheck\n\ngo 1.23\n\nrequire github.com/ebremer/lws-client/go v0.0.0\n\nreplace github.com/ebremer/lws-client/go => ${REPO}/go\n`);
  let top = "";
  let fns = "";
  for (const [topic, code] of Object.entries(book("go"))) {
    if (SKIP.has(topic)) continue;
    if (FULL.has(topic)) { mkdirSync(join(dir, ident(topic))); writeFileSync(join(dir, ident(topic), "main.go"), `${code}\n`); continue; }
    if (TOP_LEVEL.has(topic)) top += `\n${code}\n`;
    else fns += `\nfunc snippet_${ident(topic)}() error {\n${indent(code, "\t")}\n\treturn nil\n}\n`;
  }
  mkdirSync(join(dir, "fragments"));
  writeFileSync(join(dir, "fragments", "fragments.go"), `package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"slices"
	"strings"
	"time"

	lws "github.com/ebremer/lws-client/go"
)

var _, _, _, _, _, _, _, _, _ = bytes.NewReader, json.Marshal, errors.Is, fmt.Println, io.Copy, http.DefaultClient, os.Open, strings.NewReader, time.Now
var _ = slices.Contains[[]string]

var (
	ctx                                                                  context.Context
	client                                                               *lws.Client
	storage                                                              *lws.StorageDescription
	container, url, etag, idToken, accessToken, apiKey, requestURL      string
	samlAssertionXML                                                     []byte
	credentials                                                          *lws.SelfSignedCredentials
)
${top}${fns}
func main() {}
`);
  return run("go", ["build", "./..."], { cwd: dir, env: { ...process.env, GOFLAGS: "-mod=mod" } });
}

// ---------------------------------------------------------------------------- Java
function checkJava() {
  if (!existsSync(join(REPO, "java/target/classes")) || !has("javac") || !has("mvn")) return { skipped: "run mvn compile in java/ (needs javac and mvn)" };
  const dir = fresh("java");
  const cpFile = join(dir, "cp.txt");
  const cp = run("mvn", ["-q", "-f", join(REPO, "java/pom.xml"), "dependency:build-classpath", "-Dmdep.includeScope=runtime", `-Dmdep.outputFile=${cpFile}`]);
  if (!cp.ok) return cp;
  const classpath = [join(REPO, "java/target/classes"), readFileSync(cpFile, "utf8").trim()].join(delimiter);
  let methods = "";
  for (const [topic, code] of Object.entries(book("java"))) {
    if (SKIP.has(topic)) continue;
    if (FULL.has(topic)) writeFileSync(join(dir, `${/public class (\w+)/.exec(code)[1]}.java`), `${code}\n`);
    else methods += `\n    static void snippet_${ident(topic)}() throws Exception {\n${indent(code, "        ")}\n    }\n`;
  }
  writeFileSync(join(dir, "Fragments.java"), `import com.ebremer.lws.*;
import com.ebremer.lws.access.*;
import com.ebremer.lws.auth.*;
import com.ebremer.lws.auth.Authenticator;
import com.ebremer.lws.http.*;
import com.ebremer.lws.index.*;
import com.ebremer.lws.notify.*;
import com.ebremer.lws.patch.*;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.io.*;
import java.net.URI;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.time.*;
import java.util.*;

@SuppressWarnings("unused")
class Fragments {
    static LwsClient client;
    static StorageDescription storage;
    static URI container, url, requestUrl;
    static String etag, idToken, samlAssertionXml, accessToken, apiKey;
    static SelfSignedCredentials credentials;
${methods}}
`);
  const sources = readdirSync(dir).filter((f) => f.endsWith(".java"));
  return run("javac", ["-Xlint:none", "-cp", classpath, "-d", join(dir, "out"), ...sources], { cwd: dir, shell: false });
}

// ---------------------------------------------------------------------------- Rust
function checkRust() {
  if (!has("cargo")) return { skipped: "cargo not on PATH" };
  const dir = fresh("rust");
  mkdirSync(join(dir, "src/bin"), { recursive: true });
  writeFileSync(join(dir, "Cargo.toml"), `[package]\nname = "docs-check"\nversion = "0.0.0"\nedition = "2024"\npublish = false\n\n[dependencies]\nlws-client = { path = "${REPO}/rust" }\ntokio = { version = "1", features = ["macros", "rt-multi-thread"] }\nfutures-util = "0.3"\nserde_json = "1"\nhttp = "1"\n`);
  const MODULES = new Set(["custom-authenticator", "webhook"]);
  let mods = "";
  let fns = "";
  for (const [topic, code] of Object.entries(book("rust"))) {
    if (SKIP.has(topic)) continue;
    if (MODULES.has(topic)) mods += `\nmod m_${ident(topic)} {\n    #![allow(unused)]\n    use super::*;\n${indent(code, "    ")}\n}\n`;
    else if (FULL.has(topic)) writeFileSync(join(dir, "src/bin", `${ident(topic)}.rs`), `${code}\n`);
    else fns += `\nasync fn snippet_${ident(topic)}(client: &Client, storage: &StorageDescription, container: &Url, url: &Url, etag: &str, id_token: &str, saml_assertion_xml: &str, access_token: &str, api_key: &str, request_url: &Url, credentials: SelfSignedCredentials) -> lws_client::Result<()> {\n${indent(code, "    ")}\n    Ok(())\n}\n`;
  }
  writeFileSync(join(dir, "src/main.rs"), `#![allow(unused, unreachable_code, clippy::all)]\nuse std::time::{Duration, SystemTime};\nuse futures_util::TryStreamExt;\nuse lws_client::*;\nuse lws_client::crypto::*;\n${mods}${fns}\nfn main() {}\n`);
  return run("cargo", ["check", "--bins", "--quiet"], { cwd: dir, env: { ...process.env, CARGO_TARGET_DIR: join(WORK, "rust-target") } });
}

// ---------------------------------------------------------------------------- C++
function checkCpp() {
  const cxx = process.env.CXX || "g++";
  if (!has(cxx)) return { skipped: `${cxx} not found` };
  // Prefer a build configured with OpenSSL so the crypto samples can be checked.
  const configs = findDirs(join(REPO, "cpp"), (d) => d.endsWith("generated") && existsSync(join(d, "lws/config.hpp")), 4);
  const config = configs.find((d) => /LWS_WITH_OPENSSL\s+1/.test(readFileSync(join(d, "lws/config.hpp"), "utf8")));
  if (!config) return { skipped: "configure cpp/ with LWS_WITH_OPENSSL=ON once so lws/config.hpp is generated" };
  const json = [...findDirs(join(REPO, "cpp/vcpkg_installed"), (d) => existsSync(join(d, "nlohmann/json.hpp")), 2)];
  const dir = fresh("cpp");
  let top = "";
  let fns = "";
  for (const [topic, code] of Object.entries(book("cpp"))) {
    if (SKIP.has(topic)) continue;
    if (FULL.has(topic)) writeFileSync(join(dir, `${ident(topic)}.cpp`), `${code}\n`);
    else if (TOP_LEVEL.has(topic)) top += `\n${code}\n`;
    else fns += `\nvoid snippet_${ident(topic)}() {\n${indent(code, "    ")}\n}\n`;
  }
  writeFileSync(join(dir, "fragments.cpp"), `#include <algorithm>\n#include <chrono>\n#include <cstdint>\n#include <iostream>\n#include <memory>\n#include <set>\n#include <string>\n#include <vector>\n#include <lws/lws.hpp>\n
extern lws::Client client;
extern lws::StorageDescription storage;
extern std::string container, url, etag, id_token, saml_assertion_xml, access_token, api_key, request_url;
extern std::shared_ptr<lws::SelfSignedCredentials> credentials;
${top}${fns}`);
  const includes = ["-I", join(REPO, "cpp/include"), "-I", config, ...json.flatMap((d) => ["-I", d])];
  for (const f of readdirSync(dir).filter((x) => x.endsWith(".cpp"))) {
    const r = run(cxx, ["-std=c++20", "-fsyntax-only", "-Wall", "-Wextra", ...includes, f], { cwd: dir, shell: false });
    if (!r.ok || r.out) return { ok: r.ok && !r.out, out: `${f}:\n${r.out}` };
  }
  return { ok: true, out: "" };
}

// ---------------------------------------------------------------------------- C#
// C# cannot declare a type inside a method, so a fragment's column-0 type declarations (a one-line
// `record …;`, or a block that runs to the next column-0 `}`) are lifted to file scope; the rest of
// the fragment becomes the body of an async method. Readers can paste a fragment into a top-level
// Program.cs as it is, which is why the declarations come last in the books.
function liftCsharpTypes(code) {
  const types = [];
  const body = [];
  let inType = false;
  for (const line of code.split("\n")) {
    if (!inType && /^(?:(?:public|internal|file|sealed|abstract|static|partial|readonly)\s+)*(?:class|record|struct|interface|enum)\s/.test(line)) {
      types.push(line);
      inType = !/;\s*(?:\/\/.*)?$/.test(line);
    } else if (inType) {
      types.push(line);
      if (/^\}/.test(line)) inType = false;
    } else {
      body.push(line);
    }
  }
  return { types: types.join("\n"), body: body.join("\n").trim() };
}

function checkCsharp() {
  if (!has("dotnet")) return { skipped: "dotnet not on PATH" };
  const dir = fresh("csharp");
  const lib = `${REPO}/csharp/src/Ebremer.Lws.Client/Ebremer.Lws.Client.csproj`;
  // The harness's own settings; the library keeps the ones in csharp/Directory.Build.props.
  writeFileSync(join(dir, "Directory.Build.props"), `<Project>
  <PropertyGroup>
    <TargetFramework>net10.0</TargetFramework>
    <LangVersion>latest</LangVersion>
    <Nullable>enable</Nullable>
    <ImplicitUsings>enable</ImplicitUsings>
    <TreatWarningsAsErrors>true</TreatWarningsAsErrors>
    <!-- Fragments are never called and may leave values unused. -->
    <NoWarn>$(NoWarn);CS0162;CS0168;CS0169;CS0219;CS0414;CS0649;CS1998;CS8321</NoWarn>
    <IsPackable>false</IsPackable>
  </PropertyGroup>
  <ItemGroup>
    <ProjectReference Include="${lib}" />
  </ItemGroup>
</Project>
`);
  const projects = [];
  const project = (name, outputType, file, source) => {
    mkdirSync(join(dir, name));
    writeFileSync(join(dir, name, `${name}.csproj`), `<Project Sdk="Microsoft.NET.Sdk">\n  <PropertyGroup>\n    <OutputType>${outputType}</OutputType>\n  </PropertyGroup>\n</Project>\n`);
    writeFileSync(join(dir, name, file), source);
    projects.push(name);
  };
  let top = "";
  let methods = "";
  for (const [topic, code] of Object.entries(book("csharp"))) {
    if (SKIP.has(topic)) continue;
    if (FULL.has(topic)) { project(ident(topic), "Exe", "Program.cs", `${code}\n`); continue; }
    const { types, body } = liftCsharpTypes(code);
    if (types) top += `\n${types}\n`;
    methods += `\n    static async Task snippet_${ident(topic)}()\n    {\n${indent(body, "        ")}\n    }\n`;
  }
  project("fragments", "Library", "Fragments.cs", `using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Ebremer.Lws;
using Ebremer.Lws.Access;
using Ebremer.Lws.Auth;
using Ebremer.Lws.Http;
using Ebremer.Lws.Notifications;

static class Fragments
{
    static LwsClient client = null!;
    static StorageDescription storage = null!;
    static Uri container = null!, url = null!, requestUrl = null!;
    static string etag = "", idToken = "", samlAssertionXml = "", accessToken = "", apiKey = "";
    static SelfSignedCredentials credentials = null!;
${methods}}
${top}`);
  writeFileSync(join(dir, "docs-check.slnx"), `<Solution>\n${projects.map((p) => `  <Project Path="${p}/${p}.csproj" />`).join("\n")}\n</Solution>\n`);
  const env = { ...process.env, DOTNET_CLI_TELEMETRY_OPTOUT: "1", DOTNET_NOLOGO: "1", DOTNET_SKIP_FIRST_TIME_EXPERIENCE: "1" };
  return run("dotnet", ["build", "docs-check.slnx", "--nologo", "-v:q", "--disable-build-servers", `-p:ArtifactsPath=${join(WORK, "csharp-artifacts")}`],
    { cwd: dir, env });
}

// ---------------------------------------------------------------------------- Swift
// A sample that starts with an import is a whole program (main.swift of its own executable target); the others are
// fragments, each the body of a function, with the variables they use declared as module-level computed properties.
function checkSwift() {
  if (!has("swift")) return { skipped: "swift not on PATH" };
  const dir = fresh("swift");
  // SwiftPM names a path dependency after its directory.
  const identity = REPO.split("/").pop().toLowerCase();
  const targets = [];
  const target = (name, file, source) => {
    mkdirSync(join(dir, "Sources", name), { recursive: true });
    writeFileSync(join(dir, "Sources", name, file), source);
    targets.push(name);
  };
  let fragments = "";
  for (const [topic, code] of Object.entries(book("swift"))) {
    if (SKIP.has(topic)) continue;
    if (/^import /m.test(code.split("\n")[0])) { target(`Sample_${ident(topic)}`, "main.swift", `${code}\n`); continue; }
    fragments += `\nfunc snippet_${ident(topic)}() async throws {\n${indent(code, "    ")}\n}\n`;
  }
  target("Fragments", "Fragments.swift", `import Foundation
import LWS

// Never run: the fragments only have to compile.
var client: LWSClient { fatalError() }
var storage: StorageDescription { fatalError() }
var container: URL { fatalError() }
var url: URL { fatalError() }
var requestURL: URL { fatalError() }
var etag: String { fatalError() }
var idToken: String { fatalError() }
var samlAssertionXML: String { fatalError() }
var accessToken: String { fatalError() }
var credentials: SelfSignedCredentials { fatalError() }
${fragments}`);
  const kinds = targets.map((t) => t === "Fragments"
    ? `        .target(name: "${t}", dependencies: [.product(name: "LWS", package: "${identity}")])`
    : `        .executableTarget(name: "${t}", dependencies: [.product(name: "LWS", package: "${identity}")])`);
  writeFileSync(join(dir, "Package.swift"), `// swift-tools-version:6.0
import PackageDescription

let package = Package(
    name: "docs-check",
    platforms: [.macOS(.v13), .iOS(.v16)],
    dependencies: [.package(path: "${REPO}")],
    targets: [
${kinds.join(",\n")},
    ]
)
`);
  return run("swift", ["build", "--package-path", dir, "--scratch-path", join(WORK, "swift-build")]);
}

// ---------------------------------------------------------------------------- PHP
// A sample that starts with <?php is a whole program (its own file, whose require of vendor/autoload.php reaches the
// repository's autoloader); the others are fragments, each the body of a function whose parameters are the shared
// variables, in a file that imports every public class of the library.
function checkPhp() {
  if (!has("php")) return { skipped: "php not on PATH" };
  const dir = fresh("php");
  const classes = [];
  const walk = (d, ns) => {
    for (const n of readdirSync(d).sort()) {
      const p = join(d, n);
      if (statSync(p).isDirectory()) { if (n !== "Internal") walk(p, `${ns}\\${n}`); }
      else if (n.endsWith(".php")) classes.push(`${ns}\\${n.slice(0, -4)}`);
    }
  };
  walk(join(REPO, "php/src"), "Ebremer\\Lws");
  const short = (c) => c.split("\\").pop();
  const names = new Set();
  for (const c of classes) {
    if (names.has(short(c))) throw new Error(`two library classes are named ${short(c)}`);
    names.add(short(c));
  }
  const files = [];
  let fragments = `<?php
declare(strict_types=1);

${classes.map((c) => `use ${c};`).join("\n")}

// Never run: the fragments only have to type-check.
`;
  for (const [topic, code] of Object.entries(book("php"))) {
    if (SKIP.has(topic)) continue;
    if (code.startsWith("<?php")) {
      writeFileSync(join(dir, `prog_${ident(topic)}.php`), `${code}\n`);
      files.push(`prog_${ident(topic)}.php`);
      continue;
    }
    fragments += `
function snippet_${ident(topic)}(LwsClient $client, StorageDescription $storage, string $container, string $url, string $etag,
    SelfSignedCredentials $credentials, string $idToken, string $samlAssertionXml, string $accessToken, string $requestUrl): void
{
${indent(code, "    ")}
}
`;
  }
  writeFileSync(join(dir, "fragments.php"), fragments);
  files.push("fragments.php");
  for (const f of files) {
    const lint = run("php", ["-l", f], { cwd: dir, shell: false });
    if (!lint.ok) return lint;
  }
  const autoload = join(REPO, "vendor/autoload.php");
  const phpstan = join(REPO, "vendor/bin/phpstan");
  if (!existsSync(autoload) || !existsSync(phpstan)) return { skipped: `linted ${files.length} files; composer install at the repository root to type-check them` };
  mkdirSync(join(dir, "vendor"));
  writeFileSync(join(dir, "vendor/autoload.php"), `<?php\nrequire ${JSON.stringify(autoload)};\n`);
  writeFileSync(join(dir, "phpstan.neon"), `parameters:
    level: 8
    phpVersion: 80200
    paths:
        - ${dir}
    excludePaths:
        - ${join(dir, "vendor")}
    tmpDir: ${join(WORK, "php-phpstan")}
    bootstrapFiles:
        - ${autoload}
`);
  return run("php", [phpstan, "analyse", "-c", join(dir, "phpstan.neon"), "--no-progress", "--memory-limit=1G", "--error-format=raw"], { cwd: dir, shell: false });
}

// ---------------------------------------------------------------------------- Kotlin
// A sample that starts with an import is a whole file, in a package of its own; the others are fragments, each the
// body of a suspend function whose parameters are the shared variables, in a file that star-imports the library.
function checkKotlin() {
  const gradlew = join(REPO, "kotlin", isWin ? "gradlew.bat" : "gradlew");
  if (!existsSync(gradlew)) return { skipped: "kotlin/gradlew is missing" };
  if (!process.env.JAVA_HOME && !has("java")) return { skipped: "java (JDK 17+) not on PATH, and no JAVA_HOME" };
  const dir = join(homedir(), ".cache", "lws-docs-check", "kotlin");
  // Keep Gradle's caches between runs; only the sources are written afresh.
  rmSync(join(dir, "src"), { recursive: true, force: true });
  const src = join(dir, "src/main/kotlin");
  mkdirSync(src, { recursive: true });
  const plugin = /kotlin\("jvm"\) version "([^"]+)"/.exec(readFileSync(join(REPO, "kotlin/build.gradle.kts"), "utf8"))[1];
  writeFileSync(join(dir, "settings.gradle.kts"), `rootProject.name = "lws-docs-check"
includeBuild(${JSON.stringify(join(REPO, "kotlin"))})
dependencyResolutionManagement { repositories { mavenCentral() } }
`);
  writeFileSync(join(dir, "build.gradle.kts"), `plugins { kotlin("jvm") version "${plugin}" }
dependencies { implementation("com.ebremer:lws-client-kotlin:0.1.0") }
`);
  let fragments = `@file:Suppress("UNUSED_VARIABLE", "UNUSED_PARAMETER", "UNUSED_VALUE", "NAME_SHADOWING", "unused")
package fragments

import com.ebremer.lws.kotlin.*
import com.ebremer.lws.kotlin.access.*
import com.ebremer.lws.kotlin.auth.*
import com.ebremer.lws.kotlin.http.*
import com.ebremer.lws.kotlin.json.*
import com.ebremer.lws.kotlin.notify.*
import kotlinx.coroutines.*
import kotlinx.coroutines.flow.*
import kotlinx.serialization.json.*
import java.io.File
import java.net.URI
import java.time.Instant
import kotlin.time.Duration.Companion.minutes
import kotlin.time.Duration.Companion.seconds

// Never run: the fragments only have to compile.
`;
  for (const [topic, code] of Object.entries(book("kotlin"))) {
    if (SKIP.has(topic)) continue;
    if (code.startsWith("import ")) {
      writeFileSync(join(src, `Sample_${ident(topic)}.kt`), `package sample_${ident(topic)}\n\n${code}\n`);
      continue;
    }
    fragments += `
suspend fun snippet_${ident(topic)}(client: LwsClient, storage: StorageDescription, container: URI, url: URI, etag: String,
    credentials: SelfSignedCredentials, idToken: String, samlAssertionXml: String, accessToken: String, requestUrl: URI) {
${indent(code, "    ")}
}
`;
  }
  writeFileSync(join(src, "Fragments.kt"), fragments);
  return run(gradlew, ["-p", dir, "--console=plain", "-q", "compileKotlin"], { cwd: dir, shell: isWin });
}

const CHECKS = { java: checkJava, ts: checkTs, cpp: checkCpp, rust: checkRust, go: checkGo, python: checkPython, csharp: checkCsharp, swift: checkSwift, php: checkPhp, kotlin: checkKotlin };
const wanted = process.argv.slice(2).length ? process.argv.slice(2) : Object.keys(CHECKS);
let failed = 0;
for (const lang of wanted) {
  const result = CHECKS[lang]();
  if (result.skipped) console.log(`- ${lang.padEnd(6)} skipped: ${result.skipped}`);
  else if (result.ok) console.log(`✓ ${lang.padEnd(6)} all samples compile`);
  else { failed++; console.log(`✗ ${lang.padEnd(6)} failed\n${result.out}\n`); }
}
process.exit(failed ? 1 : 0);
