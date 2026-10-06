#!/usr/bin/env node
// SPDX-License-Identifier: MIT
//
// Builds the GitHub Pages site into ../docs from the page modules in ./pages.
// Zero dependencies:  node docs-src/build.mjs
//
// Each page module default-exports { path, title, description, body, wide? }.
// Static assets (CSS, JS, favicon) live directly in docs/assets and are not generated.

import { mkdirSync, readdirSync, statSync, writeFileSync } from "node:fs";
import { dirname, join, relative } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { layout } from "./lib.mjs";

const here = dirname(fileURLToPath(import.meta.url));
const out = join(here, "..", "docs");
const pagesDir = join(here, "pages");

function walk(dir) {
  return readdirSync(dir).flatMap((name) => {
    const p = join(dir, name);
    return statSync(p).isDirectory() ? walk(p) : p.endsWith(".mjs") ? [p] : [];
  });
}

const seen = new Set();
let count = 0;
for (const file of walk(pagesDir).sort()) {
  const mod = await import(pathToFileURL(file).href);
  const page = mod.default;
  if (!page || !page.path || !page.title || !page.body) {
    throw new Error(`${relative(here, file)} must default-export { path, title, description, body }`);
  }
  if (seen.has(page.path)) throw new Error(`duplicate page path ${page.path}`);
  seen.add(page.path);
  const target = join(out, page.path);
  mkdirSync(dirname(target), { recursive: true });
  writeFileSync(target, layout(page));
  count++;
}
writeFileSync(join(out, ".nojekyll"), "");
console.log(`built ${count} pages into ${relative(process.cwd(), out) || "."}`);
