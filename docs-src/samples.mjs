// SPDX-License-Identifier: MIT
//
// Code samples for the documentation, loaded from the per-language "snippet books" in
// ./samples/<lang>.txt. Each book is a sequence of sections:
//
//   @@@ <topic> [highlight-language]
//   <code…>
//
// Every snippet is compiled or type-checked against the real clients before publishing (see
// contributing.html#docs). Fragments assume these variables are in scope: client, storage,
// container, url, etag (and, for auth samples, credentials / idToken / accessToken …).
//
// S[topic] = { java: {lang, code}, ts: {…}, cpp: {…}, rust: {…}, go: {…}, python: {…} }

import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const LANGS = ["java", "ts", "cpp", "rust", "go", "python"];

function parseBook(lang) {
  const text = readFileSync(join(here, "samples", `${lang}.txt`), "utf8").replace(/\r\n/g, "\n");
  const sections = {};
  let current = null;
  for (const line of text.split("\n")) {
    const m = /^@@@ (\S+)(?: (\S+))?\s*$/.exec(line);
    if (m) {
      current = { lang: m[2] ?? lang, lines: [] };
      sections[m[1]] = current;
    } else if (current) {
      current.lines.push(line);
    }
  }
  for (const s of Object.values(sections)) {
    while (s.lines.length && s.lines[s.lines.length - 1].trim() === "") s.lines.pop();
    s.code = s.lines.join("\n");
    delete s.lines;
  }
  return sections;
}

const books = Object.fromEntries(LANGS.map((l) => [l, parseBook(l)]));

/** Samples keyed by topic, then by language. Missing languages are simply absent. */
export const S = new Proxy(
  {},
  {
    get(_, topic) {
      if (typeof topic !== "string") return undefined;
      const out = {};
      for (const l of LANGS) if (books[l][topic]) out[l] = books[l][topic];
      if (!Object.keys(out).length) throw new Error(`no samples for topic "${topic}"`);
      return out;
    },
  },
);

/** One language's sample (for single-language pages). */
export function sample(lang, topic) {
  const s = books[lang][topic];
  if (!s) throw new Error(`no ${lang} sample for topic "${topic}"`);
  return s;
}
