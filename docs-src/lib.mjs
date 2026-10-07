// SPDX-License-Identifier: MIT
// Helpers and the page layout for the static documentation site.

export const SITE = {
  name: "LWS Client",
  version: "0.1.0",
  repo: "https://github.com/ebremer/lws-client",
  url: "https://ebremer.github.io/lws-client/",
  specBaseline: "2026-10-05",
};

/** Escape text for HTML element content and attribute values. */
export function esc(text) {
  return String(text)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

/** Remove the common leading indentation of a template literal and trim blank edges. */
export function dedent(src) {
  const lines = String(src).replace(/\r\n/g, "\n").split("\n");
  while (lines.length && lines[0].trim() === "") lines.shift();
  while (lines.length && lines[lines.length - 1].trim() === "") lines.pop();
  const indent = Math.min(
    ...lines.filter((l) => l.trim() !== "").map((l) => l.match(/^ */)[0].length),
  );
  return lines.map((l) => l.slice(Number.isFinite(indent) ? indent : 0)).join("\n");
}

/** A single highlighted code block. */
export function code(lang, src, { title } = {}) {
  const t = title ? ` data-title="${esc(title)}"` : "";
  return `<pre data-lang="${esc(lang)}"${t}><code class="language-${esc(lang)}">${esc(dedent(src))}</code></pre>`;
}

const TAB_ORDER = ["java", "ts", "cpp", "rust", "go", "python", "csharp"];

const TAB_LABELS = { java: "Java", ts: "TypeScript", cpp: "C++", rust: "Rust", go: "Go", python: "Python", csharp: "C#" };

/**
 * Language tabs. `samples` maps java / ts / cpp / rust / go / python / csharp (or any language id)
 * to either source text or `{ lang, code }` when the snippet needs different highlighting
 * than its tab (e.g. install commands). The reader's chosen language is remembered across pages.
 */
export function tabs(samples) {
  const keys = [
    ...TAB_ORDER.filter((k) => samples[k] !== undefined),
    ...Object.keys(samples).filter((k) => !TAB_ORDER.includes(k)),
  ];
  const blocks = keys.map((k) => {
    const value = samples[k];
    const lang = typeof value === "string" ? k : value.lang;
    const src = typeof value === "string" ? value : value.code;
    const label = TAB_LABELS[k] ?? k;
    return `<pre data-lang="${esc(lang)}" data-tab="${esc(k)}" data-label="${esc(label)}"><code class="language-${esc(lang)}">${esc(dedent(src))}</code></pre>`;
  });
  return `<div class="code-tabs">\n${blocks.join("\n")}\n</div>`;
}

export function callout(kind, title, html) {
  const cls = kind === "note" ? "callout" : `callout ${kind}`;
  return `<div class="${cls}"><p><strong>${esc(title)}</strong>${html}</p></div>`;
}

export function table(headers, rows) {
  const head = headers.map((h) => `<th>${h}</th>`).join("");
  const body = rows.map((r) => `<tr>${r.map((c) => `<td>${c}</td>`).join("")}</tr>`).join("\n");
  return `<div class="table-wrap"><table><thead><tr>${head}</tr></thead><tbody>\n${body}\n</tbody></table></div>`;
}

const LOGO = `<svg viewBox="0 0 32 32" aria-hidden="true"><rect x="2" y="2" width="28" height="28" rx="7" fill="var(--accent)"/><path d="M9 10.5h6.5M9 16h14M9 21.5h9" stroke="var(--accent-contrast)" stroke-width="2.6" stroke-linecap="round"/><circle cx="21.5" cy="10.5" r="2.4" fill="var(--accent-contrast)"/><circle cx="22" cy="21.5" r="2.4" fill="none" stroke="var(--accent-contrast)" stroke-width="2"/></svg>`;

const ICON_MENU = `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><path d="M4 6h16M4 12h16M4 18h16"/></svg>`;
const ICON_THEME = `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 12.8A9 9 0 1 1 11.2 3a7 7 0 0 0 9.8 9.8z"/></svg>`;
const ICON_GITHUB = `<svg viewBox="0 0 24 24" fill="currentColor"><path d="M12 .5a11.5 11.5 0 0 0-3.64 22.41c.58.1.79-.25.79-.56v-2c-3.2.7-3.88-1.37-3.88-1.37-.53-1.33-1.28-1.69-1.28-1.69-1.05-.71.08-.7.08-.7 1.16.08 1.77 1.19 1.77 1.19 1.03 1.77 2.7 1.26 3.36.96.1-.75.4-1.26.73-1.55-2.56-.29-5.25-1.28-5.25-5.7 0-1.26.45-2.29 1.19-3.1-.12-.29-.52-1.46.11-3.05 0 0 .97-.31 3.17 1.18a11 11 0 0 1 5.77 0c2.2-1.49 3.17-1.18 3.17-1.18.63 1.59.23 2.76.11 3.05.74.81 1.19 1.84 1.19 3.1 0 4.43-2.7 5.4-5.27 5.69.41.36.78 1.06.78 2.14v3.17c0 .31.21.67.8.56A11.5 11.5 0 0 0 12 .5z"/></svg>`;

/**
 * Render a full page.
 * @param {{path: string, title: string, description: string, body: string, wide?: boolean}} page
 */
export function layout(page) {
  const depth = page.path.split("/").length - 1;
  const root = depth === 0 ? "./" : "../".repeat(depth);
  const fullTitle = page.path === "index.html" ? `${SITE.name} — W3C Linked Web Storage clients` : `${page.title} · ${SITE.name}`;
  const top = [
    ["getting-started.html", "Get started"],
    ["concepts.html", "Concepts"],
    ["authentication.html", "Auth"],
    ["api-reference.html", "API"],
    ["spec-coverage.html", "Spec"],
  ]
    .map(([href, label]) => `<a href="${root}${href}"${href === page.path ? ' aria-current="page"' : ""}>${label}</a>`)
    .join("\n        ");
  return `<!doctype html>
<html lang="en" data-root="${root}">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>${esc(fullTitle)}</title>
  <meta name="description" content="${esc(page.description)}">
  <meta property="og:title" content="${esc(fullTitle)}">
  <meta property="og:description" content="${esc(page.description)}">
  <meta property="og:type" content="website">
  <meta name="color-scheme" content="light dark">
  <link rel="icon" href="${root}assets/favicon.svg" type="image/svg+xml">
  <link rel="stylesheet" href="${root}assets/style.css">
  <script src="${root}assets/site.js" defer></script>
</head>
<body>
  <a class="skip-link" href="#main">Skip to content</a>
  <header class="site-header">
    <button class="icon-btn menu-toggle" id="menu-toggle" type="button" aria-label="Toggle navigation" aria-expanded="false" aria-controls="sidebar">${ICON_MENU}</button>
    <a class="brand" href="${root}index.html">${LOGO}<span>${SITE.name}</span><span class="version">v${SITE.version}</span></a>
    <nav class="header-nav" aria-label="Primary">
        ${top}
    </nav>
    <div class="header-actions">
      <button class="icon-btn" id="theme-toggle" type="button" aria-label="Toggle dark mode">${ICON_THEME}</button>
      <a class="icon-btn" href="${SITE.repo}" aria-label="GitHub repository">${ICON_GITHUB}</a>
    </div>
  </header>
  <div class="layout">
    <nav class="sidebar" id="sidebar" aria-label="Documentation">
      <ul><li><a href="${root}index.html">Overview</a></li><li><a href="${root}getting-started.html">Getting started</a></li><li><a href="${root}api-reference.html">API cross-reference</a></li></ul>
    </nav>
    <main id="main">
      <article class="${page.wide ? "content-wide" : "content"}">
${page.body}
        <nav class="page-nav" id="page-nav" aria-label="Previous and next pages"></nav>
        <footer class="site-footer">
          <p>LWS Client is MIT licensed. It implements the W3C Linked Web Storage Working Group drafts as of ${SITE.specBaseline}; it is an independent project and is not a W3C publication. <a href="${SITE.repo}">Source on GitHub</a>.</p>
        </footer>
      </article>
    </main>
  </div>
</body>
</html>
`;
}
