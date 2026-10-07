// SPDX-License-Identifier: MIT
// LWS Client documentation site behaviour: navigation, theme, language tabs,
// copy buttons, heading anchors and a small dependency-free syntax highlighter.
(function () {
  "use strict";

  var root = document.documentElement.getAttribute("data-root") || "./";

  // ------------------------------------------------------------------ nav data
  // The single source of truth for the sidebar and the previous/next links.
  var NAV = [
    { title: "Start", items: [
      ["index.html", "Overview"],
      ["getting-started.html", "Getting started"],
      ["concepts.html", "LWS concepts"],
    ] },
    { title: "Guides", items: [
      ["discovery.html", "Storage discovery"],
      ["resources.html", "Reading & writing resources"],
      ["containers.html", "Containers & pagination"],
      ["metadata.html", "Metadata & linksets"],
      ["authentication.html", "Authentication"],
      ["notifications.html", "Notifications & webhooks"],
      ["access.html", "Access requests & grants"],
      ["type-index.html", "Type index & search"],
      ["errors.html", "Errors"],
    ] },
    { title: "Languages", items: [
      ["languages/java.html", "Java", "java"],
      ["languages/javascript.html", "JavaScript / TypeScript", "js"],
      ["languages/cpp.html", "C++", "cpp"],
      ["languages/rust.html", "Rust", "rust"],
      ["languages/go.html", "Go", "go"],
      ["languages/python.html", "Python", "python"],
      ["languages/csharp.html", "C#", "csharp"],
      ["languages/swift.html", "Swift", "swift"],
      ["languages/php.html", "PHP", "php"],
      ["languages/kotlin.html", "Kotlin", "kotlin"],
      ["languages/wasm.html", "WebAssembly", "wasm"],
    ] },
    { title: "Reference", items: [
      ["api-reference.html", "API cross-reference"],
      ["spec-coverage.html", "Spec coverage"],
      ["testing.html", "Testing & mock server"],
      ["contributing.html", "Contributing & license"],
    ] },
  ];
  var LANG_COLORS = { java: "#b0721a", js: "#2f74c0", cpp: "#00599c", rust: "#a04f26", go: "#00838f", python: "#3a6e9f", csharp: "#68217a", swift: "#d8452f", php: "#777bb3", kotlin: "#7f52ff", wasm: "#654ff0" };

  function currentPath() {
    var path = location.pathname.replace(/\\/g, "/");
    var depth = (root.match(/\.\.\//g) || []).length;
    var parts = path.split("/").filter(Boolean);
    var file = parts.length ? parts[parts.length - 1] : "index.html";
    if (!/\.html?$/.test(file)) file = "index.html";
    if (depth > 0 && parts.length >= 2) return parts[parts.length - 2] + "/" + file;
    return file;
  }

  function el(tag, attrs, children) {
    var node = document.createElement(tag);
    if (attrs) for (var k in attrs) {
      if (k === "text") node.textContent = attrs[k];
      else node.setAttribute(k, attrs[k]);
    }
    (children || []).forEach(function (c) { node.appendChild(c); });
    return node;
  }

  function buildSidebar() {
    var sidebar = document.getElementById("sidebar");
    if (!sidebar) return;
    var here = currentPath();
    var frag = document.createDocumentFragment();
    NAV.forEach(function (group) {
      frag.appendChild(el("h2", { text: group.title }));
      var ul = el("ul");
      group.items.forEach(function (item) {
        var a = el("a", { href: root + item[0] });
        if (item[2]) {
          var dot = el("span", { class: "lang-dot", "aria-hidden": "true" });
          dot.style.background = LANG_COLORS[item[2]];
          a.appendChild(dot);
        }
        a.appendChild(document.createTextNode(item[1]));
        if (item[0] === here) a.setAttribute("aria-current", "page");
        ul.appendChild(el("li", null, [a]));
      });
      frag.appendChild(ul);
    });
    sidebar.innerHTML = "";
    sidebar.appendChild(frag);
  }

  function buildPageNav() {
    var host = document.getElementById("page-nav");
    if (!host) return;
    var flat = [];
    NAV.forEach(function (g) { g.items.forEach(function (i) { flat.push(i); }); });
    var here = currentPath();
    var idx = flat.findIndex(function (i) { return i[0] === here; });
    if (idx < 0) return;
    function link(item, cls, dir) {
      var a = el("a", { href: root + item[0], class: cls });
      a.appendChild(el("span", { class: "dir", text: dir }));
      a.appendChild(document.createTextNode(item[1]));
      return a;
    }
    if (idx > 0) host.appendChild(link(flat[idx - 1], "prev", "← Previous"));
    if (idx < flat.length - 1) host.appendChild(link(flat[idx + 1], "next", "Next →"));
  }

  // ------------------------------------------------------------------ storage helpers
  function load(key) {
    try { return window.localStorage.getItem(key); } catch (e) { return null; }
  }
  function save(key, value) {
    try { window.localStorage.setItem(key, value); } catch (e) { /* ignore */ }
  }

  // ------------------------------------------------------------------ theme
  function applyTheme(theme) {
    if (theme === "light" || theme === "dark") document.documentElement.setAttribute("data-theme", theme);
    else document.documentElement.removeAttribute("data-theme");
  }
  applyTheme(load("lws-docs-theme"));

  function setupThemeToggle() {
    var btn = document.getElementById("theme-toggle");
    if (!btn) return;
    btn.addEventListener("click", function () {
      var explicit = document.documentElement.getAttribute("data-theme");
      var dark = explicit ? explicit === "dark" : window.matchMedia("(prefers-color-scheme: dark)").matches;
      var next = dark ? "light" : "dark";
      applyTheme(next);
      save("lws-docs-theme", next);
    });
  }

  function setupMenu() {
    var btn = document.getElementById("menu-toggle");
    if (!btn) return;
    btn.addEventListener("click", function () {
      var open = document.body.classList.toggle("nav-open");
      btn.setAttribute("aria-expanded", open ? "true" : "false");
    });
    document.addEventListener("click", function (e) {
      if (!document.body.classList.contains("nav-open")) return;
      var sidebar = document.getElementById("sidebar");
      if (sidebar && !sidebar.contains(e.target) && !btn.contains(e.target)) {
        document.body.classList.remove("nav-open");
        btn.setAttribute("aria-expanded", "false");
      }
    });
  }

  // ------------------------------------------------------------------ highlighter
  var KEYWORDS = {
    java: "abstract assert boolean break byte case catch char class const continue default do double else enum exports extends final finally float for if implements import instanceof int interface long module native new package private protected public record requires return sealed short static strictfp super switch synchronized this throw throws transient try var void volatile while yield null true false permits",
    ts: "abstract any as async await boolean break case catch class const constructor continue declare default delete do else enum export extends false finally for from function get if implements import in instanceof interface keyof let new null number of private protected public readonly return set static string super switch this throw true try type typeof undefined unknown var void while with yield",
    cpp: "alignas auto bool break case catch char class const constexpr consteval continue co_await co_return decltype default delete do double else enum explicit export extern false float for friend if inline int long mutable namespace new noexcept nullptr operator override private protected public return short signed sizeof static static_cast struct switch template this throw true try typedef typename union unsigned using virtual void volatile while std",
    rust: "as async await break const continue crate dyn else enum extern false fn for if impl in let loop match mod move mut pub ref return self Self static struct super trait true type unsafe use where while Some None Ok Err",
    go: "break case chan const continue default defer else fallthrough for func go goto if import interface map package range return select struct switch type var nil true false err",
    python: "and as assert async await break class continue def del elif else except False finally for from global if import in is lambda None nonlocal not or pass raise return True try while with yield self",
    csharp: "abstract and as async await base bool break byte case catch char checked class const continue decimal default delegate do double dynamic else enum event explicit extern false file finally fixed float for foreach get global goto if implicit in init int interface internal is lock long nameof namespace new not null object operator or out override params partial private protected public readonly record ref required return sbyte sealed set short sizeof stackalloc static string struct switch this throw true try typeof uint ulong unchecked unsafe ushort using var virtual void volatile when where while with yield",
    swift: "actor any as associatedtype async await break case catch class continue default defer deinit do else enum extension fallthrough false fileprivate final for func guard if import in init inout internal is lazy let mutating nil nonisolated open operator override private protocol public repeat rethrows return self Self some static struct subscript super switch throw throws true try var where while",
    php: "abstract and array as break callable case catch class clone const continue declare default do echo else elseif empty enum extends false final finally fn for foreach function global goto if implements include include_once instanceof insteadof interface isset list match namespace new null or parent print private protected public readonly require require_once return self static switch throw trait true try unset use var while xor yield bool int float string iterable object mixed void never __DIR__ __FILE__ __LINE__ __CLASS__ __FUNCTION__ __METHOD__ __NAMESPACE__",
    kotlin: "abstract annotation as break by catch class companion const constructor continue crossinline data do else enum expect external false final finally for fun if import in infix init inline inner interface internal is lateinit noinline null object open operator out override package private protected public reified return sealed super suspend this throw true try typealias val value var vararg when where while",
    bash: "if then else fi for do done case esac in function export cd echo cmake cargo go npm npx node mvn pip python git dotnet swift php composer gradlew java",
    json: "true false null",
    http: "",
  };
  var ALIASES = { javascript: "ts", js: "ts", typescript: "ts", "c++": "cpp", cs: "csharp", "c#": "csharp", sh: "bash", shell: "bash", console: "bash", py: "python", golang: "go", kt: "kotlin", kts: "kotlin", toml: "bash", xml: "http", text: "http", cmake: "bash", powershell: "bash", groovy: "java" };
  var kwCache = {};
  function keywordSet(lang) {
    if (!kwCache[lang]) {
      var set = Object.create(null);
      (KEYWORDS[lang] || "").split(" ").forEach(function (w) { if (w) set[w] = true; });
      kwCache[lang] = set;
    }
    return kwCache[lang];
  }

  function esc(s) {
    return s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
  }

  function highlight(code, langName) {
    var lang = ALIASES[langName] || langName;
    if (!(lang in KEYWORDS)) return esc(code);
    var kw = keywordSet(lang);
    var hashComments = lang === "python" || lang === "bash";
    var slashComments = lang !== "python" && lang !== "bash" && lang !== "http" && lang !== "json";
    var out = "";
    var i = 0;
    var n = code.length;
    var lastSig = "";   // the last character of code (not whitespace, not a comment) emitted so far
    function push(cls, text) {
      out += cls ? '<span class="tok-' + cls + '">' + esc(text) + "</span>" : esc(text);
      if (cls !== "c") {
        var t = text.replace(/\s+$/, "");
        if (t) lastSig = t[t.length - 1];
      }
    }
    while (i < n) {
      var ch = code[i];
      var rest = code.slice(i);
      var m;
      if (slashComments && rest.startsWith("//")) {
        var end = code.indexOf("\n", i);
        if (end < 0) end = n;
        push("c", code.slice(i, end)); i = end; continue;
      }
      if (slashComments && rest.startsWith("/*")) {
        var close = code.indexOf("*/", i + 2);
        close = close < 0 ? n : close + 2;
        push("c", code.slice(i, close)); i = close; continue;
      }
      if (hashComments && ch === "#") {
        var e2 = code.indexOf("\n", i);
        if (e2 < 0) e2 = n;
        push("c", code.slice(i, e2)); i = e2; continue;
      }
      if ((lang === "python" && (rest.startsWith('"""') || rest.startsWith("'''"))) || ((lang === "csharp" || lang === "kotlin") && rest.startsWith('"""'))) {
        var q3 = rest.slice(0, 3);
        var c3 = code.indexOf(q3, i + 3);
        c3 = c3 < 0 ? n : c3 + 3;
        push("s", code.slice(i, c3)); i = c3; continue;
      }
      if (lang === "rust" && (m = /^r#*"/.exec(rest))) {
        var hashes = m[0].length - 2;
        var term = '"' + "#".repeat(hashes);
        var ce = code.indexOf(term, i + m[0].length);
        ce = ce < 0 ? n : ce + term.length;
        push("s", code.slice(i, ce)); i = ce; continue;
      }
      if (lang === "csharp" && (m = /^(?:\$@?|@\$)"/.exec(rest))) {
        // Interpolated string: quotes inside {…} holes belong to nested expressions.
        var k = i + m[0].length;
        var depth = 0;
        while (k < n && code[k] !== "\n") {
          var c = code[k];
          if (depth === 0) {
            if (c === "\\") { k += 2; continue; }
            if (c === '"') break;
            if (c === "{") { if (code[k + 1] === "{") { k += 2; continue; } depth++; }
          } else if (c === '"') {
            k++;
            while (k < n && code[k] !== '"' && code[k] !== "\n") k += code[k] === "\\" ? 2 : 1;
          } else if (c === "{") depth++;
          else if (c === "}") depth--;
          k++;
        }
        push("s", code.slice(i, k + 1)); i = k + 1; continue;
      }
      if (lang === "swift" && (m = /^#+"/.exec(rest))) {
        // Raw string: #"…"# (any number of #), quotes inside are text.
        var sterm = '"' + "#".repeat(m[0].length - 1);
        var se = code.indexOf(sterm, i + m[0].length);
        se = se < 0 ? n : se + sterm.length;
        push("s", code.slice(i, se)); i = se; continue;
      }
      if (lang === "swift" && ch === '"') {
        // Interpolation: quotes inside \(…) belong to nested expressions.
        var sk = i + 1;
        var sdepth = 0;
        while (sk < n && code[sk] !== "\n") {
          var sc = code[sk];
          if (sdepth === 0) {
            if (sc === "\\" && code[sk + 1] === "(") { sdepth = 1; sk += 2; continue; }
            if (sc === "\\") { sk += 2; continue; }
            if (sc === '"') break;
          } else if (sc === '"') {
            sk++;
            while (sk < n && code[sk] !== '"' && code[sk] !== "\n") sk += code[sk] === "\\" ? 2 : 1;
          } else if (sc === "(") sdepth++;
          else if (sc === ")") sdepth--;
          sk++;
        }
        push("s", code.slice(i, sk + 1)); i = sk + 1; continue;
      }
      if (lang === "php" && rest.startsWith("<?php")) {
        push("a", "<?php"); i += 5; continue;
      }
      if (lang === "php" && ch === "#") {
        if (code[i + 1] === "[") {
          // Attribute: #[\SensitiveParameter]
          var ae = code.indexOf("]", i);
          ae = ae < 0 ? n : ae + 1;
          push("a", code.slice(i, ae)); i = ae; continue;
        }
        var pe = code.indexOf("\n", i);
        if (pe < 0) pe = n;
        push("c", code.slice(i, pe)); i = pe; continue;
      }
      if (lang === "php" && (m = /^<<<[ \t]*(['"]?)([A-Za-z_]\w*)\1\n/.exec(rest))) {
        // Heredoc / nowdoc: up to the closing identifier at the start of a line.
        var hd = new RegExp("\\n[ \\t]*" + m[2] + "\\b").exec(code.slice(i + m[0].length - 1));
        var he = hd ? i + m[0].length - 1 + hd.index + hd[0].length : n;
        push("s", code.slice(i, he)); i = he; continue;
      }
      if (lang === "php" && ch === '"') {
        // Interpolation: quotes inside {$…} belong to nested expressions.
        var pk = i + 1;
        var pdepth = 0;
        while (pk < n && code[pk] !== "\n") {
          var pc = code[pk];
          if (pdepth === 0) {
            if (pc === "\\") { pk += 2; continue; }
            if (pc === '"') break;
            if (pc === "{" && code[pk + 1] === "$") pdepth = 1;
          } else if (pc === '"' || pc === "'") {
            var pq = pc;
            pk++;
            while (pk < n && code[pk] !== pq && code[pk] !== "\n") pk += code[pk] === "\\" ? 2 : 1;
          } else if (pc === "{") pdepth++;
          else if (pc === "}") pdepth--;
          pk++;
        }
        push("s", code.slice(i, pk + 1)); i = pk + 1; continue;
      }
      if (lang === "kotlin" && ch === '"') {
        // String template: quotes inside ${…} belong to nested expressions.
        var kk = i + 1;
        var kdepth = 0;
        while (kk < n && code[kk] !== "\n") {
          var kc = code[kk];
          if (kdepth === 0) {
            if (kc === "\\") { kk += 2; continue; }
            if (kc === '"') break;
            if (kc === "$" && code[kk + 1] === "{") { kdepth = 1; kk += 2; continue; }
          } else if (kc === '"') {
            kk++;
            while (kk < n && code[kk] !== '"' && code[kk] !== "\n") kk += code[kk] === "\\" ? 2 : 1;
          } else if (kc === "{") kdepth++;
          else if (kc === "}") kdepth--;
          kk++;
        }
        push("s", code.slice(i, kk + 1)); i = kk + 1; continue;
      }
      if (lang === "kotlin" && ch === "`") {
        // A backticked identifier: `object`
        var be = code.indexOf("`", i + 1);
        be = be < 0 ? n : be + 1;
        push(null, code.slice(i, be)); i = be; continue;
      }
      if (lang === "cpp" && (m = /^R"([^(]*)\(/.exec(rest))) {
        var t2 = ")" + m[1] + '"';
        var ce2 = code.indexOf(t2, i);
        ce2 = ce2 < 0 ? n : ce2 + t2.length;
        push("s", code.slice(i, ce2)); i = ce2; continue;
      }
      if (ch === '"' || ch === "`" || (ch === "'" && lang !== "rust")) {
        var j = i + 1;
        while (j < n && code[j] !== ch) {
          if (code[j] === "\\") j++;
          if (code[j] === "\n" && ch !== "`") break;
          j++;
        }
        push("s", code.slice(i, j + 1)); i = j + 1; continue;
      }
      if ((m = /^(?:0[xX][0-9a-fA-F_]+|\d[\d_]*(?:\.\d+)?(?:[eE][+-]?\d+)?)[a-zA-Z0-9]*/.exec(rest)) && !/[\w$]/.test(code[i - 1] || "")) {
        push("n", m[0]); i += m[0].length; continue;
      }
      if ((lang === "java" || lang === "kotlin") && ch === "@" && (m = /^@[A-Za-z_]\w*/.exec(rest))) {
        push("a", m[0]); i += m[0].length; continue;
      }
      if (lang === "rust" && (m = /^#!?\[[^\]]*\]/.exec(rest))) {
        push("a", m[0]); i += m[0].length; continue;
      }
      if (lang === "cpp" && ch === "#" && (m = /^#\s*\w+/.exec(rest))) {
        push("a", m[0]); i += m[0].length; continue;
      }
      if (lang === "python" && ch === "@" && (m = /^@[\w.]+/.exec(rest))) {
        push("a", m[0]); i += m[0].length; continue;
      }
      if (lang === "php" && (m = /^\$[A-Za-z_]\w*/.exec(rest))) {
        push(m[0] === "$this" ? "k" : "a", m[0]); i += m[0].length; continue;
      }
      if (lang === "php" && (lastSig === "(" || lastSig === ",") && (m = /^[A-Za-z_]\w*(?=:(?!:))/.exec(rest))) {
        // A named argument: slug: 'a.txt'
        push("a", m[0]); i += m[0].length; continue;
      }
      if (lang === "kotlin" && (lastSig === "(" || lastSig === ",") && (m = /^[A-Za-z_]\w*(?=\s*=(?!=))/.exec(rest))) {
        // A named argument: slug = "a.txt"
        push("a", m[0]); i += m[0].length; continue;
      }
      if ((m = /^[A-Za-z_$][\w$]*/.exec(rest))) {
        var word = m[0];
        var after = code.slice(i + word.length);
        if (kw[word]) push("k", word);
        else if (/^\s*[(!]/.test(after) && lang !== "json") push("f", word);
        else if (/^[A-Z]/.test(word) && lang !== "json" && lang !== "http") push("t", word);
        else push(null, word);
        i += word.length; continue;
      }
      if (lang === "http" && (m = /^[A-Z][A-Za-z-]+:(?= )/.exec(rest)) && (i === 0 || code[i - 1] === "\n")) {
        push("a", m[0]); i += m[0].length; continue;
      }
      push(null, ch); i++;
    }
    return out;
  }

  function langOf(pre) {
    var code = pre.querySelector("code");
    var cls = (code && code.className) || pre.className || "";
    var m = /language-([\w+#-]+)/.exec(cls);
    return pre.getAttribute("data-lang") || (m ? m[1] : "");
  }

  function decorateCodeBlock(pre) {
    if (pre.closest(".codeblock")) return;
    var lang = langOf(pre);
    var code = pre.querySelector("code") || pre;
    if (lang && !pre.hasAttribute("data-no-highlight")) code.innerHTML = highlight(code.textContent, lang.toLowerCase());
    var wrap = el("div", { class: "codeblock" });
    pre.parentNode.insertBefore(wrap, pre);
    var title = pre.getAttribute("data-title");
    if (title) wrap.appendChild(el("div", { class: "codeblock-title", text: title }));
    wrap.appendChild(pre);
    var btn = el("button", { class: "copy-btn", type: "button", text: "Copy", "aria-label": "Copy code" });
    btn.addEventListener("click", function () {
      var text = code.textContent;
      var done = function () {
        btn.textContent = "Copied";
        btn.classList.add("copied");
        setTimeout(function () { btn.textContent = "Copy"; btn.classList.remove("copied"); }, 1400);
      };
      if (navigator.clipboard && navigator.clipboard.writeText) navigator.clipboard.writeText(text).then(done, function () {});
    });
    wrap.appendChild(btn);
  }

  // ------------------------------------------------------------------ language tabs
  var LANG_LABELS = { java: "Java", ts: "TypeScript", js: "JavaScript", javascript: "JavaScript", typescript: "TypeScript", cpp: "C++", rust: "Rust", go: "Go", python: "Python", csharp: "C#", swift: "Swift", php: "PHP", kotlin: "Kotlin", bash: "Shell", http: "HTTP", json: "JSON" };
  var LANG_KEYS = { ts: "js", typescript: "js", javascript: "js", js: "js" };
  function tabKey(lang) { return LANG_KEYS[lang] || lang; }

  function setupTabs() {
    var preferred = load("lws-docs-lang");
    var groups = Array.prototype.slice.call(document.querySelectorAll(".code-tabs"));
    groups.forEach(function (group, gi) {
      var pres = Array.prototype.slice.call(group.querySelectorAll(":scope > pre"));
      if (!pres.length) return;
      var list = el("div", { class: "tab-list", role: "tablist" });
      group.insertBefore(list, group.firstChild);
      pres.forEach(function (pre, pi) {
        var lang = langOf(pre);
        var key = tabKey(pre.getAttribute("data-tab") || lang);
        var label = pre.getAttribute("data-label") || LANG_LABELS[lang] || lang;
        var id = "tabs-" + gi + "-" + pi;
        var panel = el("div", { class: "tab-panel", role: "tabpanel", id: id, "data-key": key });
        group.insertBefore(panel, pre);
        panel.appendChild(pre);
        decorateCodeBlock(pre);
        var button = el("button", { type: "button", role: "tab", "aria-controls": id, "data-key": key, text: label });
        button.addEventListener("click", function () { selectLanguage(key, true); });
        button.addEventListener("keydown", function (e) {
          var buttons = Array.prototype.slice.call(list.children);
          var idx = buttons.indexOf(button);
          if (e.key === "ArrowRight" || e.key === "ArrowLeft") {
            e.preventDefault();
            var next = buttons[(idx + (e.key === "ArrowRight" ? 1 : buttons.length - 1)) % buttons.length];
            next.focus();
            selectLanguage(next.getAttribute("data-key"), true);
          }
        });
        list.appendChild(button);
      });
      activate(group, preferred);
    });
  }

  function activate(group, key) {
    var buttons = group.querySelectorAll(".tab-list > button");
    var keys = Array.prototype.map.call(buttons, function (b) { return b.getAttribute("data-key"); });
    var chosen = keys.indexOf(key) >= 0 ? key : keys[0];
    Array.prototype.forEach.call(buttons, function (b) {
      var on = b.getAttribute("data-key") === chosen;
      b.setAttribute("aria-selected", on ? "true" : "false");
      b.tabIndex = on ? 0 : -1;
    });
    Array.prototype.forEach.call(group.querySelectorAll(":scope > .tab-panel"), function (p) {
      p.hidden = p.getAttribute("data-key") !== chosen;
    });
  }

  function selectLanguage(key, persist) {
    if (persist) save("lws-docs-lang", key);
    Array.prototype.forEach.call(document.querySelectorAll(".code-tabs"), function (g) {
      var has = g.querySelector('.tab-list > button[data-key="' + key + '"]');
      if (has) activate(g, key);
    });
  }

  // ------------------------------------------------------------------ headings
  function setupAnchors() {
    var heads = document.querySelectorAll(".content h2[id], .content h3[id], .content-wide h2[id], .content-wide h3[id]");
    Array.prototype.forEach.call(heads, function (h) {
      var a = el("a", { class: "heading-anchor", href: "#" + h.id, "aria-label": "Link to this section", text: "#" });
      h.appendChild(a);
    });
    var toc = document.getElementById("toc");
    if (toc) {
      var ol = el("ol");
      Array.prototype.forEach.call(document.querySelectorAll(".content h2[id]"), function (h) {
        var label = h.firstChild ? h.firstChild.textContent : h.textContent;
        ol.appendChild(el("li", null, [el("a", { href: "#" + h.id, text: label })]));
      });
      if (ol.children.length) {
        toc.appendChild(el("strong", { text: "On this page" }));
        toc.appendChild(ol);
      } else toc.remove();
    }
  }

  document.addEventListener("DOMContentLoaded", function () {
    buildSidebar();
    buildPageNav();
    setupThemeToggle();
    setupMenu();
    setupTabs();
    Array.prototype.forEach.call(document.querySelectorAll("pre"), decorateCodeBlock);
    setupAnchors();
  });
})();
