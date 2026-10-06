// SPDX-License-Identifier: MIT
import assert from "node:assert/strict";
import { after, before, describe, test } from "node:test";
import { authed, launch, LWS, linkTo, links, login } from "./helpers.mjs";

let server;
let base;
let http;

before(async () => {
  server = await launch({ pageSize: 5 });
  base = server.url;
  http = authed((await login(base)).token);
});
after(() => server.close());

let counter = 0;
async function newContainer(slug = `c${++counter}`, parent = `${base}/root/`) {
  const r = await http(parent, { method: "POST", headers: { link: `<${LWS}Container>; rel="type"`, slug } });
  assert.equal(r.status, 201);
  return r.headers.get("location");
}

async function createText(container, slug, text = "Hello, LWS!", headers = {}) {
  const r = await http(container, { method: "POST", headers: { "content-type": "text/plain", ...(slug ? { slug } : {}), ...headers }, body: text });
  assert.equal(r.status, 201);
  return r;
}

describe("create", () => {
  test("container creation via Link rel=type returns 201 with Location and metadata links", async () => {
    const r = await http(`${base}/root/`, { method: "POST", headers: { link: `<${LWS}Container>; rel="type"`, slug: "notes" } });
    assert.equal(r.status, 201);
    assert.equal(r.headers.get("location"), `${base}/root/notes/`);
    assert.deepEqual(linkTo(r, base, "linkset"), [`${base}/root/notes/.meta`]);
    assert.equal(links(r, base).find((l) => l.rel === "linkset").params.type, "application/linkset+json");
    assert.deepEqual(linkTo(r, base, "up"), [`${base}/root/`]);
    assert.deepEqual(linkTo(r, base, "type"), [`${LWS}Container`]);
    assert.deepEqual(linkTo(r, base, `${LWS}storage`), [`${base}/`]);
  });

  test("data resource creation honours Slug, Content-Type and user Link metadata", async () => {
    const c = await newContainer();
    const r = await createText(c, "hello.txt", "Hello, LWS!", {
      link: '<https://schema.org/Note>; rel="type", <https://example.org/shape>; rel="describedby"; title="Shape", </x/>; rel="up"',
    });
    const location = r.headers.get("location");
    assert.equal(location, `${c}hello.txt`);
    assert.deepEqual(linkTo(r, base, "type"), [`${LWS}DataResource`, "https://schema.org/Note"]);
    assert.deepEqual(linkTo(r, base, "up"), [c]);
    assert.ok(r.headers.get("etag"));
    const linkset = await (await http(`${location}.meta`)).json();
    assert.deepEqual(linkset.linkset[0].describedby, [{ href: "https://example.org/shape", title: "Shape" }]);
    assert.equal(linkset.linkset[0].up, undefined, "client-supplied up links are ignored");
  });

  test("slugs are sanitised and made unique", async () => {
    const c = await newContainer();
    assert.equal((await createText(c, "hello.txt")).headers.get("location"), `${c}hello.txt`);
    assert.equal((await createText(c, "hello.txt")).headers.get("location"), `${c}hello-1.txt`);
    assert.equal((await createText(c, "hello.txt")).headers.get("location"), `${c}hello-2.txt`);
    assert.equal((await createText(c, "My File?.txt")).headers.get("location"), `${c}My-File-.txt`);
    assert.equal((await createText(c, "x.meta")).headers.get("location"), `${c}x-meta`);
    assert.equal((await createText(c, "../../etc")).headers.get("location"), `${c}etc`);
    assert.equal((await createText(c, "na%C3%AFve")).headers.get("location"), `${c}na-ve`);
    const generated = (await createText(c)).headers.get("location");
    assert.match(generated, /\/[0-9a-f-]{36}$/);
  });

  test("create errors", async () => {
    assert.equal((await http(`${base}/root/missing/`, { method: "POST", body: "x" })).status, 404);
    const c = await newContainer();
    const file = (await createText(c, "f.txt")).headers.get("location");
    const r = await http(file, { method: "POST", body: "x" });
    assert.equal(r.status, 405);
    assert.match(r.headers.get("allow"), /PUT/);
  });
});

describe("read", () => {
  test("GET and HEAD a data resource", async () => {
    const c = await newContainer();
    const location = (await createText(c, "read.txt", "Hello, LWS!")).headers.get("location");
    const r = await http(location);
    assert.equal(r.status, 200);
    assert.equal(await r.text(), "Hello, LWS!");
    assert.equal(r.headers.get("content-type"), "text/plain");
    assert.ok(r.headers.get("etag"));
    assert.ok(r.headers.get("last-modified"));
    assert.equal(r.headers.get("accept-ranges"), "bytes");
    assert.deepEqual(linkTo(r, location, "linkset"), [`${location}.meta`]);
    assert.deepEqual(linkTo(r, location, "up"), [c]);
    assert.deepEqual(linkTo(r, location, "type"), [`${LWS}DataResource`]);
    assert.deepEqual(linkTo(r, location, `${LWS}storage`), [`${base}/`]);
    const head = await http(location, { method: "HEAD" });
    assert.equal(head.status, 200);
    assert.equal(head.headers.get("content-length"), "11");
    assert.equal(head.headers.get("etag"), r.headers.get("etag"));
    assert.equal((await head.arrayBuffer()).byteLength, 0);
  });

  test("conditional GET returns 304", async () => {
    const c = await newContainer();
    const location = (await createText(c, "cond.txt")).headers.get("location");
    const r = await http(location);
    const etag = r.headers.get("etag");
    assert.equal((await http(location, { headers: { "if-none-match": etag } })).status, 304);
    assert.equal((await http(location, { headers: { "if-none-match": `W/${etag}` } })).status, 304);
    assert.equal((await http(location, { headers: { "if-none-match": '"other"' } })).status, 200);
    const later = new Date(Date.now() + 60000).toUTCString();
    assert.equal((await http(location, { headers: { "if-modified-since": later } })).status, 304);
    assert.equal((await http(location, { headers: { "if-modified-since": "Thu, 01 Jan 1970 00:00:00 GMT" } })).status, 200);
  });

  test("range requests", async () => {
    const c = await newContainer();
    const location = (await createText(c, "range.txt", "Hello, LWS!")).headers.get("location");
    let r = await http(location, { headers: { range: "bytes=0-4" } });
    assert.equal(r.status, 206);
    assert.equal(await r.text(), "Hello");
    assert.equal(r.headers.get("content-range"), "bytes 0-4/11");
    r = await http(location, { headers: { range: "bytes=-4" } });
    assert.equal(await r.text(), "LWS!");
    r = await http(location, { headers: { range: "bytes=7-" } });
    assert.equal(await r.text(), "LWS!");
    r = await http(location, { headers: { range: "bytes=100-" } });
    assert.equal(r.status, 416);
    assert.equal(r.headers.get("content-range"), "bytes */11");
    r = await http(location, { headers: { range: "bytes=5-2" } });
    assert.equal(r.status, 200);
    r = await http(location, { headers: { range: "bytes=0-1", "if-range": '"stale"' } });
    assert.equal(r.status, 200);
  });

  test("container listing: representation, media type equivalence and Vary", async () => {
    const c = await newContainer();
    await createText(c, "a.txt", "aaa");
    await http(c, { method: "POST", headers: { link: `<${LWS}Container>; rel="type", <https://schema.org/Collection>; rel="type"`, slug: "sub" } });
    const r = await http(c);
    assert.equal(r.status, 200);
    assert.equal(r.headers.get("content-type"), "application/lws+json");
    assert.equal(r.headers.get("vary"), "Accept");
    assert.deepEqual(linkTo(r, c, "type"), [`${LWS}Container`]);
    assert.deepEqual(linkTo(r, c, "up"), [`${base}/root/`]);
    assert.deepEqual(linkTo(r, c, "linkset"), [`${c}.meta`]);
    const body = await r.json();
    const path = new URL(c).pathname;
    assert.equal(body["@context"], "https://www.w3.org/ns/lws/v1");
    assert.equal(body.id, path);
    assert.equal(body.type, "Container");
    assert.equal(body.totalItems, 2);
    const [file, sub] = body.items;
    assert.deepEqual({ ...file, modified: undefined }, { type: "DataResource", id: `${path}a.txt`, format: "text/plain", size: 3, modified: undefined });
    assert.ok(!Number.isNaN(Date.parse(file.modified)));
    assert.deepEqual(sub.type, ["Container", "https://schema.org/Collection"]);
    assert.equal(sub.id, `${path}sub/`);
    assert.equal(sub.size, undefined);

    for (const [accept, expected] of [
      ["application/ld+json", "application/ld+json"],
      ["application/json", "application/json"],
      ['application/ld+json; profile="https://www.w3.org/ns/lws/v1"', 'application/ld+json; profile="https://www.w3.org/ns/lws/v1"'],
      ["text/html, */*;q=0.1", "application/lws+json"],
      ["application/json;q=0.5, application/lws+json", "application/lws+json"],
    ]) {
      const x = await http(c, { headers: { accept } });
      assert.equal(x.status, 200, accept);
      assert.equal(x.headers.get("content-type"), expected, accept);
      assert.equal((await x.json()).totalItems, 2);
    }
    assert.equal((await http(c, { headers: { accept: "text/turtle" } })).status, 406);
    const etag = r.headers.get("etag");
    assert.equal((await http(c, { headers: { "if-none-match": etag } })).status, 304);
  });

  test("container pagination with first/next/prev/last links", async () => {
    const c = await newContainer();
    for (let i = 0; i < 7; i++) await createText(c, `item-${i}.txt`, `${i}`);
    const first = await http(c);
    const body1 = await first.json();
    assert.equal(body1.totalItems, 7);
    assert.equal(body1.items.length, 5);
    assert.deepEqual(linkTo(first, c, "first"), [`${c}?page=1`]);
    assert.deepEqual(linkTo(first, c, "last"), [`${c}?page=2`]);
    assert.deepEqual(linkTo(first, c, "next"), [`${c}?page=2`]);
    assert.deepEqual(linkTo(first, c, "prev"), []);
    const second = await http(linkTo(first, c, "next")[0]);
    const body2 = await second.json();
    assert.equal(body2.items.length, 2);
    assert.equal(body2.totalItems, 7);
    assert.equal(body2.id, new URL(c).pathname);
    assert.deepEqual(linkTo(second, c, "prev"), [`${c}?page=1`]);
    assert.deepEqual(linkTo(second, c, "next"), []);
    const ids = [...body1.items, ...body2.items].map((i) => i.id);
    assert.equal(new Set(ids).size, 7);
    assert.equal((await http(`${c}?page=3`)).status, 404);
    assert.equal((await http(`${c}?page=0`)).status, 404);
    // Small containers are not paginated.
    const small = await newContainer();
    await createText(small, "only.txt");
    const s = await http(small);
    assert.deepEqual(linkTo(s, small, "first"), []);
  });

  test("unknown paths", async () => {
    assert.equal((await http(`${base}/root/nope.txt`)).status, 404);
    assert.equal((await http(`${base}/root`)).status, 404);
    assert.equal((await http(`${base}/elsewhere`)).status, 404);
    const r = await http(`${base}/root/nope.txt`);
    assert.equal(r.headers.get("content-type"), "application/problem+json");
  });
});

describe("update", () => {
  test("PUT replaces content with optimistic concurrency", async () => {
    const c = await newContainer();
    const location = (await createText(c, "put.txt", "v1")).headers.get("location");
    const etag = (await http(location)).headers.get("etag");
    const ok = await http(location, { method: "PUT", headers: { "content-type": "text/plain", "if-match": etag }, body: "v2" });
    assert.equal(ok.status, 204);
    assert.notEqual(ok.headers.get("etag"), etag);
    assert.equal(await (await http(location)).text(), "v2");
    const stale = await http(location, { method: "PUT", headers: { "content-type": "text/plain", "if-match": etag }, body: "v3" });
    assert.equal(stale.status, 412);
    assert.equal(await (await http(location)).text(), "v2");
    assert.equal((await http(location, { method: "PUT", headers: { "if-none-match": "*" }, body: "v4" })).status, 412);
    assert.equal((await http(location, { method: "PUT", headers: { "if-match": "*", "content-type": "application/json" }, body: "{}" })).status, 204);
    assert.equal((await http(location)).headers.get("content-type"), "application/json");
    assert.equal((await http(`${c}missing.txt`, { method: "PUT", body: "x" })).status, 404);
    const onContainer = await http(c, { method: "PUT", body: "x" });
    assert.equal(onContainer.status, 405);
    assert.ok(onContainer.headers.get("allow"));
  });

  test("PATCH applies JSON Patch to JSON resources", async () => {
    const c = await newContainer();
    const created = await http(c, { method: "POST", headers: { "content-type": "application/json", slug: "profile.json" }, body: JSON.stringify({ name: "Alice", age: 30 }) });
    const location = created.headers.get("location");
    const head = await http(location, { method: "HEAD" });
    assert.equal(head.headers.get("accept-patch"), "application/json-patch+json");
    const patch = (body, headers = {}) =>
      http(location, { method: "PATCH", headers: { "content-type": "application/json-patch+json", ...headers }, body: JSON.stringify(body) });
    const r = await patch([{ op: "replace", path: "/age", value: 31 }, { op: "add", path: "/city", value: "Boston" }], { "if-match": head.headers.get("etag") });
    assert.equal(r.status, 204);
    assert.deepEqual(await (await http(location)).json(), { name: "Alice", age: 31, city: "Boston" });
    assert.equal((await patch([{ op: "test", path: "/age", value: 99 }])).status, 409);
    assert.equal((await patch([{ op: "remove", path: "/missing" }])).status, 409);
    assert.equal((await patch([{ op: "bogus", path: "/x" }])).status, 400);
    assert.equal((await patch({ op: "add" })).status, 400);
    assert.equal((await patch([{ op: "add", path: "/x", value: 1 }], { "if-match": '"stale"' })).status, 412);
    const merge = await http(location, { method: "PATCH", headers: { "content-type": "application/merge-patch+json" }, body: "{}" });
    assert.equal(merge.status, 415);
    assert.equal(merge.headers.get("accept-patch"), "application/json-patch+json");
    assert.deepEqual(await (await http(location)).json(), { name: "Alice", age: 31, city: "Boston" });
    const text = (await createText(c, "plain.txt")).headers.get("location");
    const onText = await http(text, { method: "PATCH", headers: { "content-type": "application/json-patch+json" }, body: "[]" });
    assert.equal(onText.status, 415);
  });

  test("Prefer: set-linkset updates content and metadata atomically", async () => {
    const c = await newContainer();
    const location = (await createText(c, "meta.txt", "v1", { link: '<https://example.org/a>; rel="license"' })).headers.get("location");
    const put = await http(location, {
      method: "PUT",
      headers: { "content-type": "text/plain", prefer: "set-linkset", link: '<https://example.org/shape>; rel="describedby"' },
      body: "v2",
    });
    assert.equal(put.status, 204);
    assert.equal(put.headers.get("preference-applied"), "set-linkset");
    let ls = (await (await http(`${location}.meta`)).json()).linkset[0];
    assert.deepEqual(ls.describedby, [{ href: "https://example.org/shape" }]);
    assert.equal(ls.license, undefined, "PUT replaces the linkset");
    const plain = await http(location, { method: "PUT", headers: { "content-type": "text/plain", link: '<https://example.org/ignored>; rel="related"' }, body: "v3" });
    assert.equal(plain.headers.get("preference-applied"), null);
    ls = (await (await http(`${location}.meta`)).json()).linkset[0];
    assert.equal(ls.related, undefined, "Link headers are ignored without the preference");
  });
});

describe("delete", () => {
  test("data resources are removed from their container", async () => {
    const c = await newContainer();
    const location = (await createText(c, "del.txt")).headers.get("location");
    const etag = (await http(location)).headers.get("etag");
    assert.equal((await http(location, { method: "DELETE", headers: { "if-match": '"stale"' } })).status, 412);
    assert.equal((await http(location, { method: "DELETE", headers: { "if-match": etag } })).status, 204);
    assert.equal((await http(location)).status, 404);
    assert.equal((await http(`${location}.meta`)).status, 404);
    assert.equal((await (await http(c)).json()).totalItems, 0);
  });

  test("non-empty containers require Depth: infinity", async () => {
    const c = await newContainer();
    const sub = await newContainer("inner", c);
    await createText(sub, "deep.txt");
    const conflict = await http(c, { method: "DELETE" });
    assert.equal(conflict.status, 409);
    assert.equal((await conflict.json()).status, 409);
    assert.equal((await http(c, { method: "DELETE", headers: { depth: "1" } })).status, 400);
    assert.equal((await http(c, { method: "DELETE", headers: { depth: "infinity" } })).status, 204);
    assert.equal((await http(c)).status, 404);
    assert.equal((await http(`${sub}deep.txt`)).status, 404);
  });

  test("the storage root cannot be deleted", async () => {
    const r = await http(`${base}/root/`, { method: "DELETE" });
    assert.equal(r.status, 405);
    assert.doesNotMatch(r.headers.get("allow"), /DELETE/);
  });
});

describe("misc", () => {
  test("OPTIONS reports allowed methods without authentication", async () => {
    const r = await fetch(`${base}/root/`, { method: "OPTIONS" });
    assert.equal(r.status, 204);
    assert.match(r.headers.get("allow"), /POST/);
  });

  test("CORS preflight and exposed headers", async () => {
    const pre = await fetch(`${base}/root/`, { method: "OPTIONS", headers: { origin: "https://app.example", "access-control-request-method": "QUERY", "access-control-request-headers": "authorization, slug" } });
    assert.equal(pre.status, 204);
    assert.equal(pre.headers.get("access-control-allow-origin"), "https://app.example");
    assert.match(pre.headers.get("access-control-allow-methods"), /QUERY/);
    const r = await http(`${base}/root/`, { headers: { origin: "https://app.example" } });
    assert.match(r.headers.get("access-control-expose-headers"), /Link/);
  });

  test("concurrent creates in one container all succeed with unique names", async () => {
    const c = await newContainer();
    const results = await Promise.all(Array.from({ length: 20 }, () => createText(c, "same.txt")));
    const locations = new Set(results.map((r) => r.headers.get("location")));
    assert.equal(locations.size, 20);
  });
});
