// SPDX-License-Identifier: MIT
import assert from "node:assert/strict";
import { after, before, describe, test } from "node:test";
import { authed, launch, LWS, linkTo, login } from "./helpers.mjs";

let server;
let base;
let http;

before(async () => {
  server = await launch();
  base = server.url;
  http = authed((await login(base)).token);
});
after(() => server.close());

async function newResource(slug, headers = {}) {
  const r = await http(`${base}/root/`, { method: "POST", headers: { "content-type": "application/json", slug, ...headers }, body: "{}" });
  assert.equal(r.status, 201);
  const location = r.headers.get("location");
  return { location, linkset: linkTo(r, base, "linkset")[0] };
}

const put = (url, doc, headers = {}) => http(url, { method: "PUT", headers: { "content-type": "application/linkset+json", ...headers }, body: JSON.stringify(doc) });
const patch = (url, ops, headers = {}) => http(url, { method: "PATCH", headers: { "content-type": "application/json-patch+json", ...headers }, body: JSON.stringify(ops) });

describe("linkset resources", () => {
  test("GET returns application/linkset+json with the resource as anchor", async () => {
    const { location, linkset } = await newResource("ls-get.json", { link: '<https://example.org/s>; rel="describedby"; type="application/schema+json"' });
    assert.equal(linkset, `${location}.meta`);
    const r = await http(linkset);
    assert.equal(r.status, 200);
    assert.equal(r.headers.get("content-type"), "application/linkset+json");
    assert.equal(r.headers.get("allow"), "GET, HEAD, PUT, PATCH");
    assert.equal(r.headers.get("accept-patch"), "application/json-patch+json");
    assert.ok(r.headers.get("etag"));
    assert.deepEqual(await r.json(), {
      linkset: [{ anchor: location, up: [{ href: `${base}/root/` }], describedby: [{ href: "https://example.org/s", type: "application/schema+json" }] }],
    });
    assert.equal((await http(linkset, { headers: { "if-none-match": r.headers.get("etag") } })).status, 304);
    assert.equal((await http(linkset, { method: "DELETE" })).status, 405);
  });

  test("PUT replaces the linkset (conditional)", async () => {
    const { location, linkset } = await newResource("ls-put.json");
    const etag = (await http(linkset)).headers.get("etag");
    const doc = {
      linkset: [
        {
          anchor: location,
          describedby: [{ href: "/schemas/personal-info.json" }],
          license: [{ href: "https://creativecommons.org/licenses/by/4.0/" }],
          "https://example.org/rel/reviewer": [{ href: "https://id.example/carol", hreflang: ["en", "de"], "title*": [{ value: "Carol", language: "en" }] }],
        },
      ],
    };
    const elsewhere = { linkset: [{ ...doc.linkset[0], up: [{ href: "https://evil.example/" }] }] };
    assert.equal((await put(linkset, elsewhere, { "if-match": etag })).status, 409, "an up link outside the storage is refused");
    const r = await put(linkset, doc, { "if-match": etag });
    assert.equal(r.status, 204);
    assert.notEqual(r.headers.get("etag"), etag);
    const got = (await (await http(linkset)).json()).linkset[0];
    assert.deepEqual(got.describedby, [{ href: "/schemas/personal-info.json" }]);
    assert.deepEqual(got["https://example.org/rel/reviewer"][0].hreflang, ["en", "de"]);
    assert.deepEqual(got.up, [{ href: `${base}/root/` }], "a replacement without an up link keeps it");
    assert.equal((await put(linkset, doc, { "if-match": etag })).status, 412);
    assert.equal((await put(linkset, { linkset: [{ anchor: "https://elsewhere.example/", license: [] }] })).status, 422);
    assert.equal((await put(linkset, { linkset: [{ anchor: location, license: [{ title: "no href" }] }] })).status, 422);
    assert.equal((await put(linkset, { notALinkset: true })).status, 422);
    assert.equal((await http(linkset, { method: "PUT", headers: { "content-type": "text/plain" }, body: "x" })).status, 415);
    assert.equal((await http(linkset, { method: "PUT", headers: { "content-type": "application/linkset+json" }, body: "{" })).status, 400);
  });

  test("PATCH applies JSON Patch to the linkset document", async () => {
    const { location, linkset } = await newResource("ls-patch.json");
    const etag = (await http(linkset)).headers.get("etag");
    let r = await patch(linkset, [{ op: "add", path: "/linkset/0/license", value: [{ href: "https://creativecommons.org/licenses/by/4.0/" }] }], { "if-match": etag });
    assert.equal(r.status, 204);
    r = await patch(linkset, [{ op: "add", path: "/linkset/0/license/-", value: { href: "https://example.org/license-2" } }]);
    assert.equal(r.status, 204);
    r = await patch(linkset, [{ op: "add", path: "/linkset/0/https:~1~1example.org~1rel~1reviewer", value: [{ href: "https://id.example/bob" }] }]);
    assert.equal(r.status, 204);
    const got = (await (await http(linkset)).json()).linkset[0];
    assert.equal(got.anchor, location);
    assert.deepEqual(got.license.map((l) => l.href), ["https://creativecommons.org/licenses/by/4.0/", "https://example.org/license-2"]);
    assert.deepEqual(got["https://example.org/rel/reviewer"], [{ href: "https://id.example/bob" }]);
    assert.equal((await patch(linkset, [{ op: "add", path: "/x" }], { "if-match": etag })).status, 412);
    assert.equal((await patch(linkset, [{ op: "test", path: "/linkset/0/license/0/href", value: "nope" }])).status, 409);
    assert.equal((await patch(linkset, [{ op: "add", path: "/linkset/0/license/-", value: { nohref: true } }])).status, 422);
    assert.equal((await patch(linkset, [{ op: "replace", path: "/linkset/0/anchor", value: "https://other.example/" }])).status, 422);
    const wrongType = await http(linkset, { method: "PATCH", headers: { "content-type": "application/merge-patch+json" }, body: "{}" });
    assert.equal(wrongType.status, 415);
    assert.equal(wrongType.headers.get("accept-patch"), "application/json-patch+json");
  });

  test("type links in the linkset become resource types", async () => {
    const { location, linkset } = await newResource("ls-type.json");
    await patch(linkset, [{ op: "add", path: "/linkset/0/type", value: [{ href: "https://schema.org/Person" }] }]);
    const r = await http(location, { method: "HEAD" });
    assert.deepEqual(linkTo(r, base, "type"), [`${LWS}DataResource`, "https://schema.org/Person"]);
  });

  test("containers have linksets and linksets are deleted with their resource", async () => {
    const c = await http(`${base}/root/`, { method: "POST", headers: { link: `<${LWS}Container>; rel="type"`, slug: "ls-container" } });
    const container = c.headers.get("location");
    const r = await http(`${container}.meta`);
    assert.equal(r.status, 200);
    assert.equal((await r.json()).linkset[0].anchor, container);
    const { location, linkset } = await newResource("ls-del.json");
    assert.equal((await http(location, { method: "DELETE" })).status, 204);
    assert.equal((await http(linkset)).status, 404);
  });
});

describe("moving resources", () => {
  const LS = "application/linkset+json";
  const move = (linkset, destination, headers = {}) => patch(linkset, [{ op: "replace", path: "/linkset/0/up/0/href", value: destination }], headers);
  async function newContainer(slug, parent = `${base}/root/`) {
    const r = await http(parent, { method: "POST", headers: { link: `<${LWS}Container>; rel="type"`, slug } });
    assert.equal(r.status, 201);
    return r.headers.get("location");
  }
  const items = async (container) => (await (await http(container, { headers: { accept: "application/lws+json" } })).json()).items.map((i) => i.id);

  test("a data resource moves to another container under a new identifier", async () => {
    const from = await newContainer("mv-from");
    const to = await newContainer("mv-to");
    const created = await http(from, { method: "POST", headers: { "content-type": "text/plain", slug: "note.txt", link: '<https://example.org/s>; rel="describedby"' }, body: "hello" });
    const location = created.headers.get("location");
    const linkset = `${location}.meta`;
    const etag = (await http(linkset)).headers.get("etag");
    const fromEtag = (await http(from)).headers.get("etag");

    const r = await move(linkset, to, { "if-match": etag });
    assert.equal(r.status, 200);
    assert.equal(r.headers.get("content-type"), LS);
    assert.equal(r.headers.get("content-location"), "/root/mv-to/note.txt.meta");
    assert.notEqual(r.headers.get("etag"), etag);
    const moved = `${to}note.txt`;
    assert.deepEqual(await r.json(), { linkset: [{ anchor: moved, up: [{ href: to }], describedby: [{ href: "https://example.org/s" }] }] });

    assert.equal(await (await http(moved)).text(), "hello");
    assert.deepEqual(await items(to), ["/root/mv-to/note.txt"]);
    assert.deepEqual(await items(from), []);
    assert.notEqual((await http(from)).headers.get("etag"), fromEtag);
    const old = await http(location, { redirect: "manual" });
    assert.equal(old.status, 301);
    assert.equal(old.headers.get("location"), moved);
    assert.equal((await http(linkset, { redirect: "manual" })).headers.get("location"), `${moved}.meta`);
    assert.equal((await move(`${moved}.meta`, to, { "if-match": etag })).status, 412);
  });

  test("a container moves with everything in it", async () => {
    const parent = await newContainer("mv-parent");
    const box = await newContainer("box", parent);
    const inner = await (await http(box, { method: "POST", headers: { "content-type": "text/plain", slug: "inner.txt" }, body: "x" })).headers.get("location");
    const to = await newContainer("mv-dest");
    const r = await move(`${box}.meta`, to);
    assert.equal(r.status, 200);
    assert.equal(r.headers.get("content-location"), "/root/mv-dest/box/.meta");
    assert.equal(await (await http(`${to}box/inner.txt`)).text(), "x");
    const old = await http(inner, { redirect: "manual" });
    assert.equal(old.status, 301);
    assert.equal(old.headers.get("location"), `${to}box/inner.txt`);
  });

  test("moves that would break containment are refused", async () => {
    const a = await newContainer("mv-a");
    const b = await newContainer("b", a);
    const file = (await http(a, { method: "POST", headers: { "content-type": "text/plain", slug: "f.txt" }, body: "f" })).headers.get("location");
    assert.equal((await move(`${a}.meta`, b)).status, 409, "into its own descendant");
    assert.equal((await move(`${a}.meta`, a)).status, 409, "into itself");
    assert.equal((await move(`${file}.meta`, `${base}/root/nowhere/`)).status, 409, "into a container that does not exist");
    assert.equal((await move(`${file}.meta`, `${a}f.txt`)).status, 409, "into a data resource");
    assert.equal((await move(`${file}.meta`, "https://other.example/c/")).status, 409, "out of the storage");
    assert.equal((await patch(`${file}.meta`, [{ op: "remove", path: "/linkset/0/up" }])).status, 409, "without an up link");
    assert.equal((await patch(`${base}/root/.meta`, [{ op: "add", path: "/linkset/0/up", value: [{ href: a }] }])).status, 409, "the storage root");
    const twin = await newContainer("mv-twin");
    await http(twin, { method: "POST", headers: { "content-type": "text/plain", slug: "f.txt" }, body: "g" });
    assert.equal((await move(`${file}.meta`, twin)).status, 409, "onto a name that is taken");
    assert.equal(await (await http(file)).text(), "f", "nothing moved");
  });
});
