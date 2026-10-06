// SPDX-License-Identifier: MIT
import assert from "node:assert/strict";
import { after, before, describe, test } from "node:test";
import { authed, launch, LWS, linkTo, login } from "./helpers.mjs";

let server;
let base;
let http;
let other;
const ids = {};

before(async () => {
  server = await launch({ pageSize: 2 });
  base = server.url;
  http = authed((await login(base)).token);
  other = authed((await login(base)).token);
  const create = async (slug, typeLinks, extra = "") => {
    const link = [...typeLinks.map((t) => `<${t}>; rel="type"`), extra].filter(Boolean).join(", ");
    const r = await http(`${base}/root/`, { method: "POST", headers: { "content-type": "application/json", slug, ...(link ? { link } : {}) }, body: "{}" });
    return r.headers.get("location");
  };
  ids.alice = await create("alice.json", ["https://schema.org/Person"], '<https://example.org/shapes/person>; rel="describedby"');
  ids.bob = await create("bob.json", ["http://xmlns.com/foaf/0.1/Person"]);
  ids.carol = await create("carol.json", ["https://schema.org/Person", "http://xmlns.com/foaf/0.1/Person"], '<https://example.org/shapes/agent>; rel="describedby"');
  ids.event = await create("event.json", ["https://schema.org/Event"]);
  ids.folder = (await http(`${base}/root/`, { method: "POST", headers: { link: `<${LWS}Container>; rel="type", <https://schema.org/Collection>; rel="type"`, slug: "people" } })).headers.get("location");
});
after(() => server.close());

const query = (filter, headers = {}) =>
  http(`${base}/types/search`, { method: "QUERY", headers: { "content-type": "application/lws-query+json", ...headers }, body: typeof filter === "string" ? filter : JSON.stringify(filter) });

async function searchAll(filter) {
  let r = await query(filter);
  assert.equal(r.status, 200);
  const first = await r.json();
  const items = [...first.items];
  let next = linkTo(r, base, "next")[0];
  while (next) {
    r = await http(next);
    assert.equal(r.status, 200);
    items.push(...(await r.json()).items);
    next = linkTo(r, base, "next")[0];
  }
  return { total: first.totalItems, ids: items.map((i) => i.id).sort(), items };
}

describe("type index", () => {
  test("lists distinct types across pages", async () => {
    const r = await http(`${base}/types/index`);
    assert.equal(r.status, 200);
    assert.equal(r.headers.get("content-type"), "application/lws+json");
    assert.equal(r.headers.get("cache-control"), "private");
    const body = await r.json();
    assert.equal(body.type, "TypeIndex");
    assert.equal(body["@context"], "https://www.w3.org/ns/lws/v1");
    assert.equal(body.items.length, 2);
    const types = [...body.items.map((i) => i.id)];
    let next = linkTo(r, base, "next")[0];
    assert.deepEqual(linkTo(r, base, "first"), [`${base}/types/index?page=1`]);
    while (next) {
      const page = await http(next);
      types.push(...(await page.json()).items.map((i) => i.id));
      next = linkTo(page, base, "next")[0];
    }
    assert.equal(types.length, body.totalItems);
    for (const t of [`${LWS}Container`, `${LWS}DataResource`, "https://schema.org/Person", "http://xmlns.com/foaf/0.1/Person", "https://schema.org/Event", "https://schema.org/Collection"]) {
      assert.ok(types.includes(t), t);
    }
    assert.equal((await http(`${base}/types/index?page=99`)).status, 404);
    assert.equal((await http(`${base}/types/index`, { method: "POST" })).status, 405);
  });
});

describe("type search", () => {
  test("OPTIONS advertises QUERY and Accept-Query", async () => {
    const r = await fetch(`${base}/types/search`, { method: "OPTIONS" });
    assert.equal(r.status, 204);
    assert.equal(r.headers.get("allow"), "OPTIONS, QUERY");
    assert.equal(r.headers.get("accept-query"), "application/lws-query+json");
  });

  test("conjunctive normal form over types", async () => {
    let res = await searchAll({ type: ["https://schema.org/Person"] });
    assert.deepEqual(res.ids, [ids.alice, ids.carol].sort());
    assert.equal(res.total, 2);
    res = await searchAll({ type: [["https://schema.org/Person", "http://xmlns.com/foaf/0.1/Person"]] });
    assert.deepEqual(res.ids, [ids.alice, ids.bob, ids.carol].sort());
    res = await searchAll({ type: ["https://schema.org/Person", "http://xmlns.com/foaf/0.1/Person"] });
    assert.deepEqual(res.ids, [ids.carol]);
    res = await searchAll({ type: [["https://schema.org/Person", "http://xmlns.com/foaf/0.1/Person"], `${LWS}DataResource`] });
    assert.equal(res.total, 3);
    res = await searchAll({ type: [`${LWS}Container`] });
    assert.deepEqual(res.ids, [`${base}/root/`, ids.folder].sort());
    const folder = res.items.find((i) => i.id === ids.folder);
    assert.deepEqual(folder.type, ["Container", "https://schema.org/Collection"]);
    res = await searchAll({ type: ["https://schema.org/Nothing"] });
    assert.equal(res.total, 0);
    res = await searchAll({ "@context": "https://www.w3.org/ns/lws/v1", type: [] });
    assert.equal(res.total, 6, "empty filter matches every resource");
    const item = (await searchAll({ type: ["https://schema.org/Event"] })).items[0];
    assert.equal(item.format, "application/json");
    assert.equal(item.size, 2);
  });

  test("indexed descriptive relations and unindexed structural relations", async () => {
    let res = await searchAll({ type: ["https://schema.org/Person"], describedby: [["https://example.org/shapes/person", "https://example.org/shapes/agent"]] });
    assert.deepEqual(res.ids, [ids.alice, ids.carol].sort());
    res = await searchAll({ describedby: ["https://example.org/shapes/agent"] });
    assert.deepEqual(res.ids, [ids.carol]);
    res = await searchAll({ up: [`${base}/root/`] });
    assert.equal(res.total, 0, "structural relations are not indexed");
    res = await searchAll({ "https://example.org/unknown-rel": ["https://example.org/x"] });
    assert.equal(res.total, 0);
  });

  test("response format, caching and pagination", async () => {
    const r = await query({ type: [`${LWS}DataResource`] });
    assert.equal(r.status, 200);
    assert.equal(r.headers.get("content-type"), "application/lws+json");
    assert.equal(r.headers.get("cache-control"), "private");
    const body = await r.json();
    assert.equal(body.type, "ContainerPage");
    assert.equal(body.totalItems, 4);
    assert.equal(body.items.length, 2);
    const next = linkTo(r, base, "next")[0];
    assert.match(next, /\/types\/search\?cursor=/);
    assert.equal((await other(next)).status, 404, "cursors are bound to the requesting client");
    assert.equal((await http(`${base}/types/search?cursor=bogus`)).status, 404);
    assert.equal((await http(`${base}/types/search`)).status, 405);
    const json = await query({ type: [`${LWS}DataResource`] }, { accept: "application/json" });
    assert.equal(json.headers.get("content-type"), "application/json");
  });

  test("error handling", async () => {
    // A byte body keeps fetch from adding a default Content-Type.
    const missingType = await http(`${base}/types/search`, { method: "QUERY", body: new TextEncoder().encode("{}") });
    assert.equal(missingType.status, 400);
    const sparql = await http(`${base}/types/search`, { method: "QUERY", headers: { "content-type": "application/sparql-query" }, body: "SELECT * {}" });
    assert.equal(sparql.status, 415);
    assert.equal(sparql.headers.get("accept-query"), "application/lws-query+json");
    assert.equal((await query({ type: [] }, { accept: "text/turtle" })).status, 406);
    for (const bad of [
      "{",
      "[]",
      { type: "https://schema.org/Person" },
      { type: [[]] },
      { type: [["https://schema.org/Person", 5]] },
      { type: [42] },
      { type: ["Person"] },
      { describedby: ["relative/path"] },
    ]) {
      assert.equal((await query(bad)).status, 400, JSON.stringify(bad));
    }
    const huge = { type: Array.from({ length: 40 }, (_, i) => `https://example.org/t${i}`) };
    assert.equal((await query(huge)).status, 422);
    assert.equal((await http(`${base}/types/search`, { method: "PUT", body: "x" })).status, 405);
  });
});
