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
      linkset: [{ anchor: location, describedby: [{ href: "https://example.org/s", type: "application/schema+json" }] }],
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
          up: [{ href: "https://evil.example/" }],
        },
      ],
    };
    const r = await put(linkset, doc, { "if-match": etag });
    assert.equal(r.status, 204);
    assert.notEqual(r.headers.get("etag"), etag);
    const got = (await (await http(linkset)).json()).linkset[0];
    assert.deepEqual(got.describedby, [{ href: "/schemas/personal-info.json" }]);
    assert.deepEqual(got["https://example.org/rel/reviewer"][0].hreflang, ["en", "de"]);
    assert.equal(got.up, undefined, "server-managed relations cannot be set");
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
