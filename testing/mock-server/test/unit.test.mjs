// SPDX-License-Identifier: MIT
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { describe, test } from "node:test";
import { decodeJwt, didKeyToPublicJwk, publicJwkToDidKey, publicKeyFromJwk, serializeSignatureParams, signatureBase, verifyJwtSignature } from "../lib/crypto.mjs";
import { applyPatch, escapeSegment, PatchError } from "../lib/jsonpatch.mjs";
import { parseRange } from "../lib/resources.mjs";
import { sanitizeSlug } from "../lib/store.mjs";
import { isAbsoluteIri, negotiate, parseEtagList, parseLinkHeader, preferences } from "../lib/util.mjs";

const fixture = (name) => JSON.parse(readFileSync(new URL(`../../../conformance/fixtures/${name}`, import.meta.url), "utf8"));

describe("JSON Patch (RFC 6902)", () => {
  const cases = [
    // RFC 6902 appendix A examples
    [{ foo: "bar" }, [{ op: "add", path: "/baz", value: "qux" }], { baz: "qux", foo: "bar" }],
    [{ foo: ["bar", "baz"] }, [{ op: "add", path: "/foo/1", value: "qux" }], { foo: ["bar", "qux", "baz"] }],
    [{ baz: "qux", foo: "bar" }, [{ op: "remove", path: "/baz" }], { foo: "bar" }],
    [{ foo: ["bar", "qux", "baz"] }, [{ op: "remove", path: "/foo/1" }], { foo: ["bar", "baz"] }],
    [{ baz: "qux", foo: "bar" }, [{ op: "replace", path: "/baz", value: "boo" }], { baz: "boo", foo: "bar" }],
    [{ foo: { bar: "baz", waldo: "fred" }, qux: { corge: "grault" } }, [{ op: "move", from: "/foo/waldo", path: "/qux/thud" }], { foo: { bar: "baz" }, qux: { corge: "grault", thud: "fred" } }],
    [{ foo: ["all", "grass", "cows", "eat"] }, [{ op: "move", from: "/foo/1", path: "/foo/3" }], { foo: ["all", "cows", "eat", "grass"] }],
    [{ baz: "qux", foo: ["a", 2, "c"] }, [{ op: "test", path: "/baz", value: "qux" }, { op: "test", path: "/foo/1", value: 2 }], { baz: "qux", foo: ["a", 2, "c"] }],
    [{ foo: "bar" }, [{ op: "add", path: "/child", value: { grandchild: {} } }], { foo: "bar", child: { grandchild: {} } }],
    [{ foo: ["bar"] }, [{ op: "add", path: "/foo/-", value: ["abc", "def"] }], { foo: ["bar", ["abc", "def"]] }],
    [{ "/": 9, "~1": 10 }, [{ op: "test", path: "/~01", value: 10 }], { "/": 9, "~1": 10 }],
    [{ a: 1 }, [{ op: "copy", from: "/a", path: "/b" }], { a: 1, b: 1 }],
    [{ a: 1 }, [{ op: "replace", path: "", value: [1] }], [1]],
    [{ a: { b: 1, c: [1, { d: 2 }] } }, [{ op: "test", path: "/a", value: { c: [1, { d: 2 }], b: 1 } }], { a: { b: 1, c: [1, { d: 2 }] } }],
  ];
  for (const [doc, patch, expected] of cases) {
    test(JSON.stringify(patch), () => assert.deepEqual(applyPatch(doc, patch), expected));
  }

  const failures = [
    [{ baz: "qux" }, [{ op: "test", path: "/baz", value: "bar" }], "conflict"],
    [{ foo: "bar" }, [{ op: "add", path: "/baz/bat", value: "qux" }], "conflict"],
    [{ foo: [1] }, [{ op: "add", path: "/foo/5", value: 1 }], "conflict"],
    [{ foo: [1] }, [{ op: "remove", path: "/foo/01" }], "conflict"],
    [{ foo: 1 }, [{ op: "replace", path: "/bar", value: 1 }], "conflict"],
    [{ a: { b: {} } }, [{ op: "move", from: "/a", path: "/a/b/c" }], "conflict"],
    [{}, [{ op: "add", path: "/a" }], "malformed"],
    [{}, [{ op: "nope", path: "/a" }], "malformed"],
    [{}, [{ op: "add", path: "a", value: 1 }], "malformed"],
    [{}, [{ op: "add", path: "/~2", value: 1 }], "malformed"],
    [{}, { op: "add" }, "malformed"],
  ];
  for (const [doc, patch, kind] of failures) {
    test(`fails (${kind}): ${JSON.stringify(patch)}`, () => {
      assert.throws(() => applyPatch(doc, patch), (e) => e instanceof PatchError && e.kind === kind);
    });
  }

  test("patches are atomic", () => {
    const doc = { a: 1 };
    assert.throws(() => applyPatch(doc, [{ op: "add", path: "/b", value: 2 }, { op: "test", path: "/a", value: 9 }]));
    assert.deepEqual(doc, { a: 1 });
  });

  test("pointer escaping matches the shared fixtures", () => {
    for (const { segment, escaped } of fixture("json-patch.json").pointerEscapes) assert.equal(escapeSegment(segment), escaped);
  });
});

describe("header parsing", () => {
  test("Link headers match the shared fixtures", () => {
    for (const c of fixture("link-headers.json").cases) {
      assert.deepEqual(parseLinkHeader(c.headers, c.base), c.expected, c.name);
    }
  });

  test("content negotiation", () => {
    const media = ["application/lws+json", "application/ld+json", "application/json"];
    assert.equal(negotiate(undefined, media), "application/lws+json");
    assert.equal(negotiate("application/json", media), "application/json");
    assert.equal(negotiate("text/turtle", media), null);
    assert.equal(negotiate("text/turtle, application/*;q=0.2", media), "application/lws+json");
    assert.equal(negotiate("application/lws+json;q=0", media), null);
    assert.equal(negotiate("application/lws+json;q=0, */*", media), "application/ld+json");
    assert.equal(negotiate('application/ld+json;profile="https://www.w3.org/ns/lws/v1"', media), 'application/ld+json; profile="https://www.w3.org/ns/lws/v1"');
  });

  test("ETag lists, Prefer, IRIs, slugs and ranges", () => {
    assert.equal(parseEtagList("*"), "*");
    assert.deepEqual(parseEtagList('"a", W/"b"'), [{ weak: false, tag: '"a"' }, { weak: true, tag: '"b"' }]);
    assert.ok(preferences('return=minimal; include="x", set-linkset').has("set-linkset"));
    assert.ok(isAbsoluteIri("https://schema.org/Person"));
    assert.ok(isAbsoluteIri("urn:uuid:1234"));
    assert.ok(isAbsoluteIri("https://example.org/a#frag"));
    assert.ok(!isAbsoluteIri("Person"));
    assert.ok(!isAbsoluteIri("relative/path"));
    assert.ok(!isAbsoluteIri("https://exa mple.org/"));
    assert.equal(sanitizeSlug("hello world.txt"), "hello-world.txt");
    assert.equal(sanitizeSlug(".hidden"), "hidden");
    assert.equal(sanitizeSlug("///"), null);
    assert.deepEqual(parseRange("bytes=0-0", 5), { start: 0, end: 0 });
    assert.deepEqual(parseRange("bytes=2-99", 5), { start: 2, end: 4 });
    assert.equal(parseRange("bytes=5-", 5), "unsatisfiable");
    assert.equal(parseRange("bytes=0-1,3-4", 5), null);
  });
});

describe("crypto against the shared fixtures", () => {
  test("did:key encoding and decoding", () => {
    for (const v of fixture("did-key.json").vectors) {
      assert.deepEqual(publicJwkToDidKey(v.publicJwk), { did: v.did, kid: v.kid }, v.name);
      const decoded = didKeyToPublicJwk(v.did);
      for (const k of ["kty", "crv", "x", "y"]) assert.equal(decoded[k], v.publicJwk[k], `${v.name} ${k}`);
    }
  });

  test("self-signed JWT vectors verify", () => {
    for (const v of fixture("jwt.json").vectors) {
      const jwt = decodeJwt(v.jwt);
      assert.ok(verifyJwtSignature(jwt, publicKeyFromJwk(v.publicJwk)), v.name);
      assert.ok(verifyJwtSignature(jwt, publicKeyFromJwk(didKeyToPublicJwk(v.claims.sub))), `${v.name} via did:key`);
    }
  });

  test("RFC 9421 signature base construction matches the webhook vectors", () => {
    for (const name of ["p256-valid", "ed25519-valid", "p256-two-digests-valid"]) {
      const v = fixture(`webhook/${name}.json`);
      const params = /^sig1=(.*)$/.exec(v.headers["signature-input"])[1];
      const components = [.../^\(([^)]*)\)/.exec(params)[1].matchAll(/"([^"]+)"/g)].map((m) => m[1]);
      const created = Number(/;created=(\d+)/.exec(params)[1]);
      const keyid = /;keyid="([^"]+)"/.exec(params)[1];
      const alg = /;alg="([^"]+)"/.exec(params)[1];
      assert.equal(serializeSignatureParams(components, { created, keyid, alg }), params);
      assert.equal(signatureBase(components, params, { method: v.method, url: v.url, headers: v.headers }), v.signatureBase, name);
    }
  });
});
