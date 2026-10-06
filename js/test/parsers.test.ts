// SPDX-License-Identifier: MIT
import { test, describe } from "node:test";
import assert from "node:assert/strict";
import {
  parseLinkHeader,
  formatLink,
  parseWwwAuthenticate,
  parseDictionary,
  serializeMember,
  StructuredFieldError,
  JsonPatch,
  JsonPointer,
  TypeQuery,
  parseProblemDetails,
  type BareItem,
  type SfMember,
} from "../src/index.js";
import { bytesToBase64 } from "../src/util/base64.js";
import { encodeSlug } from "../src/util/http.js";
import { fixture } from "./support/fixtures.js";

describe("Link header (RFC 8288) — conformance/fixtures/link-headers.json", () => {
  const { cases } = fixture("link-headers.json");
  for (const c of cases) {
    test(c.name, () => {
      const links = parseLinkHeader(c.headers, c.base);
      assert.deepEqual(
        links.map((l) => ({ href: l.href, rel: l.rel, params: { ...l.params } })),
        c.expected,
      );
    });
  }

  test("anchor getter resolves against the base", () => {
    const [link] = parseLinkHeader('<https://example.org/f>; rel="describedby"; anchor="#frag"', "https://example.org/doc");
    assert.equal(link!.anchor, "https://example.org/doc#frag");
    assert.equal(link!.type, undefined);
  });

  test("formatLink round-trips through the parser", () => {
    const header = formatLink({ href: "https://example.org/a", rel: "describedby", params: { title: 'say "hi"', type: "text/html" } });
    assert.equal(header, '<https://example.org/a>; rel="describedby"; title="say \\"hi\\""; type="text/html"');
    const [parsed] = parseLinkHeader(header);
    assert.equal(parsed!.params["title"], 'say "hi"');
  });
});

describe("WWW-Authenticate — conformance/fixtures/www-authenticate.json", () => {
  const { cases } = fixture("www-authenticate.json");
  for (const c of cases) {
    test(c.name, () => {
      const challenges = parseWwwAuthenticate(c.headers);
      assert.equal(challenges.length, c.expected.length);
      challenges.forEach((ch, i) => {
        const exp = c.expected[i];
        assert.equal(ch.scheme.toLowerCase(), exp.scheme.toLowerCase());
        assert.deepEqual({ ...ch.params }, exp.params);
        assert.equal(ch.token68, exp.token68);
      });
    });
  }

  test("LWS accessors", () => {
    const [c] = parseWwwAuthenticate('Bearer as_uri="https://as.example", realm="https://s.example/", error="invalid_token"');
    assert.equal(c!.asUri, "https://as.example");
    assert.equal(c!.realm, "https://s.example/");
    assert.equal(c!.error, "invalid_token");
    assert.ok(c!.is("bearer"));
  });
});

function bareToFixture(v: BareItem): unknown {
  switch (v.type) {
    case "bytes":
      return { bytes: bytesToBase64(v.value) };
    default:
      return { [v.type]: v.value };
  }
}

function paramsToFixture(p: Map<string, BareItem>): Record<string, unknown> {
  return Object.fromEntries([...p].map(([k, v]) => [k, bareToFixture(v)]));
}

function memberToFixture(m: SfMember): unknown {
  if (m.kind === "item") return { item: bareToFixture(m.value), params: paramsToFixture(m.params) };
  return {
    innerList: m.items.map((i) => ({ item: bareToFixture(i.value), params: paramsToFixture(i.params) })),
    params: paramsToFixture(m.params),
  };
}

describe("Structured fields — conformance/fixtures/structured-fields.json", () => {
  const { cases } = fixture("structured-fields.json");
  for (const c of cases) {
    test(c.name, () => {
      if (c.error) {
        assert.throws(() => parseDictionary(c.input), StructuredFieldError);
        return;
      }
      const dict = parseDictionary(c.input);
      const actual = Object.fromEntries([...dict].map(([k, m]) => [k, memberToFixture(m)]));
      assert.deepEqual(actual, c.expected);
      assert.deepEqual([...dict.keys()], Object.keys(c.expected));
      for (const [key, serialized] of Object.entries(c.serialized ?? {})) {
        assert.equal(serializeMember(dict.get(key)!), serialized);
      }
    });
  }
});

describe("JSON Patch / Pointer — conformance/fixtures/json-patch.json", () => {
  const fx = fixture("json-patch.json");
  for (const e of fx.pointerEscapes) {
    test(`escape ${JSON.stringify(e.segment)}`, () => {
      assert.equal(JsonPointer.escape(e.segment), e.escaped);
      assert.equal(JsonPointer.unescape(e.escaped), e.segment);
    });
  }
  for (const p of fx.pointers) {
    test(`pointer ${JSON.stringify(p.pointer)}`, () => {
      assert.equal(JsonPointer.from(p.segments), p.pointer);
      assert.deepEqual(JsonPointer.parse(p.pointer), p.segments);
    });
  }
  test("builder serialization", () => {
    const [add, remove, replace, move, copy, t] = fx.patch.operations;
    const patch = new JsonPatch()
      .add(add.path, add.value)
      .remove(remove.path)
      .replace(replace.path, replace.value)
      .move(move.from, move.path)
      .copy(copy.from, copy.path)
      .test(t.path, t.value);
    assert.deepEqual(JSON.parse(JSON.stringify(patch)), fx.patch.operations);
    assert.deepEqual(JSON.parse(patch.toString()), fx.patch.operations);
    assert.equal(patch.length, 6);
  });
});

describe("TypeQuery — conformance/fixtures/type-queries.json", () => {
  const { cases } = fixture("type-queries.json");
  for (const c of cases) {
    test(c.name, () => {
      const build = (): TypeQuery => {
        const q = new TypeQuery();
        for (const step of c.steps) {
          const mode = "allOf" in step ? "allOf" : "anyOf";
          const values: string[] = step[mode];
          if (step.key === "type") q[mode](...values);
          else q.relation(step.key)[mode](...values);
        }
        return q;
      };
      if (c.error) {
        assert.throws(build, TypeError);
        return;
      }
      assert.deepEqual(JSON.parse(JSON.stringify(build())), c.json);
    });
  }

  test("static shortcuts", () => {
    assert.deepEqual(TypeQuery.allOf("https://a.example/A").toJSON(), { type: ["https://a.example/A"] });
    assert.deepEqual(TypeQuery.anyOf("https://a.example/A", "https://a.example/B").toJSON(), {
      type: [["https://a.example/A", "https://a.example/B"]],
    });
    assert.ok(new TypeQuery().isEmpty);
  });
});

describe("Problem details", () => {
  test("conformance/fixtures/responses/problem-details.json", () => {
    const fx = fixture("responses/problem-details.json");
    const p = parseProblemDetails(fx.headers["content-type"], JSON.stringify(fx.body))!;
    assert.equal(p.type, fx.expected.type);
    assert.equal(p.title, fx.expected.title);
    assert.equal(p.detail, fx.expected.detail);
    assert.equal(p.instance, fx.expected.instance);
    assert.equal(p.status, 409);
    assert.deepEqual(p.extensions, fx.expected.extension);
  });

  test("non-JSON bodies are not problems", () => {
    assert.equal(parseProblemDetails("text/plain", "oops"), undefined);
    assert.equal(parseProblemDetails("application/json", "{\"foo\":1}"), undefined);
  });
});

describe("Slug encoding", () => {
  test("ASCII passes through, others are percent-encoded", () => {
    assert.equal(encodeSlug("hello.txt"), "hello.txt");
    assert.equal(encodeSlug("naïve 100%"), "na%C3%AFve 100%25");
  });
});
