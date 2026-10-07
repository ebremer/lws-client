// SPDX-License-Identifier: MIT
import { test, describe } from "node:test";
import assert from "node:assert/strict";
import { createServer, type IncomingMessage } from "node:http";
import type { AddressInfo } from "node:net";
import {
  LwsClient,
  TokenExchangeAuthenticator,
  BearerTokenAuthenticator,
  SelfSignedCredentials,
  OpenIdCredentials,
  generateKeyPair,
  verifyJwt,
  JsonPatch,
  TypeQuery,
  Linkset,
  isWithinRealm,
  metadataUrl,
  tokenExpiry,
  AuthenticationError,
  ConflictError,
  ForbiddenError,
  GoneError,
  InsufficientStorageError,
  MethodNotAllowedError,
  NotFoundError,
  PreconditionFailedError,
  ProtocolError,
  UnauthorizedError,
  UnsupportedMediaTypeError,
  UnprocessableContentError,
  BadRequestError,
  HttpError,
  LwsType,
  MediaType,
  StorageDescription,
  AccessRequest,
  Constraints,
} from "../src/index.js";
import { FakeServer, json } from "./support/fake-fetch.js";
import { fixture } from "./support/fixtures.js";

const S = "https://storage.example";
const linkHeaders = (...links: string[]): Headers => {
  const h = new Headers();
  for (const l of links) h.append("link", l);
  return h;
};

describe("discovery", () => {
  test("discoverStorage follows the storage link (HEAD) and parses the description", async () => {
    const sd = fixture("responses/storage-description.json");
    const server = new FakeServer()
      .on("HEAD", "/alice/notes/", () => new Response(null, { headers: linkHeaders(`<${S}/>; rel="https://www.w3.org/ns/lws#storage"`) }))
      .get("/", () => json(sd.body, { contentType: "application/lws+cid" }));
    const client = new LwsClient({ fetch: server.fetch });
    const desc = await client.discoverStorage(`${S}/alice/notes/`);
    assert.equal(desc.storageRoot(), "https://storage.example/root/");
    const get = server.requests.find((r) => r.method === "GET")!;
    assert.match(get.headers.get("accept")!, /^application\/lws\+cid/);
    assert.match(get.headers.get("user-agent")!, /^lws-client-js\//);
  });

  test("falls back to GET when HEAD is not allowed, and reads the storage link from a 401", async () => {
    const sd = fixture("responses/storage-description.json");
    const server = new FakeServer()
      .on("HEAD", "/a", () => new Response(null, { status: 405, headers: { allow: "GET" } }))
      .get("/a", () => new Response("x", { headers: linkHeaders(`</>; rel="https://www.w3.org/ns/lws#storage"`) }))
      .on("HEAD", "/b", () => new Response(null, { status: 401, headers: linkHeaders(`</>; rel="https://www.w3.org/ns/lws#storage"`) }))
      .get("/", () => json(sd.body, { contentType: "application/lws+cid" }));
    const client = new LwsClient({ fetch: server.fetch });
    assert.equal((await client.discoverStorage(`${S}/a`)).id, `${S}/`);
    assert.equal((await client.discoverStorage(`${S}/b`)).id, `${S}/`);
  });

  test("missing storage link is a ProtocolError", async () => {
    const server = new FakeServer().on("HEAD", "/x", () => new Response(null));
    await assert.rejects(new LwsClient({ fetch: server.fetch }).discoverStorage(`${S}/x`), ProtocolError);
  });
});

describe("resources", () => {
  test("read returns body, metadata and handles 304 / ranges", async () => {
    const server = new FakeServer().get("/notes/a.txt", (req) => {
      if (req.headers.get("if-none-match") === '"v1"') return new Response(null, { status: 304, headers: { etag: '"v1"' } });
      const headers = linkHeaders(
        `</notes/a.txt.meta>; rel="linkset"; type="application/linkset+json"`,
        `</notes/>; rel="up"`,
        `<https://www.w3.org/ns/lws#DataResource>; rel="type"`,
        `<${S}/>; rel="https://www.w3.org/ns/lws#storage"`,
      );
      headers.set("etag", '"v1"');
      headers.set("content-type", "text/plain; charset=utf-8");
      headers.set("last-modified", "Tue, 06 Oct 2026 12:00:00 GMT");
      if (req.headers.get("range") === "bytes=0-4") {
        headers.set("content-range", "bytes 0-4/11");
        return new Response("Hello", { status: 206, headers });
      }
      return new Response("Hello, LWS!", { headers });
    });
    const client = new LwsClient({ fetch: server.fetch });
    const r = await client.read(`${S}/notes/a.txt`);
    assert.equal(await r.text(), "Hello, LWS!");
    assert.equal(await r.text(), "Hello, LWS!", "buffered body can be read again");
    assert.equal(r.etag, '"v1"');
    assert.ok(r.isDataResource());
    assert.equal(r.parent, `${S}/notes/`);
    assert.equal(r.linkset, `${S}/notes/a.txt.meta`);
    assert.equal(r.storage, `${S}/`);
    assert.equal(r.mediaType, "text/plain");
    assert.equal(r.lastModified?.toISOString(), "2026-10-06T12:00:00.000Z");
    assert.equal(r.notModified, false);

    const nm = await client.read(`${S}/notes/a.txt`, { ifNoneMatch: '"v1"' });
    assert.equal(nm.notModified, true);

    const part = await client.read(`${S}/notes/a.txt`, { range: { start: 0, end: 4 } });
    assert.ok(part.partial);
    assert.equal(part.contentRange, "bytes 0-4/11");
    assert.equal(await part.text(), "Hello");
  });

  test("create sends Slug, Content-Type, user links and types; resolves Location", async () => {
    const server = new FakeServer().on("POST", "/notes/", () =>
      new Response(null, {
        status: 201,
        headers: (() => {
          const h = linkHeaders(`</notes/na%C3%AFve.txt.meta>; rel="linkset"`, `</notes/>; rel="up"`);
          h.set("location", "/notes/na%C3%AFve.txt");
          return h;
        })(),
      }),
    );
    const client = new LwsClient({ fetch: server.fetch });
    const res = await client.create(`${S}/notes/`, "hi", "text/plain", {
      slug: "naïve.txt",
      links: [{ href: "https://example.org/shape", rel: "describedby" }],
      types: ["https://schema.org/Note"],
    });
    assert.equal(res.location, `${S}/notes/na%C3%AFve.txt`);
    assert.equal(res.metadata.parent, `${S}/notes/`);
    const req = server.requests[0]!;
    assert.equal(req.headers.get("slug"), "na%C3%AFve.txt");
    assert.equal(req.headers.get("content-type"), "text/plain");
    assert.equal(req.headers.get("link"), '<https://example.org/shape>; rel="describedby", <https://schema.org/Note>; rel="type"');
    assert.equal(req.body, "hi");
  });

  test("createContainer posts the Container type link with an empty body", async () => {
    const server = new FakeServer().on("POST", "/", () => new Response(null, { status: 201, headers: { location: "/c/" } }));
    const client = new LwsClient({ fetch: server.fetch });
    const res = await client.createContainer(`${S}/`, { slug: "c" });
    assert.equal(res.location, `${S}/c/`);
    const req = server.requests[0]!;
    assert.equal(req.headers.get("link"), `<${LwsType.CONTAINER}>; rel="type"`);
    assert.equal(req.body, "");
    assert.equal(req.headers.get("content-type"), null);
  });

  test("create without Location is a ProtocolError", async () => {
    const server = new FakeServer().on("POST", "/", () => new Response(null, { status: 201 }));
    await assert.rejects(new LwsClient({ fetch: server.fetch }).createJson(`${S}/`, { a: 1 }), ProtocolError);
  });

  test("update / patch / delete send the right headers", async () => {
    const server = new FakeServer()
      .on("PUT", "/p.json", (req) =>
        req.headers.get("if-match") === '"old"' ? new Response(null, { status: 412 }) : new Response(null, { status: 204, headers: { etag: '"v2"' } }),
      )
      .on("PATCH", "/p.json", () => new Response(null, { status: 204, headers: { etag: '"v3"' } }))
      .on("DELETE", "/c/", (req) =>
        req.headers.get("depth") === "infinity" ? new Response(null, { status: 204 }) : json({ title: "not empty", status: 409 }, { status: 409, contentType: "application/problem+json" }),
      );
    const client = new LwsClient({ fetch: server.fetch });

    const up = await client.updateJson(`${S}/p.json`, { a: 1 }, { ifMatch: '"v1"', links: [{ href: "https://example.org/l", rel: "license" }], setLinkset: true });
    assert.equal(up.etag, '"v2"');
    assert.equal(up.status, 204);
    const put = server.requests.at(-1)!;
    assert.equal(put.headers.get("if-match"), '"v1"');
    assert.equal(put.headers.get("prefer"), "set-linkset");
    assert.equal(put.headers.get("link"), '<https://example.org/l>; rel="license"');
    assert.equal(put.headers.get("content-type"), "application/json");

    await assert.rejects(client.update(`${S}/p.json`, "x", "text/plain", { ifMatch: '"old"' }), PreconditionFailedError);

    const p = await client.patch(`${S}/p.json`, new JsonPatch().replace("/a", 2), { ifMatch: '"v2"' });
    assert.equal(p.etag, '"v3"');
    const patch = server.requests.at(-1)!;
    assert.equal(patch.headers.get("content-type"), MediaType.JSON_PATCH);
    assert.deepEqual(JSON.parse(patch.body), [{ op: "replace", path: "/a", value: 2 }]);

    await client.patch(`${S}/p.json`, { body: "DELETE DATA {}", contentType: "application/sparql-update" });
    assert.equal(server.requests.at(-1)!.headers.get("content-type"), "application/sparql-update");

    const err = await client.delete(`${S}/c/`).catch((e: unknown) => e);
    assert.ok(err instanceof ConflictError);
    assert.equal((err as ConflictError).problem?.title, "not empty");
    await client.delete(`${S}/c/`, { recursive: true });
  });

  test("error mapping by status", async () => {
    const statuses: [number, new (...a: any[]) => HttpError][] = [
      [400, BadRequestError],
      [403, ForbiddenError],
      [404, NotFoundError],
      [405, MethodNotAllowedError],
      [409, ConflictError],
      [410, GoneError],
      [412, PreconditionFailedError],
      [415, UnsupportedMediaTypeError],
      [422, UnprocessableContentError],
      [507, InsufficientStorageError],
      [500, HttpError],
    ];
    for (const [status, Ctor] of statuses) {
      const server = new FakeServer().get("/x", () =>
        new Response("nope", { status, headers: { allow: "GET, HEAD", "accept-patch": "application/json-patch+json" } }),
      );
      const err = await new LwsClient({ fetch: server.fetch }).read(`${S}/x`).catch((e: unknown) => e);
      assert.ok(err instanceof Ctor, `status ${status}`);
      assert.equal((err as HttpError).status, status);
      assert.equal((err as HttpError).body, "nope");
      if (err instanceof MethodNotAllowedError) assert.deepEqual(err.allow, ["GET", "HEAD"]);
      if (err instanceof UnsupportedMediaTypeError) assert.deepEqual(err.acceptPatch, [MediaType.JSON_PATCH]);
    }
    const server = new FakeServer().get("/x", () => new Response(null, { status: 401, headers: { "www-authenticate": 'Bearer realm="r"' } }));
    const err = await new LwsClient({ fetch: server.fetch }).read(`${S}/x`).catch((e: unknown) => e);
    assert.ok(err instanceof UnauthorizedError);
    assert.equal(err.challenges[0]!.realm, "r");
  });
});

describe("containers and pagination", () => {
  const page = (n: number, total: number): Response => {
    const items = Array.from({ length: 2 }, (_, i) => ({ type: "DataResource", id: `item-${n}-${i}.txt`, format: "text/plain" }));
    const headers = linkHeaders(`<https://www.w3.org/ns/lws#Container>; rel="type"`, `</c/?page=1>; rel="first"`);
    if (n < total) headers.append("link", `</c/?page=${n + 1}>; rel="next"`);
    if (n > 1) headers.append("link", `</c/?page=${n - 1}>; rel="prev"`);
    headers.set("content-type", "application/lws+json");
    return new Response(JSON.stringify({ "@context": "https://www.w3.org/ns/lws/v1", id: "/c/", type: "Container", totalItems: total * 2, items }), { headers });
  };

  test("listContainer follows next links across 3 pages", async () => {
    const server = new FakeServer().get(/^\/c\/(\?page=\d)?$/, (req) => page(Number(new URL(req.url).searchParams.get("page") ?? "1"), 3));
    const client = new LwsClient({ fetch: server.fetch });
    const first = await client.readContainer(`${S}/c/`);
    assert.equal(first.totalItems, 6);
    assert.equal(first.next, `${S}/c/?page=2`);
    const ids: string[] = [];
    for await (const item of client.listContainer(`${S}/c/`)) ids.push(item.id);
    assert.deepEqual(ids, [1, 2, 3].flatMap((n) => [0, 1].map((i) => `${S}/c/item-${n}-${i}.txt`)));
    assert.equal(server.requests.at(-1)!.headers.get("accept"), MediaType.LWS_JSON);
  });

  test("a non-container or a wrong media type is a ProtocolError", async () => {
    const server = new FakeServer()
      .get("/doc", () => json({ id: "/doc", type: "DataResource" }, { contentType: "application/lws+json" }))
      .get("/html", () => new Response("<html/>", { headers: { "content-type": "text/html" } }));
    const client = new LwsClient({ fetch: server.fetch });
    await assert.rejects(client.readContainer(`${S}/doc`), ProtocolError);
    await assert.rejects(client.readContainer(`${S}/html`), ProtocolError);
  });
});

describe("linksets", () => {
  test("readLinkset discovers the linkset and patchLinkset sends JSON Patch with If-Match", async () => {
    const fx = fixture("responses/linkset.json");
    const server = new FakeServer()
      .on("HEAD", "/alice/personalinfo.json", () => new Response(null, { headers: linkHeaders(`</alice/personalinfo.json.meta>; rel="linkset"`) }))
      .get("/alice/personalinfo.json.meta", () => json(fx.body, { contentType: fx.headers["content-type"], headers: fx.headers }))
      .on("PATCH", "/alice/personalinfo.json.meta", () => new Response(null, { status: 204, headers: { etag: '"ls-8"' } }))
      .on("PUT", "/alice/personalinfo.json.meta", () => new Response(null, { status: 405, headers: { allow: "GET, PATCH" } }));
    const client = new LwsClient({ fetch: server.fetch });
    const doc = await client.readLinkset(`${S}/alice/personalinfo.json`);
    assert.equal(doc.url, fx.expected.url);
    assert.equal(doc.etag, fx.expected.etag);
    assert.deepEqual(doc.allow, fx.expected.allow);
    assert.equal(doc.linkset.links().length, fx.expected.linkCount);
    const r = await client.patchLinkset(doc.url, new JsonPatch().add("/linkset/0/describedby/-", { href: "https://example.org/s" }), { ifMatch: doc.etag! });
    assert.equal(r.etag, '"ls-8"');
    const req = server.requests.at(-1)!;
    assert.equal(req.headers.get("if-match"), '"ls-7"');
    assert.equal(req.headers.get("content-type"), MediaType.JSON_PATCH);
    const err = await client.updateLinkset(doc.url, new Linkset()).catch((e: unknown) => e);
    assert.ok(err instanceof MethodNotAllowedError);
    assert.deepEqual(err.allow, ["GET", "PATCH"]);
  });
});

describe("authorization (token exchange)", () => {
  const AS = "https://as.example";
  function lwsServer(opts: { asUri?: string; realm?: string; tokenTypes?: string[]; issuer?: string } = {}) {
    const issued: string[] = [];
    const server = new FakeServer();
    server
      .get(/^\/(r|other)\//, (req) => {
        const auth = req.headers.get("authorization");
        if (auth && issued.includes(auth.slice(7))) return new Response("secret", { headers: { "content-type": "text/plain" } });
        return new Response(null, {
          status: 401,
          headers: {
            "www-authenticate": `Bearer as_uri="${opts.asUri ?? AS}", realm="${opts.realm ?? `${S}/r/`}", error="invalid_token"`,
          },
        });
      })
      .get("/.well-known/lws-configuration", () =>
        json({
          issuer: opts.issuer ?? AS,
          token_endpoint: `${AS}/token`,
          grant_types_supported: ["urn:ietf:params:oauth:grant-type:token-exchange"],
          subject_token_types_supported: opts.tokenTypes ?? ["urn:ietf:params:oauth:token-type:jwt"],
        }),
      )
      .on("POST", "/token", (_req, body) => {
        const form = new URLSearchParams(body);
        if (form.get("grant_type") !== "urn:ietf:params:oauth:grant-type:token-exchange") return json({ error: "unsupported_grant_type" }, { status: 400 });
        if (form.get("resource") !== (opts.realm ?? `${S}/r/`)) return json({ error: "invalid_target" }, { status: 400 });
        const token = `at-${issued.length + 1}`;
        issued.push(token);
        return json({ access_token: token, token_type: "Bearer", expires_in: 300 });
      });
    return { server, issued };
  }

  test("401 → metadata → token exchange → retry, then proactive reuse", async () => {
    const { server, issued } = lwsServer();
    const pair = await generateKeyPair();
    const creds = SelfSignedCredentials.didKey(pair);
    const client = new LwsClient({ fetch: server.fetch, authenticator: new TokenExchangeAuthenticator(creds) });
    const r = await client.read(`${S}/r/secret.txt`);
    assert.equal(await r.text(), "secret");
    assert.deepEqual(issued, ["at-1"]);
    const tokenReq = server.requests.find((q) => q.url === `${AS}/token`)!;
    const form = new URLSearchParams(tokenReq.body);
    assert.equal(form.get("subject_token_type"), "urn:ietf:params:oauth:token-type:jwt");
    assert.equal(form.get("resource"), `${S}/r/`);
    const { payload } = await verifyJwt(form.get("subject_token")!, pair.publicJwk);
    assert.deepEqual(payload["aud"], [AS]);
    assert.equal(server.requests.filter((q) => q.url.endsWith("/.well-known/lws-configuration")).length, 1);

    const before = server.requests.length;
    await client.read(`${S}/r/other.txt`);
    assert.equal(server.requests.length - before, 1, "token sent proactively, no 401 round trip");
    assert.equal(server.requests.at(-1)!.headers.get("authorization"), "Bearer at-1");
  });

  test("an invalidated token is replaced once", async () => {
    const { server, issued } = lwsServer();
    const auth = new TokenExchangeAuthenticator(SelfSignedCredentials.didKey(await generateKeyPair()));
    const client = new LwsClient({ fetch: server.fetch, authenticator: auth });
    await client.read(`${S}/r/a`);
    issued.length = 0; // server forgets the token
    issued.push("never");
    const r = await client.read(`${S}/r/a`);
    assert.equal(await r.text(), "secret");
    assert.ok(issued.includes("at-2"));
  });

  test("concurrent 401s share one token exchange", async () => {
    const { server } = lwsServer();
    const client = new LwsClient({ fetch: server.fetch, authenticator: new TokenExchangeAuthenticator(SelfSignedCredentials.didKey(await generateKeyPair())) });
    await Promise.all([1, 2, 3, 4].map((i) => client.read(`${S}/r/${i}`)));
    assert.equal(server.requests.filter((q) => q.url === `${AS}/token`).length, 1);
  });

  test("realm that does not contain the request URL is rejected", async () => {
    const { server } = lwsServer({ realm: `${S}/other/` });
    const client = new LwsClient({ fetch: server.fetch, authenticator: new TokenExchangeAuthenticator(new OpenIdCredentials("id")) });
    await assert.rejects(client.read(`${S}/r/x`), AuthenticationError);
    assert.equal(server.requests.filter((q) => q.url.startsWith(AS)).length, 0, "no credentials sent");
  });

  test("the authorization server's redirects are not followed", async () => {
    for (const redirected of ["/.well-known/lws-configuration", "/token"]) {
      let stolen = 0;
      const thief = createServer((_req, res) => {
        stolen++;
        res.end();
      });
      await new Promise<void>((resolve) => thief.listen(0, "127.0.0.1", resolve));
      const thiefBase = `http://127.0.0.1:${(thief.address() as AddressInfo).port}`;
      const server = createServer((req, res) => {
        const base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
        if (req.url === redirected) {
          res.writeHead(307, { location: thiefBase + redirected }).end();
        } else if (req.url === "/.well-known/lws-configuration") {
          res.writeHead(200, { "content-type": "application/json" }).end(JSON.stringify({ issuer: base, token_endpoint: `${base}/token` }));
        } else {
          res.writeHead(401, { "www-authenticate": `Bearer as_uri="${base}", realm="${base}/"` }).end();
        }
      });
      await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
      const base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
      try {
        const client = new LwsClient({ authenticator: new TokenExchangeAuthenticator(new OpenIdCredentials("id")) });
        await assert.rejects(client.read(`${base}/data/a`), AuthenticationError);
        assert.equal(stolen, 0, `${redirected}: the redirect target received a request`);
      } finally {
        server.close();
        thief.close();
      }
    }
  });

  test("insecure authorization servers, issuer mismatch, unsupported token types and filters are rejected", async () => {
    const creds = SelfSignedCredentials.didKey(await generateKeyPair());
    const cases: [ReturnType<typeof lwsServer>, ConstructorParameters<typeof TokenExchangeAuthenticator>[1]][] = [
      [lwsServer({ asUri: "http://as.example" }), {}],
      [lwsServer({ issuer: "https://evil.example" }), {}],
      [lwsServer({ tokenTypes: ["urn:ietf:params:oauth:token-type:id_token"] }), {}],
      [lwsServer(), { authorizationServerFilter: (asUri) => asUri === "https://trusted.example" }],
    ];
    for (const [{ server }, options] of cases) {
      const client = new LwsClient({ fetch: server.fetch, authenticator: new TokenExchangeAuthenticator(creds, options) });
      await assert.rejects(client.read(`${S}/r/x`), AuthenticationError);
    }
  });

  test("token endpoint errors surface as AuthenticationError with the OAuth error", async () => {
    const { server } = lwsServer();
    server.on("POST", "/token", () => json({ error: "invalid_request", error_description: "nope" }, { status: 400 }));
    const client = new LwsClient({ fetch: server.fetch, authenticator: new TokenExchangeAuthenticator(SelfSignedCredentials.didKey(await generateKeyPair())) });
    const err = await client.read(`${S}/r/x`).catch((e: unknown) => e);
    assert.ok(err instanceof AuthenticationError);
    assert.equal(err.error, "invalid_request");
    assert.equal(err.errorDescription, "nope");
  });

  test("BearerTokenAuthenticator respects its realm", async () => {
    const server = new FakeServer().get(/.*/, (req) => new Response(req.headers.get("authorization") ?? "none"));
    const client = new LwsClient({ fetch: server.fetch, authenticator: new BearerTokenAuthenticator("t0k", { realm: `${S}/r/` }) });
    assert.equal(await (await client.read(`${S}/r/x`)).text(), "Bearer t0k");
    assert.equal(await (await client.read(`${S}/elsewhere`)).text(), "none");
  });

  test("oauth fixtures: metadata URLs, realm containment, token expiry", () => {
    const fx = fixture("responses/oauth.json");
    for (const m of fx.metadataUrls) assert.equal(metadataUrl(m.issuer), m.url, m.issuer);
    for (const c of fx.realmChecks) assert.equal(isWithinRealm(c.url, c.realm), c.contained, `${c.url} in ${c.realm}`);
    assert.equal(tokenExpiry(fx.tokenResponse.body, 1000), 1000 + fx.tokenResponse.expectedExpiresIn * 1000);
    assert.equal(tokenExpiry(fx.tokenResponseNoExpiry.body, 0), fx.tokenResponseNoExpiry.expectedExp * 1000);
    assert.equal(tokenExpiry({ access_token: "opaque" }, 0), 300_000);
  });
});

describe("notifications, access and type services", () => {
  test("subscribe builds the fixture body and parses the response", async () => {
    const fx = fixture("responses/subscription.json");
    const server = new FakeServer()
      .on("POST", "/notifications/", () => json(fx.response.body, { status: fx.response.status, headers: fx.response.headers }))
      .get("/notifications/sub-1", () => json({ type: "WebhookSubscription", expires: "2026-06-09T12:00:00Z" }))
      .on("DELETE", "/notifications/sub-1", () => new Response(null, { status: 204 }));
    const client = new LwsClient({ fetch: server.fetch });
    const sd = new StorageDescription(fixture("webhook/storage-description.json"));
    const sub = await client.subscribe(`${S}/notifications/`, { ...fx.input, expires: new Date(fx.input.expires) });
    assert.deepEqual(JSON.parse(server.requests[0]!.body), fx.expectedRequestBody);
    assert.equal(server.requests[0]!.headers.get("content-type"), MediaType.LWS_JSON);
    assert.equal(sub.subscription, fx.expected.subscription);
    assert.equal(sub.type, fx.expected.type);
    assert.equal(sub.expires?.toISOString(), "2026-06-09T12:00:00.000Z");
    assert.ok(sd.notificationService()!.supportsWebhooks());
    const got = await client.getSubscription(`${S}/notifications/sub-1`);
    assert.equal(got.subscription, `${S}/notifications/sub-1`);
    await client.unsubscribe(got.subscription);
  });

  test("subscribe refuses a service without webhook support", async () => {
    const sd = new StorageDescription({
      id: `${S}/`,
      type: "Storage",
      service: [{ type: "NotificationService", serviceEndpoint: `${S}/n/`, subscriptionType: ["WebSocketSubscription"] }],
    });
    await assert.rejects(new LwsClient({ fetch: new FakeServer().fetch }).subscribe(sd.notificationService()!, { topics: [`${S}/`], inbox: "https://x.example/" }), ProtocolError);
  });

  test("access requests round trip", async () => {
    const fx = fixture("responses/access.json");
    const server = new FakeServer()
      .on("POST", "/access/requests/", () => new Response(null, { status: 201, headers: { location: "/access/requests/1" } }))
      .get("/access/requests/1", () => json(fx.request, { contentType: "application/lws+json" }));
    const client = new LwsClient({ fetch: server.fetch });
    const url = await client.requestAccess(`${S}/access/requests/`, {
      storage: "https://storage.example/",
      access: [{ actions: ["read"], assignee: "https://id.example/agent", constraints: [Constraints.purpose("https://purpose.example/x")] }],
    });
    assert.equal(url, `${S}/access/requests/1`);
    const sent = JSON.parse(server.requests[0]!.body);
    assert.deepEqual(sent.type, ["AccessRequest"]);
    assert.deepEqual(sent["@context"], ["https://www.w3.org/ns/lws/v1"]);
    const req = await client.getAccessRequest(url);
    assert.ok(req instanceof AccessRequest);
    assert.equal(req.inbox, "https://id.example/agent/inbox/");
  });

  test("type search uses QUERY and follows next pages with GET; type index pagination", async () => {
    const page = (ids: string[], next?: string): Response => {
      const h = new Headers({ "content-type": "application/lws+json" });
      if (next) h.append("link", `<${next}>; rel="next"`);
      return new Response(JSON.stringify({ type: "ContainerPage", totalItems: 3, items: ids.map((id) => ({ id, type: "DataResource" })) }), { headers: h });
    };
    const server = new FakeServer()
      .on("QUERY", "/types/search", () => page([`${S}/d/1`, `${S}/d/2`], `${S}/types/search?cursor=abc`))
      .get("/types/search?cursor=abc", () => page([`${S}/d/3`]))
      .on("OPTIONS", "/types/search", () => new Response(null, { status: 204, headers: { allow: "OPTIONS, QUERY", "accept-query": 'application/lws-query+json, "application/sparql-query"' } }))
      .get("/types/index", () => {
        const h = new Headers({ "content-type": "application/lws+json" });
        h.append("link", `</types/index?page=2>; rel="next"`);
        return new Response(JSON.stringify({ type: "TypeIndex", totalItems: 2, items: [{ id: "https://schema.org/Person" }] }), { headers: h });
      })
      .get("/types/index?page=2", () => json({ type: "TypeIndex", totalItems: 2, items: [{ id: "https://schema.org/Event" }] }, { contentType: "application/lws+json" }));
    const client = new LwsClient({ fetch: server.fetch });
    const ids: string[] = [];
    for await (const r of client.searchAll(`${S}/types/search`, TypeQuery.allOf("https://schema.org/Person"))) ids.push(r.id);
    assert.deepEqual(ids, [`${S}/d/1`, `${S}/d/2`, `${S}/d/3`]);
    const q = server.requests[0]!;
    assert.equal(q.method, "QUERY");
    assert.equal(q.headers.get("content-type"), MediaType.LWS_QUERY_JSON);
    assert.deepEqual(JSON.parse(q.body), { type: ["https://schema.org/Person"] });
    assert.deepEqual(await client.acceptedQueryFormats(`${S}/types/search`), ["application/lws-query+json", "application/sparql-query"]);
    const types: string[] = [];
    for await (const t of client.listTypes(`${S}/types/index`)) types.push(t);
    assert.deepEqual(types, ["https://schema.org/Person", "https://schema.org/Event"]);
  });
});

describe("over real HTTP (node:http)", () => {
  function readBody(req: IncomingMessage): Promise<string> {
    return new Promise((resolve) => {
      let data = "";
      req.setEncoding("utf8");
      req.on("data", (c: string) => (data += c));
      req.on("end", () => resolve(data));
    });
  }

  test("QUERY, streaming upload with auth preflight, abort", async () => {
    let token: string | undefined;
    const server = createServer(async (req, res) => {
      const base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
      const body = await readBody(req);
      if (req.url === "/.well-known/lws-configuration") {
        res.setHeader("content-type", "application/json");
        res.end(JSON.stringify({ issuer: base, token_endpoint: `${base}/token` }));
        return;
      }
      if (req.url === "/token") {
        token = "tok-" + Date.now();
        res.setHeader("content-type", "application/json");
        res.end(JSON.stringify({ access_token: token, token_type: "Bearer" }));
        return;
      }
      if (req.headers.authorization !== `Bearer ${token}`) {
        res.statusCode = 401;
        res.setHeader("www-authenticate", `Bearer as_uri="${base}", realm="${base}/"`);
        res.end();
        return;
      }
      if (req.url === "/slow") return; // never answers
      if (req.method === "QUERY") {
        res.setHeader("content-type", "application/lws+json");
        res.end(JSON.stringify({ type: "ContainerPage", totalItems: 1, items: [{ id: "/x", type: "DataResource", echo: JSON.parse(body) }] }));
        return;
      }
      if (req.method === "POST") {
        res.statusCode = 201;
        res.setHeader("location", `/uploaded?bytes=${body.length}`);
        res.end();
        return;
      }
      res.statusCode = 204;
      res.end();
    });
    await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
    const base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
    try {
      const client = new LwsClient({ authenticator: new TokenExchangeAuthenticator(new OpenIdCredentials("id-token")) });
      const page = await client.searchTypes(`${base}/types/search`, TypeQuery.anyOf("https://schema.org/Person", "http://xmlns.com/foaf/0.1/Person"));
      assert.equal(page.items[0]!.id, `${base}/x`);
      assert.deepEqual(page.items[0]!.raw["echo"], { type: [["https://schema.org/Person", "http://xmlns.com/foaf/0.1/Person"]] });

      token = undefined; // force re-authentication; the streaming body cannot be replayed
      (client.authenticator as TokenExchangeAuthenticator).clear();
      const stream = new ReadableStream<Uint8Array>({
        start(c) {
          c.enqueue(new TextEncoder().encode("streamed "));
          c.enqueue(new TextEncoder().encode("body"));
          c.close();
        },
      });
      const created = await client.create(`${base}/c/`, stream, "text/plain");
      assert.equal(created.location, `${base}/uploaded?bytes=13`);

      const ac = new AbortController();
      const pending = client.read(`${base}/slow`, { signal: ac.signal });
      setTimeout(() => ac.abort(), 50);
      await assert.rejects(pending, (e: unknown) => (e as Error).name === "AbortError");
    } finally {
      server.closeAllConnections();
      server.close();
    }
  });
});
