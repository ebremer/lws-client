#!/usr/bin/env node
// SPDX-License-Identifier: MIT
// Checks a driver adapter (driver/PROTOCOL.md) against the mock LWS server: starts the mock server on
// a free port, starts the adapter, runs every operation through the protocol and checks its result.
//
//   node driver/adapters/check.mjs [--verbose] -- <adapter command line>
//
// Exit status 0 when every check passes (operations the adapter does not implement are skipped),
// 1 when one fails, 2 on a usage error.

import { spawn } from "node:child_process";
import { generateKeyPairSync } from "node:crypto";
import { createServer } from "node:http";
import { createInterface } from "node:readline";
import { fileURLToPath } from "node:url";
import { startServer } from "../../testing/mock-server/lib/server.mjs";

const argv = process.argv.slice(2);
const dashdash = argv.indexOf("--");
if (dashdash < 0 || dashdash === argv.length - 1) {
  console.error(`Usage: node ${fileURLToPath(import.meta.url)} [--verbose] -- <adapter command line>`);
  process.exit(2);
}
const verbose = argv.slice(0, dashdash).includes("--verbose");
const [command, ...commandArgs] = argv.slice(dashdash + 1);

const LWS = "https://www.w3.org/ns/lws#";
const PERSON = "https://schema.org/Person";
const OPERATIONS = [
  "configure", "discover_storage", "get_storage_description", "head", "read", "read_container",
  "list_container", "create", "create_container", "update", "patch", "delete", "linkset_url",
  "read_linkset", "update_linkset", "patch_linkset", "subscribe", "list_subscriptions",
  "get_subscription", "unsubscribe", "verify_notification", "request_access", "get_access_request",
  "list_access_requests", "cancel_access_request", "grant_access", "get_access_grant",
  "list_access_grants", "revoke_access_grant", "read_type_index", "list_types", "search_types",
  "search_all", "accepted_query_formats", "shutdown",
];

// ---------------------------------------------------------------------------------------------
// Reporting

let failures = 0;
let passes = 0;
let skips = 0;

class CheckFailure extends Error {}
class Skip extends Error {}

function expect(condition, message) {
  if (!condition) throw new CheckFailure(message);
}

const hasType = (types, term) =>
  Array.isArray(types) && types.some((t) => t === term || t === `lws:${term}` || t === `${LWS}${term}`);

async function check(name, fn) {
  try {
    await fn();
    passes++;
    console.log(`ok    ${name}`);
  } catch (e) {
    if (e instanceof Skip) {
      skips++;
      console.log(`skip  ${name} (${e.message})`);
    } else {
      failures++;
      console.log(`FAIL  ${name}: ${e instanceof CheckFailure ? e.message : e.stack}`);
    }
  }
}

// ---------------------------------------------------------------------------------------------
// The adapter

class Adapter {
  constructor(cmd, args) {
    this.child = spawn(cmd, args, { stdio: ["pipe", "pipe", "pipe"] });
    this.nextId = 1;
    this.pending = new Map();
    this.lines = createInterface({ input: this.child.stdout });
    this.stderr = [];
    this.child.stderr.on("data", (chunk) => {
      this.stderr.push(chunk.toString());
      if (verbose) process.stderr.write(chunk);
    });
    this.exited = new Promise((resolve) => this.child.on("exit", (code, signal) => resolve({ code, signal })));
    this.child.on("error", (e) => {
      for (const { reject } of this.pending.values()) reject(e);
    });
    this.hello = new Promise((resolve, reject) => {
      this.helloResolve = resolve;
      this.helloReject = reject;
    });
    this.lines.on("line", (line) => this.onLine(line));
    this.exited.then(({ code, signal }) => {
      const e = new Error(`adapter exited (code ${code}, signal ${signal}); stderr:\n${this.stderr.join("").slice(-4000)}`);
      this.helloReject(e);
      for (const { reject } of this.pending.values()) reject(e);
      this.pending.clear();
    });
  }

  onLine(line) {
    if (verbose) console.log(`  <- ${line.length > 400 ? `${line.slice(0, 400)}…` : line}`);
    let message;
    try {
      message = JSON.parse(line);
    } catch {
      failures++;
      console.log(`FAIL  stdout carries protocol messages only: ${JSON.stringify(line.slice(0, 200))}`);
      return;
    }
    if (message.hello) {
      this.helloResolve(message.hello);
      return;
    }
    if (message.id === null && this.nullWaiter) {
      const resolve = this.nullWaiter;
      this.nullWaiter = undefined;
      resolve(message);
      return;
    }
    const waiter = this.pending.get(message.id);
    if (!waiter) {
      failures++;
      console.log(`FAIL  response to an unknown request id: ${line.slice(0, 200)}`);
      return;
    }
    this.pending.delete(message.id);
    waiter.resolve(message);
  }

  /** Sends a request and resolves with the whole response message. */
  send(op, args = {}, timeoutMs = 30000) {
    const id = this.nextId++;
    const line = JSON.stringify({ id, op, args });
    if (verbose) console.log(`  -> ${line.length > 400 ? `${line.slice(0, 400)}…` : line}`);
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        this.pending.delete(id);
        reject(new CheckFailure(`no response to ${op} within ${timeoutMs} ms`));
      }, timeoutMs);
      this.pending.set(id, {
        resolve: (m) => {
          clearTimeout(timer);
          resolve(m);
        },
        reject: (e) => {
          clearTimeout(timer);
          reject(e);
        },
      });
      this.child.stdin.write(`${line}\n`);
    });
  }

  /** Writes a raw line, which the adapter must answer with `"id": null`. */
  sendRaw(line, timeoutMs = 30000) {
    if (verbose) console.log(`  -> ${line}`);
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        this.nullWaiter = undefined;
        reject(new CheckFailure(`no response to ${JSON.stringify(line)} within ${timeoutMs} ms`));
      }, timeoutMs);
      this.nullWaiter = (m) => {
        clearTimeout(timer);
        resolve(m);
      };
      this.child.stdin.write(`${line}\n`);
    });
  }

  /** Sends a request that must succeed, and resolves with its result. */
  async call(op, args) {
    if (!this.operations.has(op)) throw new Skip(`${op} not implemented`);
    const m = await this.send(op, args);
    expect(m.id !== undefined, "the response has no id");
    if (!m.ok) throw new CheckFailure(`${op} failed: ${JSON.stringify(m.error)}`);
    expect(m.result !== null && typeof m.result === "object", `${op}: result is not an object`);
    return m.result;
  }

  /** Sends a request that must fail with `kind` (and `status`, when given), and resolves with the error. */
  async fails(op, args, kind, status) {
    if (!this.operations.has(op)) throw new Skip(`${op} not implemented`);
    const m = await this.send(op, args);
    if (m.ok !== false) throw new CheckFailure(`${op} should fail with ${kind}, but succeeded: ${String(JSON.stringify(m.result)).slice(0, 300)}`);
    expect(m.error && m.error.kind === kind, `${op} should fail with ${kind}, got ${JSON.stringify(m.error)}`);
    if (status !== undefined) expect(m.error.status === status, `${op}: error status ${m.error.status}, expected ${status}`);
    expect(typeof m.error.message === "string", `${op}: the error has no message`);
    return m.error;
  }
}

// ---------------------------------------------------------------------------------------------
// A local inbox, for the notification checks

function startInbox() {
  const deliveries = [];
  const waiters = [];
  const server = createServer((req, res) => {
    const chunks = [];
    req.on("data", (c) => chunks.push(c));
    req.on("end", () => {
      const headers = {};
      for (let i = 0; i < req.rawHeaders.length; i += 2) {
        const name = req.rawHeaders[i].toLowerCase();
        (headers[name] ??= []).push(req.rawHeaders[i + 1]);
      }
      const delivery = { method: req.method, headers, body: Buffer.concat(chunks) };
      deliveries.push(delivery);
      res.writeHead(202).end();
      for (const w of waiters.splice(0)) w();
    });
  });
  return new Promise((resolve) => {
    server.listen(0, "127.0.0.1", () => {
      const url = `http://127.0.0.1:${server.address().port}/inbox`;
      resolve({
        url,
        deliveries,
        close: () => new Promise((r) => server.close(r)),
        async next(predicate, timeoutMs = 5000) {
          const deadline = Date.now() + timeoutMs;
          for (;;) {
            const found = deliveries.find(predicate);
            if (found) return found;
            const left = deadline - Date.now();
            if (left <= 0) return undefined;
            await new Promise((r) => {
              const t = setTimeout(r, left);
              waiters.push(() => {
                clearTimeout(t);
                r();
              });
            });
          }
        },
      });
    });
  });
}

// ---------------------------------------------------------------------------------------------
// The checks

const server = await startServer({ port: 0, pageSize: 5, auth: true });
const base = server.url;
const root = `${base}/root/`;
const storageId = `${base}/`;
const inbox = await startInbox();
const adapter = new Adapter(command, commandArgs);
const run = `check-${Date.now()}`;
const state = {};

try {
  await check("hello announces the protocol, the language, the library and the operations", async () => {
    const hello = await Promise.race([
      adapter.hello,
      new Promise((_, reject) => setTimeout(() => reject(new CheckFailure("no hello within 60 s")), 60000)),
    ]);
    expect(hello.protocol === "lws-driver/1", `protocol is ${JSON.stringify(hello.protocol)}`);
    expect(typeof hello.language === "string" && hello.language.length > 0, "no language");
    expect(typeof hello.library === "string" && hello.library.length > 0, "no library");
    expect(Array.isArray(hello.operations), "operations is not a list");
    adapter.operations = new Set(hello.operations);
    adapter.language = hello.language;
    const unknown = hello.operations.filter((op) => !OPERATIONS.includes(op));
    expect(unknown.length === 0, `operations not in the protocol: ${unknown.join(", ")}`);
    const missing = OPERATIONS.filter((op) => !adapter.operations.has(op));
    console.log(`      ${hello.language}, ${hello.library}; ${hello.operations.length} operations${missing.length ? `, missing: ${missing.join(", ")}` : ""}`);
  });
  if (!adapter.operations) throw new Error("the adapter did not say hello");

  await check("an unknown operation is Unsupported, and the adapter keeps running", async () => {
    const m = await adapter.send("no_such_operation", {});
    expect(m.ok === false && m.error?.kind === "Unsupported", `got ${JSON.stringify(m)}`);
  });

  await check("anonymous: a read of the storage root is UnauthorizedError 401", async () => {
    await adapter.call("configure", { auth: { type: "none" } });
    await adapter.fails("read", { url: root }, "UnauthorizedError", 401);
  });

  await check("a read without a url is InvalidArguments", async () => {
    await adapter.fails("read", {}, "InvalidArguments");
  });

  await check("a line that is not a JSON object is InvalidArguments, answered with id null", async () => {
    for (const line of ["this is not JSON", "[1, 2, 3]"]) {
      const m = await adapter.sendRaw(line);
      expect(m.id === null && m.ok === false && m.error?.kind === "InvalidArguments", `${JSON.stringify(line)}: got ${JSON.stringify(m)}`);
    }
  });

  await check("a relative request target is InvalidArguments", async () => {
    await adapter.fails("read", { url: "/root/" }, "InvalidArguments");
  });

  await check("configure with a fresh did:key returns the agent", async () => {
    const r = await adapter.call("configure", { auth: { type: "didKey" }, userAgent: `lws-driver-check/${run}` });
    expect(typeof r.library === "string", "no library");
    expect(typeof r.agent === "string" && r.agent.startsWith("did:key:z"), `agent is ${r.agent}`);
    state.agent = r.agent;
  });

  await check("discover_storage finds the storage root and the services", async () => {
    const s = await adapter.call("discover_storage", { url: root });
    expect(s.id === storageId, `id ${s.id}`);
    expect(hasType(s.types, "Storage"), `types ${JSON.stringify(s.types)}`);
    expect(s.storageRoot === root, `storageRoot ${s.storageRoot}`);
    const endpoint = (type) => s.services.find((svc) => hasType(svc.types, type))?.serviceEndpoint;
    for (const type of ["NotificationService", "AccessRequestService", "AccessGrantService", "TypeIndexService", "TypeSearchService"]) {
      expect(typeof endpoint(type) === "string", `no ${type}`);
    }
    const notifications = s.services.find((svc) => hasType(svc.types, "NotificationService"));
    expect(Array.isArray(notifications.subscriptionType) && notifications.subscriptionType.includes("WebhookSubscription"),
      `subscriptionType ${JSON.stringify(notifications.subscriptionType)}`);
    expect(Array.isArray(s.verificationMethods) && s.verificationMethods.length > 0, "no verificationMethods");
    expect(s.raw && s.raw.id === storageId, "raw is not the document");
    state.services = Object.fromEntries(
      ["NotificationService", "AccessRequestService", "AccessGrantService", "TypeIndexService", "TypeSearchService"].map((t) => [t, endpoint(t)]),
    );
  });

  await check("get_storage_description reads the description itself", async () => {
    const s = await adapter.call("get_storage_description", { url: storageId });
    expect(s.id === storageId && s.storageRoot === root, `id ${s.id}, storageRoot ${s.storageRoot}`);
  });

  await check("create_container makes a container", async () => {
    const r = await adapter.call("create_container", { parent: root, slug: run });
    expect(typeof r.location === "string" && r.location.startsWith(root), `location ${r.location}`);
    expect(r.metadata && Array.isArray(r.metadata.links), "no metadata");
    state.container = r.location;
  });

  await check("create a text resource", async () => {
    const r = await adapter.call("create", { container: state.container, body: { text: "Hello, LWS!" }, contentType: "text/plain", slug: "hello.txt" });
    expect(typeof r.location === "string" && r.location.startsWith(state.container), `location ${r.location}`);
    state.hello = r.location;
  });

  await check("read returns the body and the metadata", async () => {
    const r = await adapter.call("read", { url: state.hello });
    expect(r.body?.text === "Hello, LWS!", `body ${JSON.stringify(r.body)}`);
    expect(r.notModified === false, `notModified ${r.notModified}`);
    const m = r.metadata;
    expect(m.status === 200, `status ${m.status}`);
    expect(m.url === state.hello, `url ${m.url}`);
    expect(typeof m.etag === "string" && m.etag.length > 0, "no etag");
    expect(typeof m.contentType === "string" && m.contentType.startsWith("text/plain"), `contentType ${m.contentType}`);
    expect(hasType(m.types, "DataResource"), `types ${JSON.stringify(m.types)}`);
    expect(m.parent === state.container, `parent ${m.parent}`);
    expect(typeof m.linkset === "string", "no linkset");
    expect(m.storage === storageId, `storage ${m.storage}`);
    expect(m.links.some((l) => l.rel === "linkset" && l.href === m.linkset), "links has no linkset link");
    expect(Array.isArray(m.allow) && m.allow.includes("GET"), `allow ${JSON.stringify(m.allow)}`);
    state.etag = m.etag;
  });

  await check("read with ifNoneMatch is notModified", async () => {
    const r = await adapter.call("read", { url: state.hello, ifNoneMatch: state.etag });
    expect(r.notModified === true, `notModified ${r.notModified}, status ${r.metadata?.status}`);
  });

  await check("read with a range returns the bytes and the Content-Range", async () => {
    const r = await adapter.call("read", { url: state.hello, rangeStart: 0, rangeEnd: 4 });
    expect(r.metadata.status === 206, `status ${r.metadata.status}`);
    expect(r.body?.text === "Hello", `body ${JSON.stringify(r.body)}`);
    expect(typeof r.contentRange === "string" && r.contentRange.startsWith("bytes 0-4/"), `contentRange ${r.contentRange}`);
  });

  await check("head returns the metadata", async () => {
    const m = await adapter.call("head", { url: state.hello });
    expect(m.status === 200 && m.etag === state.etag, `status ${m.status}, etag ${m.etag}`);
  });

  await check("update with ifMatch replaces the resource", async () => {
    const r = await adapter.call("update", { url: state.hello, body: { text: "Hello again" }, contentType: "text/plain", ifMatch: state.etag });
    expect([200, 204].includes(r.status), `status ${r.status}`);
    const again = await adapter.call("read", { url: state.hello });
    expect(again.body?.text === "Hello again", `body ${JSON.stringify(again.body)}`);
  });

  await check("update with a stale ETag is PreconditionFailedError 412", async () => {
    await adapter.fails("update", { url: state.hello, body: { text: "stale" }, contentType: "text/plain", ifMatch: state.etag }, "PreconditionFailedError", 412);
  });

  await check("create JSON with an extra type", async () => {
    const r = await adapter.call("create", { container: state.container, body: { json: { name: "Alice", age: 30 } }, slug: "profile.json", types: [PERSON] });
    state.profile = r.location;
    const m = await adapter.call("head", { url: state.profile });
    expect(m.types.includes(PERSON), `types ${JSON.stringify(m.types)}`);
    expect(m.contentType?.startsWith("application/json"), `contentType ${m.contentType}`);
    expect(m.acceptPatch.includes("application/json-patch+json"), `acceptPatch ${JSON.stringify(m.acceptPatch)}`);
  });

  await check("patch applies a JSON Patch", async () => {
    const r = await adapter.call("patch", { url: state.profile, patch: [{ op: "replace", path: "/age", value: 31 }, { op: "add", path: "/city", value: "Boston" }] });
    expect([200, 204].includes(r.status), `status ${r.status}`);
    const after = await adapter.call("read", { url: state.profile });
    const json = JSON.parse(after.body.text);
    expect(json.name === "Alice" && json.age === 31 && json.city === "Boston", `body ${after.body.text}`);
  });

  await check("a patch whose test fails is ConflictError 409", async () => {
    await adapter.fails("patch", { url: state.profile, patch: [{ op: "test", path: "/age", value: 99 }, { op: "remove", path: "/name" }] }, "ConflictError", 409);
  });

  await check("a binary body round-trips as base64", async () => {
    const bytes = Buffer.from([0, 1, 2, 250, 251, 252]);
    const r = await adapter.call("create", { container: state.container, body: { base64: bytes.toString("base64") }, contentType: "application/octet-stream", slug: "bytes.bin" });
    const back = await adapter.call("read", { url: r.location });
    expect(back.body?.base64 === bytes.toString("base64"), `body ${JSON.stringify(back.body)}`);
    state.binary = r.location;
  });

  await check("linkset_url finds the linkset", async () => {
    const r = await adapter.call("linkset_url", { url: state.profile });
    expect(typeof r.linkset === "string" && r.linkset.startsWith(base), `linkset ${r.linkset}`);
    state.linkset = r.linkset;
  });

  await check("read_linkset returns the document, the ETag and the advertised methods", async () => {
    const r = await adapter.call("read_linkset", { url: state.profile });
    expect(r.url === state.linkset, `url ${r.url}`);
    expect(Array.isArray(r.linkset?.linkset), `linkset ${JSON.stringify(r.linkset)}`);
    expect(r.linkset.linkset[0]?.anchor === state.profile, `anchor ${r.linkset.linkset[0]?.anchor}`);
    expect(r.allow.includes("PUT") && r.acceptPatch.includes("application/json-patch+json"), `allow ${r.allow}, acceptPatch ${r.acceptPatch}`);
    expect(typeof r.etag === "string", "no etag");
    state.linksetEtag = r.etag;
  });

  await check("patch_linkset adds a link", async () => {
    const r = await adapter.call("patch_linkset", {
      linksetUrl: state.linkset,
      patch: [{ op: "add", path: "/linkset/0/describedby", value: [{ href: "https://example.org/shapes/person" }] }],
      ifMatch: state.linksetEtag,
    });
    expect([200, 204].includes(r.status), `status ${r.status}`);
    const after = await adapter.call("read_linkset", { url: state.profile });
    const targets = after.linkset.linkset[0].describedby ?? [];
    expect(targets.some((t) => t.href === "https://example.org/shapes/person"), `linkset ${JSON.stringify(after.linkset)}`);
    state.linksetDoc = after.linkset;
  });

  await check("update_linkset replaces the linkset", async () => {
    const doc = structuredClone(state.linksetDoc);
    doc.linkset[0].license = [{ href: "https://creativecommons.org/licenses/by/4.0/" }];
    const r = await adapter.call("update_linkset", { linksetUrl: state.linkset, linkset: doc });
    expect([200, 204].includes(r.status), `status ${r.status}`);
    const after = await adapter.call("read_linkset", { url: state.profile });
    expect((after.linkset.linkset[0].license ?? []).some((t) => t.href === "https://creativecommons.org/licenses/by/4.0/"), `linkset ${JSON.stringify(after.linkset)}`);
  });

  await check("read_container pages a container, and list_container follows the pages", async () => {
    for (let i = 0; i < 5; i++) {
      await adapter.call("create", { container: state.container, body: { text: `item ${i}` }, contentType: "text/plain", slug: `item-${i}.txt` });
    }
    const page = await adapter.call("read_container", { url: state.container });
    expect(page.id === state.container, `id ${page.id}`);
    expect(hasType(page.types, "Container"), `types ${JSON.stringify(page.types)}`);
    expect(page.totalItems === 8, `totalItems ${page.totalItems}`);
    expect(page.items.length === 5, `${page.items.length} items on the first page`);
    expect(typeof page.next === "string", "no next");
    expect(page.metadata?.status === 200, "no metadata");
    const all = await adapter.call("list_container", { url: state.container });
    expect(all.items.length === 8 && all.truncated === false, `${all.items.length} items, truncated ${all.truncated}`);
    const ids = all.items.map((i) => i.id);
    expect(ids.includes(state.hello) && ids.includes(state.profile), `ids ${ids}`);
    const hello = all.items.find((i) => i.id === state.hello);
    expect(hasType(hello.types, "DataResource") && hello.format?.startsWith("text/plain"), `item ${JSON.stringify(hello)}`);
    const some = await adapter.call("list_container", { url: state.container, limit: 3 });
    expect(some.items.length === 3 && some.truncated === true, `${some.items.length} items, truncated ${some.truncated}`);
  });

  await check("malformed arguments are InvalidArguments", async () => {
    await adapter.fails("create", { container: state.container, body: { base64: "not base64!" }, contentType: "application/octet-stream" }, "InvalidArguments");
    await adapter.fails("list_container", { url: state.container, limit: -1 }, "InvalidArguments");
    await adapter.fails("list_container", { url: state.container, limit: 1.5 }, "InvalidArguments");
    await adapter.fails("update_linkset", { linksetUrl: state.linkset, linkset: { linkset: "not a list" } }, "InvalidArguments");
    await adapter.fails("patch", { url: state.profile, patch: [{ op: "jump", path: "/a" }] }, "InvalidArguments");
    await adapter.fails("search_types", { serviceUrl: state.services.TypeSearchService, query: { type: [42] } }, "InvalidArguments");
  });

  await check("the type index lists the type, and search finds the resource", async () => {
    const indexUrl = state.services?.TypeIndexService;
    const searchUrl = state.services?.TypeSearchService;
    expect(indexUrl && searchUrl, "no index services");
    const page = await adapter.call("read_type_index", { url: indexUrl });
    expect(Array.isArray(page.types), `types ${JSON.stringify(page.types)}`);
    const types = await adapter.call("list_types", { serviceUrl: indexUrl });
    expect(types.types.includes(PERSON), `types ${JSON.stringify(types.types)}`);
    const found = await adapter.call("search_types", { serviceUrl: searchUrl, query: { type: [PERSON] } });
    expect(found.items.some((i) => i.id === state.profile), `items ${JSON.stringify(found.items)}`);
    const all = await adapter.call("search_all", { serviceUrl: searchUrl, query: { type: [[PERSON, "http://xmlns.com/foaf/0.1/Person"]] } });
    expect(all.items.some((i) => i.id === state.profile), `items ${JSON.stringify(all.items)}`);
    const formats = await adapter.call("accepted_query_formats", { serviceUrl: searchUrl });
    expect(formats.formats.includes("application/lws-query+json"), `formats ${formats.formats}`);
  });

  await check("subscribe, receive a signed notification, and verify it", async () => {
    const serviceUrl = state.services?.NotificationService;
    expect(serviceUrl, "no notification service");
    const sub = await adapter.call("subscribe", { serviceUrl, topics: [state.container], inbox: inbox.url });
    expect(typeof sub.subscription === "string", `subscription ${sub.subscription}`);
    state.subscription = sub.subscription;
    await adapter.call("update", { url: state.hello, body: { text: "Hello, notifications" }, contentType: "text/plain" });
    const delivery = await inbox.next((d) => d.body.toString().includes(state.hello));
    expect(delivery, "no notification arrived within 5 s");
    const args = { method: delivery.method, url: inbox.url, headers: delivery.headers, bodyBase64: delivery.body.toString("base64"), trustedStorages: [storageId] };
    const v = await adapter.call("verify_notification", args);
    expect(v.storage === storageId, `storage ${v.storage}`);
    expect(typeof v.keyid === "string" && v.keyid.includes("#"), `keyid ${v.keyid}`);
    expect(v.activities.some((a) => hasType(a.types, "Update") && a.object === state.hello), `activities ${JSON.stringify(v.activities)}`);
    state.delivery = args;
  });

  await check("a notification altered after signing is SignatureVerificationError", async () => {
    if (!state.delivery) throw new Skip("no delivery");
    const body = Buffer.from(state.delivery.bodyBase64, "base64").toString().replace("Update", "Delete");
    await adapter.fails("verify_notification", { ...state.delivery, bodyBase64: Buffer.from(body).toString("base64") }, "SignatureVerificationError");
  });

  await check("list_subscriptions, get_subscription and unsubscribe", async () => {
    if (!state.subscription) throw new Skip("no subscription");
    const serviceUrl = state.services.NotificationService;
    const list = await adapter.call("list_subscriptions", { serviceUrl });
    expect(list.items.some((i) => i.id === state.subscription), `items ${JSON.stringify(list.items)}`);
    const got = await adapter.call("get_subscription", { url: state.subscription });
    expect(got.subscription === state.subscription, `subscription ${got.subscription}`);
    await adapter.call("unsubscribe", { url: state.subscription });
    await adapter.fails("get_subscription", { url: state.subscription }, "NotFoundError", 404);
  });

  await check("access requests and grants", async () => {
    const policy = {
      type: ["AccessPolicy"], action: ["read"], assignee: state.agent,
      target: { type: "StorageResource", value: [state.container] },
      constraint: [{ leftOperand: "purpose", operator: "eq", rightOperand: "https://purpose.example/testing" }],
    };
    const doc = (type) => ({ "@context": ["https://www.w3.org/ns/lws/v1"], type: [type], storage: storageId, access: [policy] });
    const request = await adapter.call("request_access", { serviceUrl: state.services.AccessRequestService, request: doc("AccessRequest") });
    expect(typeof request.location === "string", `location ${request.location}`);
    const gotRequest = await adapter.call("get_access_request", { url: request.location });
    expect(hasType([].concat(gotRequest.document?.type), "AccessRequest"), `document ${JSON.stringify(gotRequest.document)}`);
    expect(gotRequest.document.access?.[0]?.assignee === state.agent, "the policy did not round-trip");
    const requests = await adapter.call("list_access_requests", { serviceUrl: state.services.AccessRequestService });
    expect(requests.items.some((i) => i.id === request.location), `items ${JSON.stringify(requests.items)}`);
    const grant = await adapter.call("grant_access", { serviceUrl: state.services.AccessGrantService, grant: doc("AccessGrant") });
    const gotGrant = await adapter.call("get_access_grant", { url: grant.location });
    expect(hasType([].concat(gotGrant.document?.type), "AccessGrant"), `document ${JSON.stringify(gotGrant.document)}`);
    const grants = await adapter.call("list_access_grants", { serviceUrl: state.services.AccessGrantService });
    expect(grants.items.some((i) => i.id === grant.location), `items ${JSON.stringify(grants.items)}`);
    await adapter.call("revoke_access_grant", { url: grant.location });
    await adapter.call("cancel_access_request", { url: request.location });
    await adapter.fails("get_access_request", { url: request.location }, "NotFoundError", 404);
  });

  await check("self-signed credentials for an https agent", async () => {
    const { privateKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
    const privateJwk = privateKey.export({ format: "jwk" });
    const { d, ...publicJwk } = privateJwk;
    const created = await adapter.call("create", { container: state.container, body: { json: {} }, slug: "agent.json" });
    const agent = created.location;
    const kid = `${agent}#key-1`;
    const cid = {
      "@context": ["https://www.w3.org/ns/cid/v1"], id: agent,
      authentication: [{ id: kid, type: "JsonWebKey", controller: agent, publicKeyJwk: publicJwk }],
    };
    await adapter.call("update", { url: agent, body: { json: cid }, contentType: "application/json" });
    await adapter.call("configure", { auth: { type: "selfSigned", agent, privateJwk: { ...privateJwk, kid } } });
    const r = await adapter.call("read", { url: state.hello });
    expect(r.metadata.status === 200, `status ${r.metadata.status}`);
  });

  await check("delete: a non-empty container is ConflictError 409 with flat problem details, recursive deletes it", async () => {
    const error = await adapter.fails("delete", { url: state.container }, "ConflictError", 409);
    expect(error.problem && error.problem.status === 409 && typeof error.problem.title === "string", `problem ${JSON.stringify(error.problem)}`);
    expect(!("extensions" in error.problem), `problem members must be flat: ${JSON.stringify(error.problem)}`);
    await adapter.call("delete", { url: state.container, recursive: true });
    await adapter.fails("read", { url: state.hello }, "NotFoundError", 404);
  });

  await check("shutdown answers, and the adapter exits with status 0", async () => {
    await adapter.call("shutdown", {});
    const { code } = await Promise.race([adapter.exited, new Promise((r) => setTimeout(() => r({ code: "timeout" }), 10000))]);
    expect(code === 0, `exit code ${code}`);
  });
} catch (e) {
  failures++;
  console.log(`FAIL  ${e.stack ?? e}`);
} finally {
  adapter.child.kill();
  await inbox.close();
  await server.close();
}

console.log(`\n${adapter.language ?? command}: ${passes} passed, ${failures} failed, ${skips} skipped`);
process.exit(failures > 0 ? 1 : 0);
