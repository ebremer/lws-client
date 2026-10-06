// SPDX-License-Identifier: MIT
// End-to-end scenario of conformance/scenario.md against the mock server.
// Runs only when LWS_TEST_SERVER is set, e.g.:
//   node testing/mock-server/server.mjs --port 8787
//   LWS_TEST_SERVER=http://localhost:8787 npm test
import { test } from "node:test";
import assert from "node:assert/strict";
import { createServer } from "node:http";
import type { AddressInfo } from "node:net";
import {
  LwsClient,
  TokenExchangeAuthenticator,
  SelfSignedCredentials,
  generateKeyPair,
  JsonPatch,
  TypeQuery,
  WebhookVerifier,
  ConflictError,
  NotFoundError,
  PreconditionFailedError,
  Constraints,
  MediaType,
  type Notification,
} from "../src/index.js";
import { createWebhookHandler } from "../src/node.js";

const BASE = process.env["LWS_TEST_SERVER"]?.replace(/\/$/, "");

test("interop scenario (conformance/scenario.md)", { skip: BASE ? false : "LWS_TEST_SERVER not set" }, async (t) => {
  const base = BASE!;
  const pair = await generateKeyPair("ES256");
  const credentials = SelfSignedCredentials.didKey(pair);
  const client = new LwsClient({ authenticator: new TokenExchangeAuthenticator(credentials) });
  const name = `interop-js-${Date.now()}`;

  // 1. Authenticate + discover
  const storage = await client.discoverStorage(`${base}/root/`);
  assert.equal(storage.storageRoot(), `${base}/root/`);
  for (const s of [
    storage.notificationService(),
    storage.accessRequestService(),
    storage.accessGrantService(),
    storage.typeIndexService(),
    storage.typeSearchService(),
  ]) {
    assert.ok(s, "service advertised");
  }

  // 2. Container
  const C = (await client.createContainer(storage.storageRoot(), { slug: name })).location;
  await t.test("container created", async () => assert.ok((await client.readContainer(C)).isContainer()));

  // 3–4. Create + read text
  const H = (await client.createText(C, "Hello, LWS!", { slug: "hello.txt" })).location;
  const h = await client.read(H);
  assert.equal(await h.text(), "Hello, LWS!");
  assert.ok(h.etag, "ETag present");
  assert.ok(h.isDataResource());
  assert.equal(h.parent, C);
  assert.ok(h.linkset);
  assert.equal(h.storage, `${base}/`);

  // 5. Conditional read
  assert.equal((await client.read(H, { ifNoneMatch: h.etag! })).notModified, true);

  // 6. Update with If-Match; stale ETag fails
  await client.update(H, "Hello again", "text/plain", { ifMatch: h.etag! });
  await assert.rejects(client.update(H, "stale", "text/plain", { ifMatch: h.etag! }), PreconditionFailedError);

  // 7. JSON + JSON Patch
  const P = (await client.createJson(C, { name: "Alice", age: 30 }, { slug: "profile.json", types: ["https://schema.org/Person"] })).location;
  await client.patch(P, new JsonPatch().replace("/age", 31).add("/city", "Boston"));
  assert.deepEqual(await (await client.read(P)).json(), { name: "Alice", age: 31, city: "Boston" });

  // 8. Linkset
  const ls = await client.readLinkset(P);
  await client.patchLinkset(ls.url, new JsonPatch().add("/linkset/0/describedby", [{ href: "https://example.org/shapes/person" }]), { ifMatch: ls.etag! });
  const ls2 = await client.readLinkset(P);
  assert.ok(ls2.linkset.targets("describedby").some((t) => t.href === "https://example.org/shapes/person"));

  // 9. Pagination
  for (let i = 0; i < 6; i++) await client.createText(C, `item ${i}`, { slug: `item-${i}.txt` });
  const first = await client.readContainer(C);
  assert.equal(first.totalItems, 8);
  assert.ok(first.next, "paginated");
  const ids: string[] = [];
  for await (const item of client.listContainer(C)) ids.push(item.id);
  assert.equal(ids.length, 8);
  assert.ok(ids.includes(H) && ids.includes(P));

  // 10. Type index / search
  const types: string[] = [];
  for await (const ty of client.listTypes(storage.typeIndexService()!)) types.push(ty);
  assert.ok(types.includes("https://schema.org/Person"));
  const found: string[] = [];
  for await (const r of client.searchAll(storage.typeSearchService()!, TypeQuery.allOf("https://schema.org/Person"))) found.push(r.id);
  assert.ok(found.includes(P));
  assert.ok((await client.acceptedQueryFormats(storage.typeSearchService()!)).includes(MediaType.LWS_QUERY_JSON));

  // 11. Notifications with a local inbox
  const received: Notification[] = [];
  const verifier = new WebhookVerifier({
    resolveStorageDescription: (id) => client.getStorageDescription(id),
    trustedStorages: [`${base}/`],
  });
  const inbox = createServer();
  await new Promise<void>((r) => inbox.listen(0, "127.0.0.1", r));
  const inboxUrl = `http://127.0.0.1:${(inbox.address() as AddressInfo).port}/inbox`;
  const errors: unknown[] = [];
  const handler = createWebhookHandler(verifier, (n) => void received.push(n), { inboxUrl, onError: (e) => errors.push(e) });
  inbox.on("request", (req, res) => void handler(req, res));
  try {
    const sub = await client.subscribe(storage.notificationService()!, { topics: [C], inbox: inboxUrl });
    const subs: string[] = [];
    for await (const s of client.listSubscriptions(storage.notificationService()!)) subs.push(s.id);
    assert.ok(subs.includes(sub.subscription), "subscription listed");
    await client.update(H, "Hello once more", "text/plain");
    const deadline = Date.now() + 5000;
    const isUpdateOfH = (): boolean => received.some((n) => n.activities.some((a) => a.isUpdate() && a.object.id === H));
    while (!isUpdateOfH() && Date.now() < deadline) await new Promise((r) => setTimeout(r, 50));
    assert.ok(isUpdateOfH(), `verified Update notification received (errors: ${errors.map(String).join("; ")})`);
    await client.unsubscribe(sub.subscription);
  } finally {
    inbox.close();
  }

  // 12. Access requests / grants
  const policy = {
    actions: ["read"],
    assignee: credentials.agent,
    target: { type: "StorageResource", values: [C] },
    constraints: [Constraints.purpose("https://purpose.example/collaboration")],
  };
  const reqUrl = await client.requestAccess(storage.accessRequestService()!, { storage: `${base}/`, access: [policy] });
  const ar = await client.getAccessRequest(reqUrl);
  assert.equal(ar.access[0]!.assignee, credentials.agent);
  const reqs: string[] = [];
  for await (const r of client.listAccessRequests(storage.accessRequestService()!)) reqs.push(r.id);
  assert.ok(reqs.includes(reqUrl));
  const grantUrl = await client.grantAccess(storage.accessGrantService()!, { storage: `${base}/`, access: [policy] });
  assert.deepEqual((await client.getAccessGrant(grantUrl)).access[0]!.actions, ["read"]);
  await client.revokeAccessGrant(grantUrl);
  await client.cancelAccessRequest(reqUrl);

  // 13. Delete
  await assert.rejects(client.delete(C), ConflictError);
  await client.delete(C, { recursive: true });
  await assert.rejects(client.read(H), NotFoundError);
});
