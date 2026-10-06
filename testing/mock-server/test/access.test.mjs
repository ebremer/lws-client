// SPDX-License-Identifier: MIT
import assert from "node:assert/strict";
import { after, before, describe, test } from "node:test";
import { activitiesOf, authed, launch, login, startInbox, verifyDelivery } from "./helpers.mjs";

let server;
let base;
let http;

before(async () => {
  server = await launch();
  base = server.url;
  http = authed((await login(base)).token);
});
after(() => server.close());

const policy = (overrides = {}) => ({
  type: ["AccessPolicy"],
  action: ["read", "create"],
  assignee: "https://id.example/agent",
  target: { type: "StorageResource", value: [`${base}/root/projects/`] },
  constraint: [
    { leftOperand: "purpose", operator: "eq", rightOperand: "https://purpose.example/collaboration" },
    { leftOperand: "dateTime", operator: "lteq", rightOperand: "2026-06-09T10:00:00Z" },
  ],
  ...overrides,
});

const document = (type, overrides = {}) => ({
  "@context": ["https://www.w3.org/ns/lws/v1"],
  type: [type],
  storage: `${base}/`,
  access: [policy()],
  ...overrides,
});

const post = (path, body, headers = {}) =>
  http(`${base}${path}`, { method: "POST", headers: { "content-type": "application/lws+json", ...headers }, body: JSON.stringify(body) });

for (const [path, type] of [
  ["/access/requests/", "AccessRequest"],
  ["/access/grants/", "AccessGrant"],
]) {
  describe(`${type} endpoint`, () => {
    test("create, list, read, delete", async () => {
      const doc = document(type, { inbox: "https://id.example/agent/inbox/" });
      const r = await post(path, doc);
      assert.equal(r.status, 201);
      const location = r.headers.get("location");
      assert.ok(location.startsWith(`${base}${path}`));
      const got = await http(location);
      assert.equal(got.status, 200);
      assert.equal(got.headers.get("content-type"), "application/lws+json");
      const stored = await got.json();
      assert.deepEqual({ ...stored, id: undefined }, { ...doc, id: undefined });
      assert.equal(stored.id, location);

      const list = await (await http(`${base}${path}`)).json();
      assert.equal(list.type, "Container");
      const item = list.items.find((i) => new URL(i.id, base).href === location);
      assert.deepEqual(item.type, ["DataResource", type]);
      assert.equal(item.format, "application/lws+json");

      assert.equal((await http(location, { method: "DELETE" })).status, 204);
      assert.equal((await http(location)).status, 404);
    });

    test("validation", async () => {
      const bad = [
        document(type, { "@context": ["https://example.org/other"] }),
        document(type, { type: ["Something"] }),
        document(type, { storage: "https://other.example/" }),
        document(type, { access: [] }),
        document(type, { access: [policy({ type: ["Policy"] })] }),
        document(type, { access: [policy({ action: [] })] }),
        document(type, { access: [policy({ action: ["write"] })] }),
        document(type, { access: [policy({ assignee: undefined })] }),
        document(type, { access: [policy({ target: { type: "StorageResource", value: [] } })] }),
        document(type, { access: [policy({ constraint: [{ leftOperand: "purpose" }] })] }),
        document(type, { inbox: "not a uri" }),
      ];
      for (const doc of bad) assert.equal((await post(path, doc)).status, 400, JSON.stringify(doc));
      assert.equal((await post(path, document(type), { "content-type": "text/plain" })).status, 415);
      assert.equal((await http(`${base}${path}`, { method: "POST", headers: { "content-type": "application/lws+json" }, body: "{" })).status, 400);
      assert.equal((await post(path, document(type, { access: [policy({ assignee: "http://xmlns.com/foaf/0.1/Agent", target: undefined, constraint: undefined })] }))).status, 201);
    });
  });
}

describe("grant notifications", () => {
  test("the requesting agent's inbox is notified when a grant is created", async () => {
    const inbox = await startInbox();
    try {
      await post("/access/requests/", document("AccessRequest", { inbox: inbox.url, access: [policy({ assignee: "https://id.example/requester" })] }));
      const grant = await post("/access/grants/", document("AccessGrant", { access: [policy({ assignee: "https://id.example/requester", action: ["read"] })] }));
      const [delivery] = await inbox.waitFor(1);
      const { notification } = await verifyDelivery(delivery, inbox.url);
      const [activity] = activitiesOf(notification);
      assert.deepEqual(activity.type, ["Create"]);
      assert.equal(activity.object.id, grant.headers.get("location"));
      assert.deepEqual(activity.object.type, ["DataResource", "AccessGrant"]);
    } finally {
      await inbox.close();
    }
  });
});
