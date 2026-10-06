// SPDX-License-Identifier: MIT
import assert from "node:assert/strict";
import { after, before, describe, test } from "node:test";
import { activitiesOf, authed, launch, LWS, login, startInbox, verifyDelivery } from "./helpers.mjs";

let server;
let base;
let http;
let agentDid;

before(async () => {
  server = await launch();
  base = server.url;
  const { token, agent } = await login(base);
  http = authed(token);
  agentDid = agent.did;
});
after(() => server.close());

const subscribe = (body, headers = {}) =>
  http(`${base}/notifications/`, { method: "POST", headers: { "content-type": "application/lws+json", ...headers }, body: JSON.stringify(body) });

async function container(slug) {
  const r = await http(`${base}/root/`, { method: "POST", headers: { link: `<${LWS}Container>; rel="type"`, slug } });
  return r.headers.get("location");
}

describe("subscriptions", () => {
  test("validation", async () => {
    const c = await container("sub-validation");
    const valid = { "@context": ["https://www.w3.org/ns/lws/v1"], type: "WebhookSubscription", topic: [c], inbox: "https://receiver.example/hooks/lws" };
    assert.equal((await subscribe(valid, { "content-type": "text/plain" })).status, 415);
    assert.equal((await subscribe({ ...valid, type: "WebSocketSubscription" })).status, 400);
    assert.equal((await subscribe({ ...valid, type: undefined })).status, 400);
    assert.equal((await subscribe({ ...valid, topic: [] })).status, 400);
    assert.equal((await subscribe({ ...valid, topic: [`${base}/root/does-not-exist`] })).status, 400);
    assert.equal((await subscribe({ ...valid, topic: ["https://other.example/x"] })).status, 400);
    assert.equal((await subscribe({ ...valid, inbox: "not a url" })).status, 400);
    assert.equal((await subscribe({ ...valid, expires: "2001-01-01T00:00:00Z" })).status, 400);
    assert.equal((await subscribe({ ...valid, expires: "soon" })).status, 400);
    assert.equal((await http(`${base}/notifications/`, { method: "POST", headers: { "content-type": "application/lws+json" }, body: "{" })).status, 400);
  });

  test("lifecycle: create, list, read, delete", async () => {
    const c = await container("sub-lifecycle");
    const expires = new Date(Date.now() + 3600_000).toISOString();
    const r = await subscribe({ "@context": ["https://www.w3.org/ns/lws/v1"], type: "WebhookSubscription", topic: [c], inbox: "https://receiver.example/hooks/lws", expires });
    assert.equal(r.status, 200);
    assert.equal(r.headers.get("content-type"), "application/lws+json");
    const body = await r.json();
    assert.equal(body.type, "WebhookSubscription");
    assert.equal(body.expires, expires);
    assert.equal(r.headers.get("location"), body.subscription);
    assert.ok(body.subscription.startsWith(`${base}/notifications/`));

    const list = await http(`${base}/notifications/`);
    assert.equal(list.status, 200);
    const listing = await list.json();
    assert.equal(listing.type, "Container");
    const item = listing.items.find((i) => new URL(i.id, base).href === body.subscription);
    assert.ok(item);
    assert.deepEqual(item.type, ["DataResource", "WebhookSubscription"]);

    const got = await http(body.subscription);
    assert.equal(got.status, 200);
    assert.deepEqual((await got.json()).topic, [c]);

    const other = authed((await login(base)).token);
    assert.equal((await other(body.subscription)).status, 404, "subscriptions are private to their subscriber");
    assert.equal((await (await other(`${base}/notifications/`)).json()).totalItems, 0);

    assert.equal((await http(body.subscription, { method: "DELETE" })).status, 204);
    assert.equal((await http(body.subscription)).status, 404);
  });

  test("default expiry is assigned", async () => {
    const c = await container("sub-default-expiry");
    const body = await (await subscribe({ type: "WebhookSubscription", topic: [c], inbox: "https://receiver.example/x" })).json();
    assert.ok(Date.parse(body.expires) > Date.now());
  });
});

describe("webhook delivery", () => {
  test("signed Create, Update and Delete notifications are delivered for container topics", async () => {
    const inbox = await startInbox();
    try {
      const c = await container("watched");
      const sub = await (await subscribe({ type: "WebhookSubscription", topic: [c], inbox: inbox.url })).json();

      const created = await http(c, { method: "POST", headers: { "content-type": "text/plain", slug: "n.txt" }, body: "one" });
      const location = created.headers.get("location");
      await inbox.waitFor(1);
      await http(location, { method: "PUT", headers: { "content-type": "text/plain" }, body: "two" });
      await inbox.waitFor(2);
      await http(`${location}.meta`, { method: "PATCH", headers: { "content-type": "application/json-patch+json" }, body: JSON.stringify([{ op: "add", path: "/linkset/0/license", value: [{ href: "https://example.org/l" }] }]) });
      await inbox.waitFor(3);
      await http(location, { method: "DELETE" });
      const deliveries = await inbox.waitFor(4);

      const kinds = [];
      for (const d of deliveries) {
        assert.equal(d.method, "POST");
        assert.equal(d.headers["content-type"], "application/lws+json");
        const { keyid, notification, signatureBase } = await verifyDelivery(d, inbox.url);
        assert.equal(keyid, `${base}/#webhook-key`);
        assert.match(signatureBase, /"@authority": 127\.0\.0\.1:\d+\n/);
        assert.match(d.headers["signature-input"], /^sig1=\("@method" "@scheme" "@authority" "@path" "content-type" "content-digest"\);created=\d+;keyid="[^"]+";alg="ecdsa-p256-sha256"$/);
        assert.deepEqual(notification["@context"], ["https://www.w3.org/ns/lws/v1", "https://www.w3.org/ns/activitystreams"]);
        assert.equal(notification.type, "Notification");
        for (const a of activitiesOf(notification)) {
          assert.match(a.id, /^urn:uuid:/);
          assert.equal(a.object.id, location);
          assert.deepEqual(a.object.type, ["DataResource"]);
          assert.equal(a.actor, agentDid);
          assert.ok(!Number.isNaN(Date.parse(a.published)));
          kinds.push(a.type[0]);
          if (a.type[0] === "Create") assert.equal(a.target, c);
          if (a.type[0] === "Delete") assert.equal(a.origin, c);
        }
      }
      assert.deepEqual(kinds, ["Create", "Update", "Update", "Delete"]);
      await http(sub.subscription, { method: "DELETE" });
    } finally {
      await inbox.close();
    }
  });

  test("recursive deletes are batched and data-resource topics are not recursive", async () => {
    const inbox = await startInbox();
    const fileInbox = await startInbox();
    try {
      const c = await container("batched");
      const inner = (await http(c, { method: "POST", headers: { link: `<${LWS}Container>; rel="type"`, slug: "inner" } })).headers.get("location");
      const f1 = (await http(inner, { method: "POST", headers: { "content-type": "text/plain", slug: "a.txt" }, body: "a" })).headers.get("location");
      const other = (await http(c, { method: "POST", headers: { "content-type": "text/plain", slug: "b.txt" }, body: "b" })).headers.get("location");
      await subscribe({ type: "WebhookSubscription", topic: [c], inbox: inbox.url });
      await subscribe({ type: "WebhookSubscription", topic: [other], inbox: fileInbox.url });

      await http(c, { method: "DELETE", headers: { depth: "infinity" } });
      const [delivery] = await inbox.waitFor(1);
      const { notification } = await verifyDelivery(delivery, inbox.url);
      const activities = activitiesOf(notification);
      assert.ok(Array.isArray(notification.activity));
      assert.deepEqual(new Set(activities.map((a) => a.object.id)), new Set([f1, inner, other, c]));
      assert.ok(activities.every((a) => a.type[0] === "Delete"));
      assert.equal(activities.find((a) => a.object.id === f1).origin, inner);
      assert.deepEqual(activities.find((a) => a.object.id === inner).object.type, ["Container"]);

      const [fileDelivery] = await fileInbox.waitFor(1);
      const fileActivities = activitiesOf((await verifyDelivery(fileDelivery, fileInbox.url)).notification);
      assert.deepEqual(fileActivities.map((a) => a.object.id), [other]);
    } finally {
      await inbox.close();
      await fileInbox.close();
    }
  });

  test("failed deliveries are retried", async () => {
    let calls = 0;
    const inbox = await startInbox({ status: 500 });
    try {
      const c = await container("retry");
      await subscribe({ type: "WebhookSubscription", topic: [c], inbox: inbox.url });
      await http(c, { method: "POST", headers: { "content-type": "text/plain" }, body: "x" });
      const deliveries = await inbox.waitFor(3, 4000);
      calls = deliveries.length;
      assert.equal(calls, 3);
    } finally {
      await inbox.close();
    }
  });
});
