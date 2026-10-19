// SPDX-License-Identifier: MIT
import { test, describe } from "node:test";
import assert from "node:assert/strict";
import {
  StorageDescription,
  ContainerPage,
  ResourceMetadata,
  Linkset,
  parseNotification,
  AccessRequest,
  AccessGrant,
  Constraints,
  Action,
  TypeIndexPage,
  ProtocolError,
  LwsType,
  MoveCapability,
} from "../src/index.js";
import { movePatch, readMoveResult } from "../src/models/move.js";
import { fixture } from "./support/fixtures.js";

function headersOf(h: Record<string, string | string[]>): Headers {
  const out = new Headers();
  for (const [k, v] of Object.entries(h)) for (const value of Array.isArray(v) ? v : [v]) out.append(k, value);
  return out;
}

describe("StorageDescription — responses/storage-description.json", () => {
  const fx = fixture("responses/storage-description.json");
  const sd = new StorageDescription(fx.body, fx.url);
  const e = fx.expected;

  test("core members", () => {
    assert.equal(sd.id, e.id);
    assert.deepEqual(sd.types, e.types);
    assert.equal(sd.storageRoot(), e.storageRoot);
    assert.equal(sd.services().length, e.serviceCount);
    assert.deepEqual(sd.capabilities().map((c) => c.types[0]), e.capabilityTypes);
  });

  test("service helpers", () => {
    assert.equal(sd.notificationService()?.serviceEndpoint, e.notificationService);
    assert.deepEqual(sd.notificationService()?.subscriptionTypes, e.notificationSubscriptionTypes);
    assert.ok(sd.notificationService()?.supportsWebhooks());
    assert.equal(sd.typeIndexService()?.serviceEndpoint, e.typeIndexService);
    assert.equal(sd.typeSearchService()?.serviceEndpoint, e.typeSearchService);
    assert.equal(sd.accessRequestService()?.serviceEndpoint, e.accessRequestService);
    assert.equal(sd.accessGrantService()?.serviceEndpoint, e.accessGrantService);
    const custom = sd.service(e.customService.type)!;
    assert.equal(custom.id, e.customService.id);
    assert.equal(custom.serviceEndpoint, e.customService.serviceEndpoint);
    assert.ok(sd.service("https://www.w3.org/ns/lws#StorageRoot"), "full IRI matches short term");
    assert.deepEqual(sd.accessGrantService()?.conformsTo, ["https://www.w3.org/ns/lws#AccessProfile"]);
  });

  const moveOf = (m: MoveCapability | undefined): unknown =>
    m && {
      appliesTo: m.appliesTo,
      preservesIdentifier: m.preservesIdentifier ?? null,
      movesDataResources: m.movesDataResources(),
      movesContainers: m.movesContainers(),
    };

  test("move capability", () => {
    assert.deepEqual(moveOf(sd.moveCapability()), e.moveCapability);
    assert.equal(sd.capability("MoveResource"), sd.moveCapability());
  });

  for (const c of fx.moveCapabilities) {
    test(`move capability: ${c.name}`, () => {
      const body = { id: fx.url, type: "Storage", ...(c.capability === null ? {} : { capability: c.capability }) };
      assert.deepEqual(moveOf(new StorageDescription(body).moveCapability()) ?? null, c.expected);
    });
  }

  test("invalid documents", () => {
    assert.throws(() => new StorageDescription(fx.invalid.notStorage), ProtocolError);
    const noRoot = new StorageDescription(fx.invalid.noRoot);
    assert.throws(() => noRoot.storageRoot(), ProtocolError);
  });
});

describe("ContainerPage — responses/container-page.json", () => {
  const fx = fixture("responses/container-page.json");
  const meta = new ResourceMetadata(fx.url, fx.status, headersOf(fx.headers));
  const page = new ContainerPage(fx.body, meta);
  const e = fx.expected;

  test("page members and links", () => {
    assert.equal(page.id, e.id);
    assert.equal(page.isContainer(), e.isContainer);
    assert.equal(page.totalItems, e.totalItems);
    assert.equal(page.etag, e.etag);
    assert.equal(page.linkset, e.linkset);
    assert.equal(page.parent, e.parent);
    assert.equal(page.storage, e.storage);
    assert.equal(page.first, e.first);
    assert.equal(page.next, e.next);
    assert.equal(page.prev ?? null, e.prev);
    assert.equal(page.last, e.last);
    assert.ok(meta.isContainer());
  });

  test("items", () => {
    assert.equal(page.items.length, e.items.length);
    page.items.forEach((item, i) => {
      const x = e.items[i];
      assert.equal(item.id, x.id);
      assert.equal(item.isContainer(), x.isContainer);
      assert.equal(item.isDataResource(), x.isDataResource);
      assert.equal(item.format ?? null, x.format);
      assert.equal(item.size ?? null, x.size);
      assert.deepEqual(item.types, x.types);
      if (x.modified) assert.equal(item.modified?.getTime(), new Date(x.modified).getTime());
      else assert.equal(item.modified, undefined);
      if (x.modifiedRaw) assert.equal(item.modifiedRaw, x.modifiedRaw);
      if (x.hasType) assert.ok(item.hasType(x.hasType));
    });
  });
});

describe("Linkset — responses/linkset.json", () => {
  const fx = fixture("responses/linkset.json");
  const e = fx.expected;

  test("parse, targets and round trip", () => {
    const ls = Linkset.parse(fx.body);
    assert.equal(ls.contexts.length, e.contexts);
    assert.equal(ls.contexts[0]!.anchor, e.anchor);
    assert.equal(ls.links().length, e.linkCount);
    for (const [rel, hrefs] of Object.entries(e.targets)) {
      assert.deepEqual(ls.targets(rel).map((t) => t.href), hrefs);
    }
    assert.deepEqual(JSON.parse(JSON.stringify(ls)), fx.body);
  });

  test("add and remove", () => {
    const ls = Linkset.parse(fx.body);
    const op = e.afterAdd.operation;
    ls.add(op.anchor, op.rel, op.href);
    assert.deepEqual(ls.targets("license").map((t) => t.href), e.afterAdd.licenseTargets);
    assert.equal(ls.remove(op.anchor, "license", op.href), 1);
    assert.equal(ls.remove(op.anchor, "license"), 1);
    assert.equal(ls.targets("license").length, 0);
    const copy = Linkset.parse(fx.body).clone();
    assert.deepEqual(copy.toJSON(), fx.body);
  });

  test("metadata headers", () => {
    const meta = new ResourceMetadata(fx.url, 200, headersOf(fx.headers));
    assert.deepEqual(meta.allow, e.allow);
    assert.deepEqual(meta.acceptPatch, e.acceptPatch);
    assert.equal(meta.etag, e.etag);
  });
});

describe("Notifications — responses/notification.json", () => {
  const fx = fixture("responses/notification.json");

  for (const kind of ["single", "batch", "move"] as const) {
    test(kind, () => {
      const n = parseNotification(JSON.stringify(fx[kind]));
      const exp = fx[`${kind}Expected`];
      assert.equal(n.storage, exp.storage);
      assert.equal(n.activities.length, exp.activities.length);
      n.activities.forEach((a, i) => {
        const x = exp.activities[i];
        assert.equal(a.id, x.id);
        assert.deepEqual(a.types, x.types);
        assert.equal(a.object.id, x.objectId);
        if (x.objectTypes) assert.deepEqual(a.object.types, x.objectTypes);
        if (x.target) assert.equal(a.target, x.target);
        if (x.origin) assert.equal(a.origin, x.origin);
        if (x.actor) assert.equal(a.actor, x.actor);
        if (x.published) assert.equal(a.published?.getTime(), new Date(x.published).getTime());
        if (x.isCreate !== undefined) assert.equal(a.isCreate(), x.isCreate);
        if (x.isUpdate !== undefined) assert.equal(a.isUpdate(), x.isUpdate);
        if (x.isDelete !== undefined) assert.equal(a.isDelete(), x.isDelete);
        if (x.isMove !== undefined) assert.equal(a.isMove(), x.isMove);
      });
    });
  }

  test("invalid", () => {
    assert.throws(() => parseNotification(fx.invalid), ProtocolError);
    assert.throws(() => parseNotification("{not json"), ProtocolError);
  });

  test("bytes input", () => {
    const n = parseNotification(new TextEncoder().encode(JSON.stringify(fx.single)));
    assert.equal(n.activities[0]!.isDelete(), true);
  });
});

describe("Moves — move.json", () => {
  const fx = fixture("move.json");

  for (const c of fx.patches) {
    test(`patch: ${c.name}`, () => {
      const build = () => movePatch(c.resource, c.linksetUrl, c.linkset, c.destination);
      if (c.error) {
        assert.throws(build, ProtocolError);
        return;
      }
      assert.deepEqual(build().toJSON(), c.expected);
      assert.deepEqual(movePatch(c.resource, c.linksetUrl, Linkset.parse(c.linkset), c.destination).toJSON(), c.expected);
    });
  }

  for (const c of fx.responses) {
    test(`response: ${c.name}`, async () => {
      const body = c.body === null ? null : JSON.stringify(c.body);
      const r = await readMoveResult(c.resource, c.linksetUrl, new Response(body, { status: c.status, headers: c.headers }));
      assert.equal(r.status, c.status);
      assert.equal(r.location, c.expected.location);
      assert.equal(r.linkset, c.expected.linkset);
      assert.equal(r.identifierPreserved, c.expected.identifierPreserved);
      assert.equal(r.etag ?? null, c.expected.etag);
      assert.equal(r.metadata.status, c.status);
      assert.equal(r.document === undefined, c.body === null);
    });
  }

  test("an answer that is not a linkset is a ProtocolError", async () => {
    const response = new Response("[1]", { status: 200, headers: { "content-type": "application/linkset+json" } });
    await assert.rejects(readMoveResult("https://s.example/a", "https://s.example/a.meta", response), ProtocolError);
  });
});

describe("Access requests and grants — responses/access.json", () => {
  const fx = fixture("responses/access.json");

  test("parse request and grant", () => {
    const req = AccessRequest.parse(fx.request);
    assert.equal(req.storage, "https://storage.example/");
    assert.equal(req.inbox, "https://id.example/agent/inbox/");
    assert.deepEqual(req.access[0]!.actions, ["read", "create"]);
    assert.equal(req.access[0]!.constraints?.length, 2);
    const grant = AccessGrant.parse(fx.grant);
    assert.deepEqual(grant.access[0]!.constraints![0]!.rightOperand, ["image/jpeg", "image/png"]);
    assert.throws(() => AccessGrant.parse(fx.request), ProtocolError);
  });

  test("builder output equals the fixture", () => {
    const req = new AccessRequest({
      storage: "https://storage.example/",
      inbox: "https://id.example/agent/inbox/",
      access: [
        {
          actions: [Action.READ, Action.CREATE],
          assignee: "https://id.example/agent",
          target: { type: "StorageResource", values: ["https://storage.example/root/projects/"] },
          constraints: [Constraints.purpose("https://purpose.example/collaboration"), Constraints.notAfter(new Date("2026-06-09T10:00:00Z"))],
        },
      ],
    });
    assert.deepEqual(req.toJSON(), fx.request);
    assert.deepEqual(AccessGrant.parse(fx.grant).toJSON(), fx.grant);
  });

  test("validation", () => {
    assert.throws(() => new AccessRequest({ storage: "", access: [] }), TypeError);
    assert.throws(
      () => new AccessGrant({ storage: "https://s.example/", access: [{ actions: [], assignee: "x" }] }).toJSON(),
      TypeError,
    );
  });
});

describe("Type index / search pages — responses/type-index.json", () => {
  const fx = fixture("responses/type-index.json");

  test("type index page", () => {
    const t = fx.typeIndex;
    const page = new TypeIndexPage(t.body, new ResourceMetadata(t.url, 200, headersOf(t.headers)));
    assert.equal(page.totalItems, t.expected.totalItems);
    assert.deepEqual(page.types, t.expected.types);
    assert.equal(page.next, t.expected.next);
  });

  test("search page", () => {
    const s = fx.search;
    const page = new ContainerPage(s.body, new ResourceMetadata(s.url, 200, headersOf(s.headers)));
    assert.equal(page.totalItems, s.expected.totalItems);
    assert.deepEqual(page.items.map((i) => i.id), s.expected.ids);
    assert.equal(page.next, s.expected.next);
    assert.ok(page.items[2]!.isContainer());
    assert.ok(page.items[0]!.hasType(LwsType.DATA_RESOURCE));
  });
});
