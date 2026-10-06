// SPDX-License-Identifier: MIT
import { test, describe } from "node:test";
import assert from "node:assert/strict";
import { createServer } from "node:http";
import type { AddressInfo } from "node:net";
import {
  WebhookVerifier,
  SignatureVerificationError,
  parseDictionary,
  signatureBase,
  StorageDescription,
  LwsClient,
  type SfInnerList,
} from "../src/index.js";
import { createWebhookHandler } from "../src/node.js";
import { fixture } from "./support/fixtures.js";

const index = fixture("webhook/index.json");
const description = fixture("webhook/storage-description.json");

function verifierAt(nowSeconds: number, extra: Partial<ConstructorParameters<typeof WebhookVerifier>[0]> = {}): WebhookVerifier {
  return new WebhookVerifier({
    resolveStorageDescription: async () => description,
    clock: () => nowSeconds * 1000,
    ...extra,
  });
}

describe("Webhook vectors — conformance/fixtures/webhook", () => {
  for (const file of index.vectors as string[]) {
    const v = fixture(`webhook/${file}`);
    test(`${v.name}: ${v.expected.valid ? "valid" : "invalid"}`, async () => {
      const verifier = verifierAt(v.now);
      const request = { method: v.method, url: v.url, headers: v.headers, body: v.body };
      if (v.expected.valid) {
        const result = await verifier.verify(request);
        assert.equal(result.keyid, v.expected.keyid);
        assert.equal(result.storage, "https://storage.example/");
        const n = result.notification;
        assert.equal(n.storage, v.expected.notification.storage);
        assert.deepEqual(
          n.activities.map((a) => ({ types: a.types, objectId: a.object.id, ...(a.target ? { target: a.target } : {}) })),
          v.expected.notification.activities,
        );
      } else {
        await assert.rejects(verifier.verify(request), SignatureVerificationError);
      }
    });
  }

  test("signature base matches the fixture exactly", () => {
    for (const file of index.vectors as string[]) {
      const v = fixture(`webhook/${file}`);
      if (!v.signatureBase) continue;
      const dict = parseDictionary(v.headers["signature-input"]);
      const member = dict.get("sig1") as SfInnerList;
      assert.equal(signatureBase(member, v.method, new URL(v.url), new Headers(v.headers)), v.signatureBase);
    }
  });

  test("accepts a Fetch API Request and an inboxUrl override", async () => {
    const v = fixture("webhook/p256-valid.json");
    const verifier = verifierAt(v.now);
    const req = new Request("http://10.0.0.5:8080/hooks/lws?subscription=9e8d7c6b5a4f", {
      method: "POST",
      headers: v.headers,
      body: v.body,
    });
    const result = await verifier.verify(req, { inboxUrl: v.url });
    assert.equal(result.label, "sig1");
  });

  test("trustedStorages", async () => {
    const v = fixture("webhook/p256-valid.json");
    const request = { method: v.method, url: v.url, headers: v.headers, body: v.body };
    await assert.rejects(verifierAt(v.now, { trustedStorages: ["https://other.example/"] }).verify(request), SignatureVerificationError);
    await verifierAt(v.now, { trustedStorages: ["https://storage.example/"] }).verify(request);
  });

  test("key rotation: a stale cached description is refetched once", async () => {
    const v = fixture("webhook/p256-valid.json");
    const stale = JSON.parse(JSON.stringify(description));
    stale.verificationMethod[0].publicKeyJwk = description.verificationMethod[2].publicKeyJwk; // wrong key
    let calls = 0;
    const verifier = new WebhookVerifier({
      resolveStorageDescription: async () => (calls++ === 0 ? stale : description),
      clock: () => v.now * 1000,
    });
    const request = { method: v.method, url: v.url, headers: v.headers, body: v.body };
    // First call: fresh (uncached) stale key → fails without retry.
    await assert.rejects(verifier.verify(request), SignatureVerificationError);
    // Second call: cached stale key fails, refetch returns the right key.
    await verifier.verify(request);
    assert.equal(calls, 2);
  });

  test("resolves storage descriptions through an LwsClient", async () => {
    const v = fixture("webhook/ed25519-valid.json");
    const client = new LwsClient({
      fetch: async (input) => {
        assert.equal(String(input), "https://storage.example/");
        return new Response(JSON.stringify(description), { headers: { "content-type": "application/lws+cid" } });
      },
    });
    const verifier = new WebhookVerifier({
      resolveStorageDescription: (id) => client.getStorageDescription(id),
      clock: () => v.now * 1000,
    });
    const result = await verifier.verify({ method: v.method, url: v.url, headers: v.headers, body: new TextEncoder().encode(v.body) });
    assert.ok(result.notification.activities[0]!.isCreate());
    assert.ok(new StorageDescription(description).isAuthenticationKey("#key-ed25519"));
  });
});

describe("Node webhook handler (lws-client/node)", () => {
  test("verifies a real HTTP delivery and answers 204 / 401", async () => {
    const v = fixture("webhook/p256-valid.json");
    const received: string[] = [];
    const handler = createWebhookHandler(verifierAt(v.now), (n) => void received.push(n.activities[0]!.object.id), {
      inboxUrl: v.url,
    });
    const server = createServer((req, res) => void handler(req, res));
    await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
    const port = (server.address() as AddressInfo).port;
    try {
      const ok = await fetch(`http://127.0.0.1:${port}/hooks/lws`, { method: "POST", headers: v.headers, body: v.body });
      assert.equal(ok.status, 204);
      assert.deepEqual(received, ["https://storage.example/root/notes/meeting.txt"]);
      const bad = await fetch(`http://127.0.0.1:${port}/hooks/lws`, { method: "POST", headers: v.headers, body: v.body + " " });
      assert.equal(bad.status, 401);
      const get = await fetch(`http://127.0.0.1:${port}/hooks/lws`);
      assert.equal(get.status, 405);
    } finally {
      server.close();
    }
  });
});
