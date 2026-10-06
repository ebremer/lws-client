// SPDX-License-Identifier: MIT
// Receive verified webhook notifications (lws10-notifications-webhook) in Node.js.
//
//   LWS_SERVER=http://localhost:8787 node examples/webhook-receiver.mjs
import { createServer } from "node:http";
import {
  LwsClient,
  TokenExchangeAuthenticator,
  SelfSignedCredentials,
  generateKeyPair,
  WebhookVerifier,
} from "lws-client";
import { createWebhookHandler } from "lws-client/node";

const server = (process.env.LWS_SERVER ?? "http://localhost:8787").replace(/\/$/, "");
const port = Number(process.env.INBOX_PORT ?? 8790);
const inboxUrl = process.env.INBOX_URL ?? `http://127.0.0.1:${port}/inbox`; // must be reachable by the storage

const client = new LwsClient({
  authenticator: new TokenExchangeAuthenticator(SelfSignedCredentials.didKey(await generateKeyPair())),
});
const storage = await client.discoverStorage(`${server}/root/`);

// Verify signatures with the key published in the storage description.
const verifier = new WebhookVerifier({
  resolveStorageDescription: (id) => client.getStorageDescription(id),
  trustedStorages: [storage.id],
});

const handler = createWebhookHandler(
  verifier,
  (notification) => {
    for (const a of notification.activities) {
      console.log(`${a.published?.toISOString() ?? "?"} ${a.types.join(",")} ${a.object.id}`);
    }
  },
  { inboxUrl, onError: (e) => console.error("rejected delivery:", e.message) },
);
createServer((req, res) => void handler(req, res)).listen(port, "127.0.0.1");

// Subscribe to the whole storage root (container subscriptions are recursive).
const subscription = await client.subscribe(storage.notificationService(), {
  topics: [storage.storageRoot()],
  inbox: inboxUrl,
  expires: new Date(Date.now() + 60 * 60 * 1000),
});
console.log("subscribed:", subscription.subscription, "— listening on", inboxUrl);

// Make a change so there is something to see, then clean up on Ctrl+C.
const { location } = await client.createText(storage.storageRoot(), "ping", { slug: "ping.txt" });
await client.delete(location);
process.on("SIGINT", async () => {
  await client.unsubscribe(subscription.subscription);
  process.exit(0);
});
