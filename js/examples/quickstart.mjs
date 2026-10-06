// SPDX-License-Identifier: MIT
// Quickstart: discover a storage, create / read / update / patch / list / delete.
//
//   npm run build
//   node ../testing/mock-server/server.mjs --port 8787      (in another terminal)
//   LWS_SERVER=http://localhost:8787 node examples/quickstart.mjs
import {
  LwsClient,
  TokenExchangeAuthenticator,
  SelfSignedCredentials,
  generateKeyPair,
  JsonPatch,
  NotFoundError,
} from "lws-client";

const server = (process.env.LWS_SERVER ?? "http://localhost:8787").replace(/\/$/, "");

// A self-sovereign identity for this script (did:key over a fresh P-256 key).
const credentials = SelfSignedCredentials.didKey(await generateKeyPair("ES256"));
const client = new LwsClient({ authenticator: new TokenExchangeAuthenticator(credentials) });
console.log("agent:", credentials.agent);

// 1. Discovery: any resource URL leads to the storage description.
const storage = await client.discoverStorage(`${server}/root/`);
const root = storage.storageRoot();
console.log("storage:", storage.id, "root:", root);

// 2. Create a container and a couple of resources in it.
const { location: notes } = await client.createContainer(root, { slug: `notes-${Date.now()}` });
const { location: list } = await client.createText(notes, "milk\neggs\nbread\n", { slug: "shopping.txt" });
const { location: todo } = await client.createJson(notes, { done: false, task: "write docs" }, { slug: "todo.json" });
console.log("created:", list, todo);

// 3. Read with metadata; update with optimistic concurrency.
const resource = await client.read(list);
console.log(await resource.text(), "etag:", resource.etag, "parent:", resource.parent);
await client.update(list, "milk\neggs\nbread\nbutter\n", "text/plain", { ifMatch: resource.etag });

// 4. Partial update with JSON Patch (the LWS baseline patch format).
await client.patch(todo, new JsonPatch().replace("/done", true));
console.log("todo:", await (await client.read(todo)).json());

// 5. List the container (pagination is followed automatically).
for await (const item of client.listContainer(notes)) {
  console.log(` - ${item.id} (${item.format ?? "container"}, ${item.size ?? "?"} bytes)`);
}

// 6. Metadata lives in the resource's linkset.
const linkset = await client.readLinkset(todo);
await client.patchLinkset(
  linkset.url,
  new JsonPatch().add("/linkset/0/describedby", [{ href: "https://example.org/shapes/todo" }]),
  { ifMatch: linkset.etag },
);
console.log("describedby:", (await client.readLinkset(todo)).linkset.targets("describedby").map((t) => t.href));

// 7. Clean up.
await client.delete(notes, { recursive: true });
try {
  await client.read(list);
} catch (e) {
  if (e instanceof NotFoundError) console.log("deleted.");
  else throw e;
}
