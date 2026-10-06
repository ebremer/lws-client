// SPDX-License-Identifier: MIT
// Self-signed authentication (lws10-authn-ssi-cid) for bots and server-side scripts.
//
// Two identities are shown:
//   * did:key — the identifier is derived from the public key; nothing to host.
//   * an HTTPS agent URI — you publish a controlled identifier document listing the key.
//
//   LWS_SERVER=http://localhost:8787 node examples/self-signed-auth.mjs
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import {
  LwsClient,
  TokenExchangeAuthenticator,
  SelfSignedCredentials,
  generateKeyPair,
  importKeyPair,
  exportPrivateJwk,
  controlledIdentifierDocument,
} from "lws-client";

const server = (process.env.LWS_SERVER ?? "http://localhost:8787").replace(/\/$/, "");
const keyFile = process.env.LWS_KEY_FILE ?? "agent-key.jwk.json";

// Persist the key so the agent keeps the same identity between runs.
let pair;
if (existsSync(keyFile)) {
  pair = await importKeyPair(JSON.parse(readFileSync(keyFile, "utf8")));
} else {
  pair = await generateKeyPair("ES256", { extractable: true });
  writeFileSync(keyFile, JSON.stringify(await exportPrivateJwk(pair), null, 2), { mode: 0o600 });
  console.log(`new key written to ${keyFile} (keep it secret)`);
}

// did:key identity.
const didKeyCredentials = SelfSignedCredentials.didKey(pair);
console.log("did:key agent:", didKeyCredentials.agent);

// HTTPS identity: publish this document at the agent URI.
const agent = "https://bot.example/agent";
console.log("CID document to publish at", agent, JSON.stringify(controlledIdentifierDocument(agent, pair.publicJwk, "key-1"), null, 2));
const _httpsCredentials = SelfSignedCredentials.forAgent(agent, pair, "key-1");

// Authenticate: the first request receives a 401 challenge, the authenticator
// fetches the authorization server metadata, exchanges a freshly signed JWT for
// an access token, and the client retries transparently.
const client = new LwsClient({
  authenticator: new TokenExchangeAuthenticator(didKeyCredentials, {
    // Only trust the authorization server we expect (recommended for static tokens).
    authorizationServerFilter: (asUri) => new URL(asUri).origin === new URL(server).origin,
  }),
});
const meta = await client.head(`${server}/root/`);
console.log("authenticated HEAD:", meta.status, "container:", meta.isContainer());
