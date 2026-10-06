// SPDX-License-Identifier: MIT
// Test helpers: server lifecycle, did:key agents, token exchange, an inbox server and an
// independent RFC 9421 / RFC 9530 webhook verifier.

import { createHash, createPublicKey, generateKeyPairSync, randomUUID, verify } from "node:crypto";
import http from "node:http";
import { publicJwkToDidKey, signJwt } from "../lib/crypto.mjs";
import { startServer } from "../lib/server.mjs";

export const JWT_TYPE = "urn:ietf:params:oauth:token-type:jwt";
export const TOKEN_EXCHANGE = "urn:ietf:params:oauth:grant-type:token-exchange";
export const LWS = "https://www.w3.org/ns/lws#";

export function launch(options = {}) {
  return startServer({ port: 0, ...options });
}

export function didKeyAgent(kind = "P-256") {
  const { privateKey, publicKey } = kind === "Ed25519" ? generateKeyPairSync("ed25519") : generateKeyPairSync("ec", { namedCurve: "P-256" });
  const publicJwk = publicKey.export({ format: "jwk" });
  const { did, kid } = publicJwkToDidKey(publicJwk);
  const alg = kind === "Ed25519" ? "EdDSA" : "ES256";
  return {
    did,
    kid,
    alg,
    privateKey,
    publicJwk,
    credential(aud, claims = {}, header = {}) {
      const iat = Math.floor(Date.now() / 1000);
      return signJwt(
        { alg, typ: "JWT", kid, ...header },
        { sub: did, iss: did, client_id: did, aud: [aud], iat, exp: iat + 300, jti: randomUUID(), ...claims },
        privateKey,
      );
    },
  };
}

export async function exchange(base, subjectToken, { type = JWT_TYPE, resource = `${base}/`, extra = {} } = {}) {
  const params = { grant_type: TOKEN_EXCHANGE, resource, subject_token: subjectToken, subject_token_type: type, ...extra };
  for (const [k, v] of Object.entries(params)) if (v === undefined || v === null) delete params[k];
  const response = await fetch(`${base}/oauth/token`, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams(params),
  });
  return { status: response.status, headers: response.headers, body: await response.json() };
}

export async function login(base, agent = didKeyAgent()) {
  const { status, body } = await exchange(base, agent.credential(base));
  if (status !== 200) throw new Error(`token exchange failed: ${JSON.stringify(body)}`);
  return { token: body.access_token, agent };
}

/** fetch() bound to a bearer token. */
export function authed(token) {
  return (url, init = {}) => fetch(url, { ...init, headers: { authorization: `Bearer ${token}`, ...(init.headers ?? {}) } });
}

export function decodePayload(jwt) {
  return JSON.parse(Buffer.from(jwt.split(".")[1], "base64url").toString("utf8"));
}

export function linkHeader(response) {
  return response.headers.get("link") ?? "";
}

/** Minimal Link parser for assertions: returns [{href, rel, params}] (hrefs resolved against base). */
export function links(response, base) {
  const out = [];
  const re = /<([^>]*)>([^,<]*)/g;
  let m;
  while ((m = re.exec(linkHeader(response)))) {
    const params = {};
    for (const p of m[2].split(";").slice(1)) {
      const [k, v = ""] = p.split("=");
      params[k.trim().toLowerCase()] = v.trim().replace(/^"|"$/g, "");
    }
    for (const rel of (params.rel ?? "").split(/\s+/).filter(Boolean)) out.push({ href: new URL(m[1], base).href, rel, params });
  }
  return out;
}

export const linkTo = (response, base, rel) => links(response, base).filter((l) => l.rel === rel).map((l) => l.href);

export async function startInbox({ status = 202 } = {}) {
  const received = [];
  const waiters = new Set();
  const server = http.createServer((req, res) => {
    const chunks = [];
    req.on("data", (c) => chunks.push(c));
    req.on("end", () => {
      received.push({ method: req.method, url: req.url, headers: req.headers, body: Buffer.concat(chunks) });
      res.writeHead(status).end();
      for (const w of waiters) w();
    });
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const url = `http://127.0.0.1:${server.address().port}/inbox`;
  return {
    url,
    received,
    async waitFor(n, timeoutMs = 5000) {
      const deadline = Date.now() + timeoutMs;
      while (received.length < n) {
        if (Date.now() > deadline) throw new Error(`timed out waiting for ${n} deliveries (got ${received.length})`);
        await new Promise((resolve) => {
          const done = () => {
            waiters.delete(done);
            resolve();
          };
          waiters.add(done);
          setTimeout(done, 50);
        });
      }
      return received;
    },
    close: () =>
      new Promise((resolve) => {
        server.close(() => resolve());
        server.closeAllConnections?.();
      }),
  };
}

/**
 * Independent RFC 9421 verification of a webhook delivery as described in
 * lws10-notifications-webhook "Signature Verification". Returns {keyid, notification}; throws on failure.
 */
export async function verifyDelivery(delivery, inboxUrl, { maxAge = 300 } = {}) {
  const h = delivery.headers;
  const digest = /sha-256=:([^:]+):/.exec(h["content-digest"] ?? "")?.[1];
  if (!digest) throw new Error("missing sha-256 Content-Digest");
  if (createHash("sha256").update(delivery.body).digest("base64") !== digest) throw new Error("content digest mismatch");

  const input = h["signature-input"];
  const label = input.slice(0, input.indexOf("="));
  const params = input.slice(label.length + 1);
  const components = [.../^\(([^)]*)\)/.exec(params)[1].matchAll(/"([^"]+)"/g)].map((m) => m[1]);
  for (const required of ["@method", "@scheme", "@authority", "@path", "content-type", "content-digest"]) {
    if (!components.includes(required)) throw new Error(`component ${required} not covered`);
  }
  const created = Number(/;created=(\d+)/.exec(params)?.[1]);
  const keyid = /;keyid="([^"]+)"/.exec(params)?.[1];
  if (!created || !keyid) throw new Error("created and keyid are required");
  if (Math.abs(Date.now() / 1000 - created) > maxAge) throw new Error("signature outside the allowed window");

  const target = new URL(inboxUrl);
  const value = (c) =>
    ({
      "@method": delivery.method.toUpperCase(),
      "@scheme": target.protocol.slice(0, -1),
      "@authority": target.host,
      "@path": target.pathname,
    })[c] ?? String(h[c]).trim();
  const base = [...components.map((c) => `"${c}": ${value(c)}`), `"@signature-params": ${params}`].join("\n");

  const keyUrl = new URL(keyid);
  if (!keyUrl.hash) throw new Error("keyid has no fragment");
  const storageId = keyid.slice(0, keyid.indexOf("#"));
  const description = await (await fetch(storageId)).json();
  if (description.id !== storageId) throw new Error("storage description id mismatch");
  const vm = description.verificationMethod.find((m) => m.id === keyid || m.id === keyUrl.hash);
  if (!vm) throw new Error("verification method not found");
  if (!description.authentication.includes(vm.id)) throw new Error("key not referenced from authentication");
  const signature = Buffer.from(/=:([^:]+):/.exec(h.signature)[1], "base64");
  const key = createPublicKey({ key: { kty: vm.publicKeyJwk.kty, crv: vm.publicKeyJwk.crv, x: vm.publicKeyJwk.x, y: vm.publicKeyJwk.y }, format: "jwk" });
  if (!verify("sha256", Buffer.from(base), { key, dsaEncoding: "ieee-p1363" }, signature)) throw new Error("signature verification failed");
  const notification = JSON.parse(delivery.body.toString("utf8"));
  if (notification.storage !== storageId) throw new Error("notification storage mismatch");
  return { keyid, notification, signatureBase: base };
}

export const activitiesOf = (notification) => (Array.isArray(notification.activity) ? notification.activity : [notification.activity]);
