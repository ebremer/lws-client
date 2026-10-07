#!/usr/bin/env node
// SPDX-License-Identifier: MIT
// Plays Touchstone's part: for each language, starts a Touchstone client session, drives that language's
// lws-client through the driver's MCP tools so that it meets every client rule (the checklist's tasks and
// faults included), and reads back the session's verdict.
//
//   node driver/touchstone/run-sessions.mjs --touchstone http://localhost:18090/touchstone/clients \
//       --driver http://127.0.0.1:18095/mcp [--token T] [--languages java,js,python,go,rust,cpp] [--out dir] [--keep]
//
// The Touchstone service must be able to deliver notifications to the driver's inbox: run it locally with
// --allow-private-inboxes, or give the driver a public base URL. Exit status 0 when no session has a MUST
// failure.

import { createHash, randomBytes } from "node:crypto";
import { mkdir, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { parseArgs } from "node:util";
import { McpClient } from "./mcp-client.mjs";

const { values: opts } = parseArgs({
  options: {
    touchstone: { type: "string", default: "http://localhost:18090/touchstone/clients" },
    driver: { type: "string", default: "http://127.0.0.1:18095/mcp" },
    token: { type: "string", default: process.env.LWS_DRIVER_TOKEN },
    languages: { type: "string" },
    areas: { type: "string", default: "core,authentication,notifications,index" },
    out: { type: "string" },
    keep: { type: "boolean", default: false },
    verbose: { type: "boolean", default: false },
  },
});

const PERSON = "https://schema.org/Person";
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const hasType = (types, term) => (types ?? []).some((t) => t === term || t.endsWith(`#${term}`) || t === `lws:${term}`);

const mcp = new McpClient(opts.driver, { token: opts.token });
await mcp.connect();

const available = (await mcp.call("list_languages", {})).languages.filter((l) => l.available).map((l) => l.language);
const languages = opts.languages ? opts.languages.split(",") : available;
if (opts.out) await mkdir(opts.out, { recursive: true });

let mustFailures = 0;
const summaries = [];
for (const language of languages) {
  try {
    const summary = await drive(language);
    summaries.push(summary);
    mustFailures += summary.verdict.mustFailed + (summary.scenarioError ? 1 : 0);
  } catch (e) {
    mustFailures++;
    summaries.push({ language, error: e.message });
  }
}
await mcp.close();

console.log("");
for (const s of summaries) {
  if (s.error) {
    console.log(`${s.language.padEnd(7)} ERROR ${s.error}`);
    continue;
  }
  const c = s.counts;
  console.log(`${s.language.padEnd(7)} ${s.library.padEnd(24)} ${s.verdict.text}  (passed ${c.passed}, failed ${c.failed}, untested ${c.untested}, inapplicable ${c.inapplicable})`);
  for (const r of s.failed) console.log(`        failed ${r.level} ${r.rule}: ${r.guidance}`);
  if (s.scenarioError) console.log(`        scenario stopped early: ${s.scenarioError}`);
  if (s.untested.length) console.log(`        untested: ${s.untested.join(", ")}`);
  if (s.page) console.log(`        session: ${s.page}`);
}
process.exit(mustFailures > 0 ? 1 : 0);

// ---------------------------------------------------------------------------------------------

async function drive(language) {
  const log = (line) => console.log(`[${language}] ${line}`);
  const run = `${language}-${Date.now()}`;

  // The session, as Touchstone holds it.
  const created = await touchstone("POST", `${opts.touchstone}/sessions`, undefined, {
    clientUnderTest: { name: `lws-client (${language})`, homepage: "https://github.com/ebremer/lws-client" },
    areas: opts.areas.split(","),
  });
  const { key, api, storage } = created;
  const session = await touchstone("GET", api, key);
  const alice = await touchstone("GET", `${api}/credentials/alice`, key);
  const task = (rule) => touchstone("POST", `${api}/tasks/${rule}`, key);
  let scenarioError;
  log(`session ${api}, storage ${storage}`);

  // The client, as the driver runs it: alice's self-issued credentials (the CID suite).
  const started = await mcp.call("start_client", {
    language, authType: "selfSigned", agent: alice.webid, privateJwk: alice.privateKeyJwk, kid: alice.verificationMethod,
    label: `touchstone ${run}`,
  });
  const client = started.client;
  await touchstone("PATCH", api, key, { clientUnderTest: { name: `lws-client (${language})`, version: started.library } });
  const inbox = (await mcp.call("open_inbox", { client })).inbox;
  log(`client ${client} (${started.library}), inbox ${inbox}`);

  async function op(name, args, expect) {
    const response = await mcp.call(name, { client, ...args });
    const outcome = response.ok ? "ok" : `${response.error.kind}${response.error.status ? ` ${response.error.status}` : ""}`;
    if (opts.verbose || (expect ?? "ok") !== outcome) log(`${name} -> ${outcome}${response.ok ? "" : `: ${response.error.message}`}`);
    if (expect !== undefined && outcome !== expect) log(`  (expected ${expect})`);
    if (expect === undefined && !response.ok) throw new Error(`${name} failed: ${response.error.kind}: ${response.error.message}`);
    return response.ok ? response.result : response.error;
  }

  // A careful client writes only what it has just read: If-Match with the ETag of its last read.
  const etagOf = async (url) => (await op("head", { url })).etag;

  async function nextDelivery(after) {
    for (let i = 0; i < 50; i++) {
      const { deliveries } = await mcp.call("inbox_deliveries", { client, after });
      if (deliveries.length) return deliveries[0];
      await sleep(200);
    }
    return undefined;
  }

  try {
    // Discovery and listing.
    const description = await op("discover_storage", { url: storage });
    const root = description.storageRoot;
    const service = (type) => description.services.find((s) => hasType(s.types, type))?.serviceEndpoint;
    const rootPage = await op("read_container", { url: root });
    await op("list_container", { url: root });

    // Containers and data resources.
    await task("client-create-container-type-link");
    const container = (await op("create_container", { parent: root, slug: run })).location;
    const hello = (await op("create", { container, body: { text: "Hello, Touchstone" }, contentType: "text/plain", slug: "hello.txt" })).location;
    const first = await op("read", { url: hello });
    await op("read", { url: hello, ifNoneMatch: first.metadata.etag });
    await op("head", { url: hello });
    await op("update", { url: hello, body: { text: "Hello again" }, contentType: "text/plain", ifMatch: first.metadata.etag });
    await op("update", { url: hello, body: { text: "stale" }, contentType: "text/plain", ifMatch: first.metadata.etag }, "PreconditionFailedError 412");

    const profile = (await op("create", { container, body: { json: { name: "Alice", age: 30 } }, slug: "profile.json", types: [PERSON] })).location;
    await op("patch", { url: profile, patch: [{ op: "replace", path: "/age", value: 31 }, { op: "add", path: "/city", value: "Boston" }] });

    // Linksets, and a refused PUT that must not be repeated.
    const linkset = await op("read_linkset", { url: profile });
    await op("patch_linkset", { linksetUrl: linkset.url, ifMatch: linkset.etag,
      patch: [{ op: "add", path: "/linkset/0/describedby", value: [{ href: "https://example.org/shapes/person" }] }] });
    const current = await op("read_linkset", { url: profile });
    await task("client-no-repeat-after-405-415");
    await op("update_linkset", { linksetUrl: current.url, linkset: current.linkset, ifMatch: current.etag }, "MethodNotAllowedError 405");
    await op("read_linkset", { url: profile });

    // A create whose answer is lost: look before creating again.
    await task("client-no-blind-retry-of-create");
    await op("create", { container, body: { text: "maybe" }, contentType: "text/plain", slug: "lost.txt" }, "HttpError 503");
    await op("read_container", { url: container });

    // Type index and search, with a page that has expired.
    for (let i = 0; i < 5; i++) {
      await op("create", { container, body: { json: { name: `Person ${i}` } }, slug: `person-${i}.json`, types: [PERSON] });
    }
    await op("list_container", { url: container });
    const typeIndex = service("TypeIndexService");
    const typeSearch = service("TypeSearchService");
    if (typeIndex && typeSearch) {
      await sleep(4000);
      await op("read_type_index", { url: typeIndex });
      await op("list_types", { serviceUrl: typeIndex });
      await op("accepted_query_formats", { serviceUrl: typeSearch });
      await op("search_types", { serviceUrl: typeSearch, query: { type: [PERSON] } });
      await task("client-restart-after-refused-page");
      await op("search_all", { serviceUrl: typeSearch, query: { type: [PERSON] } }, "GoneError 410");
      await op("search_types", { serviceUrl: typeSearch, query: { type: [PERSON] } });
    }

    // Notifications: a genuine one, then four forgeries the inbox must refuse.
    const notifications = service("NotificationService");
    if (notifications) {
      const subscription = await op("subscribe", { serviceUrl: notifications, topics: [container] });
      let seen = 0;
      await op("update", { url: hello, body: { text: "Hello, notifications" }, contentType: "text/plain", ifMatch: await etagOf(hello) });
      const genuine = await nextDelivery(seen);
      log(`genuine notification: ${genuine ? `answered ${genuine.answer}` : "none arrived"}`);
      seen = genuine?.sequence ?? seen;
      for (const rule of ["client-inbox-refuses-unpublished-key", "client-inbox-refuses-altered-body",
        "client-inbox-refuses-keyid-without-fragment", "client-inbox-refuses-foreign-key-document"]) {
        await task(rule);
        await op("update", { url: hello, body: { text: `Hello, ${rule}` }, contentType: "text/plain", ifMatch: await etagOf(hello) });
        const forged = await nextDelivery(seen);
        log(`${rule}: ${forged ? `answered ${forged.answer}` : "none arrived"}`);
        seen = forged?.sequence ?? seen;
      }
      await op("list_subscriptions", { serviceUrl: notifications });
      await op("get_subscription", { url: subscription.subscription });
      await op("unsubscribe", { url: subscription.subscription });
    }

    // Access requests and grants, when the storage has the services.
    const requests = service("AccessRequestService");
    const grants = service("AccessGrantService");
    if (requests && grants) {
      const bob = session.identities?.bob?.webid;
      const policy = {
        type: ["AccessPolicy"], action: ["read"], assignee: bob, target: { type: "StorageResource", value: [container] },
        constraint: [{ leftOperand: "purpose", operator: "eq", rightOperand: "https://purpose.example/testing" }],
      };
      const doc = (type) => ({ "@context": ["https://www.w3.org/ns/lws/v1"], type: [type], storage: description.id, inbox, access: [policy] });
      const request = (await op("request_access", { serviceUrl: requests, request: doc("AccessRequest") })).location;
      await op("get_access_request", { url: request });
      await op("list_access_requests", { serviceUrl: requests });
      const grant = (await op("grant_access", { serviceUrl: grants, grant: doc("AccessGrant") })).location;
      await op("get_access_grant", { url: grant });
      await op("list_access_grants", { serviceUrl: grants });
      await op("revoke_access_grant", { url: grant });
      await op("cancel_access_request", { url: request });
    }

    // The decoy names a realm that does not contain it; then the token expires.
    await task("client-token-for-containing-realm");
    // The root container lists the decoy first.
    const decoy = rootPage.items[0]?.id;
    if (decoy) {
      const outcome = await mcp.call("read", { client, url: decoy });
      log(`decoy ${decoy} -> ${outcome.ok ? "ok" : outcome.error.kind}`);
    }
    const afterExpiry = await mcp.call("read", { client, url: hello });
    log(`read after the token expired -> ${afterExpiry.ok ? "ok" : `${afterExpiry.error.kind}: ${afterExpiry.error.message}`}`);

    // The OpenID Connect suite: sign in at the session's provider as alice, and give a second client her
    // ID Token to exchange.
    const idToken = await signIn(api, key, session, alice);
    const oidc = (await mcp.call("start_client", { language, authType: "openid", idToken, label: `touchstone ${run} openid` })).client;
    try {
      const read = await mcp.call("read", { client: oidc, url: hello });
      log(`openid client read -> ${read.ok ? "ok" : `${read.error.kind}: ${read.error.message}`}`);
    } finally {
      await mcp.call("stop_client", { client: oidc }).catch(() => {});
    }

    // Delete the container with everything in it.
    await op("delete", { url: container, ifMatch: await etagOf(container) }, "ConflictError 409");
    await task("client-delete-container-depth");
    await op("delete", { url: container, recursive: true, ifMatch: await etagOf(container) });
  } catch (e) {
    // The client did something the scenario could not go on from; the session's verdict says what.
    scenarioError = e.message;
    log(`scenario stopped: ${e.message}`);
  } finally {
    await mcp.call("stop_client", { client }).catch(() => {});
  }

  const results = await touchstone("GET", `${api}/results`, key);
  if (opts.out) {
    await writeFile(join(opts.out, `${language}.json`), JSON.stringify(results, null, 2));
    await writeFile(join(opts.out, `${language}-junit.xml`), await touchstone("GET", `${api}/results?format=junit`, key, undefined, "text"));
    await writeFile(join(opts.out, `${language}-earl.ttl`), await touchstone("GET", `${api}/results?format=earl`, key, undefined, "text"));
  }
  if (!opts.keep) await touchstone("DELETE", api, key, undefined, "text");
  log(results.verdict.text);
  return {
    language,
    library: started.library,
    verdict: results.verdict,
    counts: results.counts,
    failed: results.rules.filter((r) => r.outcome === "failed"),
    untested: results.rules.filter((r) => r.outcome === "untested").map((r) => r.rule),
    page: opts.keep ? created.pageWithKey : undefined,
    scenarioError,
  };
}

/** The authorization code flow with PKCE at the session's OpenID Provider, signing in with the form. */
async function signIn(api, key, session, identity) {
  const b64url = (bytes) => Buffer.from(bytes).toString("base64url");
  const redirect = "http://127.0.0.1/callback";
  const registered = await touchstone("POST", `${api}/clients`, key, { redirect_uris: [redirect] });
  const clientId = registered.client_id;
  const issuer = session.openidProvider.issuer;
  const config = await (await fetch(session.openidProvider.discovery)).json();
  const verifier = b64url(randomBytes(32));
  const state = b64url(randomBytes(16));
  const query = new URLSearchParams({
    response_type: "code", client_id: clientId, redirect_uri: redirect, scope: "openid webid", state,
    nonce: b64url(randomBytes(16)), code_challenge: b64url(createHash("sha256").update(verifier).digest()),
    code_challenge_method: "S256",
  });
  const authorize = new URL(`${config.authorization_endpoint}?${query}`);
  const page = await (await fetch(authorize)).text();
  const handle = /name="request" value="([^"]*)"/.exec(page)?.[1];
  if (!handle) throw new Error("the OpenID Provider showed no sign-in form");
  const back = await fetch(new URL("authorize", authorize), {
    method: "POST", redirect: "manual", headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ request: handle, username: identity.username, password: identity.password }),
  });
  const answer = new URL(back.headers.get("location") ?? "about:blank").searchParams;
  if (!answer.get("code") || answer.get("state") !== state || answer.get("iss") !== issuer) {
    throw new Error(`the sign-in did not come back with a code: ${back.status}`);
  }
  const tokens = await (await fetch(config.token_endpoint, {
    method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ grant_type: "authorization_code", code: answer.get("code"), redirect_uri: redirect, client_id: clientId, code_verifier: verifier }),
  })).json();
  if (!tokens.id_token) throw new Error(`the token endpoint gave no ID Token: ${JSON.stringify(tokens)}`);
  return tokens.id_token;
}

async function touchstone(method, url, key, body, as = "json") {
  const headers = {};
  if (key) headers.Authorization = `Bearer ${key}`;
  if (body !== undefined) headers["Content-Type"] = "application/json";
  const response = await fetch(url, { method, headers, body: body === undefined ? undefined : JSON.stringify(body) });
  if (!response.ok) throw new Error(`${method} ${url}: HTTP ${response.status} ${await response.text()}`);
  if (response.status === 204 || as === "text") return response.text();
  return response.json();
}
