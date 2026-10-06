// SPDX-License-Identifier: MIT
// NotificationService with the Webhook notification suite (lws10-core "Notifications",
// lws10-notifications-webhook): subscription management and RFC 9421-signed delivery.

import { generateKeyPairSync, randomUUID } from "node:crypto";
import { contentDigest, signRequest } from "./crypto.mjs";
import { renderListing } from "./resources.mjs";
import {
  AS_CONTEXT,
  HttpError,
  isHttpUrl,
  isObject,
  LWS_CONTEXT,
  makeEtag,
  MEDIA,
  mediaTypeOf,
  parseJsonBody,
  readBody,
  REL_STORAGE,
  send,
  serializeLink,
  TYPE_DATA_RESOURCE,
} from "./util.mjs";

export const NOTIFICATIONS_PATH = "/notifications/";
const DEFAULT_SUBSCRIPTION_LIFETIME_MS = 24 * 60 * 60 * 1000;
const RETRY_DELAYS_MS = [250, 1000];

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

export function createNotifications(app) {
  const { privateKey, publicKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
  const publicJwk = { ...publicKey.export({ format: "jwk" }), kid: "webhook-key", alg: "ES256" };
  const subscriptions = new Map();
  const pending = new Set();

  const keyId = () => `${app.storageId}#webhook-key`;
  const subscriptionUrl = (sub) => `${app.base}${NOTIFICATIONS_PATH}${sub.id}`;
  const isActive = (sub) => sub.expires.getTime() > Date.now();

  function verificationMethod() {
    return { id: keyId(), type: "JsonWebKey", controller: app.storageId, publicKeyJwk: publicJwk };
  }

  function envelope(activities) {
    return {
      "@context": [LWS_CONTEXT, AS_CONTEXT],
      type: "Notification",
      storage: app.storageId,
      activity: activities.length === 1 ? activities[0] : activities,
    };
  }

  function toActivity(event, actor) {
    const activity = {
      id: `urn:uuid:${randomUUID()}`,
      type: [event.kind],
      object: event.object,
      published: new Date().toISOString(),
    };
    if (actor) activity.actor = actor;
    if (event.target) activity.target = event.target;
    if (event.origin) activity.origin = event.origin;
    return activity;
  }

  async function post(inbox, body) {
    const headers = { "content-type": MEDIA.LWS_JSON, "content-digest": contentDigest(body) };
    for (let attempt = 0; attempt <= RETRY_DELAYS_MS.length; attempt++) {
      const signed = signRequest({ method: "POST", url: inbox, headers, privateKey, keyid: keyId() });
      try {
        const response = await fetch(inbox, {
          method: "POST",
          headers: { ...headers, "signature-input": signed["Signature-Input"], signature: signed.Signature },
          body,
          signal: AbortSignal.timeout(5000),
        });
        await response.arrayBuffer().catch(() => undefined);
        if (response.ok) {
          app.log?.(`delivered notification to ${inbox}`);
          return true;
        }
        app.log?.(`delivery to ${inbox} failed: HTTP ${response.status}`);
      } catch (e) {
        app.log?.(`delivery to ${inbox} failed: ${e.message}`);
      }
      if (attempt < RETRY_DELAYS_MS.length) await sleep(RETRY_DELAYS_MS[attempt]);
    }
    return false;
  }

  /** Delivers a notification envelope to an inbox (fire-and-forget; serialised per inbox chain). */
  function deliver(inbox, activities, chainOwner) {
    const body = Buffer.from(JSON.stringify(envelope(activities)));
    const run = () => post(inbox, body);
    const chained = chainOwner ? (chainOwner.queue = (chainOwner.queue ?? Promise.resolve()).then(run, run)) : run();
    pending.add(chained);
    chained.finally(() => pending.delete(chained));
    return chained;
  }

  const covers = (topicPath, path) => topicPath === path || (topicPath.endsWith("/") && path.startsWith(topicPath));

  /** Called for every resource change: events are [{kind, object, path, target?, origin?}]. */
  function notify(events, agent) {
    if (events.length === 0) return;
    const actor = agent?.sub && agent.sub !== "anonymous" ? agent.sub : undefined;
    for (const sub of subscriptions.values()) {
      if (!isActive(sub)) {
        subscriptions.delete(sub.id);
        continue;
      }
      const matched = events.filter((e) => sub.topicPaths.some((t) => covers(t, e.path)));
      if (matched.length) deliver(sub.inbox, matched.map((e) => toActivity(e, actor)), sub);
    }
  }

  function representation(sub) {
    return {
      "@context": [LWS_CONTEXT],
      type: "WebhookSubscription",
      subscription: subscriptionUrl(sub),
      topic: sub.topics,
      inbox: sub.inbox,
      expires: sub.expiresRaw,
    };
  }

  async function subscribe(req, res, agent) {
    const ct = mediaTypeOf(req.headers["content-type"]);
    if (ct !== MEDIA.LWS_JSON && ct !== MEDIA.LD_JSON && ct !== MEDIA.JSON) {
      throw new HttpError(415, `Subscription requests must use ${MEDIA.LWS_JSON}`);
    }
    const body = parseJsonBody(await readBody(req), "subscription request");
    if (!isObject(body)) throw new HttpError(400, "A subscription request must be a JSON object");
    if (typeof body.type !== "string") throw new HttpError(400, 'A subscription request requires a "type" string');
    if (body.type !== "WebhookSubscription") throw new HttpError(400, `Unsupported subscription type ${body.type}; supported: WebhookSubscription`);
    if (!Array.isArray(body.topic) || body.topic.length === 0 || !body.topic.every((t) => typeof t === "string")) {
      throw new HttpError(400, '"topic" must be a non-empty array of resource URIs');
    }
    const topics = [];
    const topicPaths = [];
    for (const t of body.topic) {
      let u;
      try {
        u = new URL(t, app.base);
      } catch {
        throw new HttpError(400, `Topic ${t} is not a valid URI`);
      }
      if (u.origin !== new URL(app.base).origin || !app.store.resolve(u.pathname)) {
        throw new HttpError(400, `Topic ${t} is not a resource in this storage`);
      }
      topics.push(u.href);
      topicPaths.push(u.pathname);
    }
    if (!isHttpUrl(body.inbox)) throw new HttpError(400, '"inbox" must be an absolute http(s) URL');
    let expires;
    let expiresRaw;
    if (body.expires !== undefined) {
      const ms = typeof body.expires === "string" ? Date.parse(body.expires) : NaN;
      if (Number.isNaN(ms)) throw new HttpError(400, '"expires" must be an RFC 3339 date-time');
      if (ms <= Date.now()) throw new HttpError(400, '"expires" must be in the future');
      expires = new Date(ms);
      expiresRaw = body.expires;
    } else {
      expires = new Date(Date.now() + DEFAULT_SUBSCRIPTION_LIFETIME_MS);
      expiresRaw = expires.toISOString();
    }
    const sub = {
      id: randomUUID(),
      owner: agent.sub,
      topics,
      topicPaths,
      inbox: body.inbox,
      expires,
      expiresRaw,
      created: new Date(),
    };
    subscriptions.set(sub.id, sub);
    app.log?.(`subscription ${sub.id} -> ${sub.inbox} for ${topics.join(", ")}`);
    send(req, res, 200, { "Content-Type": MEDIA.LWS_JSON, Location: subscriptionUrl(sub) }, representation(sub));
  }

  function listingItem(sub) {
    const json = JSON.stringify(representation(sub));
    return {
      type: ["DataResource", "WebhookSubscription"],
      id: `${NOTIFICATIONS_PATH}${sub.id}`,
      format: MEDIA.LWS_JSON,
      size: Buffer.byteLength(json),
      modified: sub.created.toISOString(),
    };
  }

  async function handle(req, res, url, agent) {
    const path = url.pathname;
    if (path === NOTIFICATIONS_PATH) {
      switch (req.method) {
        case "GET":
        case "HEAD": {
          const mine = [...subscriptions.values()].filter((s) => isActive(s) && s.owner === agent.sub);
          return renderListing(app, req, res, url, {
            path: NOTIFICATIONS_PATH,
            items: mine.map(listingItem),
            links: [serializeLink(`https://www.w3.org/ns/lws#Container`, "type"), serializeLink(app.storageId, REL_STORAGE)],
            headers: { Allow: "GET, HEAD, POST, OPTIONS", "Cache-Control": "private" },
          });
        }
        case "POST":
          return subscribe(req, res, agent);
        default:
          throw new HttpError(405, undefined, { headers: { Allow: "GET, HEAD, POST, OPTIONS" } });
      }
    }
    const id = path.slice(NOTIFICATIONS_PATH.length);
    const sub = subscriptions.get(id);
    if (!sub || !isActive(sub) || sub.owner !== agent.sub) throw new HttpError(404, `No subscription at ${path}`);
    switch (req.method) {
      case "GET":
      case "HEAD": {
        const rep = representation(sub);
        send(
          req,
          res,
          200,
          {
            "Content-Type": MEDIA.LWS_JSON,
            ETag: makeEtag(JSON.stringify(rep)),
            Allow: "GET, HEAD, DELETE, OPTIONS",
            "Cache-Control": "private",
            Link: [serializeLink(NOTIFICATIONS_PATH, "up"), serializeLink(TYPE_DATA_RESOURCE, "type"), serializeLink(app.storageId, REL_STORAGE)],
          },
          rep,
        );
        return;
      }
      case "DELETE":
        subscriptions.delete(sub.id);
        app.log?.(`subscription ${sub.id} cancelled`);
        return send(req, res, 204);
      default:
        throw new HttpError(405, undefined, { headers: { Allow: "GET, HEAD, DELETE, OPTIONS" } });
    }
  }

  async function drain(timeoutMs = 5000) {
    await Promise.race([Promise.allSettled([...pending]), new Promise((r) => setTimeout(r, timeoutMs).unref())]);
  }

  return { handle, notify, deliver, verificationMethod, keyId, drain, subscriptions };
}
