// SPDX-License-Identifier: MIT
// LWS mock server: wiring, storage description, CORS, routing and startServer().

import http from "node:http";
import { createAccessService, ACCESS_GRANTS_PATH, ACCESS_REQUESTS_PATH } from "./access.mjs";
import { createAuth } from "./auth.mjs";
import { createIndexService, TYPE_INDEX_PATH, TYPE_SEARCH_PATH } from "./index-service.mjs";
import { createNotifications, NOTIFICATIONS_PATH } from "./notifications.mjs";
import { allowFor, createResourceHandlers } from "./resources.mjs";
import { ROOT_PATH, Store } from "./store.mjs";
import {
  CID_CONTEXT,
  HttpError,
  isNotModified,
  LWS_CONTEXT,
  makeEtag,
  MEDIA,
  negotiate,
  REL_STORAGE,
  send,
  sendProblem,
  serializeLink,
} from "./util.mjs";

const PROTECTED_PREFIXES = ["/root", "/notifications", "/access", "/types"];

const EXPOSED_HEADERS = [
  "Accept-Patch",
  "Accept-Post",
  "Accept-Query",
  "Accept-Ranges",
  "Allow",
  "Content-Range",
  "ETag",
  "Last-Modified",
  "Link",
  "Location",
  "Preference-Applied",
  "Vary",
  "WWW-Authenticate",
].join(", ");

/**
 * Creates the application state and request handler. `base` is assigned by startServer() once the
 * listening port is known.
 */
export function createApp({ pageSize = 5, auth = true, verbose = false, log = console.log } = {}) {
  const app = {
    base: "",
    pageSize,
    authEnabled: auth,
    store: new Store(),
    log: verbose ? (msg) => log(`[lws-mock] ${msg}`) : null,
    get issuer() {
      return this.base;
    },
    get realm() {
      return `${this.base}/`;
    },
    get storageId() {
      return `${this.base}/`;
    },
  };
  app.auth = createAuth(app);
  app.notifications = createNotifications(app);
  app.notify = (events, agent) => app.notifications.notify(events, agent);
  app.resources = createResourceHandlers(app);
  app.access = createAccessService(app);
  app.index = createIndexService(app);

  function storageDescription() {
    const service = (type, path, extra = {}) => ({ type, serviceEndpoint: `${app.base}${path}`, ...extra });
    const vm = app.notifications.verificationMethod();
    return {
      "@context": [CID_CONTEXT, LWS_CONTEXT],
      id: app.storageId,
      type: "Storage",
      verificationMethod: [vm],
      authentication: [vm.id],
      service: [
        service("StorageRoot", ROOT_PATH),
        service("NotificationService", NOTIFICATIONS_PATH, { subscriptionType: ["WebhookSubscription"] }),
        service("AccessRequestService", ACCESS_REQUESTS_PATH, { conformsTo: ["https://www.w3.org/ns/lws#AccessProfile"] }),
        service("AccessGrantService", ACCESS_GRANTS_PATH, { conformsTo: ["https://www.w3.org/ns/lws#AccessProfile"] }),
        service("TypeIndexService", TYPE_INDEX_PATH),
        service("TypeSearchService", TYPE_SEARCH_PATH),
      ],
    };
  }

  function handleStorageDescription(req, res) {
    if (req.method === "OPTIONS") return send(req, res, 204, { Allow: "GET, HEAD, OPTIONS" });
    if (req.method !== "GET" && req.method !== "HEAD") throw new HttpError(405, undefined, { headers: { Allow: "GET, HEAD, OPTIONS" } });
    // application/lws+cid unless content negotiation explicitly asks for a JSON-LD / JSON alternative.
    const contentType = negotiate(req.headers.accept, [MEDIA.LWS_CID, MEDIA.LD_JSON, MEDIA.JSON]) ?? MEDIA.LWS_CID;
    const json = JSON.stringify(storageDescription());
    const etag = makeEtag(contentType, json);
    const headers = { ETag: etag, Vary: "Accept", Link: serializeLink(app.storageId, REL_STORAGE) };
    if (isNotModified(req, etag)) return send(req, res, 304, headers);
    send(req, res, 200, { ...headers, "Content-Type": contentType }, json);
  }

  function cors(req, res) {
    const origin = req.headers.origin;
    if (!origin) return false;
    res.setHeader("Access-Control-Allow-Origin", origin);
    res.setHeader("Vary", "Origin");
    res.setHeader("Access-Control-Expose-Headers", EXPOSED_HEADERS);
    if (req.method === "OPTIONS" && req.headers["access-control-request-method"]) {
      res.setHeader("Access-Control-Allow-Methods", "GET, HEAD, POST, PUT, PATCH, DELETE, OPTIONS, QUERY");
      res.setHeader(
        "Access-Control-Allow-Headers",
        req.headers["access-control-request-headers"] ??
          "Authorization, Content-Type, Slug, Link, If-Match, If-None-Match, If-Modified-Since, Prefer, Depth, Range",
      );
      res.setHeader("Access-Control-Max-Age", "600");
      send(req, res, 204);
      return true;
    }
    return false;
  }

  function protectedArea(path) {
    return PROTECTED_PREFIXES.find((p) => path === p || path.startsWith(`${p}/`)) ?? null;
  }

  function optionsFor(url) {
    const fromIndex = app.index.options(url);
    if (fromIndex) return fromIndex;
    const found = url.pathname.startsWith(ROOT_PATH) ? app.resources.lookup(url.pathname) : null;
    if (found?.linkset) return { Allow: "GET, HEAD, PUT, PATCH", "Accept-Patch": MEDIA.JSON_PATCH };
    if (found) return { Allow: allowFor(found.resource), ...(found.resource.isContainer ? { "Accept-Post": "*/*" } : {}) };
    if (url.pathname === NOTIFICATIONS_PATH || url.pathname === ACCESS_REQUESTS_PATH || url.pathname === ACCESS_GRANTS_PATH) {
      return { Allow: "GET, HEAD, POST, OPTIONS" };
    }
    return { Allow: "GET, HEAD, DELETE, OPTIONS" };
  }

  async function route(req, res) {
    // Only origin-form targets are accepted; resolving "//host/..." would let a request override the authority.
    if (!req.url.startsWith("/")) throw new HttpError(400, "Only origin-form request targets are supported");
    let url;
    try {
      url = new URL(app.base + req.url);
    } catch {
      throw new HttpError(400, "Invalid request target");
    }
    const path = url.pathname;
    if (path === "/") return handleStorageDescription(req, res);
    if (path === "/.well-known/lws-configuration" || path === "/.well-known/oauth-authorization-server") {
      return app.auth.handleMetadata(req, res);
    }
    if (path === "/oauth/token") return app.auth.handleToken(req, res);
    if (path === "/oauth/jwks") return app.auth.handleJwks(req, res);

    const area = protectedArea(path);
    if (!area) throw new HttpError(404, `No resource at ${path}`);
    if (req.method === "OPTIONS") return send(req, res, 204, optionsFor(url));
    const agent = app.authEnabled ? app.auth.authenticate(req) : { sub: "anonymous", clientId: null };
    switch (area) {
      case "/root":
        if (path === "/root") throw new HttpError(404, `No resource at ${path}; the storage root is ${ROOT_PATH}`);
        return app.resources.handle(req, res, url, agent);
      case "/notifications":
        if (path === "/notifications") throw new HttpError(404, `No resource at ${path}`);
        return app.notifications.handle(req, res, url, agent);
      case "/access":
        return app.access.handle(req, res, url, agent);
      case "/types":
        return app.index.handle(req, res, url, agent);
      default:
        throw new HttpError(404);
    }
  }

  async function handle(req, res) {
    const started = Date.now();
    if (app.log) res.on("finish", () => app.log(`${req.method} ${req.url} -> ${res.statusCode} (${Date.now() - started} ms)`));
    try {
      if (cors(req, res)) return;
      await route(req, res);
    } catch (err) {
      let error = err;
      if (!(error instanceof HttpError)) {
        log(`[lws-mock] internal error handling ${req.method} ${req.url}: ${err?.stack ?? err}`);
        error = new HttpError(500, "Internal server error");
      }
      if (res.headersSent) {
        res.destroy();
        return;
      }
      // Drain any unread request body so keep-alive connections stay usable.
      if (!req.complete) req.resume();
      sendProblem(req, res, error);
    }
  }

  return { app, handle, storageDescription };
}

function listen(server, port, host) {
  return new Promise((resolve, reject) => {
    const onError = (e) => {
      server.off("listening", onListening);
      reject(e);
    };
    const onListening = () => {
      server.off("error", onError);
      resolve();
    };
    server.once("error", onError);
    server.once("listening", onListening);
    server.listen(port, host);
  });
}

/**
 * Starts the mock server.
 * @param {{port?: number, host?: string, baseUrl?: string, pageSize?: number, auth?: boolean, verbose?: boolean, log?: Function}} [options]
 * @returns {Promise<{url: string, port: number, app: object, close: () => Promise<void>}>}
 */
export async function startServer(options = {}) {
  const { port = 8787, host, baseUrl, pageSize = 5, auth = true, verbose = false, log = console.log } = options;
  if (!Number.isInteger(pageSize) || pageSize < 1) throw new Error("pageSize must be a positive integer");
  const { app, handle } = createApp({ pageSize, auth, verbose, log });
  const servers = [];
  const primary = http.createServer(handle);
  primary.keepAliveTimeout = 5000;
  await listen(primary, port, host ?? "127.0.0.1");
  servers.push(primary);
  const actualPort = primary.address().port;
  if (!host) {
    // "localhost" may resolve to ::1 first; listen on the IPv6 loopback too when it is available.
    const v6 = http.createServer(handle);
    v6.keepAliveTimeout = 5000;
    try {
      await listen(v6, actualPort, "::1");
      servers.push(v6);
    } catch {
      // IPv6 loopback unavailable — IPv4 only.
    }
  }
  app.base = (baseUrl ?? `http://localhost:${actualPort}`).replace(/\/+$/, "");
  return {
    url: app.base,
    port: actualPort,
    app,
    async close() {
      await Promise.all(
        servers.map(
          (s) =>
            new Promise((resolve) => {
              s.close(() => resolve());
              s.closeAllConnections?.();
            }),
        ),
      );
      await app.notifications.drain(2000);
    },
  };
}

