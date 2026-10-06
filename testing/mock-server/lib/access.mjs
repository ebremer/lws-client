// SPDX-License-Identifier: MIT
// AccessRequestService / AccessGrantService (lws10-core "Access Requests and Grants").

import { randomUUID } from "node:crypto";
import { renderListing } from "./resources.mjs";
import {
  asArray,
  HttpError,
  isAbsoluteIri,
  isObject,
  LWS_CONTEXT,
  LWS_NS,
  makeEtag,
  MEDIA,
  mediaTypeOf,
  parseJsonBody,
  readBody,
  REL_STORAGE,
  send,
  serializeLink,
  TYPE_CONTAINER,
  TYPE_DATA_RESOURCE,
} from "./util.mjs";

export const ACCESS_REQUESTS_PATH = "/access/requests/";
export const ACCESS_GRANTS_PATH = "/access/grants/";
const ACTIONS = new Set(["read", "modify", "create", "delete"]);

const hasTerm = (types, term) => types.includes(term) || types.includes(`${LWS_NS}${term}`) || types.includes(`lws:${term}`);

export function createAccessService(app) {
  const collections = [
    { path: ACCESS_REQUESTS_PATH, type: "AccessRequest", items: new Map() },
    { path: ACCESS_GRANTS_PATH, type: "AccessGrant", items: new Map() },
  ];

  function validate(doc, expectedType) {
    const bad = (detail) => new HttpError(400, detail);
    if (!isObject(doc)) throw bad("The document must be a JSON object");
    if (!asArray(doc["@context"]).includes(LWS_CONTEXT)) throw bad(`@context must include ${LWS_CONTEXT}`);
    const types = asArray(doc.type);
    if (!types.every((t) => typeof t === "string") || !hasTerm(types, expectedType)) throw bad(`type must include ${expectedType}`);
    if (doc.storage !== app.storageId) throw bad(`storage must be ${app.storageId}`);
    if (doc.inbox !== undefined && !isAbsoluteIri(doc.inbox)) throw bad("inbox must be an absolute URI");
    if (!Array.isArray(doc.access) || doc.access.length === 0) throw bad("access must be a non-empty array");
    doc.access.forEach((policy, i) => {
      const where = `access[${i}]`;
      if (!isObject(policy)) throw bad(`${where} must be an object`);
      if (!hasTerm(asArray(policy.type), "AccessPolicy")) throw bad(`${where}.type must include AccessPolicy`);
      if (!Array.isArray(policy.action) || policy.action.length === 0) throw bad(`${where}.action must be a non-empty array`);
      for (const a of policy.action) if (!ACTIONS.has(a)) throw bad(`${where}.action contains unsupported action ${JSON.stringify(a)}`);
      if (typeof policy.assignee !== "string" || !isAbsoluteIri(policy.assignee)) throw bad(`${where}.assignee must be a URI`);
      if (policy.target !== undefined) {
        const t = policy.target;
        if (!isObject(t) || typeof t.type !== "string") throw bad(`${where}.target must be an object with a type`);
        if (!Array.isArray(t.value) || t.value.length === 0 || !t.value.every((v) => typeof v === "string")) {
          throw bad(`${where}.target.value must be a non-empty array of strings`);
        }
      }
      if (policy.constraint !== undefined) {
        if (!Array.isArray(policy.constraint)) throw bad(`${where}.constraint must be an array`);
        policy.constraint.forEach((c, j) => {
          if (!isObject(c) || typeof c.leftOperand !== "string" || typeof c.operator !== "string" || !("rightOperand" in c)) {
            throw bad(`${where}.constraint[${j}] requires leftOperand, operator and rightOperand`);
          }
        });
      }
    });
  }

  const itemUrl = (coll, entry) => `${app.base}${coll.path}${entry.id}`;

  function notifyGrant(coll, entry, agent) {
    const grant = entry.doc;
    const assignees = new Set(grant.access.map((p) => p.assignee));
    const inboxes = new Set();
    if (typeof grant.inbox === "string") inboxes.add(grant.inbox);
    else {
      for (const req of collections[0].items.values()) {
        if (typeof req.doc.inbox === "string" && req.doc.access.some((p) => assignees.has(p.assignee))) inboxes.add(req.doc.inbox);
      }
    }
    for (const inbox of inboxes) {
      if (!/^https?:/i.test(inbox)) continue;
      app.notifications.deliver(inbox, [
        {
          id: `urn:uuid:${randomUUID()}`,
          type: ["Create"],
          object: { id: itemUrl(coll, entry), type: ["DataResource", "AccessGrant"] },
          target: `${app.base}${coll.path}`,
          ...(agent?.sub && agent.sub !== "anonymous" ? { actor: agent.sub } : {}),
          published: new Date().toISOString(),
        },
      ]);
    }
  }

  async function createEntry(req, res, coll, agent) {
    const ct = mediaTypeOf(req.headers["content-type"]);
    if (ct !== MEDIA.LWS_JSON && ct !== MEDIA.LD_JSON && ct !== MEDIA.JSON) {
      throw new HttpError(415, `${coll.type} documents must use ${MEDIA.LWS_JSON}`);
    }
    const doc = parseJsonBody(await readBody(req), `${coll.type} document`);
    validate(doc, coll.type);
    const entry = { id: randomUUID(), doc, owner: agent.sub, created: new Date() };
    entry.doc = { ...doc, id: itemUrl(coll, entry) };
    entry.json = JSON.stringify(entry.doc);
    entry.etag = makeEtag(entry.json);
    coll.items.set(entry.id, entry);
    if (coll.type === "AccessGrant") notifyGrant(coll, entry, agent);
    send(
      req,
      res,
      201,
      {
        Location: itemUrl(coll, entry),
        "Content-Type": MEDIA.LWS_JSON,
        ETag: entry.etag,
        Link: [serializeLink(coll.path, "up"), serializeLink(TYPE_DATA_RESOURCE, "type"), serializeLink(app.storageId, REL_STORAGE)],
      },
      entry.json,
    );
  }

  async function handle(req, res, url, agent) {
    const path = url.pathname;
    const coll = collections.find((c) => path.startsWith(c.path));
    if (!coll) throw new HttpError(404, `No resource at ${path}`);
    const rest = path.slice(coll.path.length);
    if (rest === "") {
      switch (req.method) {
        case "GET":
        case "HEAD":
          return renderListing(app, req, res, url, {
            path: coll.path,
            items: [...coll.items.values()].map((e) => ({
              type: ["DataResource", coll.type],
              id: `${coll.path}${e.id}`,
              format: MEDIA.LWS_JSON,
              size: Buffer.byteLength(e.json),
              modified: e.created.toISOString(),
            })),
            links: [serializeLink(TYPE_CONTAINER, "type"), serializeLink(app.storageId, REL_STORAGE)],
            headers: { Allow: "GET, HEAD, POST, OPTIONS" },
          });
        case "POST":
          return createEntry(req, res, coll, agent);
        default:
          throw new HttpError(405, undefined, { headers: { Allow: "GET, HEAD, POST, OPTIONS" } });
      }
    }
    const entry = coll.items.get(rest);
    if (!entry) throw new HttpError(404, `No ${coll.type} at ${path}`);
    switch (req.method) {
      case "GET":
      case "HEAD":
        return send(
          req,
          res,
          200,
          {
            "Content-Type": MEDIA.LWS_JSON,
            ETag: entry.etag,
            Allow: "GET, HEAD, DELETE, OPTIONS",
            Link: [serializeLink(coll.path, "up"), serializeLink(TYPE_DATA_RESOURCE, "type"), serializeLink(app.storageId, REL_STORAGE)],
          },
          entry.json,
        );
      case "DELETE":
        coll.items.delete(entry.id);
        return send(req, res, 204);
      default:
        throw new HttpError(405, undefined, { headers: { Allow: "GET, HEAD, DELETE, OPTIONS" } });
    }
  }

  return { handle, collections };
}
