// SPDX-License-Identifier: MIT
// TypeIndexService (GET) and TypeSearchService (HTTP QUERY, application/lws-query+json) per lws10-index.

import { randomBytes } from "node:crypto";
import {
  CONTAINER_MEDIA,
  HttpError,
  isAbsoluteIri,
  isNotModified,
  isObject,
  LWS_CONTEXT,
  makeEtag,
  MEDIA,
  mediaTypeOf,
  negotiate,
  normalizeRel,
  parseJsonBody,
  readBody,
  send,
  serializeLink,
} from "./util.mjs";

export const TYPE_INDEX_PATH = "/types/index";
export const TYPE_SEARCH_PATH = "/types/search";
const SEARCH_ALLOW = "OPTIONS, QUERY";
const CURSOR_TTL_MS = 10 * 60 * 1000;
const MAX_SNAPSHOTS = 500;
const MAX_GROUPS = 32;
const MAX_IRIS = 128;

export function createIndexService(app) {
  /** cursor -> { snapshot, index } */
  const cursors = new Map();
  const snapshots = [];

  function sweep() {
    const t = Date.now();
    while (snapshots.length && (snapshots[0].expires <= t || snapshots.length > MAX_SNAPSHOTS)) {
      const s = snapshots.shift();
      for (const c of s.cursors) cursors.delete(c);
    }
  }

  function storageResources() {
    return [...app.store.walk()];
  }

  // -------------------------------------------------------------------------
  // Type Index
  // -------------------------------------------------------------------------

  function typeIndex(req, res, url) {
    if (req.method !== "GET" && req.method !== "HEAD") throw new HttpError(405, undefined, { headers: { Allow: "GET, HEAD, OPTIONS" } });
    const contentType = negotiate(req.headers.accept, CONTAINER_MEDIA);
    if (!contentType) throw new HttpError(406, `The type index is available as ${CONTAINER_MEDIA.join(", ")}`, { headers: { Vary: "Accept" } });
    const types = new Set();
    for (const r of storageResources()) for (const t of r.allTypes(app.base)) types.add(t);
    const all = [...types].sort();
    const pageSize = app.pageSize;
    const pages = Math.max(1, Math.ceil(all.length / pageSize));
    const pageParam = url.searchParams.get("page");
    let page = 1;
    if (pageParam !== null) {
      if (!/^[1-9][0-9]*$/.test(pageParam) || Number(pageParam) > pages) throw new HttpError(404, "This type index page does not exist");
      page = Number(pageParam);
    }
    const body = {
      "@context": LWS_CONTEXT,
      type: "TypeIndex",
      totalItems: all.length,
      items: all.slice((page - 1) * pageSize, page * pageSize).map((id) => ({ id })),
    };
    const json = JSON.stringify(body);
    const links = [];
    if (pages > 1) {
      const pageUrl = (n) => `${app.base}${TYPE_INDEX_PATH}?page=${n}`;
      links.push(serializeLink(pageUrl(1), "first"), serializeLink(pageUrl(pages), "last"));
      if (page > 1) links.push(serializeLink(pageUrl(page - 1), "prev"));
      if (page < pages) links.push(serializeLink(pageUrl(page + 1), "next"));
    }
    const etag = makeEtag(mediaTypeOf(contentType), json);
    const headers = { ETag: etag, "Cache-Control": "private", Vary: "Accept, Authorization", Link: links };
    if (isNotModified(req, etag)) return send(req, res, 304, headers);
    send(req, res, 200, { ...headers, "Content-Type": contentType }, json);
  }

  // -------------------------------------------------------------------------
  // Type Search
  // -------------------------------------------------------------------------

  /** Parses an application/lws-query+json filter into [{key, groups: Set[]}] (conjunctive normal form). */
  function parseFilter(filter) {
    if (!isObject(filter)) throw new HttpError(400, "A filter document must be a JSON object");
    const constraints = [];
    let groupCount = 0;
    let iriCount = 0;
    for (const [member, value] of Object.entries(filter)) {
      if (member.startsWith("@")) continue;
      if (!Array.isArray(value)) throw new HttpError(400, `"${member}" must be an array`);
      const groups = [];
      const seen = new Set();
      for (const element of value) {
        let group;
        if (typeof element === "string") group = [element];
        else if (Array.isArray(element)) {
          if (element.length === 0) throw new HttpError(400, `"${member}" contains an empty group`);
          if (!element.every((x) => typeof x === "string")) throw new HttpError(400, `Groups in "${member}" must contain only strings`);
          group = element;
        } else {
          throw new HttpError(400, `Elements of "${member}" must be strings or non-empty arrays of strings`);
        }
        for (const iri of group) if (!isAbsoluteIri(iri)) throw new HttpError(400, `"${iri}" is not an absolute IRI`);
        const signature = JSON.stringify([...new Set(group)].sort());
        if (seen.has(signature)) continue;
        seen.add(signature);
        groups.push(new Set(group));
        groupCount++;
        iriCount += group.length;
      }
      if (groups.length) constraints.push({ key: member === "type" ? "type" : normalizeRel(member), groups });
    }
    if (groupCount > MAX_GROUPS || iriCount > MAX_IRIS) {
      throw new HttpError(422, `Filters are limited to ${MAX_GROUPS} groups and ${MAX_IRIS} IRIs`);
    }
    return constraints;
  }

  function matches(resource, constraints) {
    for (const { key, groups } of constraints) {
      const values = key === "type" ? new Set(resource.allTypes(app.base)) : resource.relationTargets(key, app.base);
      for (const group of groups) {
        let ok = false;
        for (const v of group) {
          if (values.has(v)) {
            ok = true;
            break;
          }
        }
        if (!ok) return false;
      }
    }
    return true;
  }

  function sendPage(req, res, snapshot, index, contentType) {
    const body = {
      "@context": LWS_CONTEXT,
      type: "ContainerPage",
      totalItems: snapshot.total,
      items: snapshot.pages[index],
    };
    const links = [];
    const n = snapshot.pages.length;
    if (n > 1) {
      const pageUrl = (i) => `${app.base}${TYPE_SEARCH_PATH}?cursor=${snapshot.cursors[i]}`;
      links.push(serializeLink(pageUrl(0), "first"), serializeLink(pageUrl(n - 1), "last"));
      if (index > 0) links.push(serializeLink(pageUrl(index - 1), "prev"));
      if (index < n - 1) links.push(serializeLink(pageUrl(index + 1), "next"));
    }
    send(req, res, 200, { "Content-Type": contentType, "Cache-Control": "private", Vary: "Accept, Authorization", Link: links }, body);
  }

  async function query(req, res, agent) {
    const ct = req.headers["content-type"];
    if (!ct) throw new HttpError(400, "QUERY requests require a Content-Type");
    if (mediaTypeOf(ct) !== MEDIA.LWS_QUERY_JSON) {
      throw new HttpError(415, `Unsupported query format ${mediaTypeOf(ct)}`, { headers: { "Accept-Query": MEDIA.LWS_QUERY_JSON } });
    }
    const contentType = negotiate(req.headers.accept, CONTAINER_MEDIA);
    if (!contentType) throw new HttpError(406, `Search results are available as ${CONTAINER_MEDIA.join(", ")}`, { headers: { Vary: "Accept" } });
    const constraints = parseFilter(parseJsonBody(await readBody(req), "filter document"));
    const items = storageResources()
      .filter((r) => matches(r, constraints))
      .map((r) => r.describe(app.base, { absolute: true }));
    const pages = [];
    for (let i = 0; i < items.length; i += app.pageSize) pages.push(items.slice(i, i + app.pageSize));
    if (pages.length === 0) pages.push([]);
    sweep();
    const snapshot = {
      owner: agent.sub,
      total: items.length,
      pages,
      cursors: pages.map(() => randomBytes(12).toString("base64url")),
      expires: Date.now() + CURSOR_TTL_MS,
    };
    snapshot.cursors.forEach((c, index) => cursors.set(c, { snapshot, index }));
    snapshots.push(snapshot);
    sendPage(req, res, snapshot, 0, contentType);
  }

  function cursorPage(req, res, url, agent) {
    const cursor = url.searchParams.get("cursor");
    if (!cursor) throw new HttpError(405, "Searches use the QUERY method", { headers: { Allow: SEARCH_ALLOW } });
    sweep();
    const entry = cursors.get(cursor);
    if (!entry || entry.snapshot.expires <= Date.now() || entry.snapshot.owner !== agent.sub) {
      throw new HttpError(404, "This search page has expired or is unknown; re-send the QUERY request");
    }
    const contentType = negotiate(req.headers.accept, CONTAINER_MEDIA);
    if (!contentType) throw new HttpError(406, `Search results are available as ${CONTAINER_MEDIA.join(", ")}`, { headers: { Vary: "Accept" } });
    sendPage(req, res, entry.snapshot, entry.index, contentType);
  }

  async function handle(req, res, url, agent) {
    if (url.pathname === TYPE_INDEX_PATH) return typeIndex(req, res, url);
    if (url.pathname === TYPE_SEARCH_PATH) {
      switch (req.method) {
        case "QUERY":
          return query(req, res, agent);
        case "GET":
        case "HEAD":
          return cursorPage(req, res, url, agent);
        default:
          throw new HttpError(405, undefined, { headers: { Allow: SEARCH_ALLOW } });
      }
    }
    throw new HttpError(404, `No resource at ${url.pathname}`);
  }

  function options(url) {
    if (url.pathname === TYPE_SEARCH_PATH) return { Allow: SEARCH_ALLOW, "Accept-Query": MEDIA.LWS_QUERY_JSON };
    if (url.pathname === TYPE_INDEX_PATH) return { Allow: "GET, HEAD, OPTIONS" };
    return null;
  }

  return { handle, options, parseFilter };
}

