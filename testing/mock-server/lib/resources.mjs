// SPDX-License-Identifier: MIT
// Storage resources under /root/: read, create, update, delete (lws10-core "Operations")
// and linkset metadata resources (lws10-core "Metadata").

import { applyPatch, PatchError } from "./jsonpatch.mjs";
import { sanitizeSlug } from "./store.mjs";
import {
  checkPreconditions,
  CONTAINER_MEDIA,
  HttpError,
  isJsonMedia,
  isNotModified,
  isObject,
  makeEtag,
  MEDIA,
  mediaTypeOf,
  negotiate,
  normalizeRel,
  parseJsonBody,
  parseLinkHeader,
  preferences,
  readBody,
  REL_STORAGE,
  send,
  serializeLink,
  STRUCTURAL_RELS,
  TYPE_CONTAINER,
  TYPE_DATA_RESOURCE,
  LWS_CONTEXT,
} from "./util.mjs";

const LINKSET_ALLOW = "GET, HEAD, PUT, PATCH";

export function allowFor(resource) {
  if (!resource.isContainer) return "GET, HEAD, PUT, PATCH, DELETE, OPTIONS";
  return resource.parent ? "GET, HEAD, POST, DELETE, OPTIONS" : "GET, HEAD, POST, OPTIONS";
}

/** Server-managed Link headers for a storage resource (linkset, up, type, storage). */
export function resourceLinks(app, resource) {
  const links = [serializeLink(resource.linksetPath, "linkset", { type: MEDIA.LINKSET_JSON })];
  if (resource.parent) links.push(serializeLink(resource.parent.path, "up"));
  links.push(serializeLink(resource.isContainer ? TYPE_CONTAINER : TYPE_DATA_RESOURCE, "type"));
  for (const t of resource.userTypes(app.base)) links.push(serializeLink(t, "type"));
  links.push(serializeLink(app.storageId, REL_STORAGE));
  return links;
}

function patchHeaders(resource) {
  return !resource.isContainer && isJsonMedia(resource.contentType) ? { "Accept-Patch": MEDIA.JSON_PATCH } : {};
}

/**
 * Renders an LWS container representation (also used for the subscription and access collections),
 * honouring media type equivalence, conditional requests and link-based pagination.
 */
export function renderListing(app, req, res, url, { path, items, links = [], lastModified, headers = {} }) {
  const contentType = negotiate(req.headers.accept, CONTAINER_MEDIA);
  if (!contentType) {
    throw new HttpError(406, `Container representations are available as ${CONTAINER_MEDIA.join(", ")}`, { headers: { Vary: "Accept" } });
  }
  const pageSize = app.pageSize;
  const total = items.length;
  const paginated = total > pageSize;
  const pages = Math.max(1, Math.ceil(total / pageSize));
  let page = 1;
  const pageParam = url.searchParams.get("page");
  if (pageParam !== null) {
    if (!/^[1-9][0-9]*$/.test(pageParam) || Number(pageParam) > pages) throw new HttpError(404, `Page ${pageParam} does not exist`);
    page = Number(pageParam);
  }
  const body = {
    "@context": LWS_CONTEXT,
    id: path,
    type: "Container",
    totalItems: total,
    items: paginated ? items.slice((page - 1) * pageSize, page * pageSize) : items,
  };
  const json = JSON.stringify(body);
  const etag = makeEtag(mediaTypeOf(contentType), json);
  const linkHeaders = [...links];
  if (paginated) {
    const pageUrl = (n) => `${path}?page=${n}`;
    linkHeaders.push(serializeLink(pageUrl(1), "first"));
    linkHeaders.push(serializeLink(pageUrl(pages), "last"));
    if (page > 1) linkHeaders.push(serializeLink(pageUrl(page - 1), "prev"));
    if (page < pages) linkHeaders.push(serializeLink(pageUrl(page + 1), "next"));
  }
  const common = {
    ETag: etag,
    Vary: "Accept",
    Link: linkHeaders,
    "Last-Modified": lastModified?.toUTCString(),
    ...headers,
  };
  if (isNotModified(req, etag, lastModified)) return send(req, res, 304, common);
  send(req, res, 200, { ...common, "Content-Type": contentType }, json);
}

// ---------------------------------------------------------------------------
// Link metadata helpers
// ---------------------------------------------------------------------------

/** Converts parsed request Link headers into user-managed linkset relations (server-managed ones are ignored). */
function linksFromHeaders(parsed) {
  const relations = {};
  for (const { href, rel, params } of parsed) {
    if (STRUCTURAL_RELS.has(rel)) continue;
    if (rel === "type" && (href === TYPE_CONTAINER || href === TYPE_DATA_RESOURCE)) continue;
    const target = { href };
    for (const [k, v] of Object.entries(params)) if (k !== "anchor") target[k] = v;
    (relations[rel] ??= []).push(target);
  }
  return relations;
}

function mergeLinks(existing, added) {
  const merged = structuredClone(existing);
  for (const [rel, targets] of Object.entries(added)) {
    const list = (merged[rel] ??= []);
    for (const t of targets) if (!list.some((x) => x.href === t.href)) list.push(t);
  }
  return merged;
}

function linksetDocument(app, resource) {
  return { linkset: [{ anchor: app.base + resource.path, ...structuredClone(resource.links) }] };
}

/** Validates an application/linkset+json document describing `resource` and returns its user-managed relations. */
function linksFromLinksetDocument(app, resource, doc) {
  const unprocessable = (detail) => new HttpError(422, detail);
  if (!isObject(doc) || !Array.isArray(doc.linkset)) throw unprocessable('A linkset document must be an object with a "linkset" array');
  if (doc.linkset.length !== 1) throw unprocessable("The linkset must contain exactly one link context object describing the resource");
  const ctx = doc.linkset[0];
  if (!isObject(ctx)) throw unprocessable("Link context objects must be JSON objects");
  const resourceUrl = app.base + resource.path;
  if (ctx.anchor !== undefined) {
    let anchor;
    try {
      anchor = new URL(ctx.anchor, resourceUrl).href;
    } catch {
      throw unprocessable("anchor is not a valid URI reference");
    }
    if (anchor !== resourceUrl) throw unprocessable(`anchor must identify the described resource ${resourceUrl}`);
  }
  const relations = {};
  for (const [member, targets] of Object.entries(ctx)) {
    if (member === "anchor") continue;
    if (!Array.isArray(targets)) throw unprocessable(`Relation "${member}" must map to an array of target objects`);
    const rel = normalizeRel(member);
    if (STRUCTURAL_RELS.has(rel)) continue; // server-managed relations are not client-modifiable
    for (const t of targets) {
      if (!isObject(t) || typeof t.href !== "string") throw unprocessable(`Targets of "${member}" must be objects with a string "href"`);
      try {
        new URL(t.href, resourceUrl);
      } catch {
        throw unprocessable(`"${t.href}" is not a valid URI reference`);
      }
    }
    relations[rel] = structuredClone(targets);
  }
  return relations;
}

function patchErrorToHttp(e) {
  if (e instanceof PatchError) return new HttpError(e.kind === "malformed" ? 400 : 409, e.message);
  return e;
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

export function createResourceHandlers(app) {
  const absolute = (resource) => app.base + resource.path;
  const objectOf = (resource) => ({ id: absolute(resource), type: resource.isContainer ? ["Container", ...resource.userTypes(app.base)] : ["DataResource", ...resource.userTypes(app.base)] });

  function getData(req, res, resource) {
    const headers = {
      ETag: resource.etag,
      "Last-Modified": resource.modified.toUTCString(),
      Link: resourceLinks(app, resource),
      Allow: allowFor(resource),
      "Accept-Ranges": "bytes",
      ...patchHeaders(resource),
    };
    if (isNotModified(req, resource.etag, resource.modified)) return send(req, res, 304, headers);
    const size = resource.body.length;
    const rangeHeader = req.headers.range;
    const ifRange = req.headers["if-range"];
    if (rangeHeader && (!ifRange || ifRange === resource.etag)) {
      const range = parseRange(rangeHeader, size);
      if (range === "unsatisfiable") {
        throw new HttpError(416, "Range not satisfiable", { headers: { "Content-Range": `bytes */${size}`, ...headers } });
      }
      if (range) {
        return send(
          req,
          res,
          206,
          { ...headers, "Content-Type": resource.contentType, "Content-Range": `bytes ${range.start}-${range.end}/${size}` },
          resource.body.subarray(range.start, range.end + 1),
        );
      }
    }
    send(req, res, 200, { ...headers, "Content-Type": resource.contentType }, resource.body);
  }

  function getContainer(req, res, url, resource) {
    renderListing(app, req, res, url, {
      path: resource.path,
      items: [...resource.children.values()].map((c) => c.describe(app.base)),
      links: resourceLinks(app, resource),
      lastModified: resource.modified,
      headers: { Allow: allowFor(resource), "Accept-Post": "*/*" },
    });
  }

  async function create(req, res, container, agent) {
    const body = await readBody(req);
    const parsed = parseLinkHeader(req.headers.link, absolute(container));
    const isContainer = parsed.some((l) => l.rel === "type" && l.href === TYPE_CONTAINER);
    const slug = sanitizeSlug(req.headers.slug);
    const resource = app.store.create(container, {
      slug,
      isContainer,
      contentType: isContainer ? null : req.headers["content-type"] || "application/octet-stream",
      body: isContainer ? Buffer.alloc(0) : body,
      links: linksFromHeaders(parsed),
    });
    app.notify([{ kind: "Create", object: objectOf(resource), path: resource.path, target: absolute(container) }], agent);
    send(req, res, 201, {
      Location: absolute(resource),
      Link: resourceLinks(app, resource),
      ETag: resource.etag ?? undefined,
      "Last-Modified": resource.modified.toUTCString(),
    });
  }

  function applyPreferredLinks(req, resource, replace) {
    if (!preferences(req.headers.prefer).has("set-linkset")) return false;
    const added = linksFromHeaders(parseLinkHeader(req.headers.link, absolute(resource)));
    resource.setLinks(replace ? added : mergeLinks(resource.links, added));
    return true;
  }

  async function put(req, res, resource, agent) {
    if (resource.isContainer) {
      throw new HttpError(405, "Container representations are server-managed", { headers: { Allow: allowFor(resource) } });
    }
    checkPreconditions(req, { etag: resource.etag, lastModified: resource.modified });
    const body = await readBody(req);
    resource.setContent(req.headers["content-type"] || resource.contentType, body);
    const applied = applyPreferredLinks(req, resource, true);
    app.notify([{ kind: "Update", object: objectOf(resource), path: resource.path }], agent);
    send(req, res, 204, { ETag: resource.etag, "Last-Modified": resource.modified.toUTCString(), "Preference-Applied": applied ? "set-linkset" : undefined });
  }

  async function patch(req, res, resource, agent) {
    if (resource.isContainer) {
      throw new HttpError(405, "Container representations are server-managed", { headers: { Allow: allowFor(resource) } });
    }
    if (mediaTypeOf(req.headers["content-type"]) !== MEDIA.JSON_PATCH) {
      throw new HttpError(415, `Supported patch formats: ${MEDIA.JSON_PATCH}`, { headers: patchHeaders(resource) });
    }
    if (!isJsonMedia(resource.contentType)) {
      throw new HttpError(415, "JSON Patch can only be applied to JSON resources");
    }
    checkPreconditions(req, { etag: resource.etag, lastModified: resource.modified });
    const patchDoc = parseJsonBody(await readBody(req), "JSON Patch document");
    let current;
    try {
      current = JSON.parse(resource.body.toString("utf8"));
    } catch {
      throw new HttpError(409, "The stored resource is not valid JSON");
    }
    let result;
    try {
      result = applyPatch(current, patchDoc);
    } catch (e) {
      throw patchErrorToHttp(e);
    }
    resource.setContent(resource.contentType, Buffer.from(JSON.stringify(result)));
    const applied = applyPreferredLinks(req, resource, false);
    app.notify([{ kind: "Update", object: objectOf(resource), path: resource.path }], agent);
    send(req, res, 204, { ETag: resource.etag, "Last-Modified": resource.modified.toUTCString(), "Preference-Applied": applied ? "set-linkset" : undefined });
  }

  function del(req, res, resource, agent) {
    if (!resource.parent) throw new HttpError(405, "The storage root cannot be deleted", { headers: { Allow: allowFor(resource) } });
    const depth = req.headers.depth;
    let recursive = false;
    if (depth !== undefined) {
      const d = String(depth).trim().toLowerCase();
      if (d === "infinity") recursive = true;
      else if (d !== "0") throw new HttpError(400, 'Depth must be "0" or "infinity"');
    }
    checkPreconditions(req, { etag: resource.etag ?? makeEtag(resource.path, resource.modified.toISOString()), lastModified: resource.modified });
    if (resource.isContainer && resource.children.size > 0 && !recursive) {
      throw new HttpError(409, `Cannot delete container ${resource.path} - container is not empty.`);
    }
    const events = app.store.remove(resource).map((r) => ({ kind: "Delete", object: objectOf(r), path: r.path, origin: absolute(r.parent) }));
    app.notify(events, agent);
    send(req, res, 204);
  }

  function getLinkset(req, res, resource) {
    const headers = {
      ETag: resource.linksetEtag,
      "Last-Modified": resource.linksetModified.toUTCString(),
      Allow: LINKSET_ALLOW,
      "Accept-Patch": MEDIA.JSON_PATCH,
      Link: serializeLink(app.storageId, REL_STORAGE),
    };
    if (isNotModified(req, resource.linksetEtag, resource.linksetModified)) return send(req, res, 304, headers);
    send(req, res, 200, { ...headers, "Content-Type": MEDIA.LINKSET_JSON }, linksetDocument(app, resource));
  }

  async function updateLinkset(req, res, resource, agent, method) {
    if (method === "PUT") {
      const ct = mediaTypeOf(req.headers["content-type"]);
      if (ct !== MEDIA.LINKSET_JSON && ct !== MEDIA.JSON) {
        throw new HttpError(415, `Linksets are replaced with ${MEDIA.LINKSET_JSON}`);
      }
    } else if (mediaTypeOf(req.headers["content-type"]) !== MEDIA.JSON_PATCH) {
      throw new HttpError(415, `Supported patch formats: ${MEDIA.JSON_PATCH}`, { headers: { "Accept-Patch": MEDIA.JSON_PATCH } });
    }
    checkPreconditions(req, { etag: resource.linksetEtag, lastModified: resource.linksetModified });
    const input = parseJsonBody(await readBody(req), method === "PUT" ? "linkset document" : "JSON Patch document");
    let doc = input;
    if (method === "PATCH") {
      try {
        doc = applyPatch(linksetDocument(app, resource), input);
      } catch (e) {
        throw patchErrorToHttp(e);
      }
    }
    resource.setLinks(linksFromLinksetDocument(app, resource, doc));
    app.notify([{ kind: "Update", object: objectOf(resource), path: resource.path }], agent);
    send(req, res, 204, { ETag: resource.linksetEtag });
  }

  async function handleLinkset(req, res, resource, agent) {
    switch (req.method) {
      case "GET":
      case "HEAD":
        return getLinkset(req, res, resource);
      case "PUT":
      case "PATCH":
        return updateLinkset(req, res, resource, agent, req.method);
      case "OPTIONS":
        return send(req, res, 204, { Allow: LINKSET_ALLOW, "Accept-Patch": MEDIA.JSON_PATCH });
      default:
        throw new HttpError(405, undefined, { headers: { Allow: LINKSET_ALLOW } });
    }
  }

  /** Looks up the resource (or linkset) a /root/ path refers to. */
  function lookup(path) {
    if (path.endsWith(".meta")) {
      const target = app.store.resolve(path.slice(0, -5));
      if (target) return { resource: target, linkset: true };
    }
    const resource = app.store.resolve(path);
    return resource ? { resource, linkset: false } : null;
  }

  async function handle(req, res, url, agent) {
    const found = lookup(url.pathname);
    if (!found) throw new HttpError(404, `No resource at ${url.pathname}`);
    const { resource, linkset } = found;
    if (linkset) return handleLinkset(req, res, resource, agent);
    switch (req.method) {
      case "GET":
      case "HEAD":
        return resource.isContainer ? getContainer(req, res, url, resource) : getData(req, res, resource);
      case "POST":
        if (!resource.isContainer) throw new HttpError(405, "Resources are created by POSTing to a container", { headers: { Allow: allowFor(resource) } });
        return create(req, res, resource, agent);
      case "PUT":
        return put(req, res, resource, agent);
      case "PATCH":
        return patch(req, res, resource, agent);
      case "DELETE":
        return del(req, res, resource, agent);
      case "OPTIONS":
        return send(req, res, 204, { Allow: allowFor(resource), ...patchHeaders(resource), ...(resource.isContainer ? { "Accept-Post": "*/*" } : {}) });
      default:
        throw new HttpError(405, undefined, { headers: { Allow: allowFor(resource) } });
    }
  }

  return { handle, lookup };
}

/** Parses a single-range "bytes=" Range header. Returns {start,end}, "unsatisfiable", or null (ignore). */
export function parseRange(header, size) {
  const m = /^\s*bytes\s*=\s*(\d*)\s*-\s*(\d*)\s*$/i.exec(header);
  if (!m || (m[1] === "" && m[2] === "")) return null;
  let start;
  let end;
  if (m[1] === "") {
    const suffix = Number(m[2]);
    if (suffix === 0 || size === 0) return "unsatisfiable";
    start = Math.max(0, size - suffix);
    end = size - 1;
  } else {
    start = Number(m[1]);
    if (m[2] !== "" && Number(m[2]) < start) return null;
    end = m[2] === "" ? size - 1 : Math.min(Number(m[2]), size - 1);
    if (start >= size) return "unsatisfiable";
  }
  return { start, end };
}
