#!/usr/bin/env node
// SPDX-License-Identifier: MIT
// The JavaScript/TypeScript adapter of the lws-client driver: runs the operations of
// driver/PROTOCOL.md with the lws-client of ../../../js (build it first: npm run build there).

import { createInterface } from "node:readline";
import {
  AccessGrant,
  AccessRequest,
  BearerTokenAuthenticator,
  HttpError,
  JsonPatch,
  Linkset,
  LwsClient,
  OpenIdCredentials,
  SelfSignedCredentials,
  TokenExchangeAuthenticator,
  TypeQuery,
  WebhookVerifier,
  generateKeyPair,
  importKeyPair,
} from "../../../js/dist/index.js";

const LIBRARY = "lws-client-js/0.1.0";

class AdapterError extends Error {
  constructor(kind, message) {
    super(message);
    this.kind = kind;
  }
}

const invalid = (message) => new AdapterError("InvalidArguments", message);

// ---------------------------------------------------------------------------------------------
// Arguments

function required(args, name, type = "string") {
  const value = args[name];
  if (value === undefined || value === null) throw invalid(`missing argument '${name}'`);
  if (type === "array" ? !Array.isArray(value) : typeof value !== type) throw invalid(`argument '${name}' must be a ${type}`);
  return value;
}

function optional(args, name, type = "string") {
  const value = args[name];
  if (value === undefined || value === null) return undefined;
  if (type === "array" ? !Array.isArray(value) : typeof value !== type) throw invalid(`argument '${name}' must be a ${type}`);
  return value;
}

/** A `body` argument as bytes, with the content type it implies. */
function bodyOf(body, contentType) {
  if (body === undefined || body === null) return { bytes: new Uint8Array(0), contentType: contentType ?? "application/octet-stream" };
  if (typeof body !== "object") throw invalid("argument 'body' must be an object");
  if (typeof body.text === "string") return { bytes: new TextEncoder().encode(body.text), contentType: contentType ?? "text/plain" };
  if (typeof body.base64 === "string") return { bytes: base64Bytes(body.base64, "body.base64"), contentType: contentType ?? "application/octet-stream" };
  if ("json" in body) return { bytes: new TextEncoder().encode(JSON.stringify(body.json)), contentType: contentType ?? "application/json" };
  throw invalid("argument 'body' must have text, base64 or json");
}

/** Strict base64: anything but the standard alphabet with its padding is InvalidArguments. */
function base64Bytes(text, name) {
  if (!/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(text)) throw invalid(`argument '${name}' is not base64`);
  return new Uint8Array(Buffer.from(text, "base64"));
}

/** A JSON document argument parsed by the library's model; a document it rejects is InvalidArguments. */
function documentOf(parse, value, name) {
  try {
    return parse(value);
  } catch (e) {
    throw invalid(`argument '${name}' is not a valid document: ${e.message}`);
  }
}

function patchOf(operations) {
  if (!Array.isArray(operations)) throw invalid("argument 'patch' must be an array of operations");
  const patch = new JsonPatch();
  for (const op of operations) {
    if (op === null || typeof op !== "object" || typeof op.op !== "string") throw invalid("a patch operation must be an object with an op");
    switch (op.op) {
      case "add": patch.add(op.path, op.value); break;
      case "remove": patch.remove(op.path); break;
      case "replace": patch.replace(op.path, op.value); break;
      case "move": patch.move(op.from, op.path); break;
      case "copy": patch.copy(op.from, op.path); break;
      case "test": patch.test(op.path, op.value); break;
      default: throw invalid(`unknown patch operation '${op.op}'`);
    }
  }
  return patch;
}

function queryOf(query) {
  if (query === null || typeof query !== "object" || Array.isArray(query)) throw invalid("argument 'query' must be an object");
  const q = new TypeQuery();
  for (const [key, groups] of Object.entries(query)) {
    if (!Array.isArray(groups)) throw invalid(`query member '${key}' must be a list of groups`);
    for (const group of groups) {
      if (typeof group === "string") q.where(key, "allOf", [group]);
      else if (Array.isArray(group)) q.where(key, "anyOf", group);
      else throw invalid(`a group of query member '${key}' must be an IRI or a list of IRIs`);
    }
  }
  return q;
}

function limitOf(args) {
  const limit = optional(args, "limit", "number") ?? 1000;
  if (!Number.isInteger(limit) || limit < 0) throw invalid("argument 'limit' must be a non-negative integer");
  return limit;
}

// ---------------------------------------------------------------------------------------------
// Results

const TEXTUAL = /^(text\/[^;]*|application\/(json|xml)|[^;]*\+(json|xml))\s*(;|$)/i;

function bodyResult(bytes, contentType) {
  if (contentType && TEXTUAL.test(contentType.trim())) return { text: new TextDecoder().decode(bytes) };
  return { base64: Buffer.from(bytes).toString("base64") };
}

function metadataResult(m) {
  return {
    url: m.url,
    status: m.status,
    etag: m.etag,
    lastModified: m.headers.get("last-modified") ?? undefined,
    contentType: m.contentType,
    contentLength: m.contentLength,
    links: m.links().map((l) => ({ href: l.href, rel: l.rel, params: { ...l.params } })),
    linkset: m.linkset,
    parent: m.parent,
    storage: m.storage,
    types: m.types,
    allow: m.allow,
    acceptPatch: m.acceptPatch,
  };
}

const itemResult = (i) => ({ id: i.id, types: i.types, format: i.format, size: i.size, modified: i.modifiedRaw });

function pageResult(p) {
  return {
    id: p.id, types: p.types, totalItems: p.totalItems, items: p.items.map(itemResult),
    first: p.first, next: p.next, prev: p.prev, last: p.last, metadata: metadataResult(p.metadata),
  };
}

const updateResult = (u) => ({ status: u.status, etag: u.etag, metadata: metadataResult(u.metadata) });
const createdResult = (c) => ({ location: c.location, metadata: metadataResult(c.metadata) });

function storageResult(s) {
  let storageRoot;
  try {
    storageRoot = s.storageRoot();
  } catch {
    storageRoot = undefined;
  }
  return {
    id: s.id,
    types: s.types,
    storageRoot,
    services: s.services().map((svc) => ({
      id: svc.id, types: svc.types, serviceEndpoint: svc.serviceEndpoint,
      subscriptionType: svc.property("subscriptionType") === undefined ? undefined : svc.subscriptionTypes,
    })),
    verificationMethods: s.verificationMethods.map((vm) => ({ id: vm.id, type: vm.type, controller: vm.controller })),
    raw: s.raw,
  };
}

const subscriptionResult = (s) => ({ subscription: s.subscription, types: [s.type], expires: s.expiresRaw, raw: s.raw });

async function take(iterable, limit) {
  const items = [];
  for await (const item of iterable) {
    if (items.length === limit) return { items, truncated: true };
    items.push(item);
  }
  return { items, truncated: false };
}

// ---------------------------------------------------------------------------------------------
// The client

let client = new LwsClient();

async function configure(args) {
  const auth = args.auth ?? { type: "none" };
  if (auth === null || typeof auth !== "object") throw invalid("argument 'auth' must be an object");
  const exchangeOptions = {};
  const allowInsecureHttp = optional(args, "allowInsecureHttp", "boolean");
  if (allowInsecureHttp !== undefined) exchangeOptions.allowInsecureHttp = allowInsecureHttp;
  const result = { library: LIBRARY };
  let authenticator;
  switch (auth.type) {
    case "none":
      break;
    case "bearer":
      authenticator = new BearerTokenAuthenticator(required(auth, "token"), { realm: optional(auth, "realm") });
      break;
    case "openid":
      authenticator = new TokenExchangeAuthenticator(new OpenIdCredentials(required(auth, "idToken")), exchangeOptions);
      break;
    case "selfSigned": {
      const agent = required(auth, "agent");
      const jwk = required(auth, "privateJwk", "object");
      const kid = optional(auth, "kid") ?? jwk.kid;
      if (typeof kid !== "string") throw invalid("selfSigned needs 'kid', or a 'kid' in the private JWK");
      const key = await importKeyPair(jwk);
      authenticator = new TokenExchangeAuthenticator(SelfSignedCredentials.forAgent(agent, key, kid), exchangeOptions);
      result.agent = agent;
      result.kid = kid;
      break;
    }
    case "didKey": {
      const algorithm = optional(auth, "algorithm") ?? "ES256";
      if (algorithm !== "ES256" && algorithm !== "EdDSA") throw invalid(`unknown algorithm '${algorithm}'`);
      const credentials = SelfSignedCredentials.didKey(await generateKeyPair(algorithm));
      authenticator = new TokenExchangeAuthenticator(credentials, exchangeOptions);
      result.agent = credentials.agent;
      result.kid = credentials.kid;
      break;
    }
    default:
      throw invalid(`unknown auth type '${auth.type}'`);
  }
  const options = { authenticator };
  const userAgent = optional(args, "userAgent");
  if (userAgent !== undefined) options.userAgent = userAgent;
  const timeoutSeconds = optional(args, "timeoutSeconds", "number");
  if (timeoutSeconds !== undefined) options.timeoutMs = timeoutSeconds * 1000;
  const headers = optional(args, "headers", "object");
  if (headers !== undefined) options.headers = headers;
  client = new LwsClient(options);
  return result;
}

// ---------------------------------------------------------------------------------------------
// Operations

const operations = {
  configure,

  async discover_storage(args) {
    return storageResult(await client.discoverStorage(required(args, "url")));
  },

  async get_storage_description(args) {
    return storageResult(await client.getStorageDescription(required(args, "url")));
  },

  async head(args) {
    return metadataResult(await client.head(required(args, "url")));
  },

  async read(args) {
    const options = {};
    const accept = optional(args, "accept");
    if (accept !== undefined) options.accept = accept;
    const start = optional(args, "rangeStart", "number");
    const end = optional(args, "rangeEnd", "number");
    if (start !== undefined) options.range = end === undefined ? { start } : { start, end };
    else if (end !== undefined) throw invalid("rangeEnd needs rangeStart");
    const ifNoneMatch = optional(args, "ifNoneMatch");
    if (ifNoneMatch !== undefined) options.ifNoneMatch = ifNoneMatch;
    const prefer = optional(args, "prefer");
    if (prefer !== undefined) options.prefer = prefer;
    const resource = await client.read(required(args, "url"), options);
    const bytes = resource.notModified ? new Uint8Array(0) : await resource.bytes();
    return {
      metadata: metadataResult(resource),
      notModified: resource.notModified,
      contentRange: resource.contentRange,
      body: bodyResult(bytes, resource.contentType),
    };
  },

  async read_container(args) {
    return pageResult(await client.readContainer(required(args, "url")));
  },

  async list_container(args) {
    const { items, truncated } = await take(client.listContainer(required(args, "url")), limitOf(args));
    return { items: items.map(itemResult), truncated };
  },

  async create(args) {
    const { bytes, contentType } = bodyOf(args.body, optional(args, "contentType"));
    const options = {};
    const slug = optional(args, "slug");
    if (slug !== undefined) options.slug = slug;
    const types = optional(args, "types", "array");
    if (types !== undefined) options.types = types;
    const links = optional(args, "links", "array");
    if (links !== undefined) options.links = links.map((l) => ({ href: l.href, rel: l.rel }));
    return createdResult(await client.create(required(args, "container"), bytes, contentType, options));
  },

  async create_container(args) {
    const options = {};
    const slug = optional(args, "slug");
    if (slug !== undefined) options.slug = slug;
    return createdResult(await client.createContainer(required(args, "parent"), options));
  },

  async update(args) {
    const url = required(args, "url");
    if (args.body === undefined || args.body === null) throw invalid("missing argument 'body'");
    const { bytes, contentType } = bodyOf(args.body, optional(args, "contentType"));
    const options = {};
    const ifMatch = optional(args, "ifMatch");
    if (ifMatch !== undefined) options.ifMatch = ifMatch;
    const ifNoneMatch = optional(args, "ifNoneMatch");
    if (ifNoneMatch !== undefined) options.ifNoneMatch = ifNoneMatch;
    return updateResult(await client.update(url, bytes, contentType, options));
  },

  async patch(args) {
    const options = {};
    const ifMatch = optional(args, "ifMatch");
    if (ifMatch !== undefined) options.ifMatch = ifMatch;
    return updateResult(await client.patch(required(args, "url"), patchOf(args.patch), options));
  },

  async delete(args) {
    const options = {};
    const ifMatch = optional(args, "ifMatch");
    if (ifMatch !== undefined) options.ifMatch = ifMatch;
    if (optional(args, "recursive", "boolean")) options.recursive = true;
    await client.delete(required(args, "url"), options);
    return {};
  },

  async linkset_url(args) {
    return { linkset: await client.linksetUrl(required(args, "url")) };
  },

  async read_linkset(args) {
    const doc = await client.readLinkset(required(args, "url"));
    return { url: doc.url, etag: doc.etag, linkset: doc.linkset.toJSON(), allow: doc.allow, acceptPatch: doc.acceptPatch };
  },

  async update_linkset(args) {
    const linkset = documentOf((v) => Linkset.parse(v), required(args, "linkset", "object"), "linkset");
    const options = {};
    const ifMatch = optional(args, "ifMatch");
    if (ifMatch !== undefined) options.ifMatch = ifMatch;
    return updateResult(await client.updateLinkset(required(args, "linksetUrl"), linkset, options));
  },

  async patch_linkset(args) {
    const options = {};
    const ifMatch = optional(args, "ifMatch");
    if (ifMatch !== undefined) options.ifMatch = ifMatch;
    return updateResult(await client.patchLinkset(required(args, "linksetUrl"), patchOf(args.patch), options));
  },

  async subscribe(args) {
    const request = { topics: required(args, "topics", "array"), inbox: required(args, "inbox") };
    const expires = optional(args, "expires");
    if (expires !== undefined) request.expires = expires;
    return subscriptionResult(await client.subscribe(required(args, "serviceUrl"), request));
  },

  async list_subscriptions(args) {
    const { items, truncated } = await take(client.listSubscriptions(required(args, "serviceUrl")), limitOf(args));
    return { items: items.map(itemResult), truncated };
  },

  async get_subscription(args) {
    return subscriptionResult(await client.getSubscription(required(args, "url")));
  },

  async unsubscribe(args) {
    await client.unsubscribe(required(args, "url"));
    return {};
  },

  async verify_notification(args) {
    const headers = required(args, "headers", "object");
    const verifier = new WebhookVerifier({
      resolveStorageDescription: (id) => client.getStorageDescription(id),
      trustedStorages: optional(args, "trustedStorages", "array"),
    });
    const verified = await verifier.verify({
      method: required(args, "method"),
      url: required(args, "url"),
      headers,
      body: base64Bytes(required(args, "bodyBase64"), "bodyBase64"),
    });
    return {
      storage: verified.storage,
      keyid: verified.keyid,
      activities: verified.notification.activities.map((a) => ({ id: a.id || undefined, types: a.types, object: a.object.id, objectTypes: a.object.types })),
      raw: verified.notification.raw,
    };
  },

  async request_access(args) {
    const request = documentOf((v) => AccessRequest.parse(v), required(args, "request", "object"), "request");
    return { location: await client.requestAccess(required(args, "serviceUrl"), request) };
  },

  async get_access_request(args) {
    const document = await client.getAccessRequest(required(args, "url"));
    return { document: document.raw ?? document.toJSON() };
  },

  async list_access_requests(args) {
    const { items, truncated } = await take(client.listAccessRequests(required(args, "serviceUrl")), limitOf(args));
    return { items: items.map(itemResult), truncated };
  },

  async cancel_access_request(args) {
    await client.cancelAccessRequest(required(args, "url"));
    return {};
  },

  async grant_access(args) {
    const grant = documentOf((v) => AccessGrant.parse(v), required(args, "grant", "object"), "grant");
    return { location: await client.grantAccess(required(args, "serviceUrl"), grant) };
  },

  async get_access_grant(args) {
    const document = await client.getAccessGrant(required(args, "url"));
    return { document: document.raw ?? document.toJSON() };
  },

  async list_access_grants(args) {
    const { items, truncated } = await take(client.listAccessGrants(required(args, "serviceUrl")), limitOf(args));
    return { items: items.map(itemResult), truncated };
  },

  async revoke_access_grant(args) {
    await client.revokeAccessGrant(required(args, "url"));
    return {};
  },

  async read_type_index(args) {
    const page = await client.readTypeIndex(required(args, "url"));
    return { totalItems: page.totalItems, types: [...page.types], first: page.first, next: page.next, prev: page.prev, last: page.last };
  },

  async list_types(args) {
    const { items, truncated } = await take(client.listTypes(required(args, "serviceUrl")), limitOf(args));
    return { types: items, truncated };
  },

  async search_types(args) {
    return pageResult(await client.searchTypes(required(args, "serviceUrl"), queryOf(required(args, "query", "object"))));
  },

  async search_all(args) {
    const query = queryOf(required(args, "query", "object"));
    const { items, truncated } = await take(client.searchAll(required(args, "serviceUrl"), query), limitOf(args));
    return { items: items.map(itemResult), truncated };
  },

  async accepted_query_formats(args) {
    return { formats: await client.acceptedQueryFormats(required(args, "serviceUrl")) };
  },

  async shutdown() {
    return {};
  },
};

// ---------------------------------------------------------------------------------------------
// Errors

function errorResult(e) {
  if (e instanceof AdapterError) return { kind: e.kind, message: e.message };
  if (e instanceof HttpError) {
    const error = { kind: e.name, status: e.status, message: e.message };
    if (e.problem) {
      // RFC 9457 members are flat: the library keeps extension members apart, the wire does not.
      const { extensions, ...members } = e.problem;
      error.problem = { ...(extensions ?? {}), ...members };
    }
    if (e.name === "MethodNotAllowedError") error.allow = e.allow;
    if (e.name === "UnsupportedMediaTypeError") error.acceptPatch = e.acceptPatch;
    return error;
  }
  switch (e?.name) {
    case "AuthenticationError":
      return { kind: "AuthenticationError", message: e.message, oauthError: e.error, oauthErrorDescription: e.errorDescription };
    case "ProtocolError":
    case "SignatureVerificationError":
      return { kind: e.name, message: e.message };
    case "AbortError":
    case "TimeoutError":
      return { kind: "TransportError", message: e.message };
    case "TypeError":
      // fetch reports a failure to connect as a TypeError ("fetch failed") with the reason as its cause.
      if (e.message === "fetch failed") return { kind: "TransportError", message: `${e.message}: ${e.cause?.message ?? e.cause ?? ""}` };
      return { kind: "InvalidArguments", message: e.message };
    default:
      return { kind: "InternalError", message: e?.stack ?? String(e) };
  }
}

// ---------------------------------------------------------------------------------------------
// The protocol loop

function write(message) {
  process.stdout.write(`${JSON.stringify(message)}\n`);
}

// Logs belong on stderr: stdout carries protocol messages only.
console.log = console.info = console.debug = (...args) => console.error(...args);

write({ hello: { protocol: "lws-driver/1", language: "js", library: LIBRARY, operations: Object.keys(operations) } });

const lines = createInterface({ input: process.stdin, crlfDelay: Infinity });
for await (const line of lines) {
  if (line.trim() === "") continue;
  let request;
  try {
    request = JSON.parse(line);
  } catch {
    write({ id: null, ok: false, error: { kind: "InvalidArguments", message: "the request is not JSON" } });
    continue;
  }
  if (request === null || typeof request !== "object" || Array.isArray(request)) {
    write({ id: null, ok: false, error: { kind: "InvalidArguments", message: "the request is not a JSON object" } });
    continue;
  }
  const { id, op } = request;
  const args = request.args ?? {};
  const operation = Object.hasOwn(operations, op) ? operations[op] : undefined;
  if (!operation) {
    write({ id, ok: false, error: { kind: "Unsupported", message: `unknown operation '${op}'` } });
    continue;
  }
  try {
    if (args === null || typeof args !== "object" || Array.isArray(args)) throw invalid("args must be an object");
    write({ id, ok: true, result: await operation(args) });
  } catch (e) {
    write({ id, ok: false, error: errorResult(e) });
  }
  if (op === "shutdown") break;
}
process.exit(0);
