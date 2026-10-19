// SPDX-License-Identifier: MIT
// Moving a resource between containers (lws10-core "Moving Resources"): the JSON Patch that
// changes the up link in its linkset, and what the storage's answer says about where it went.
import { Rel } from "../constants.js";
import { ProtocolError } from "../errors.js";
import { normalizeRel } from "../http/link.js";
import { JsonPatch, JsonPointer } from "../json-patch.js";
import { isJsonMediaType, resolveUrl, type UrlLike } from "../util/http.js";
import { isObject } from "../util/types.js";
import { Linkset } from "./linkset.js";
import { ResourceMetadata } from "./resource.js";

/** Result of a move. */
export interface MoveResult {
  status: number;
  /** Absolute URL of the resource after the move. */
  location: string;
  /** Absolute URL of its linkset after the move. */
  linkset: string;
  /** True when the resource kept its URL (`location` is the URL that was moved). */
  identifierPreserved: boolean;
  /** New ETag of the linkset, when the server returned one. */
  etag: string | undefined;
  metadata: ResourceMetadata;
  /** The updated linkset, when the storage answered `200` with it. */
  document: Linkset | undefined;
}

const isUp = (rel: string): boolean => normalizeRel(rel) === Rel.UP;

/**
 * The JSON Patch that moves `resourceUrl` into `destinationUrl`, for its
 * linkset as read from `linksetUrl`: `test` that the `up` link still holds the
 * target as read, and `replace` it with the destination. The link context is
 * the first whose `anchor` resolves to the resource, or the only one when it
 * has no `anchor`; the `up` link is its first `up` target. A linkset that
 * shows no `up` link of the resource is a {@link ProtocolError}.
 */
export function movePatch(resourceUrl: UrlLike, linksetUrl: UrlLike, linkset: unknown, destinationUrl: UrlLike): JsonPatch {
  const resource = new URL(resourceUrl).href;
  const base = new URL(linksetUrl).href;
  const doc = linkset instanceof Linkset ? linkset.toJSON() : linkset;
  if (!isObject(doc) || !Array.isArray(doc["linkset"])) {
    throw new ProtocolError(`the linkset ${base} is not an object with a 'linkset' array`);
  }
  const contexts: unknown[] = doc["linkset"];
  let i = contexts.findIndex((c) => isObject(c) && typeof c["anchor"] === "string" && resolveUrl(c["anchor"], base) === resource);
  if (i < 0 && contexts.length === 1 && isObject(contexts[0]) && contexts[0]["anchor"] === undefined) i = 0;
  const context = contexts[i];
  if (!isObject(context)) throw new ProtocolError(`the linkset ${base} has no link context for ${resource}`);
  for (const [rel, targets] of Object.entries(context)) {
    if (rel === "anchor" || !isUp(rel) || !Array.isArray(targets)) continue;
    const j = targets.findIndex((t) => isObject(t) && typeof t["href"] === "string");
    if (j < 0) continue;
    const path = JsonPointer.from(["linkset", i, rel, j, "href"]);
    return new JsonPatch().test(path, (targets[j] as Record<string, unknown>)["href"]).replace(path, new URL(destinationUrl).href);
  }
  throw new ProtocolError(`the linkset ${base} has no up link for ${resource}`);
}

/**
 * Read the storage's answer to a move patch. A storage that keeps identifiers
 * answers `204` (or `200` with the linkset); one that does not answers `200`
 * with the updated linkset, whose `anchor` is the new identifier, and
 * `Content-Location`, the linkset's new URL.
 */
export async function readMoveResult(resourceUrl: UrlLike, linksetUrl: UrlLike, response: Response): Promise<MoveResult> {
  const resource = new URL(resourceUrl).href;
  const metadata = ResourceMetadata.fromResponse(response, new URL(linksetUrl).href);
  const contentLocation = response.headers.get("content-location");
  const linkset = contentLocation ? resolveUrl(contentLocation, metadata.url) : metadata.url;
  const text = await response.text();
  let document: Linkset | undefined;
  if (text.trim() && isJsonMediaType(response.headers.get("content-type"))) {
    try {
      document = Linkset.parse(JSON.parse(text));
    } catch (e) {
      throw new ProtocolError(`the answer to the move of ${resource} is not a linkset`, { cause: e });
    }
  }
  const anchor = document?.contexts.find((c) => [...c.relations].some(([rel, t]) => isUp(rel) && t.length > 0))?.anchor;
  const location = anchor === undefined ? resource : resolveUrl(anchor, linkset);
  return {
    status: response.status,
    location,
    linkset,
    identifierPreserved: location === resource,
    etag: metadata.etag,
    metadata,
    document,
  };
}
