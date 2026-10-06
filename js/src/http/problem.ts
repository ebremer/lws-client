// SPDX-License-Identifier: MIT
// RFC 9457 problem details.
import { isJsonMediaType } from "../util/http.js";
import { isObject } from "../util/types.js";

/** An RFC 9457 problem details object. */
export interface ProblemDetails {
  type?: string;
  title?: string;
  status?: number;
  detail?: string;
  instance?: string;
  /** Extension members (everything except the five standard members). */
  extensions: Record<string, unknown>;
}

const STANDARD = new Set(["type", "title", "status", "detail", "instance"]);

/** Build problem details from a parsed JSON value; `undefined` if it is not one. */
export function toProblemDetails(json: unknown): ProblemDetails | undefined {
  if (!isObject(json)) return undefined;
  if (![...STANDARD].some((k) => k in json)) return undefined;
  const problem: ProblemDetails = { extensions: {} };
  if (typeof json["type"] === "string") problem.type = json["type"];
  if (typeof json["title"] === "string") problem.title = json["title"];
  if (typeof json["status"] === "number") problem.status = json["status"];
  if (typeof json["detail"] === "string") problem.detail = json["detail"];
  if (typeof json["instance"] === "string") problem.instance = json["instance"];
  for (const [k, v] of Object.entries(json)) if (!STANDARD.has(k)) problem.extensions[k] = v;
  return problem;
}

/** Parse problem details from a response body when the media type is JSON-based. */
export function parseProblemDetails(contentType: string | null | undefined, body: string): ProblemDetails | undefined {
  if (!isJsonMediaType(contentType) || !body) return undefined;
  try {
    return toProblemDetails(JSON.parse(body));
  } catch {
    return undefined;
  }
}
