// SPDX-License-Identifier: MIT
import { ACTIVITYSTREAMS_NS, LWS_NS } from "../constants.js";

const SCHEME = /^[A-Za-z][A-Za-z0-9+.-]*:/;

/** True when `value` is an absolute IRI (has a scheme). */
export function isAbsoluteIri(value: string): boolean {
  return SCHEME.test(value);
}

/**
 * Expand an LWS vocabulary term to its full IRI: `Container`, `lws:Container`
 * and `https://www.w3.org/ns/lws#Container` all expand to the latter. Other
 * absolute IRIs are returned unchanged.
 */
export function expandLwsTerm(term: string): string {
  if (term.startsWith("lws:")) return LWS_NS + term.slice(4);
  if (!term.includes(":") && !term.includes("/")) return LWS_NS + term;
  return term;
}

/** Compare two type values, treating LWS short terms and full IRIs as equal. */
export function typeEquals(a: string, b: string): boolean {
  return a === b || expandLwsTerm(a) === expandLwsTerm(b);
}

/** True when `types` contains `type` (LWS term aware). */
export function hasType(types: readonly string[], type: string): boolean {
  return types.some((t) => typeEquals(t, type));
}

/** Compare Activity Streams types: `Create`, `as:Create` and the full IRI are equal. */
export function activityTypeEquals(a: string, b: string): boolean {
  const expand = (t: string): string =>
    t.startsWith("as:") ? ACTIVITYSTREAMS_NS + t.slice(3) : t.includes(":") ? t : ACTIVITYSTREAMS_NS + t;
  return a === b || expand(a) === expand(b);
}

/** Normalise a JSON `type` value (string or array) into a string list. */
export function toStringList(value: unknown): string[] {
  if (value === undefined || value === null) return [];
  if (Array.isArray(value)) return value.filter((v): v is string => typeof v === "string");
  return typeof value === "string" ? [value] : [];
}

/** True for a non-null, non-array object. */
export function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
