// SPDX-License-Identifier: MIT
// Type Index pages and Type Search queries (lws10-index).
import { Rel } from "../constants.js";
import { ProtocolError } from "../errors.js";
import { isAbsoluteIri, isObject, toStringList } from "../util/types.js";
import type { PageLinks } from "./container.js";
import type { ResourceMetadata } from "./resource.js";

/** One page of a Type Index listing. */
export class TypeIndexPage implements PageLinks {
  readonly totalItems: number | undefined;
  /** Type IRIs on this page. */
  readonly types: readonly string[];
  readonly first: string | undefined;
  readonly next: string | undefined;
  readonly prev: string | undefined;
  readonly last: string | undefined;
  readonly metadata: ResourceMetadata;
  readonly raw: Readonly<Record<string, unknown>>;

  constructor(json: unknown, metadata: ResourceMetadata) {
    if (!isObject(json)) throw new ProtocolError("type index is not a JSON object");
    this.raw = json;
    this.metadata = metadata;
    this.totalItems = typeof json["totalItems"] === "number" ? json["totalItems"] : undefined;
    const items = Array.isArray(json["items"]) ? json["items"] : [];
    this.types = items
      .map((i: unknown) => (typeof i === "string" ? i : isObject(i) && typeof i["id"] === "string" ? i["id"] : undefined))
      .filter((t): t is string => t !== undefined);
    this.first = metadata.link(Rel.FIRST)?.href;
    this.next = metadata.link(Rel.NEXT)?.href;
    this.prev = metadata.link(Rel.PREV)?.href;
    this.last = metadata.link(Rel.LAST)?.href;
  }

  /** Document types as received (`TypeIndex`). */
  get documentTypes(): string[] {
    return toStringList(this.raw["type"]);
  }
}

type Group = readonly string[];

function checkIri(iri: string): string {
  if (typeof iri !== "string" || !isAbsoluteIri(iri)) {
    throw new TypeError(`type search values must be absolute IRIs (got ${JSON.stringify(iri)})`);
  }
  return iri;
}

/** Filter clause for one indexed link relation. */
export class RelationFilter {
  readonly #query: TypeQuery;
  readonly #key: string;
  constructor(query: TypeQuery, key: string) {
    this.#query = query;
    this.#key = key;
  }
  /** Each target becomes its own AND group. */
  allOf(...targets: string[]): TypeQuery {
    return this.#query.where(this.#key, "allOf", targets);
  }
  /** All targets form one OR group. */
  anyOf(...targets: string[]): TypeQuery {
    return this.#query.where(this.#key, "anyOf", targets);
  }
}

/**
 * An `application/lws-query+json` filter in conjunctive normal form.
 *
 * ```ts
 * const q = TypeQuery.anyOf(SCHEMA_PERSON, FOAF_PERSON).allOf(LwsType.DATA_RESOURCE);
 * ```
 */
export class TypeQuery {
  readonly #filters = new Map<string, Group[]>();

  /** A query whose `type` must include every IRI. */
  static allOf(...types: string[]): TypeQuery {
    return new TypeQuery().allOf(...types);
  }
  /** A query whose `type` must include at least one IRI. */
  static anyOf(...types: string[]): TypeQuery {
    return new TypeQuery().anyOf(...types);
  }

  /** Require every type (one AND group each). */
  allOf(...types: string[]): this {
    return this.where("type", "allOf", types);
  }
  /** Require at least one of the types (one OR group). */
  anyOf(...types: string[]): this {
    return this.where("type", "anyOf", types);
  }
  /** Filter on an indexed descriptive link relation. */
  relation(rel: string): RelationFilter {
    if (!rel || rel.startsWith("@")) throw new TypeError(`invalid relation key ${JSON.stringify(rel)}`);
    return new RelationFilter(this, rel);
  }

  /** Low-level: add groups under `key`. */
  where(key: string, mode: "allOf" | "anyOf", values: readonly string[]): this {
    const groups = this.#filters.get(key) ?? [];
    if (mode === "allOf") {
      for (const v of values) groups.push([checkIri(v)]);
    } else {
      if (values.length === 0) throw new TypeError("an anyOf group must not be empty");
      groups.push(values.map(checkIri));
    }
    this.#filters.set(key, groups);
    return this;
  }

  /** True when the query has no constraints (it matches every visible resource). */
  get isEmpty(): boolean {
    return [...this.#filters.values()].every((g) => g.length === 0);
  }

  /** The JSON filter document. */
  toJSON(): Record<string, (string | string[])[]> {
    const out: Record<string, (string | string[])[]> = {};
    for (const [key, groups] of this.#filters) {
      out[key] = groups.map((g) => (g.length === 1 ? g[0]! : [...g]));
    }
    return out;
  }

  toString(): string {
    return JSON.stringify(this.toJSON());
  }
}
