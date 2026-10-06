// SPDX-License-Identifier: MIT
// JSON Patch (RFC 6902) builder and JSON Pointer (RFC 6901) helpers.

/** A JSON Patch operation. */
export type JsonPatchOperation =
  | { op: "add"; path: string; value: unknown }
  | { op: "remove"; path: string }
  | { op: "replace"; path: string; value: unknown }
  | { op: "move"; from: string; path: string }
  | { op: "copy"; from: string; path: string }
  | { op: "test"; path: string; value: unknown };

/** JSON Pointer helpers. */
export const JsonPointer = {
  /** Escape one reference token: `~` → `~0`, `/` → `~1`. */
  escape(segment: string): string {
    return segment.replace(/~/g, "~0").replace(/\//g, "~1");
  },
  /** Unescape one reference token. */
  unescape(segment: string): string {
    return segment.replace(/~1/g, "/").replace(/~0/g, "~");
  },
  /** Build a pointer from unescaped segments (`[]` → `""`). */
  from(segments: readonly (string | number)[]): string {
    return segments.map((s) => "/" + JsonPointer.escape(String(s))).join("");
  },
  /** Split a pointer into unescaped segments. */
  parse(pointer: string): string[] {
    if (pointer === "") return [];
    if (!pointer.startsWith("/")) throw new SyntaxError(`invalid JSON Pointer: ${pointer}`);
    return pointer.slice(1).split("/").map((s) => JsonPointer.unescape(s));
  },
} as const;

/**
 * A chainable JSON Patch document.
 *
 * ```ts
 * const patch = new JsonPatch().replace("/age", 31).add("/city", "Boston");
 * ```
 */
export class JsonPatch {
  readonly #ops: JsonPatchOperation[];

  constructor(operations: readonly JsonPatchOperation[] = []) {
    this.#ops = [...operations];
  }

  /** Create a patch from operations. */
  static of(...operations: JsonPatchOperation[]): JsonPatch {
    return new JsonPatch(operations);
  }

  /** The operations, in order. */
  get operations(): readonly JsonPatchOperation[] {
    return this.#ops;
  }

  /** Number of operations. */
  get length(): number {
    return this.#ops.length;
  }

  add(path: string, value: unknown): this {
    this.#ops.push({ op: "add", path, value });
    return this;
  }
  remove(path: string): this {
    this.#ops.push({ op: "remove", path });
    return this;
  }
  replace(path: string, value: unknown): this {
    this.#ops.push({ op: "replace", path, value });
    return this;
  }
  move(from: string, path: string): this {
    this.#ops.push({ op: "move", from, path });
    return this;
  }
  copy(from: string, path: string): this {
    this.#ops.push({ op: "copy", from, path });
    return this;
  }
  test(path: string, value: unknown): this {
    this.#ops.push({ op: "test", path, value });
    return this;
  }

  /** The JSON array representation. */
  toJSON(): JsonPatchOperation[] {
    return this.#ops.map((o) => ({ ...o }));
  }

  /** Serialised `application/json-patch+json` body. */
  toString(): string {
    return JSON.stringify(this.#ops);
  }
}
