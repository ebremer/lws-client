// SPDX-License-Identifier: MIT
// JSON Patch (RFC 6902) over JSON Pointer (RFC 6901). Patches are applied atomically to a copy.

/**
 * kind "malformed": the patch document itself is invalid (maps to 400 Bad Request).
 * kind "conflict":  the patch cannot be applied to the current state (maps to 409 Conflict).
 */
export class PatchError extends Error {
  constructor(kind, message) {
    super(message);
    this.kind = kind;
  }
}

const isObj = (v) => v !== null && typeof v === "object" && !Array.isArray(v);
const hasOwn = (o, k) => Object.prototype.hasOwnProperty.call(o, k);

export function parsePointer(pointer) {
  if (typeof pointer !== "string") throw new PatchError("malformed", "JSON Pointer must be a string");
  if (pointer === "") return [];
  if (pointer[0] !== "/") throw new PatchError("malformed", `Invalid JSON Pointer "${pointer}"`);
  return pointer
    .slice(1)
    .split("/")
    .map((seg) => {
      if (/~(?![01])/.test(seg)) throw new PatchError("malformed", `Invalid escape in JSON Pointer "${pointer}"`);
      return seg.replace(/~1/g, "/").replace(/~0/g, "~");
    });
}

export function escapeSegment(segment) {
  return segment.replace(/~/g, "~0").replace(/\//g, "~1");
}

export function deepEqual(a, b) {
  if (a === b) return true;
  if (typeof a !== typeof b || a === null || b === null || typeof a !== "object") return false;
  if (Array.isArray(a) !== Array.isArray(b)) return false;
  if (Array.isArray(a)) return a.length === b.length && a.every((x, i) => deepEqual(x, b[i]));
  const ka = Object.keys(a);
  const kb = Object.keys(b);
  return ka.length === kb.length && ka.every((k) => hasOwn(b, k) && deepEqual(a[k], b[k]));
}

function arrayIndex(arr, token, allowEnd) {
  if (allowEnd && token === "-") return arr.length;
  if (!/^(0|[1-9][0-9]*)$/.test(token)) throw new PatchError("conflict", `"${token}" is not a valid array index`);
  const i = Number(token);
  if (i > arr.length || (!allowEnd && i === arr.length)) throw new PatchError("conflict", `Array index ${i} is out of bounds`);
  return i;
}

function resolve(doc, tokens) {
  let cur = doc;
  for (const t of tokens) {
    if (Array.isArray(cur)) cur = cur[arrayIndex(cur, t, false)];
    else if (isObj(cur) && hasOwn(cur, t)) cur = cur[t];
    else throw new PatchError("conflict", `Path "/${tokens.join("/")}" does not exist`);
  }
  return cur;
}

function parentOf(doc, tokens) {
  const parent = resolve(doc, tokens.slice(0, -1));
  if (!Array.isArray(parent) && !isObj(parent)) {
    throw new PatchError("conflict", `Parent of "/${tokens.join("/")}" is not a container`);
  }
  return parent;
}

function add(doc, tokens, value) {
  if (tokens.length === 0) return value;
  const parent = parentOf(doc, tokens);
  const last = tokens[tokens.length - 1];
  if (Array.isArray(parent)) parent.splice(arrayIndex(parent, last, true), 0, value);
  else parent[last] = value;
  return doc;
}

function remove(doc, tokens) {
  if (tokens.length === 0) throw new PatchError("conflict", "Cannot remove the whole document");
  const parent = parentOf(doc, tokens);
  const last = tokens[tokens.length - 1];
  if (Array.isArray(parent)) parent.splice(arrayIndex(parent, last, false), 1);
  else if (hasOwn(parent, last)) delete parent[last];
  else throw new PatchError("conflict", `Path "/${tokens.join("/")}" does not exist`);
  return doc;
}

function replace(doc, tokens, value) {
  if (tokens.length === 0) return value;
  const parent = parentOf(doc, tokens);
  const last = tokens[tokens.length - 1];
  if (Array.isArray(parent)) parent[arrayIndex(parent, last, false)] = value;
  else if (hasOwn(parent, last)) parent[last] = value;
  else throw new PatchError("conflict", `Path "/${tokens.join("/")}" does not exist`);
  return doc;
}

const isPrefix = (a, b) => a.length < b.length && a.every((t, i) => t === b[i]);

export function applyPatch(document, patch) {
  if (!Array.isArray(patch)) throw new PatchError("malformed", "A JSON Patch document must be a JSON array");
  let doc = structuredClone(document);
  for (const [index, op] of patch.entries()) {
    if (!isObj(op) || typeof op.op !== "string") {
      throw new PatchError("malformed", `Operation ${index} must be an object with an "op" member`);
    }
    const path = parsePointer(op.path);
    const needValue = () => {
      if (!hasOwn(op, "value")) throw new PatchError("malformed", `Operation ${index} (${op.op}) requires "value"`);
      return structuredClone(op.value);
    };
    switch (op.op) {
      case "add":
        doc = add(doc, path, needValue());
        break;
      case "remove":
        doc = remove(doc, path);
        break;
      case "replace":
        doc = replace(doc, path, needValue());
        break;
      case "move": {
        const from = parsePointer(op.from);
        if (isPrefix(from, path)) throw new PatchError("conflict", `Cannot move "${op.from}" into its own child`);
        const value = resolve(doc, from);
        doc = remove(doc, from);
        doc = add(doc, path, value);
        break;
      }
      case "copy": {
        const from = parsePointer(op.from);
        doc = add(doc, path, structuredClone(resolve(doc, from)));
        break;
      }
      case "test":
        if (!deepEqual(resolve(doc, path), needValue())) {
          throw new PatchError("conflict", `Test operation ${index} failed at "${op.path}"`);
        }
        break;
      default:
        throw new PatchError("malformed", `Unknown operation "${op.op}"`);
    }
  }
  return doc;
}
