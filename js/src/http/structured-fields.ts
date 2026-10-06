// SPDX-License-Identifier: MIT
// Structured Field Values for HTTP (RFC 8941 / RFC 9651): dictionaries, items,
// inner lists and parameters — the subset needed for Signature-Input,
// Signature and Content-Digest — with canonical serialisation.
import { base64ToBytes, bytesToBase64 } from "../util/base64.js";

/** A bare item, tagged with its structured-field type. */
export type BareItem =
  | { readonly type: "integer"; readonly value: number }
  | { readonly type: "decimal"; readonly value: number }
  | { readonly type: "string"; readonly value: string }
  | { readonly type: "token"; readonly value: string }
  | { readonly type: "bytes"; readonly value: Uint8Array }
  | { readonly type: "boolean"; readonly value: boolean }
  | { readonly type: "date"; readonly value: number }
  | { readonly type: "displaystring"; readonly value: string };

/** Parameters: an ordered map of key → bare item. */
export type Parameters = Map<string, BareItem>;

/** An item with parameters. */
export interface SfItem {
  readonly kind: "item";
  readonly value: BareItem;
  readonly params: Parameters;
}

/** An inner list with parameters. */
export interface SfInnerList {
  readonly kind: "innerList";
  readonly items: SfItem[];
  readonly params: Parameters;
}

/** A dictionary member. */
export type SfMember = SfItem | SfInnerList;

/** An ordered dictionary. */
export type SfDictionary = Map<string, SfMember>;

/** Thrown when a structured field cannot be parsed. */
export class StructuredFieldError extends SyntaxError {
  override name = "StructuredFieldError";
}

const isDigit = (c: string | undefined): boolean => c !== undefined && c >= "0" && c <= "9";
const isLcAlpha = (c: string | undefined): boolean => c !== undefined && c >= "a" && c <= "z";
const isAlpha = (c: string | undefined): boolean => c !== undefined && /[A-Za-z]/.test(c);
const TCHAR = /[!#$%&'*+\-.^_`|~0-9A-Za-z]/;

class Parser {
  i = 0;
  constructor(readonly s: string) {}

  fail(msg: string): never {
    throw new StructuredFieldError(`${msg} at position ${this.i}`);
  }
  peek(): string | undefined {
    return this.s[this.i];
  }
  done(): boolean {
    return this.i >= this.s.length;
  }
  skipSp(): void {
    while (this.peek() === " ") this.i++;
  }
  skipOws(): void {
    while (this.peek() === " " || this.peek() === "\t") this.i++;
  }

  dictionary(): SfDictionary {
    const dict: SfDictionary = new Map();
    this.skipSp();
    if (this.done()) return dict;
    for (;;) {
      const key = this.key();
      let member: SfMember;
      if (this.peek() === "=") {
        this.i++;
        member = this.itemOrInnerList();
      } else {
        member = { kind: "item", value: { type: "boolean", value: true }, params: this.parameters() };
      }
      dict.set(key, member);
      this.skipOws();
      if (this.done()) return dict;
      if (this.peek() !== ",") this.fail("expected ','");
      this.i++;
      this.skipOws();
      if (this.done()) this.fail("trailing comma");
    }
  }

  itemOrInnerList(): SfMember {
    return this.peek() === "(" ? this.innerList() : this.item();
  }

  innerList(): SfInnerList {
    this.i++; // (
    const items: SfItem[] = [];
    for (;;) {
      this.skipSp();
      if (this.peek() === ")") {
        this.i++;
        return { kind: "innerList", items, params: this.parameters() };
      }
      if (this.done()) this.fail("unterminated inner list");
      items.push(this.item());
      const c = this.peek();
      if (c !== " " && c !== ")") this.fail("expected ' ' or ')' in inner list");
    }
  }

  item(): SfItem {
    const value = this.bareItem();
    return { kind: "item", value, params: this.parameters() };
  }

  parameters(): Parameters {
    const params: Parameters = new Map();
    while (this.peek() === ";") {
      this.i++;
      this.skipSp();
      const key = this.key();
      let value: BareItem = { type: "boolean", value: true };
      if (this.peek() === "=") {
        this.i++;
        value = this.bareItem();
      }
      params.set(key, value);
    }
    return params;
  }

  key(): string {
    const c = this.peek();
    if (!isLcAlpha(c) && c !== "*") this.fail("invalid key");
    let key = "";
    while (!this.done()) {
      const ch = this.peek()!;
      if (isLcAlpha(ch) || isDigit(ch) || ch === "_" || ch === "-" || ch === "." || ch === "*") {
        key += ch;
        this.i++;
      } else break;
    }
    return key;
  }

  bareItem(): BareItem {
    const c = this.peek();
    if (c === "-" || isDigit(c)) return this.number();
    if (c === '"') return { type: "string", value: this.string() };
    if (c === "*" || isAlpha(c)) return { type: "token", value: this.token() };
    if (c === ":") return { type: "bytes", value: this.bytes() };
    if (c === "?") return { type: "boolean", value: this.boolean() };
    if (c === "@") {
      this.i++;
      const n = this.number();
      if (n.type !== "integer") this.fail("date must be an integer");
      return { type: "date", value: n.value };
    }
    if (c === "%") return { type: "displaystring", value: this.displayString() };
    return this.fail("unexpected character");
  }

  number(): BareItem {
    let sign = 1;
    if (this.peek() === "-") {
      sign = -1;
      this.i++;
    }
    if (!isDigit(this.peek())) this.fail("expected digit");
    let num = "";
    let decimal = false;
    while (!this.done()) {
      const ch = this.peek()!;
      if (isDigit(ch)) num += ch;
      else if (ch === "." && !decimal) {
        if (num.length > 12) this.fail("decimal integer part too long");
        decimal = true;
        num += ch;
      } else break;
      this.i++;
      if (!decimal && num.length > 15) this.fail("integer too long");
      if (decimal && num.length > 16) this.fail("decimal too long");
    }
    if (!decimal) return { type: "integer", value: sign * Number.parseInt(num, 10) };
    if (num.endsWith(".")) this.fail("decimal ends with '.'");
    if (num.length - num.indexOf(".") - 1 > 3) this.fail("too many fractional digits");
    return { type: "decimal", value: sign * Number.parseFloat(num) };
  }

  string(): string {
    this.i++; // "
    let out = "";
    for (;;) {
      if (this.done()) this.fail("unterminated string");
      const ch = this.s[this.i++]!;
      if (ch === "\\") {
        if (this.done()) this.fail("unterminated escape");
        const next = this.s[this.i++]!;
        if (next !== '"' && next !== "\\") this.fail("invalid escape");
        out += next;
      } else if (ch === '"') {
        return out;
      } else {
        const code = ch.charCodeAt(0);
        if (code < 0x20 || code > 0x7e) this.fail("invalid string character");
        out += ch;
      }
    }
  }

  token(): string {
    let out = "";
    while (!this.done()) {
      const ch = this.peek()!;
      if (TCHAR.test(ch) || ch === ":" || ch === "/") {
        out += ch;
        this.i++;
      } else break;
    }
    return out;
  }

  bytes(): Uint8Array {
    this.i++; // :
    const end = this.s.indexOf(":", this.i);
    if (end < 0) this.fail("unterminated byte sequence");
    const b64 = this.s.slice(this.i, end);
    this.i = end + 1;
    try {
      return base64ToBytes(b64);
    } catch {
      return this.fail("invalid base64 in byte sequence");
    }
  }

  boolean(): boolean {
    this.i++; // ?
    const c = this.s[this.i++];
    if (c === "1") return true;
    if (c === "0") return false;
    return this.fail("invalid boolean");
  }

  displayString(): string {
    this.i++; // %
    if (this.s[this.i++] !== '"') this.fail("expected '\"'");
    const bytes: number[] = [];
    for (;;) {
      if (this.done()) this.fail("unterminated display string");
      const ch = this.s[this.i++]!;
      if (ch === '"') return new TextDecoder("utf-8", { fatal: true }).decode(new Uint8Array(bytes));
      if (ch === "%") {
        const hex = this.s.slice(this.i, this.i + 2);
        if (!/^[0-9a-f]{2}$/.test(hex)) this.fail("invalid percent escape");
        bytes.push(Number.parseInt(hex, 16));
        this.i += 2;
      } else bytes.push(ch.charCodeAt(0));
    }
  }
}

/** Parse a structured-field dictionary (e.g. `Signature-Input`). */
export function parseDictionary(input: string): SfDictionary {
  const p = new Parser(input);
  const dict = p.dictionary();
  p.skipSp();
  if (!p.done()) p.fail("unexpected trailing characters");
  return dict;
}

/** Parse a structured-field item. */
export function parseItem(input: string): SfItem {
  const p = new Parser(input);
  p.skipSp();
  const item = p.item();
  p.skipSp();
  if (!p.done()) p.fail("unexpected trailing characters");
  return item;
}

/** Canonically serialise a bare item. */
export function serializeBareItem(item: BareItem): string {
  switch (item.type) {
    case "integer":
      return String(Math.trunc(item.value));
    case "decimal": {
      const rounded = Math.round(item.value * 1000) / 1000;
      const s = String(rounded);
      return s.includes(".") ? s : `${s}.0`;
    }
    case "string":
      return `"${item.value.replace(/\\/g, "\\\\").replace(/"/g, '\\"')}"`;
    case "token":
      return item.value;
    case "bytes":
      return `:${bytesToBase64(item.value)}:`;
    case "boolean":
      return item.value ? "?1" : "?0";
    case "date":
      return `@${Math.trunc(item.value)}`;
    case "displaystring": {
      let out = '%"';
      for (const b of new TextEncoder().encode(item.value)) {
        if (b === 0x25 || b === 0x22 || b < 0x20 || b > 0x7e) out += "%" + b.toString(16).padStart(2, "0");
        else out += String.fromCharCode(b);
      }
      return out + '"';
    }
  }
}

/** Canonically serialise parameters (`;key=value`, `;key` for true). */
export function serializeParams(params: Parameters): string {
  let out = "";
  for (const [key, value] of params) {
    out += value.type === "boolean" && value.value ? `;${key}` : `;${key}=${serializeBareItem(value)}`;
  }
  return out;
}

/** Canonically serialise an item or inner list. */
export function serializeMember(member: SfMember): string {
  if (member.kind === "item") return serializeBareItem(member.value) + serializeParams(member.params);
  return `(${member.items.map((i) => serializeMember(i)).join(" ")})${serializeParams(member.params)}`;
}

/** Canonically serialise a dictionary. */
export function serializeDictionary(dict: SfDictionary): string {
  const parts: string[] = [];
  for (const [key, member] of dict) {
    if (member.kind === "item" && member.value.type === "boolean" && member.value.value) {
      parts.push(key + serializeParams(member.params));
    } else parts.push(`${key}=${serializeMember(member)}`);
  }
  return parts.join(", ");
}
