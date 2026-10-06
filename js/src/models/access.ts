// SPDX-License-Identifier: MIT
// Access requests and access grants (ODRL-based LWS Access Profile).
import { AccessType, LWS_CONTEXT, Operand, Operator } from "../constants.js";
import { ProtocolError } from "../errors.js";
import { formatDateTime } from "../util/http.js";
import { hasType, isObject, toStringList } from "../util/types.js";

/** A constraint (ODRL constraint model). */
export interface Constraint {
  leftOperand: string;
  operator: string;
  rightOperand: unknown;
}

/** The resources an access policy applies to. */
export interface AccessTarget {
  /** Target matcher type, e.g. `StorageResource`, `Container`, `DataResource`. */
  type: string;
  /** Resource identifiers. */
  values: string[];
}

/** One access policy (`AccessPolicy`). */
export interface AccessPolicy {
  /** Policy types (defaults to `["AccessPolicy"]`). */
  types?: string[];
  /** Actions: `read`, `modify`, `create`, `delete`… */
  actions: string[];
  /** Agent requesting/receiving access (or `PUBLIC_AGENT`). */
  assignee: string;
  target?: AccessTarget;
  constraints?: Constraint[];
}

/** Convenience factories for the constraints defined by the LWS access profile. */
export const Constraints = {
  purpose: (uri: string): Constraint => ({ leftOperand: Operand.PURPOSE, operator: Operator.EQ, rightOperand: uri }),
  purposeAnyOf: (uris: string[]): Constraint => ({ leftOperand: Operand.PURPOSE, operator: Operator.IS_ANY_OF, rightOperand: [...uris] }),
  client: (uri: string): Constraint => ({ leftOperand: Operand.CLIENT, operator: Operator.EQ, rightOperand: uri }),
  format: (mediaType: string): Constraint => ({ leftOperand: Operand.FORMAT, operator: Operator.EQ, rightOperand: mediaType }),
  formatAnyOf: (mediaTypes: string[]): Constraint => ({ leftOperand: Operand.FORMAT, operator: Operator.IS_ANY_OF, rightOperand: [...mediaTypes] }),
  type: (uri: string): Constraint => ({ leftOperand: Operand.TYPE, operator: Operator.EQ, rightOperand: uri }),
  typeAnyOf: (uris: string[]): Constraint => ({ leftOperand: Operand.TYPE, operator: Operator.IS_ANY_OF, rightOperand: [...uris] }),
  /** Access starts at `dateTime` (`dateTime gteq`). */
  notBefore: (dateTime: Date | string): Constraint => ({ leftOperand: Operand.DATE_TIME, operator: Operator.GTEQ, rightOperand: formatDateTime(dateTime) }),
  /** Access ends at `dateTime` (`dateTime lteq`). */
  notAfter: (dateTime: Date | string): Constraint => ({ leftOperand: Operand.DATE_TIME, operator: Operator.LTEQ, rightOperand: formatDateTime(dateTime) }),
} as const;

/** Fields shared by access requests and grants. */
export interface AccessDocumentInit {
  /** The storage the access is scoped to. */
  storage: string;
  /** Inbox for notifications about this request/grant. */
  inbox?: string;
  /** One or more access policies. */
  access: AccessPolicy[];
  /** Extra types besides `AccessRequest` / `AccessGrant`. */
  types?: string[];
  /** Extra JSON members (extension terms). */
  extra?: Record<string, unknown>;
}

function policyToJson(p: AccessPolicy): Record<string, unknown> {
  if (!p.actions.length) throw new TypeError("an access policy needs at least one action");
  if (!p.assignee) throw new TypeError("an access policy needs an assignee");
  const out: Record<string, unknown> = {
    type: p.types && p.types.length ? [...p.types] : [AccessType.POLICY],
    action: [...p.actions],
    assignee: p.assignee,
  };
  if (p.target) out["target"] = { type: p.target.type, value: [...p.target.values] };
  if (p.constraints && p.constraints.length) {
    out["constraint"] = p.constraints.map((c) => ({ leftOperand: c.leftOperand, operator: c.operator, rightOperand: c.rightOperand }));
  }
  return out;
}

function policyFromJson(raw: Record<string, unknown>): AccessPolicy {
  const target = raw["target"];
  const policy: AccessPolicy = {
    types: toStringList(raw["type"]),
    actions: toStringList(raw["action"]),
    assignee: typeof raw["assignee"] === "string" ? raw["assignee"] : "",
  };
  if (isObject(target)) {
    policy.target = { type: typeof target["type"] === "string" ? target["type"] : "", values: toStringList(target["value"]) };
  }
  const constraints = raw["constraint"];
  if (Array.isArray(constraints)) {
    policy.constraints = constraints.filter(isObject).map((c) => ({
      leftOperand: String(c["leftOperand"] ?? ""),
      operator: String(c["operator"] ?? ""),
      rightOperand: c["rightOperand"],
    }));
  }
  return policy;
}

abstract class AccessDocument {
  readonly types: string[];
  readonly storage: string;
  readonly inbox: string | undefined;
  readonly access: readonly AccessPolicy[];
  /** Raw JSON (for parsed documents) or extension members. */
  readonly raw: Readonly<Record<string, unknown>>;

  protected constructor(kind: string, init: AccessDocumentInit, raw?: Record<string, unknown>) {
    if (!init.storage) throw new TypeError(`${kind} needs a storage`);
    if (!init.access.length) throw new TypeError(`${kind} needs at least one access policy`);
    const types = init.types ? [...init.types] : [];
    if (!hasType(types, kind)) types.unshift(kind);
    this.types = types;
    this.storage = init.storage;
    this.inbox = init.inbox;
    this.access = init.access;
    this.raw = raw ?? { ...(init.extra ?? {}) };
  }

  /** The `application/lws+json` JSON-LD representation. */
  toJSON(): Record<string, unknown> {
    const extra = Object.fromEntries(
      Object.entries(this.raw).filter(([k]) => !["@context", "type", "storage", "inbox", "access"].includes(k)),
    );
    const out: Record<string, unknown> = { "@context": [LWS_CONTEXT], type: [...this.types] };
    if (this.inbox !== undefined) out["inbox"] = this.inbox;
    out["storage"] = this.storage;
    out["access"] = this.access.map(policyToJson);
    return { ...out, ...extra };
  }
}

function parseInit(kind: string, json: unknown): { init: AccessDocumentInit; raw: Record<string, unknown> } {
  if (!isObject(json)) throw new ProtocolError(`${kind} is not a JSON object`);
  const types = toStringList(json["type"]);
  if (!hasType(types, kind)) throw new ProtocolError(`document type must include "${kind}"`);
  if (typeof json["storage"] !== "string") throw new ProtocolError(`${kind} without a storage`);
  const access = Array.isArray(json["access"]) ? json["access"].filter(isObject).map(policyFromJson) : [];
  if (!access.length) throw new ProtocolError(`${kind} without access policies`);
  const init: AccessDocumentInit = { storage: json["storage"], access, types };
  if (typeof json["inbox"] === "string") init.inbox = json["inbox"];
  return { init, raw: json };
}

/** A request by an agent for access to resources. */
export class AccessRequest extends AccessDocument {
  constructor(init: AccessDocumentInit, raw?: Record<string, unknown>) {
    super(AccessType.REQUEST, init, raw);
  }
  /** Parse an access request document. */
  static parse(json: unknown): AccessRequest {
    const { init, raw } = parseInit(AccessType.REQUEST, json);
    return new AccessRequest(init, raw);
  }
}

/** A storage controller's record of granted access. */
export class AccessGrant extends AccessDocument {
  constructor(init: AccessDocumentInit, raw?: Record<string, unknown>) {
    super(AccessType.GRANT, init, raw);
  }
  /** Parse an access grant document. */
  static parse(json: unknown): AccessGrant {
    const { init, raw } = parseInit(AccessType.GRANT, json);
    return new AccessGrant(init, raw);
  }
}
