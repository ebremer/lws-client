// SPDX-License-Identifier: MIT
// Storage description resource (a Controlled Identifier document specialisation).
import { ServiceType, SUBSCRIPTION_WEBHOOK } from "../constants.js";
import { ProtocolError } from "../errors.js";
import { resolveUrl } from "../util/http.js";
import { hasType, isObject, toStringList } from "../util/types.js";

/** A service entry of a storage description. */
export class Service {
  /** Optional service id (absolute). */
  readonly id: string | undefined;
  /** Service types as received. */
  readonly types: string[];
  /** Absolute service endpoint URL. */
  readonly serviceEndpoint: string;
  /** The raw JSON object (extra properties such as `subscriptionType`, `conformsTo`). */
  readonly raw: Readonly<Record<string, unknown>>;

  constructor(raw: Record<string, unknown>, base: string) {
    this.raw = raw;
    this.types = toStringList(raw["type"]);
    this.id = typeof raw["id"] === "string" ? resolveUrl(raw["id"], base) : undefined;
    const endpoint = raw["serviceEndpoint"];
    if (typeof endpoint !== "string") throw new ProtocolError("service entry without a serviceEndpoint URI");
    this.serviceEndpoint = resolveUrl(endpoint, base);
  }

  /** True when the service has the given type (LWS term aware). */
  hasType(type: string): boolean {
    return hasType(this.types, type);
  }

  /** An extra property of the service object. */
  property(name: string): unknown {
    return this.raw[name];
  }

  /** `subscriptionType` values of a NotificationService. */
  get subscriptionTypes(): string[] {
    return toStringList(this.raw["subscriptionType"]);
  }

  /** `conformsTo` values (e.g. supported access profiles). */
  get conformsTo(): string[] {
    return toStringList(this.raw["conformsTo"]);
  }

  /** True when a NotificationService supports webhook subscriptions. */
  supportsWebhooks(): boolean {
    return this.subscriptionTypes.some((t) => hasType([t], SUBSCRIPTION_WEBHOOK));
  }
}

/** A capability entry of a storage description. */
export class Capability {
  readonly id: string | undefined;
  readonly types: string[];
  readonly raw: Readonly<Record<string, unknown>>;

  constructor(raw: Record<string, unknown>, base: string) {
    this.raw = raw;
    this.types = toStringList(raw["type"]);
    this.id = typeof raw["id"] === "string" ? resolveUrl(raw["id"], base) : undefined;
  }

  hasType(type: string): boolean {
    return hasType(this.types, type);
  }

  property(name: string): unknown {
    return this.raw[name];
  }
}

/** A verification method (public key) of a controlled identifier document. */
export interface VerificationMethod {
  /** The id as written (may be absolute, `#fragment` or a bare fragment). */
  readonly id: string;
  readonly type: string | undefined;
  readonly controller: string | undefined;
  readonly publicKeyJwk: JsonWebKey | undefined;
  readonly raw: Readonly<Record<string, unknown>>;
}

function toVerificationMethod(raw: Record<string, unknown>): VerificationMethod {
  return {
    id: typeof raw["id"] === "string" ? raw["id"] : "",
    type: typeof raw["type"] === "string" ? raw["type"] : undefined,
    controller: typeof raw["controller"] === "string" ? raw["controller"] : undefined,
    publicKeyJwk: isObject(raw["publicKeyJwk"]) ? (raw["publicKeyJwk"] as JsonWebKey) : undefined,
    raw,
  };
}

const asObjects = (value: unknown): Record<string, unknown>[] =>
  (Array.isArray(value) ? value : value === undefined ? [] : [value]).filter(isObject);

/** A parsed storage description resource (`application/lws+cid`). */
export class StorageDescription {
  /** Canonical storage URI. */
  readonly id: string;
  /** Types as received (must include `Storage`). */
  readonly types: string[];
  /** Verification methods (keys), e.g. webhook signing keys. */
  readonly verificationMethods: readonly VerificationMethod[];
  /** `authentication` verification relationship entries (references or embedded methods). */
  readonly authentication: readonly (string | VerificationMethod)[];
  /** The raw JSON document. */
  readonly raw: Readonly<Record<string, unknown>>;
  readonly #services: Service[];
  readonly #capabilities: Capability[];

  /**
   * @param json the parsed document
   * @param url the URL it was retrieved from (base for relative references)
   */
  constructor(json: unknown, url?: string) {
    if (!isObject(json)) throw new ProtocolError("storage description is not a JSON object");
    this.raw = json;
    const base = typeof json["id"] === "string" ? resolveUrl(json["id"], url) : url;
    if (!base) throw new ProtocolError("storage description has no id");
    this.id = base;
    this.types = toStringList(json["type"]);
    if (!hasType(this.types, "Storage")) {
      throw new ProtocolError(`storage description type must include "Storage" (got ${JSON.stringify(json["type"])})`);
    }
    this.#services = asObjects(json["service"]).map((s) => new Service(s, base));
    this.#capabilities = asObjects(json["capability"]).map((c) => new Capability(c, base));
    this.verificationMethods = asObjects(json["verificationMethod"]).map(toVerificationMethod);
    this.authentication = (Array.isArray(json["authentication"]) ? json["authentication"] : [])
      .map((a: unknown) => (typeof a === "string" ? a : isObject(a) ? toVerificationMethod(a) : undefined))
      .filter((a): a is string | VerificationMethod => a !== undefined);
  }

  /** All services, or the services of a given type. */
  services(type?: string): Service[] {
    return type === undefined ? [...this.#services] : this.#services.filter((s) => s.hasType(type));
  }

  /** The first service of a type. */
  service(type: string): Service | undefined {
    return this.#services.find((s) => s.hasType(type));
  }

  /** All capabilities, or those of a given type. */
  capabilities(type?: string): Capability[] {
    return type === undefined ? [...this.#capabilities] : this.#capabilities.filter((c) => c.hasType(type));
  }

  /** The first capability of a type. */
  capability(type: string): Capability | undefined {
    return this.#capabilities.find((c) => c.hasType(type));
  }

  /** The storage root container URL. Throws {@link ProtocolError} when missing. */
  storageRoot(): string {
    const root = this.service(ServiceType.STORAGE_ROOT);
    if (!root) throw new ProtocolError("storage description has no StorageRoot service");
    return root.serviceEndpoint;
  }

  notificationService(): Service | undefined {
    return this.service(ServiceType.NOTIFICATION);
  }
  accessRequestService(): Service | undefined {
    return this.service(ServiceType.ACCESS_REQUEST);
  }
  accessGrantService(): Service | undefined {
    return this.service(ServiceType.ACCESS_GRANT);
  }
  typeIndexService(): Service | undefined {
    return this.service(ServiceType.TYPE_INDEX);
  }
  typeSearchService(): Service | undefined {
    return this.service(ServiceType.TYPE_SEARCH);
  }

  /**
   * Find a verification method by absolute id, `#fragment` or bare fragment;
   * relative ids are resolved against the storage id.
   */
  verificationMethod(idOrFragment: string): VerificationMethod | undefined {
    const target = this.#resolveKeyRef(idOrFragment);
    return this.verificationMethods.find((vm) => this.#resolveKeyRef(vm.id) === target);
  }

  /** True when the key `idOrFragment` is referenced from `authentication`. */
  isAuthenticationKey(idOrFragment: string): boolean {
    const target = this.#resolveKeyRef(idOrFragment);
    return this.authentication.some((a) => this.#resolveKeyRef(typeof a === "string" ? a : a.id) === target);
  }

  #resolveKeyRef(ref: string): string {
    if (!ref.includes(":") && !ref.startsWith("#") && !ref.startsWith("/")) ref = "#" + ref;
    return resolveUrl(ref, this.id);
  }
}
