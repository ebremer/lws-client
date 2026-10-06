// SPDX-License-Identifier: MIT
// Notification envelopes and webhook subscriptions.
import { ActivityType } from "../constants.js";
import { ProtocolError } from "../errors.js";
import { parseDateTime } from "../util/http.js";
import { utf8Decode } from "../util/base64.js";
import { activityTypeEquals, hasType, isObject, toStringList } from "../util/types.js";

/** The resource an activity is about. */
export interface ActivityObject {
  id: string;
  types: string[];
}

/** An Activity Streams 2.0 activity describing a change. */
export class Activity {
  readonly id: string;
  readonly types: string[];
  readonly object: ActivityObject;
  /** Agent that performed the action. */
  readonly actor: string | undefined;
  /** Container the resource was added to (Create). */
  readonly target: string | undefined;
  /** Container the resource was removed from (Delete). */
  readonly origin: string | undefined;
  readonly published: Date | undefined;
  readonly publishedRaw: string | undefined;
  readonly raw: Readonly<Record<string, unknown>>;

  constructor(raw: Record<string, unknown>) {
    this.raw = raw;
    this.id = typeof raw["id"] === "string" ? raw["id"] : "";
    this.types = toStringList(raw["type"]);
    const obj = raw["object"];
    if (isObject(obj) && typeof obj["id"] === "string") {
      this.object = { id: obj["id"], types: toStringList(obj["type"]) };
    } else if (typeof obj === "string") {
      this.object = { id: obj, types: [] };
    } else {
      throw new ProtocolError("activity without an object id");
    }
    const str = (k: string): string | undefined => {
      const v = raw[k];
      if (typeof v === "string") return v;
      if (isObject(v) && typeof v["id"] === "string") return v["id"];
      return undefined;
    };
    this.actor = str("actor");
    this.target = str("target");
    this.origin = str("origin");
    this.publishedRaw = typeof raw["published"] === "string" ? raw["published"] : undefined;
    this.published = parseDateTime(raw["published"]);
  }

  /** True when the activity has the Activity Streams type (`Create`, `as:Create` or full IRI). */
  isType(type: string): boolean {
    return this.types.some((t) => activityTypeEquals(t, type));
  }
  isCreate(): boolean {
    return this.isType(ActivityType.CREATE);
  }
  isUpdate(): boolean {
    return this.isType(ActivityType.UPDATE);
  }
  isDelete(): boolean {
    return this.isType(ActivityType.DELETE);
  }
}

/** A notification envelope. */
export class Notification {
  /** The storage the notification is associated with. */
  readonly storage: string;
  /** Activities (always a list, even when the envelope carried a single object). */
  readonly activities: readonly Activity[];
  readonly raw: Readonly<Record<string, unknown>>;

  constructor(raw: Record<string, unknown>) {
    if (!hasType(toStringList(raw["type"]), "Notification")) {
      throw new ProtocolError(`notification type must be "Notification" (got ${JSON.stringify(raw["type"])})`);
    }
    if (typeof raw["storage"] !== "string") throw new ProtocolError("notification without a storage");
    this.raw = raw;
    this.storage = raw["storage"];
    const activity = raw["activity"];
    const list = Array.isArray(activity) ? activity : activity === undefined ? [] : [activity];
    this.activities = list.filter(isObject).map((a) => new Activity(a));
  }
}

/** Parse a notification from JSON text, bytes or an already parsed value. */
export function parseNotification(input: string | Uint8Array | ArrayBuffer | object): Notification {
  let json: unknown = input;
  try {
    if (typeof input === "string") json = JSON.parse(input);
    else if (input instanceof Uint8Array) json = JSON.parse(utf8Decode(input));
    else if (input instanceof ArrayBuffer) json = JSON.parse(utf8Decode(new Uint8Array(input)));
  } catch (e) {
    throw new ProtocolError("notification is not valid JSON", { cause: e });
  }
  if (!isObject(json)) throw new ProtocolError("notification is not a JSON object");
  return new Notification(json);
}

/** Input of `subscribe`. */
export interface WebhookSubscriptionRequest {
  /** Resources (containers are recursive) to subscribe to. */
  topics: readonly (string | URL)[];
  /** Inbox URL that will receive signed POST deliveries. */
  inbox: string | URL;
  /** Requested expiry. */
  expires?: Date | string;
}

/** A webhook subscription. */
export class Subscription {
  readonly type: string;
  /** Absolute URL of the subscription (GET to inspect, DELETE to cancel). */
  readonly subscription: string;
  readonly expires: Date | undefined;
  readonly expiresRaw: string | undefined;
  readonly raw: Readonly<Record<string, unknown>>;

  constructor(raw: Record<string, unknown>, subscriptionUrl: string) {
    this.raw = raw;
    this.type = typeof raw["type"] === "string" ? raw["type"] : toStringList(raw["type"])[0] ?? "";
    this.subscription = subscriptionUrl;
    this.expiresRaw = typeof raw["expires"] === "string" ? raw["expires"] : undefined;
    this.expires = parseDateTime(raw["expires"]);
  }
}
