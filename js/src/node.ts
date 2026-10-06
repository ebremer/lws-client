// SPDX-License-Identifier: MIT
/**
 * Node.js adapters (`lws-client/node`): receive signed webhook deliveries with
 * `node:http` (or Express/Fastify raw requests). Structurally typed — this
 * module does not import any `node:` module itself.
 *
 * @module
 */
import type { Notification } from "./models/notification.js";
import type { VerifiedNotification, WebhookRequestLike, WebhookVerifier } from "./notifications/webhook.js";
import { SignatureVerificationError } from "./errors.js";

/** The parts of `http.IncomingMessage` used here. */
export interface IncomingMessageLike extends AsyncIterable<Uint8Array | string> {
  method?: string | undefined;
  url?: string | undefined;
  headers: Record<string, string | string[] | undefined>;
}

/** The parts of `http.ServerResponse` used here. */
export interface ServerResponseLike {
  statusCode: number;
  setHeader(name: string, value: string): unknown;
  end(body?: string): unknown;
}

/** Read the complete body of an incoming request. */
export async function readBody(req: AsyncIterable<Uint8Array | string>, limitBytes = 1 << 20): Promise<Uint8Array> {
  const chunks: Uint8Array[] = [];
  let size = 0;
  for await (const chunk of req) {
    const bytes = typeof chunk === "string" ? new TextEncoder().encode(chunk) : chunk;
    size += bytes.length;
    if (size > limitBytes) throw new RangeError(`request body exceeds ${limitBytes} bytes`);
    chunks.push(bytes);
  }
  const out = new Uint8Array(size);
  let offset = 0;
  for (const c of chunks) {
    out.set(c, offset);
    offset += c.length;
  }
  return out;
}

/**
 * Convert an `IncomingMessage` into a {@link WebhookRequestLike}. `inboxUrl` is
 * the URL you registered as the subscription inbox (the request only carries
 * a path; behind proxies the public URL differs from the local one).
 */
export async function webhookRequestFromIncomingMessage(
  req: IncomingMessageLike,
  inboxUrl: string,
  options: { limitBytes?: number } = {},
): Promise<WebhookRequestLike> {
  const body = await readBody(req, options.limitBytes);
  const headers: Record<string, string | readonly string[] | undefined> = req.headers;
  return { method: req.method ?? "POST", url: inboxUrl, headers, body };
}

/** Options of {@link createWebhookHandler}. */
export interface WebhookHandlerOptions {
  /** The registered inbox URL (public URL of this endpoint). */
  inboxUrl: string;
  /** Maximum body size (default 1 MiB). */
  limitBytes?: number;
  /** Called with verification failures (the handler answers 401). */
  onError?: (error: unknown) => void;
}

/**
 * Create a `node:http` request handler that verifies deliveries, answers
 * `204` on success (`401` on verification failure, `405` for non-POST) and
 * passes the verified notification to `onNotification`.
 */
export function createWebhookHandler(
  verifier: WebhookVerifier,
  onNotification: (notification: Notification, verified: VerifiedNotification) => void | Promise<void>,
  options: WebhookHandlerOptions,
): (req: IncomingMessageLike, res: ServerResponseLike) => Promise<void> {
  return async (req, res) => {
    if ((req.method ?? "").toUpperCase() !== "POST") {
      res.statusCode = 405;
      res.setHeader("allow", "POST");
      res.end();
      return;
    }
    let verified: VerifiedNotification;
    try {
      const request = await webhookRequestFromIncomingMessage(req, options.inboxUrl, { limitBytes: options.limitBytes ?? 1 << 20 });
      verified = await verifier.verify(request);
    } catch (e) {
      options.onError?.(e);
      res.statusCode = e instanceof SignatureVerificationError ? 401 : 400;
      res.end();
      return;
    }
    res.statusCode = 204;
    res.end();
    await onNotification(verified.notification, verified);
  };
}
