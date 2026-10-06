// SPDX-License-Identifier: MIT
// A scriptable in-process fetch for client tests.

export interface Recorded {
  method: string;
  url: string;
  headers: Headers;
  body: string;
}

export type Handler = (req: Request, body: string) => Response | Promise<Response>;

interface Route {
  method: string | undefined;
  path: string | RegExp;
  handler: Handler;
}

export class FakeServer {
  readonly requests: Recorded[] = [];
  readonly #routes: Route[] = [];

  constructor(readonly origin = "https://storage.example") {}

  on(method: string | undefined, path: string | RegExp, handler: Handler): this {
    this.#routes.unshift({ method, path, handler });
    return this;
  }

  get(path: string | RegExp, handler: Handler): this {
    return this.on("GET", path, handler);
  }

  readonly fetch: typeof fetch = async (input, init) => {
    const req = new Request(input as RequestInfo, init);
    const body = req.body ? await req.clone().text() : "";
    this.requests.push({ method: req.method, url: req.url, headers: new Headers(req.headers), body });
    const url = new URL(req.url);
    const target = url.pathname + url.search;
    for (const r of this.#routes) {
      if (r.method && r.method !== req.method) continue;
      const hit = typeof r.path === "string" ? r.path === target || r.path === url.pathname : r.path.test(target);
      if (hit) return r.handler(req, body);
    }
    return new Response("not found", { status: 404 });
  };

  /** Requests to a path (any method). */
  to(path: string): Recorded[] {
    return this.requests.filter((r) => new URL(r.url).pathname === path);
  }
}

export function json(body: unknown, init: ResponseInit & { contentType?: string } = {}): Response {
  const headers = new Headers(init.headers);
  if (!headers.has("content-type")) headers.set("content-type", init.contentType ?? "application/json");
  return new Response(JSON.stringify(body), { ...init, headers });
}
