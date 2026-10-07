// SPDX-License-Identifier: MIT
// A minimal MCP client over Streamable HTTP, with no dependencies: enough to call the driver's tools.

const PROTOCOL_VERSION = "2025-06-18";

export class McpClient {
  /**
   * @param {string} endpoint the MCP endpoint, such as http://127.0.0.1:18095/mcp
   * @param {{token?: string}} options a bearer token, when the driver has one
   */
  constructor(endpoint, { token } = {}) {
    this.endpoint = endpoint;
    this.token = token;
    this.nextId = 1;
    this.sessionId = undefined;
    this.protocolVersion = undefined;
  }

  async connect() {
    const result = await this.request("initialize", {
      protocolVersion: PROTOCOL_VERSION,
      capabilities: {},
      clientInfo: { name: "lws-driver-touchstone", version: "0.1.0" },
    });
    this.protocolVersion = result.protocolVersion;
    await this.post({ jsonrpc: "2.0", method: "notifications/initialized" });
    return result;
  }

  async listTools() {
    const tools = [];
    let cursor;
    do {
      const page = await this.request("tools/list", cursor ? { cursor } : {});
      tools.push(...page.tools);
      cursor = page.nextCursor;
    } while (cursor);
    return tools;
  }

  /** Calls a tool and returns its result's JSON; a tool error throws. */
  async call(name, args = {}) {
    const result = await this.request("tools/call", { name, arguments: args });
    const text = (result.content ?? []).find((c) => c.type === "text")?.text ?? "";
    if (result.isError) throw new Error(`${name}: ${text}`);
    return result.structuredContent ?? JSON.parse(text);
  }

  async close() {
    if (!this.sessionId) return;
    await fetch(this.endpoint, { method: "DELETE", headers: this.headers() }).catch(() => {});
  }

  async request(method, params) {
    const id = this.nextId++;
    const message = await this.post({ jsonrpc: "2.0", id, method, params }, id);
    if (message.error) throw new Error(`${method}: ${message.error.message} (${message.error.code})`);
    return message.result;
  }

  headers() {
    const headers = { "Content-Type": "application/json", Accept: "application/json, text/event-stream" };
    if (this.token) headers.Authorization = `Bearer ${this.token}`;
    if (this.sessionId) headers["Mcp-Session-Id"] = this.sessionId;
    if (this.protocolVersion) headers["MCP-Protocol-Version"] = this.protocolVersion;
    return headers;
  }

  async post(body, id) {
    const response = await fetch(this.endpoint, { method: "POST", headers: this.headers(), body: JSON.stringify(body) });
    const session = response.headers.get("mcp-session-id");
    if (session) this.sessionId = session;
    if (id === undefined) {
      if (!response.ok) throw new Error(`${body.method}: HTTP ${response.status}`);
      await response.arrayBuffer();
      return undefined;
    }
    if (!response.ok) throw new Error(`${body.method}: HTTP ${response.status} ${await response.text()}`);
    const type = response.headers.get("content-type") ?? "";
    if (type.startsWith("application/json")) return response.json();
    if (type.startsWith("text/event-stream")) return readEvents(response, id);
    throw new Error(`${body.method}: unexpected content type ${type}`);
  }
}

/** Reads a server-sent event stream until the JSON-RPC response with `id` arrives. */
async function readEvents(response, id) {
  const decoder = new TextDecoder();
  let buffer = "";
  for await (const chunk of response.body) {
    buffer += decoder.decode(chunk, { stream: true });
    let end;
    while ((end = buffer.search(/\r?\n\r?\n/)) >= 0) {
      const event = buffer.slice(0, end);
      buffer = buffer.slice(end).replace(/^\r?\n\r?\n/, "");
      const data = event.split(/\r?\n/).filter((l) => l.startsWith("data:")).map((l) => l.slice(5).trimStart()).join("\n");
      if (!data) continue;
      const message = JSON.parse(data);
      if (message.id === id) {
        response.body.cancel().catch(() => {});
        return message;
      }
    }
  }
  throw new Error(`the event stream ended without a response to request ${id}`);
}
