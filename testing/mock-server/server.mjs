#!/usr/bin/env node
// SPDX-License-Identifier: MIT
// LWS mock server command line entry point.

import { parseArgs } from "node:util";
import { startServer } from "./lib/server.mjs";

const usage = `Usage: node server.mjs [options]

Options:
  --port <n>        port to listen on (default 8787; 0 picks a free port)
  --host <addr>     interface to bind (default: IPv4 and IPv6 loopback)
  --base-url <url>  public base URL (default http://localhost:<port>)
  --page-size <n>   container / index / search page size (default 5)
  --no-auth         disable authentication (every request is anonymous)
  --verbose         log requests, token exchanges and webhook deliveries
  --help            show this help`;

let values;
try {
  ({ values } = parseArgs({
    options: {
      port: { type: "string", default: "8787" },
      host: { type: "string" },
      "base-url": { type: "string" },
      "page-size": { type: "string", default: "5" },
      "no-auth": { type: "boolean", default: false },
      verbose: { type: "boolean", default: false },
      help: { type: "boolean", default: false },
    },
  }));
} catch (e) {
  console.error(`${e.message}\n\n${usage}`);
  process.exit(2);
}

if (values.help) {
  console.log(usage);
  process.exit(0);
}

const port = Number(values.port);
const pageSize = Number(values["page-size"]);
if (!Number.isInteger(port) || port < 0 || port > 65535) {
  console.error(`Invalid --port ${values.port}`);
  process.exit(2);
}
if (!Number.isInteger(pageSize) || pageSize < 1) {
  console.error(`Invalid --page-size ${values["page-size"]}`);
  process.exit(2);
}

const server = await startServer({
  port,
  host: values.host,
  baseUrl: values["base-url"],
  pageSize,
  auth: !values["no-auth"],
  verbose: values.verbose,
});
console.log(`LWS mock server listening on ${server.url}`);

let closing = false;
const shutdown = async () => {
  if (closing) return;
  closing = true;
  await server.close();
  process.exit(0);
};
process.on("SIGINT", shutdown);
process.on("SIGTERM", shutdown);
