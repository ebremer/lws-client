// SPDX-License-Identifier: MIT
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";
import { test } from "node:test";

const entry = fileURLToPath(new URL("../server.mjs", import.meta.url));

function run(args) {
  const child = spawn(process.execPath, [entry, ...args], { stdio: ["ignore", "pipe", "pipe"] });
  const firstLine = new Promise((resolve, reject) => {
    let out = "";
    child.stdout.on("data", (d) => {
      out += d;
      const nl = out.indexOf("\n");
      if (nl >= 0) resolve(out.slice(0, nl).trim());
    });
    child.on("exit", (code) => reject(new Error(`server exited with ${code}`)));
  });
  return { child, firstLine };
}

test("prints the listening line and serves the storage description", async () => {
  const { child, firstLine } = run(["--port", "0", "--page-size", "3", "--no-auth"]);
  try {
    const line = await firstLine;
    const m = /^LWS mock server listening on (http:\/\/localhost:(\d+))$/.exec(line);
    assert.ok(m, line);
    const description = await (await fetch(`${m[1]}/`)).json();
    assert.equal(description.id, `${m[1]}/`);
    assert.equal((await fetch(`${m[1]}/root/`)).status, 200, "--no-auth disables authentication");
  } finally {
    child.kill();
  }
});

test("rejects invalid options", async () => {
  const child = spawn(process.execPath, [entry, "--page-size", "0"], { stdio: "ignore" });
  const code = await new Promise((resolve) => child.on("exit", resolve));
  assert.equal(code, 2);
});
