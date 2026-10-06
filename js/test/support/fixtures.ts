// SPDX-License-Identifier: MIT
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

// Compiled location: js/build-test/test/support/fixtures.js → repo/conformance/fixtures
const root = new URL("../../../../conformance/fixtures/", import.meta.url);

/** Load a shared conformance fixture (path relative to conformance/fixtures). */
export function fixture<T = any>(path: string): T {
  return JSON.parse(readFileSync(fileURLToPath(new URL(path, root)), "utf8")) as T;
}
