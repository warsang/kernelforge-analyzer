#!/usr/bin/env node
/**
 * Generates vendor/browsercc/dist/headers-manifest.json from
 * packages/compiler-worker/include/*.h (base64 per header).
 *
 * The wasm worker fetches this manifest at compile time and injects the
 * headers into clang's in-memory FS under /wdm/include. Run after any edit
 * to the include/ tree; committed so browsers don't need a build step.
 *
 * Usage: node packages/compiler-worker/scripts/gen-headers-manifest.mjs
 */

import { readFile, writeFile, mkdir } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { HEADERS } from "../src/wdk-headers.mjs";

const includeDir = path.join(
  path.dirname(fileURLToPath(import.meta.url)), "../include");
const outPath = path.join(
  path.dirname(fileURLToPath(import.meta.url)),
  "../../../vendor/browsercc/dist/headers-manifest.json");

const manifest = {};
for (const h of HEADERS) {
  const bytes = await readFile(path.join(includeDir, h));
  manifest[`wdm/include/${h}`] = bytes.toString("base64");
}
await mkdir(path.dirname(outPath), { recursive: true });
await writeFile(outPath, JSON.stringify(manifest));
console.log(`wrote ${outPath} (${Object.keys(manifest).length} headers)`);
