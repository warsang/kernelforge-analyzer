#!/usr/bin/env node
/**
 * Generates vendor/browsercc/dist/linux-headers-manifest.json from
 * packages/compiler-worker/include/linux/*.h (base64 per header).
 */
import { readFile, writeFile, mkdir } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { LINUX_HEADERS } from "../src/linux-headers.mjs";

const includeDir = path.join(path.dirname(fileURLToPath(import.meta.url)), "../include");
const outPath = path.join(path.dirname(fileURLToPath(import.meta.url)), "../../../vendor/browsercc/dist/linux-headers-manifest.json");

const manifest={};
for(const h of LINUX_HEADERS){
  const bytes=await readFile(path.join(includeDir, h));
  manifest[`linux/include/${h}`]=bytes.toString("base64");
}
await mkdir(path.dirname(outPath), {recursive:true});
await writeFile(outPath, JSON.stringify(manifest));
console.log(`wrote ${outPath} (${Object.keys(manifest).length} headers)`);
