#!/usr/bin/env node
/**
 * fetch-sogen-wasm.mjs — download the sogen emulator wasm payload.
 *
 * The 32-bit emscripten glue (analyzer.js) and worker loader are vendored
 * in-repo; the ~90 MB analyzer.wasm is fetched at install/boot time into
 * apps/web/public/sogen/32/ (gitignored — same policy as the v86 bzImage).
 *
 * Usage: node tools/fetch-sogen-wasm.mjs [--check]
 *   --check: exit 0 + print sha256 when present, exit 1 when missing.
 */
import { createHash } from "node:crypto";
import { createWriteStream, existsSync, statSync } from "node:fs";
import { mkdir } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
const OUT_DIR = path.join(ROOT, "apps", "web", "public", "sogen", "32");
const OUT = path.join(OUT_DIR, "analyzer.wasm");

// Pinned artifact: sogen.dev production deploy, last-modified 2026-08-25T07:20:17Z.
// Rebuild-from-source recipe: packages/sogen-runtime/vendor/README.md.
const URL_ =
  process.env.SOGEN_WASM_URL ?? "https://sogen.dev/32/analyzer.wasm";
const KNOWN_SHA256 = process.env.SOGEN_WASM_SHA256 ??
  "883249f7d2c6b92656198daf08683ea865b1094fcab24e8719aa4a52b2f8be3c"; // pinned deploy

const check = process.argv.includes("--check");

if (!existsSync(OUT)) {
  if (check) {
    console.error("sogen wasm missing:", OUT);
    process.exit(1);
  }
  await mkdir(OUT_DIR, { recursive: true });
  console.log(`[sogen] fetching ${URL_} -> ${OUT} (~90 MB)`);
  const res = await fetch(URL_);
  if (!res.ok || !res.body) {
    console.error("[sogen] fetch failed:", res.status);
    process.exit(2);
  }
  const hash = createHash("sha256");
  const file = createWriteStream(OUT);
  for await (const chunk of res.body) {
    hash.update(chunk);
    file.write(Buffer.from(chunk));
  }
  await new Promise((r) => file.end(r));
  const sha = hash.digest("hex");
  console.log(`[sogen] sha256 ${sha}`);
  if (KNOWN_SHA256 && sha !== KNOWN_SHA256) {
    console.error("[sogen] SHA MISMATCH against pinned SOGEN_WASM_SHA256!");
    process.exit(3);
  }
} else if (check) {
  const { readFile } = await import("node:fs/promises");
  const buf = await readFile(OUT);
  console.log(`[sogen] present: ${OUT} (${statSync(OUT).size} bytes)`);
  console.log("[sogen] sha256", createHash("sha256").update(buf).digest("hex"));
}
