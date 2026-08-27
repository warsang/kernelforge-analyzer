#!/usr/bin/env node
/**
 * One-time vendoring of the Ghidra native decompiler as WebAssembly,
 * via the adopted pyre pipeline (packages/ghidra-decompiler/vendor/README.md):
 *
 *   npm run vendor:ghidra [-- PYRE_SRC]
 *
 * Steps:
 *   1. shallow-clone ant4g0nist/pyre (reused when PYRE_DIR/PYRE_SRC given or
 *      /tmp/opencode/pyre already exists)
 *   2. run its decompiler-wasm/build.sh with the LOCAL emsdk (emcc on PATH;
 *      homebrew emscripten needs python>=3.10 first on PATH)
 *   3. stage dist/{pyre_decompiler.js,wasm} + specs/dist (x86 slice + manifest)
 *      into apps/web/public/vendor/ghidra/
 *   4. copy the versioned shim to decompiler-wasm.mjs
 *
 * Artifacts are UNTRACKED (legal policy: engines never committed) — this tool
 * is the reproducible rebuild path; sha256 provenance prints at the end.
 */

import { execSync } from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const OUT_DIR = path.join(repoRoot, "apps/web/public/vendor/ghidra");
const SHIM_SRC = path.join(repoRoot, "packages/ghidra-decompiler/vendor/shim.mjs");

const pyreDir = process.env.PYRE_DIR
  ?? process.argv[2]
  ?? (fs.existsSync("/tmp/opencode/pyre") ? "/tmp/opencode/pyre" : null);

if (!pyreDir || !fs.existsSync(path.join(pyreDir, "decompiler-wasm/build.sh"))) {
  console.error("cloning ant4g0nist/pyre (shallow)...");
  execSync(
    `git clone --depth 1 https://github.com/ant4g0nist/pyre.git "${pyreDir}"`,
    { stdio: "inherit" },
  );
}

console.error(`[vendor:ghidra] building in ${pyreDir} (local emsdk)...`);
execSync("bash decompiler-wasm/build.sh", {
  cwd: pyreDir,
  stdio: "inherit",
  env: process.env,
});

const dist = path.join(pyreDir, "decompiler-wasm/dist");
const specsDist = path.join(pyreDir, "specs/dist");

fs.rmSync(OUT_DIR, { recursive: true, force: true });
fs.mkdirSync(path.join(OUT_DIR, "specs"), { recursive: true });

for (const f of ["pyre_decompiler.js", "pyre_decompiler.wasm"]) {
  fs.copyFileSync(path.join(dist, f), path.join(OUT_DIR, f));
}
fs.copyFileSync(path.join(specsDist, "manifest.json"),
  path.join(OUT_DIR, "specs/manifest.json"));
fs.cpSync(path.join(specsDist, "x86"), path.join(OUT_DIR, "specs/x86"),
  { recursive: true });
fs.copyFileSync(SHIM_SRC, path.join(OUT_DIR, "decompiler-wasm.mjs"));

const pyreCommit = (() => {
  try {
    return execSync(`git -C "${pyreDir}" rev-parse HEAD`).toString().trim();
  } catch { return "(unknown — external checkout)"; }
})();

const sha = (p) =>
  crypto.createHash("sha256").update(fs.readFileSync(p)).digest("hex");

console.log(`\n[vendor:ghidra] staged ${OUT_DIR}`);
for (const rel of [
  "decompiler-wasm.mjs",
  "pyre_decompiler.js",
  "pyre_decompiler.wasm",
  "specs/x86/data/languages/x86-64.sla",
]) {
  console.log(`  ${rel}\n    sha256 ${sha(path.join(OUT_DIR, rel))}`);
}
console.log(`\n  pyre commit: ${pyreCommit}`);
try {
  console.log(`  emcc: ${
    execSync("emcc --version").toString().split("\n")[0].trim()}`);
} catch { /* optional */ }
console.log("\nDone. Reload the app — !decomp / Pseudocode now use real Ghidra.");
