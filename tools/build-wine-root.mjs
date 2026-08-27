#!/usr/bin/env node
/**
 * build-wine-root.mjs — assemble a Wine-derived sogen emulation root.
 *
 * Sogen labs boot against real system DLLs. We cannot redistribute Microsoft's;
 * the platform ships a minimal root built from a local Wine installation
 * (LGPL — redistribution is fine, attribution required) so every student gets
 * a working world out of the box with zero downloads.
 *
 * Usage:
 *   node tools/build-wine-root.mjs [--prefix ~/.wine] [--out artifacts/wine-root]
 *
 * Output:
 *   <out>/drive_c/windows/system32/*.dll     copied from the WINEPREFIX
 *   <out>/root-manifest.json                 { files: [{path, sha256, bytes}] }
 *   <out>/wine-root.tar.gz                   ready-to-serve artifact
 *
 * The manifest is what packages/sogen-runtime verifies at session start; labs
 * only rely on APIs covered by its parity test battery.
 */

import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import { existsSync, mkdirSync, readdirSync, copyFileSync, statSync, writeFileSync, readFileSync } from "node:fs";
import { join, basename, resolve } from "node:path";

const args = process.argv.slice(2);
function argOf(flag, dflt) {
  const i = args.indexOf(flag);
  return i >= 0 && args[i + 1] ? args[i + 1] : dflt;
}

const prefix = resolve(argOf("--prefix", join(process.env.HOME ?? "~", ".wine")));
const out = resolve(argOf("--out", "artifacts/wine-root"));
const sys32 = join(prefix, "drive_c", "windows", "system32");

if (!existsSync(sys32)) {
  console.error(`No Wine system32 at ${sys32}`);
  console.error("Initialize one first:  WINEPREFIX=<dir> wineboot -u");
  process.exit(1);
}

// Minimal set the userland track actually exercises (kept small on purpose —
// the artifact rides along with static hosting).
const WANT = new Set([
  "ntdll.dll", "kernel32.dll", "kernelbase.dll", "user32.dll",
  "gdi32.dll", "opengl32.dll", "msvcrt.dll", "advapi32.dll",
]);

const staging = join(out, "drive_c", "windows", "system32");
mkdirSync(staging, { recursive: true });

const files = [];
for (const name of readdirSync(sys32)) {
  if (!WANT.has(name.toLowerCase())) continue;
  const src = join(sys32, name);
  if (!statSync(src).isFile()) continue;
  copyFileSync(src, join(staging, name));
  const bytes = statSync(src).size;
  files.push({ path: `drive_c/windows/system32/${name}`, sha256: sha256File(src), bytes });
}

if (!files.length) {
  console.error("No candidate DLLs found — is this a populated WINEPREFIX?");
  process.exit(1);
}

const manifest = {
  generator: "tools/build-wine-root.mjs",
  source: "wine (LGPL) — see docs/legal.md attribution",
  createdAt: new Date().toISOString(),
  files,
};
writeFileSync(join(out, "root-manifest.json"), JSON.stringify(manifest, null, 2));

try {
  execFileSync("tar", ["-czf", "wine-root.tar.gz", "-C", out, "drive_c", "root-manifest.json"], { cwd: out });
} catch {
  console.warn("tar unavailable; skipping archive step");
}

console.log(`wine root: ${files.length} DLLs -> ${out}`);
for (const f of files) console.log(`  ${basename(f.path)}  ${f.bytes} B`);

function sha256File(p) {
  return createHash("sha256").update(readFileSync(p)).digest("hex");
}
