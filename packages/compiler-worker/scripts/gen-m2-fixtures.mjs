/**
 * Compile the module-2 attack/defense starters into committed COFF fixtures.
 *
 * Mirrors src/browser.worker.mjs exactly: same wasm clang, same flags, same
 * /wdm/include sysroot — so test fixtures are byte-equivalent to what a
 * student's browser compiles from the identical starter text.
 *
 * Usage: node scripts/gen-m2-fixtures.mjs
 */
import { readFile, writeFile, mkdir } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { createRequire } from "node:module";

const require = createRequire(import.meta.url);
const pkgDir = path.dirname(path.dirname(fileURLToPath(import.meta.url))); // packages/compiler-worker
const root = path.join(pkgDir, "../..");
const distDir = path.join(root, "vendor/browsercc/dist");

const { default: Clang } = await import(
  new URL("clang.js", `file://${distDir}/`).href);

// inject the compiler sysroot + WDK teaching headers once into a template
// FS snapshot; each compile gets a FRESH clang instance (callMain is
// effectively single-shot in this build).
const sysrootU8 = new Uint8Array(await readFile(path.join(distDir, "sysroot.tar")));
const manifest = JSON.parse(
  await readFile(path.join(distDir, "headers-manifest.json"), "utf8"));

async function freshClang() {
  let stderrBuf = "";
  const clang = await Clang({ thisProgram: "clang", printErr: (s) => { stderrBuf += s + "\n"; } });
  const dec = new TextDecoder();
  let off = 0;
  while (off + 512 <= sysrootU8.length) {
    const hdr = sysrootU8.slice(off, off + 512);
    const name = dec.decode(hdr.slice(0, 100)).replace(/\0.*$/, "");
    if (!name) break;
    const size = parseInt(dec.decode(hdr.slice(124, 136)).replace(/\0.*$/, "").trim(), 8) || 0;
    if (size > 0 && !name.endsWith("/")) {
      const dir = path.posix.dirname(name);
      try { clang.FS.mkdirTree(dir); } catch { /* exists */ }
      clang.FS.writeFile(name, sysrootU8.slice(off + 512, off + 512 + size));
    }
    off += 512 + Math.ceil(size / 512) * 512;
  }
  for (const [vpath, b64] of Object.entries(manifest)) {
    const bytes = Uint8Array.from(Buffer.from(b64, "base64"));
    const dir = path.posix.dirname(vpath);
    try { clang.FS.mkdirTree(dir); } catch { /* exists */ }
    clang.FS.writeFile(vpath, bytes);
  }
  clang.FS.mkdirTree("/work");
  return { clang, getStderr: () => stderrBuf };
}

const { ATTACK_WPOFF_STARTER, ATTACK_LOCKDOWN_STARTER,
  ATTACK_TIMERDPC_STARTER, ATTACK_HIJACK_STARTER,
  SENSOR_TELEMETRY_STARTER, SENSOR_DEADLINE_STARTER } =
  await import(pathToFileUrl(path.join(root,
    "packages/course-content/src/starters.mjs")));

function pathToFileUrl(p) {
  return "file://" + path.resolve(p);
}

const JOBS = [
  ["kfwpoff.obj", ATTACK_WPOFF_STARTER],
  ["kflockdown.obj", ATTACK_LOCKDOWN_STARTER],
  ["kftimerdpc.obj", ATTACK_TIMERDPC_STARTER],
  ["kfhijack.obj", ATTACK_HIJACK_STARTER],
  ["kfsentinel_telemetry.obj", SENSOR_TELEMETRY_STARTER],
  ["kfdeadline.obj", SENSOR_DEADLINE_STARTER],
];

const outDir = path.join(pkgDir, "test/fixtures");
await mkdir(outDir, { recursive: true });

for (const [name, source] of JOBS) {
  const { clang, getStderr } = await freshClang();
  clang.FS.writeFile("/work/driver.c", source);
  const code = clang.callMain([
    "--target=x86_64-pc-windows-msvc",
    "-O1", "-ffreestanding", "-fno-stack-protector",
    "-isystem", "/wdm/include",
    "-c", "/work/driver.c", "-o", `/work/${name}`,
  ]);
  if (code !== 0) {
    console.error(`FAIL ${name} (clang exit ${code})`);
    console.error(getStderr().split("\n").filter(Boolean).slice(-15).join("\n"));
    process.exit(1);
  }
  const obj = clang.FS.readFile(`/work/${name}`, { encoding: "binary" });
  await writeFile(path.join(outDir, name), Buffer.from(obj));
  console.log(`wrote ${name} (${obj.length} bytes)`);
}
console.log("done");
