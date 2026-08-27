/**
 * Recompile the committed COFF fixtures with the HOST clang.
 *
 * Fallback for environments without vendor/browsercc/dist/sysroot.tar (the
 * wasm-clang sysroot is a gitignored build artifact). Flags mirror
 * compile-bridge.mjs / browser.worker.mjs exactly; only the compiler binary
 * differs, so emitted COFF is equivalent for teaching purposes.
 *
 * Usage: node scripts/regen-fixtures-host.mjs [name.obj ...]
 */
import { execFile } from "node:child_process";
import { writeFile, mkdir, mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";

const execFileP = promisify(execFile);
const pkgDir = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
const root = path.join(pkgDir, "../..");
const outDir = path.join(pkgDir, "test/fixtures");

const starters = await import(path.join(root, "packages/course-content/src/starters.mjs"));

const JOBS = {
  "kfwpoff.obj": starters.ATTACK_WPOFF_STARTER,
  "kflockdown.obj": starters.ATTACK_LOCKDOWN_STARTER,
  "kftimerdpc.obj": starters.ATTACK_TIMERDPC_STARTER,
  "kfhijack.obj": starters.ATTACK_HIJACK_STARTER,
  "kfsentinel_telemetry.obj": starters.SENSOR_TELEMETRY_STARTER,
  "kfdeadline.obj": starters.SENSOR_DEADLINE_STARTER,
};

const only = process.argv.slice(2);
await mkdir(outDir, { recursive: true });
const tmp = await mkdtemp(path.join(tmpdir(), "kf-fixturegen-"));
try {
  for (const [name, source] of Object.entries(JOBS)) {
    if (only.length && !only.includes(name)) continue;
    const cFile = path.join(tmp, name.replace(/\.obj$/, ".c"));
    const oFile = path.join(outDir, name);
    await writeFile(cFile, source);
    try {
      await execFileP("clang", [
        "--target=x86_64-pc-windows-msvc",
        "-O1", "-ffreestanding", "-fno-stack-protector",
        "-isystem", path.join(pkgDir, "include"),
        "-c", cFile, "-o", oFile,
      ], { timeout: 20000 });
      console.log(`wrote ${name}`);
    } catch (e) {
      console.error(`FAIL ${name}\n${(e.stderr ?? e.message).split("\n").slice(-12).join("\n")}`);
      process.exitCode = 1;
    }
  }
} finally {
  await rm(tmp, { recursive: true, force: true });
}
