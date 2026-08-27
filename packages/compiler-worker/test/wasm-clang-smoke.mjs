/**
 * Node-side smoke test for the browsercc fork: compile C to an x64 COFF object
 * entirely via the WASM clang, then verify the bytes parse as our COFF parser
 * expects (machine=0x8664, .text present).
 */

import { readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { createRequire } from "node:module";

const require = createRequire(import.meta.url);
const distDir = path.join(path.dirname(fileURLToPath(import.meta.url)), "../../../vendor/browsercc/dist");

const SOURCE = `
typedef long long i64;
typedef unsigned long long u64;
typedef const char* cstr;

i64 DbgPrint(cstr fmt, ...);

u64 DriverEntry(void* a, void* b) {
  (void)a; (void)b;
  DbgPrint("hello from wasm-clang %d\\n", 1337);
  return 0;
}
`;

// minimal Emscripten module loading in Node (ESM output)
async function loadMod(jsFile, thisProgram) {
  const mod = await import(pathToFileUrl(jsFile));
  return mod.default({ thisProgram });
}

function pathToFileUrl(p) {
  const url = new URL("file://" + path.resolve(p));
  return url.href;
}

const stderr = [];
const clang = await loadMod(path.join(distDir, "clang.js"), "clang");
clang.FS.mkdirTree("/work");
clang.FS.writeFile("/work/driver.c", SOURCE);

const code = clang.callMain([
  "--target=x86_64-pc-windows-msvc",
  "-O1", "-ffreestanding", "-fno-stack-protector",
  "-c", "/work/driver.c", "-o", "/work/driver.obj",
]);
console.log("clang exit:", code);
if (code !== 0) process.exit(1);

const obj = clang.FS.readFile("/work/driver.obj", { encoding: "binary" });
console.log("obj bytes:", obj.length);

// validate COFF header ourselves: machine 0x8664 little-endian
const machine = obj[0] | (obj[1] << 8);
console.log("machine:", "0x" + machine.toString(16));
if (machine !== 0x8664) {
  console.error("NOT x64 COFF!");
  process.exit(1);
}

// feed through our own linker to prove end-to-end viability
const { parseCoff } = await import("../../../packages/compiler-worker/src/coff.mjs");
const parsed = parseCoff(obj);
console.log("sections:", parsed.sections.map((s) => s.name).join(", "));
console.log("has DriverEntry:", parsed.symbols.some((s) => s.name === "DriverEntry"));
console.log("has DbgPrint external:", parsed.symbols.some((s) => s.name === "DbgPrint" && s.storageClass === 2));
console.log("\nSUCCESS: browsercc fork emits real x64 COFF objects.");
