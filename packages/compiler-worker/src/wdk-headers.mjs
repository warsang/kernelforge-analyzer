/**
 * WDK teaching headers — build-time manifest.
 *
 * Served to BOTH compile paths:
 *  - compile bridge (Node):  includeDir() -> absolute path, passed via -isystem
 *  - wasm worker (browser):  fileMap()    -> {vpath: Uint8Array}, injected
 *                             into clang's in-memory FS before compilation
 *
 * Keep the file list explicit: clang's #include <...> resolution walks these
 * as system headers; nothing else is exposed to student code.
 */

import { readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

const INCLUDE_DIR = path.join(
  path.dirname(fileURLToPath(import.meta.url)),
  "../include"
);

/** Explicit header list (compile-time known; no directory scans). */
export const HEADERS = [
  "ntddk.h",
  "wdm.h",
  "ntdef.h",
  "ntstatus.h",
  "winapifamily.h", // some WDK headers guard on it; we provide a permissive stub
  "intrin.h",       // shim: shadows the resource-dir intrinsics header (issue #21)
];

/** Absolute include dir for the Node-side bridge. */
export function includeDir() {
  return INCLUDE_DIR;
}

/**
 * Browser path: read every header once at worker startup.
 * @returns {Promise<Record<string, Uint8Array>>} map of "wdm/include/<name>" -> bytes
 */
export async function fileMap() {
  const out = {};
  for (const h of HEADERS) {
    const bytes = await readFile(path.join(INCLUDE_DIR, h));
    out[`wdm/include/${h}`] = new Uint8Array(bytes);
  }
  return out;
}
