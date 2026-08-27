/**
 * Unified compile entry for apps/web.
 *
 * Strategy: in-browser WASM clang (browsercc fork) when available, automatic
 * fallback to the /api/compile server bridge (dev convenience, weak devices).
 * The rest of the app only ever calls `compileDriverSource`.
 */

import { BrowserCompiler } from "@kernelforge/compiler-worker/browser.client.mjs";

let browserCompiler = null;
let wasmBroken = false;

function getBrowserCompiler() {
  if (!browserCompiler) browserCompiler = new BrowserCompiler();
  return browserCompiler;
}

/** Kick off WASM toolchain preload; never throws, no-op outside browsers. */
export function warmupCompiler() {
  try {
    if (!BrowserCompiler.supported) return;
    getBrowserCompiler().warmup().then((ok) => { if (!ok) wasmBroken = true; });
  } catch {
    wasmBroken = true;
  }
}

/**
 * @param {string} source C source
 * @param {{target?: string}} [opts] target "windows" (default) or "linux"
 * @returns {Promise<{objBytes: Uint8Array, via: "wasm"|"server"}>}
 */
export async function compileDriverSource(source, opts={}) {
  const target = opts.target ?? "windows";
  if (!wasmBroken) {
    try {
      const objBytes = await getBrowserCompiler().compileSource(source, target);
      return { objBytes, via: "wasm" };
    } catch (e) {
      console.warn("[compiler] wasm path failed, falling back to server:", e?.message);
      wasmBroken = true;
    }
  }

  const resp = await fetch("/api/compile", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ source, target }),
  });
  if (!resp.ok) {
    let msg = `compile API ${resp.status}`;
    try { msg = (await resp.json()).error ?? msg; } catch {}
    throw new Error(msg);
  }
  const { objBase64 } = await resp.json();
  const bin = atob(objBase64);
  const objBytes = Uint8Array.from(bin, (c) => c.charCodeAt(0));
  return { objBytes, via: "server" };
}
