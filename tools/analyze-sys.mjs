#!/usr/bin/env node
// Usage:
//   node tools/analyze-sys.mjs [--backend=qemu|hybrid|unicorn|js] path/to/driver.sys
//
// Run any x64 .sys through the emulated kernel without the WebUI.
//   --backend=js       deterministic JS interpreter (default, no extra deps)
//   --backend=hybrid   JS front + Unicorn fallback on unimplemented opcode
//   --backend=unicorn  pure Unicorn WASM backend (high ISA coverage, ~1MB wasm)
//   --backend=qemu     QEMU userspace backend (@kernelforge/ntsim-qemu + qemu-system-x86_64)
//
// Notes:
// - WASM backends (hybrid/unicorn) are lazy-loaded — no cost unless selected.
// - Safe serializer handles BigInt/circular refs/large buffers to avoid
//   "Invalid string length" on huge reports.
// - Kernel DbgPrint/SEH/IRQL are drained synchronously post-DriverEntry.

import { existsSync } from "node:fs";
import { readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import process from "node:process";
import { analyzeDriver } from "../packages/ntsim-analyzer/src/index.mjs";
import { StructTables } from "../packages/ntsim/src/structs.mjs";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = path.resolve(__dirname, "..");

const VALID_BACKENDS = new Set(["js", "hybrid", "unicorn", "qemu"]);

const MAX_STRING_LEN = 100_000;    // truncate very long strings
const MAX_ARRAY_LEN = 10_000;      // summarize huge arrays
const MAX_DEPTH = 6;               // depth limit for object traversal

function parseArgs(argv) {
  const args = { backend: "js", file: null };
  for (let i = 2; i < argv.length; i++) {
    const a = argv[i];
    if (a.startsWith("--backend=")) {
      const v = a.split("=", 2)[1]?.trim().toLowerCase();
      if (!VALID_BACKENDS.has(v)) {
        console.error(`unknown --backend="${v}" (expected one of ${[...VALID_BACKENDS].join("|")})`);
        process.exit(2);
      }
      args.backend = v;
    } else if (a.startsWith("--help") || a === "-h") {
      console.error("Usage: node tools/analyze-sys.mjs [--backend=qemu|hybrid|unicorn|js] path/to/driver.sys");
      process.exit(0);
    } else if (!args.file) {
      args.file = a;
    } else {
      // ignore extras
    }
  }
  return args;
}

// A replacer for JSON.stringify that:
//  - converts BigInt -> hex strings
//  - collapses circular references to "[Circular]"
//  - truncates very long strings
//  - summarizes big arrays/typed arrays/buffers
//  - enforces a max object depth to avoid runaway recursion / huge outputs
function safeStringify(obj, space = 2) {
  const seen = new WeakSet();
  const depthMap = new WeakMap();

  return JSON.stringify(obj, function replacer(key, value) {
    // convert BigInt
    if (typeof value === "bigint") {
      return `0x${value.toString(16)}`;
    }

    // drop functions
    if (typeof value === "function") return undefined;

    // guard against enormous strings
    if (typeof value === "string") {
      if (value.length > MAX_STRING_LEN) {
        return `${value.slice(0, MAX_STRING_LEN)}... [truncated, total length=${value.length}]`;
      }
      return value;
    }

    // handle primitive values quickly
    if (value === null || typeof value !== "object") return value;

    // typed arrays / ArrayBuffer / Buffer summarization
    if (ArrayBuffer.isView(value)) {
      // e.g., Uint8Array, DataView, Buffer
      try {
        const ctorName = value.constructor?.name ?? "TypedArray";
        return `<${ctorName} length=${value.byteLength ?? value.length}>`;
      } catch {
        return "<TypedArray>";
      }
    }
    if (value instanceof ArrayBuffer) {
      return `<ArrayBuffer byteLength=${value.byteLength}>`;
    }

    // arrays - summarize if too large
    if (Array.isArray(value)) {
      if (value.length > MAX_ARRAY_LEN) {
        return `[Array length=${value.length}]`;
      }
    }

    // detect parent depth (this === parent object during stringify replacer calls)
    const parent = this;
    const parentDepth = depthMap.get(parent) ?? 0;
    const curDepth = parentDepth + 1;
    // save depth for this object so its children can compute their depth
    depthMap.set(value, curDepth);

    if (curDepth > MAX_DEPTH) {
      return `[Object depth>${MAX_DEPTH}]`;
    }

    // circular detection
    if (seen.has(value)) return "[Circular]";
    seen.add(value);

    return value;
  }, space);
}

function resolveQemuPath() {
  if (process.env.QEMU_PATH && existsSync(process.env.QEMU_PATH)) return process.env.QEMU_PATH;
  const candidates = [
    "/opt/homebrew/bin/qemu-system-x86_64",
    "/usr/local/bin/qemu-system-x86_64",
    "/usr/bin/qemu-system-x86_64",
  ];
  for (const p of candidates) if (existsSync(p)) return p;
  return process.env.QEMU_PATH || candidates[0];
}

async function makeQemuBackendFactory(qemuPath) {
  // Returns a factory function () => Promise<backend>
  return async () => {
    let mod;
    try {
      mod = await import("@kernelforge/ntsim-qemu");
    } catch (e) {
      // Sometimes the package exposes a subpath; try common alternatives
      try {
        mod = await import("@kernelforge/ntsim-qemu/src/qemu.mjs");
      } catch (_e) {
        throw new Error("failed to import @kernelforge/ntsim-qemu; ensure it is installed");
      }
    }
    // Try common export names
    const QemuCpuBackend = mod.QemuCpuBackend ?? mod.default ?? mod.QemuBackend ?? mod.Qemu;
    if (!QemuCpuBackend || typeof QemuCpuBackend.create !== "function") {
      // expose keys to help debugging
      throw new Error(`@kernelforge/ntsim-qemu did not export a create() API. exports: ${Object.keys(mod).join(", ")}`);
    }

    // preferred args: serial to stdio so the guest/kernel console prints to our stdout
    const args = {
      qemuPath: qemuPath || resolveQemuPath(),
      qemuArgs: ["-machine", "q35", "-m", "512M", "-display", "none", "-serial", "stdio"],
      // many create() implementations accept spawn options or stdio; try to set 'stdio' as a hint
      stdio: "inherit",
    };

    const backend = await QemuCpuBackend.create(args);

    // If the backend exposes the child process, pipe stdout/stderr to ours (best-effort).
    // Different versions expose different property names (qemu, qemuProcess, proc, child).
    const proc = backend.qemuProcess ?? backend.child ?? backend.proc ?? backend.qemu;
    try {
      if (proc?.stdout && proc.stdout.pipe) proc.stdout.pipe(process.stdout);
      if (proc?.stderr && proc.stderr.pipe) proc.stderr.pipe(process.stderr);
    } catch {
      // non-fatal
    }
    return backend;
  };
}

async function makeHybridBackendFactory() {
  return async () => {
    // dynamic import for the hybrid/backend used previously
    const mod = await import("@kernelforge/ntsim-unicorn/src/hybrid.mjs");
    const HybridCpuBackend = mod.HybridCpuBackend ?? mod.default;
    if (!HybridCpuBackend || typeof HybridCpuBackend.create !== "function") {
      throw new Error("hybrid backend module not found or missing create()");
    }
    const b = await HybridCpuBackend.create(null);
    return b;
  };
}

async function makeUnicornBackendFactory() {
  return async () => {
    let mod;
    try {
      mod = await import("@kernelforge/ntsim-unicorn");
    } catch (e) {
      // fallback to direct backend path (exports map)
      try {
        mod = await import("@kernelforge/ntsim-unicorn/src/backend.mjs");
      } catch (_) {
        throw e;
      }
    }
    const createUnicornBackend =
      mod.createUnicornBackend ??
      mod.default?.createUnicornBackend ??
      mod.default ??
      mod.create;
    if (typeof createUnicornBackend !== "function") {
      throw new Error(`@kernelforge/ntsim-unicorn: createUnicornBackend factory not found. exports: ${Object.keys(mod).join(", ")}`);
    }
    // Analyzer builds backends with mem=null and late-binds via attachMemory
    return await createUnicornBackend(null);
  };
}

async function main() {
  const args = parseArgs(process.argv);
  if (!args.file) {
    console.error("Usage: node tools/analyze-sys.mjs [--backend=qemu|hybrid|unicorn|js] path/to/driver.sys");
    process.exit(2);
  }

  const fpath = path.isAbsolute(args.file) ? args.file : path.resolve(process.cwd(), args.file);
  const bytes = new Uint8Array(await readFile(fpath));

  // Local Vergilius / struct tables (repo-root relative, not cwd-relative)
  const tablesDir = path.resolve(REPO_ROOT, "packages/ntsim-assets/data/vergilius/windows-10/22h2");
  let tables;
  try {
    tables = await StructTables.loadDir(tablesDir, [
      "_EPROCESS", "_ETHREAD", "_KLDR_DATA_TABLE_ENTRY", "_LDR_DATA_TABLE_ENTRY",
      "_KPCR", "_KPRCB", "_UNICODE_STRING", "_LIST_ENTRY",
    ]);
  } catch (e) {
    console.error(`failed to load struct tables from ${tablesDir}: ${e.message}`);
    throw e;
  }

  // choose backend factory based on CLI flag
  let makeBackend = undefined;
  if (args.backend === "qemu") {
    const qemuPath = resolveQemuPath();
    makeBackend = await makeQemuBackendFactory(qemuPath);
    console.log(`Using QEMU backend (qemu=${qemuPath}).`);
  } else if (args.backend === "hybrid") {
    makeBackend = await makeHybridBackendFactory();
    console.log("Using Hybrid backend (JS + Unicorn fallback).");
  } else if (args.backend === "unicorn") {
    makeBackend = await makeUnicornBackendFactory();
    console.log("Using Unicorn backend (WASM-only).");
  } else {
    console.log("Using JS interpreter backend (deterministic).");
  }

  // common options for analyzeDriver
  const opts = {
    name: path.basename(fpath),
    backendName: args.backend,
    tables,
    carvedState: undefined,
    runUnload: false,
    // attach makeBackend only when provided
    ...(makeBackend ? { makeBackend } : {}),
  };

  console.log(`analyzing ${fpath} (${bytes.length} bytes) ...`);
  const report = await analyzeDriver(bytes, opts);

  // Drain any post-run kernel logs synchronously (DriverEntry + deferred drains
  // already flushed into report.dbgLog/exceptions during analyzeDriver). The
  // live session may still hold newly queued deferred DbgPrint from the last
  // drain — emit them once before serializing.
  const session = report.__session;
  if (session?.kernel) {
    const k = session.kernel;
    const drain = (arr, prefix, isErr) => {
      while (arr?.length) {
        const v = arr.shift();
        if (prefix === "[DBG]") {
          const s = (typeof v === "string" && v.length > 10000) ? v.slice(0, 10000) + " ...[truncated]" : v;
          console.log(prefix, s);
        } else if (prefix === "[SEH]") {
          console.error(prefix, v.faultRip, v.handled ? "handled" : "UNHANDLED", v.detail);
        } else if (prefix === "[IRQL]") {
          console.error(prefix, v.name, "at", v.irql);
        } else {
          (isErr ? console.error : console.log)(prefix, v);
        }
      }
    };
    drain(k.dbgLog, "[DBG]");
    drain(k.exceptionTrace, "[SEH]");
    drain(k.irqlViolations, "[IRQL]");
    if (k.bugcheck || k.crash) {
      console.error("BUGCHECK/CRASH:", JSON.stringify(k.bugcheck ?? k.crash));
    }
  }

  // Do not serialize the live kernel session (circular, huge). Consumers that
  // need interactive follow-ups can keep the in-memory report.__session, but
  // the JSON dump stays bounded. Use safeStringify's depth/circular guards as
  // a second layer.
  const { __session: _omit, ...serializable } = report;

  // Finally print the report with the safe serializer
  const out = safeStringify(serializable, 2);
  console.log(out);
}

main().catch((e) => {
  console.error("ERROR:", e && e.message ? e.message : e);
  // print stack for debugging
  if (e && e.stack) console.error(e.stack);
  process.exit(1);
});
