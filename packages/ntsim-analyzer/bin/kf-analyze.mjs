#!/usr/bin/env node
// kf-analyze — small unified CLI for kernelforge-analyzer.
//
//   kf-analyze <driver.sys|module.ko> [options]
//
// Runs a Windows .sys through analyzeDriver or a Linux .ko through analyzeKo
// without the WebUI and prints a bounded JSON report to stdout (or --json).
// Works from a repo checkout (`node packages/ntsim-analyzer/bin/kf-analyze.mjs`)
// and from an npm install (`npx @kernelforge/ntsim-analyzer driver.sys` once
// the package `bin` is wired). All heavy backends are lazy-loaded.

import { existsSync } from "node:fs";
import { readFile, writeFile } from "node:fs/promises";
import { createRequire } from "node:module";
import path from "node:path";
import { fileURLToPath } from "node:url";
import process from "node:process";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
// packages/ntsim-analyzer/bin -> repo root is ../../.. in a checkout;
// in the analyzer split repo the layout is identical.
const REPO_ROOT = path.resolve(__dirname, "..", "..", "..");
const require = createRequire(import.meta.url);

const VALID_BACKENDS = new Set(["js", "hybrid", "unicorn", "qemu"]);
const TABLE_NAMES = [
  "_EPROCESS",
  "_ETHREAD",
  "_KLDR_DATA_TABLE_ENTRY",
  "_LDR_DATA_TABLE_ENTRY",
  "_KPCR",
  "_KPRCB",
  "_UNICODE_STRING",
  "_LIST_ENTRY",
];

const USAGE = `Usage: kf-analyze <driver.sys|module.ko> [options]

Options:
  --backend js|hybrid|unicorn|qemu   CPU backend (default js, deterministic)
  --ioctl 0xCODE                     scripted IOCTL/file-op code (repeatable)
  --input <hex>                      input bytes for scripted ops (default empty)
  --output-len N                     output buffer length (default 64)
  --op <name>                        .ko file_op (default unlocked_ioctl)
  --auto-irp | --auto-ops | --auto   auto-drive harvested codes after entry
  --max-codes N                      cap for auto-drive (default 16)
  --run-unload                       invoke DriverUnload (.sys) after IOCTLs
  --run-cleanup                      invoke cleanup_module (.ko) at the end
  --no-arch                          disable CPUID/MSR/TSC/KUSD virtualization
  --intel                            spoof Intel CPUID brand/frequencies
  --hv                               claim a hypervisor (CPUID leaves + HV page)
  --no-diag                          disable probe/SEH/self-read diagnostics
  --no-events                        skip simulated notify/Ob/Cm callback events
  --no-bcd                           skip BCD hive virtualization
  --tables <dir>                     Vergilius struct-table dir (.sys only)
  --probe                            bounded DriverEntry trajectory probe
                                     (chunked run + spin detection, no IOCTLs)
  --probe-steps N                    steps per probe chunk (default 20000)
  --probe-chunks N                   probe chunk budget (default 250)
  --probe-wall MS                    probe wall-clock budget (default 100000)
  --probe-trace FILE                 write traced RIPs to FILE
  --probe-trace-from N               step index to start RIP tracing
  --probe-trace-to N                 step index to end RIP tracing
  --probe-dispatch RVA               extra hook: record rdx each hit at RVA
  --probe-stack-fill BYTE            pre-fill stack window (0-255, default zero)
  --json [out.json]                  write full report JSON to file (default stdout)
  --quiet, -q                        only print the JSON report
  --help, -h                         show this help
(value flags accept both --flag=value and --flag value)`;

function parseArgs(argv) {
  const args = {
    backend: "js",
    file: null,
    ioctls: [],
    input: "",
    outputLen: 64,
    op: "unlocked_ioctl",
    auto: false,
    maxCodes: 16,
    runUnload: false,
    runCleanup: false,
    noArch: false,
    intel: false,
    hypervisor: false,
    diag: true,
    simulateEvents: true,
    bcd: true,
    tables: null,
    probe: false,
    probeSteps: 20000,
    probeChunks: 250,
    probeWall: 100000,
    probeTrace: null,
    probeTraceFrom: -1,
    probeTraceTo: -1,
    probeDispatch: null,
    probeStackFill: null,
    json: null,
    jsonToStdout: true,
    quiet: false,
  };
  // Value flags accept both --flag=value and --flag value.
  const takeValue = (i, inline) => {
    if (inline !== "") return { value: inline, next: i };
    const nxt = argv[i + 1];
    if (nxt === undefined || nxt.startsWith("-")) return { value: "", next: i };
    return { value: nxt, next: i + 1 };
  };
  for (let i = 2; i < argv.length; i++) {
    const a = argv[i];
    const inline = a.includes("=") ? a.slice(a.indexOf("=") + 1) : "";
    const flag = a.includes("=") ? a.slice(0, a.indexOf("=")) : a;
    if (flag === "--backend") {
      const r = takeValue(i, inline);
      i = r.next;
      const v = r.value.trim().toLowerCase();
      if (!VALID_BACKENDS.has(v)) {
        console.error(`unknown --backend="${r.value}" (expected js|hybrid|unicorn|qemu)`);
        process.exit(2);
      }
      args.backend = v;
    } else if (flag === "--ioctl") {
      const r = takeValue(i, inline);
      i = r.next;
      if (r.value !== "") args.ioctls.push(r.value);
    } else if (flag === "--input") {
      const r = takeValue(i, inline);
      i = r.next;
      args.input = r.value;
    } else if (flag === "--output-len") {
      const r = takeValue(i, inline);
      i = r.next;
      args.outputLen = Number(r.value) || 64;
    } else if (flag === "--op") {
      const r = takeValue(i, inline);
      i = r.next;
      if (r.value !== "") args.op = r.value;
    } else if (a === "--auto-irp" || a === "--auto-ops" || a === "--auto") {
      args.auto = true;
    } else if (flag === "--max-codes") {
      const r = takeValue(i, inline);
      i = r.next;
      args.maxCodes = Number(r.value) || 16;
    } else if (a === "--run-unload") {
      args.runUnload = true;
    } else if (a === "--run-cleanup") {
      args.runCleanup = true;
    } else if (a === "--no-arch") {
      args.noArch = true;
    } else if (a === "--intel") {
      args.intel = true;
    } else if (a === "--hv" || a === "--hypervisor") {
      args.hypervisor = true;
    } else if (a === "--no-diag") {
      args.diag = false;
    } else if (a === "--no-events") {
      args.simulateEvents = false;
    } else if (a === "--no-bcd") {
      args.bcd = false;
    } else if (flag === "--tables") {
      const r = takeValue(i, inline);
      i = r.next;
      args.tables = r.value || null;
    } else if (a === "--probe") {
      args.probe = true;
    } else if (flag === "--probe-steps") {
      const r = takeValue(i, inline);
      i = r.next;
      args.probeSteps = Number(r.value) || 20000;
    } else if (flag === "--probe-chunks") {
      const r = takeValue(i, inline);
      i = r.next;
      args.probeChunks = Number(r.value) || 250;
    } else if (flag === "--probe-wall") {
      const r = takeValue(i, inline);
      i = r.next;
      args.probeWall = Number(r.value) || 100000;
    } else if (flag === "--probe-trace") {
      const r = takeValue(i, inline);
      i = r.next;
      args.probeTrace = r.value || "/tmp/kf-trace.txt";
    } else if (flag === "--probe-trace-from") {
      const r = takeValue(i, inline);
      i = r.next;
      args.probeTraceFrom = Number(r.value) || 0;
    } else if (flag === "--probe-trace-to") {
      const r = takeValue(i, inline);
      i = r.next;
      args.probeTraceTo = Number(r.value);
      if (!Number.isFinite(args.probeTraceTo)) args.probeTraceTo = -1;
    } else if (flag === "--probe-dispatch") {
      const r = takeValue(i, inline);
      i = r.next;
      args.probeDispatch = r.value || null;
    } else if (flag === "--probe-stack-fill") {
      const r = takeValue(i, inline);
      i = r.next;
      const v = Number(r.value);
      args.probeStackFill = Number.isFinite(v) ? v & 0xff : null;
    } else if (a === "--json") {
      const r = takeValue(i, "");
      if (r.next !== i && r.value !== "") {
        args.json = r.value;
        i = r.next;
      } else {
        args.json = true;
      }
      args.jsonToStdout = false;
    } else if (flag === "--json") {
      args.json = inline;
      args.jsonToStdout = false;
    } else if (a === "--quiet" || a === "-q") {
      args.quiet = true;
    } else if (a === "--help" || a === "-h") {
      console.error(USAGE);
      process.exit(0);
    } else if (a.startsWith("-")) {
      console.error(`unknown flag "${a}"\n${USAGE}`);
      process.exit(2);
    } else if (!args.file) {
      args.file = a;
    }
  }
  return args;
}

function hexToBytes(hex) {
  const hx = String(hex ?? "").replace(/[^0-9a-fA-F]/g, "");
  if (!hx) return new Uint8Array(0);
  return new Uint8Array(hx.match(/.{2}/g).map((x) => parseInt(x, 16)));
}

// Bounded serializer: BigInt -> hex, drop functions, truncate huge
// strings/buffers, cap depth, collapse circulars.
function safeStringify(obj, space = 2) {
  const seen = new WeakSet();
  const depths = new WeakMap();
  return JSON.stringify(
    obj,
    function (key, value) {
      if (typeof value === "bigint") return `0x${value.toString(16)}`;
      if (typeof value === "function") return undefined;
      if (typeof value === "string") {
        return value.length > 100_000
          ? `${value.slice(0, 100_000)}... [truncated, total=${value.length}]`
          : value;
      }
      if (value === null || typeof value !== "object") return value;
      if (ArrayBuffer.isView(value)) {
        return `<${value.constructor?.name ?? "TypedArray"} length=${value.byteLength ?? value.length}>`;
      }
      if (value instanceof ArrayBuffer) return `<ArrayBuffer byteLength=${value.byteLength}>`;
      if (Array.isArray(value) && value.length > 10_000) return `[Array length=${value.length}]`;
      const depth = (depths.get(this) ?? 0) + 1;
      depths.set(value, depth);
      if (depth > 6) return "[Object depth>6]";
      if (seen.has(value)) return "[Circular]";
      seen.add(value);
      return value;
    },
    space,
  );
}

async function loadStructTables(overrideDir) {
  let mod;
  try {
    mod = await import("@kernelforge/ntsim/src/structs.mjs");
  } catch {
    mod = await import("../../ntsim/src/structs.mjs");
  }
  const candidates = [
    ...(overrideDir ? [path.resolve(overrideDir)] : []),
    path.resolve(REPO_ROOT, "packages/ntsim-assets/data/vergilius/windows-10/22h2"),
    path.resolve(REPO_ROOT, "apps/web/public/tables/windows-10/22h2"),
  ];
  try {
    const pkgDir = path.dirname(
      require.resolve("@kernelforge/ntsim-assets/package.json"),
    );
    candidates.push(path.join(pkgDir, "data/vergilius/windows-10/22h2"));
  } catch {
    /* package not installed — checkout candidates above cover it */
  }
  let lastErr;
  for (const dir of candidates) {
    if (!existsSync(dir)) continue;
    try {
      return await mod.StructTables.loadDir(dir, TABLE_NAMES);
    } catch (e) {
      lastErr = e;
    }
  }
  throw new Error(
    `no Vergilius struct tables found (tried ${candidates.join(", ")}). ` +
      `Pass --tables=<dir>.${lastErr ? ` Last error: ${lastErr.message}` : ""}`,
  );
}

function resolveQemuPath() {
  if (process.env.QEMU_PATH && existsSync(process.env.QEMU_PATH)) return process.env.QEMU_PATH;
  for (const p of [
    "/opt/homebrew/bin/qemu-system-x86_64",
    "/usr/local/bin/qemu-system-x86_64",
    "/usr/bin/qemu-system-x86_64",
  ]) {
    if (existsSync(p)) return p;
  }
  return process.env.QEMU_PATH || "/usr/bin/qemu-system-x86_64";
}

async function makeBackendFactory(backend) {
  if (backend === "hybrid") {
    return async () => {
      const mod = await import("@kernelforge/ntsim-unicorn/src/hybrid.mjs");
      const Hybrid = mod.HybridCpuBackend ?? mod.default;
      if (!Hybrid || typeof Hybrid.create !== "function") {
        throw new Error("hybrid backend unavailable (@kernelforge/ntsim-unicorn)");
      }
      return Hybrid.create(null);
    };
  }
  if (backend === "unicorn") {
    return async () => {
      let mod;
      try {
        mod = await import("@kernelforge/ntsim-unicorn");
      } catch {
        mod = await import("@kernelforge/ntsim-unicorn/src/backend.mjs");
      }
      const create =
        mod.createUnicornBackend ?? mod.default?.createUnicornBackend ?? mod.default ?? mod.create;
      if (typeof create !== "function") {
        throw new Error(
          `@kernelforge/ntsim-unicorn has no backend factory (exports: ${Object.keys(mod).join(", ")})`,
        );
      }
      return create(null);
    };
  }
  if (backend === "qemu") {
    return async () => {
      let mod;
      try {
        mod = await import("@kernelforge/ntsim-qemu");
      } catch {
        mod = await import("@kernelforge/ntsim-qemu/src/qemu.mjs");
      }
      const Backend = mod.QemuCpuBackend ?? mod.default ?? mod.QemuBackend ?? mod.Qemu;
      if (!Backend || typeof Backend.create !== "function") {
        throw new Error("@kernelforge/ntsim-qemu did not export a create() API");
      }
      return Backend.create({
        qemuPath: resolveQemuPath(),
        qemuArgs: ["-machine", "q35", "-m", "512M", "-display", "none", "-serial", "stdio"],
        stdio: "inherit",
      });
    };
  }
  return undefined;
}

async function loadAnalyzer(kind) {
  if (kind === "ko") {
    try {
      return (await import("@kernelforge/linux-analyzer/src/index.mjs")).analyzeKo;
    } catch {
      return (await import("../../linux-analyzer/src/index.mjs")).analyzeKo;
    }
  }
  try {
    return (await import("@kernelforge/ntsim-analyzer/src/index.mjs")).analyzeDriver;
  } catch {
    return (await import("../src/index.mjs")).analyzeDriver;
  }
}

async function loadProbe() {
  try {
    return (await import("@kernelforge/ntsim-analyzer/src/probe.mjs")).probeDriver;
  } catch {
    return (await import("../src/probe.mjs")).probeDriver;
  }
}

async function emitJson(out, args, fpath, log) {
  if (typeof args.json === "string") {
    await writeFile(args.json, out);
    log(`wrote ${args.json}`);
  } else if (args.json === true) {
    const outPath = fpath + ".report.json";
    await writeFile(outPath, out);
    log(`wrote ${outPath}`);
  } else {
    process.stdout.write(out + "\n");
  }
}

async function main() {
  const args = parseArgs(process.argv);
  if (!args.file) {
    console.error(USAGE);
    process.exit(2);
  }
  const fpath = path.isAbsolute(args.file) ? args.file : path.resolve(process.cwd(), args.file);
  const ext = path.extname(fpath).toLowerCase();
  const kind = ext === ".ko" ? "ko" : "sys";

  const bytes = new Uint8Array(await readFile(fpath));
  const name = path.basename(fpath);
  const log = (...m) => {
    if (!args.quiet) console.error(...m);
  };

  // --probe: bounded trajectory instead of the full analyze pipeline.
  if (args.probe) {
    if (kind !== "sys") {
      console.error("--probe currently supports .sys drivers only");
      process.exit(2);
    }
    const [probeDriver, tables, probeBackend] = await Promise.all([
      loadProbe(),
      loadStructTables(args.tables),
      makeBackendFactory(args.backend),
    ]);
    log(`Using ${args.backend} backend.`);
    const traj = await probeDriver(bytes, {
      name,
      tables,
      chunkSteps: args.probeSteps,
      maxChunks: args.probeChunks,
      wallMs: args.probeWall,
      traceFrom: args.probeTrace ? args.probeTraceFrom : -1,
      traceTo: args.probeTrace ? args.probeTraceTo : -1,
      dispatchRva: args.probeDispatch,
      stackFill: args.probeStackFill,
      ...(probeBackend ? { makeBackend: probeBackend } : {}),
      onProgress: (...m) => log(...m),
    });
    if (args.probeTrace && traj.trace?.length) {
      await writeFile(args.probeTrace, traj.trace.join("\n") + "\n");
      log(`wrote ${traj.trace.length} traced RIPs to ${args.probeTrace}`);
    }
    log(`probe ${fpath}: outcome=${traj.outcome} steps=${traj.steps} ` +
      `elapsed=${traj.elapsedMs}ms${traj.spin ? ` spin=${traj.spin.rvaLo}..${traj.spin.rvaHi}` : ""}`);
    await emitJson(safeStringify(traj, 2), args, fpath, log);
    return;
  }

  const makeBackend = await makeBackendFactory(args.backend);
  log(`Using ${args.backend} backend.`);

  const input = hexToBytes(args.input);
  let report;
  if (kind === "ko") {
    const analyzeKo = await loadAnalyzer("ko").catch((e) => {
      throw new Error(`.ko support needs @kernelforge/linux-analyzer: ${e.message}`);
    });
    report = await analyzeKo(bytes, {
      name,
      backendName: args.backend,
      ...(makeBackend ? { makeBackend } : {}),
      fileOps: args.ioctls.map((code) => ({
        op: args.op,
        cmd: code,
        input,
        outputLen: args.outputLen,
      })),
      ...(args.auto ? { autoOps: { maxOps: args.maxCodes, outputLen: args.outputLen } } : {}),
      runCleanup: args.runCleanup,
    });
  } else {
    const [analyzeDriver, tables] = await Promise.all([
      loadAnalyzer("sys"),
      loadStructTables(args.tables),
    ]);
    report = await analyzeDriver(bytes, {
      name,
      backendName: args.backend,
      tables,
      ...(makeBackend ? { makeBackend } : {}),
      ioctls: args.ioctls.map((code) => ({ code, input, outputLen: args.outputLen })),
      ...(args.auto ? { autoIrp: { maxCodes: args.maxCodes, outputLen: args.outputLen } } : {}),
      runUnload: args.runUnload,
      arch: args.noArch ? false : { intel: args.intel, hypervisor: args.hypervisor },
      diag: args.diag,
      simulateEvents: args.simulateEvents,
      bcd: args.bcd,
    });
  }

  log(`analyzed ${fpath} (${bytes.length} bytes): entry=${JSON.stringify(report.entry ?? report.init)}`);
  for (const line of report.dbgLog?.slice(0, 20) ?? []) log("[DBG]", String(line).slice(0, 500));
  if (report.bugcheck) log("BUGCHECK:", JSON.stringify(report.bugcheck));

  const { __session: _omit, ...serializable } = report;
  await emitJson(safeStringify(serializable, 2), args, fpath, log);
}

main().catch((e) => {
  console.error("ERROR:", e?.message ?? e);
  if (e?.stack) console.error(e.stack);
  process.exit(1);
});
