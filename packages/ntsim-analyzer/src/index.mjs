/**
 * ntsim-analyzer — run any uploaded .sys through the emulated kernel.
 *
 * Pipeline:
 *   bytes -> mapPe (provisioned import resolution: every import resolves)
 *         -> DriverEntry via SEH-aware call
 *         -> deferred drains (DPC / work items / APCs)
 *         -> scripted IRPs (DeviceIoControl + optional read/write/create)
 *         -> optional DriverUnload
 *         -> report {load, entry, dbgLog, apiTrace, exceptions, ioctls, ...}
 *
 * The same code runs in Node tests and in the browser (no fs, no Buffer).
 */

import {
  NtKernel,
  mapPe,
  parsePe,
  createDriverObject,
  initDriverObjectName,
  createDeviceObject,
  sendIrp,
  callDriverUnload,
  IRP_MJ,
} from "@kernelforge/ntsim/src/index.mjs";

const DEFAULT_DRIVER_BASE = 0xfffff80300000000n;

/** "C:\Windows\mhyprot2.SYS" -> service key basename "mhyprot2" (no extension). */
function serviceKeyOf(name) {
  const base = String(name ?? "uploaded.sys").split(/[\\/]/).pop() || "uploaded.sys";
  const dot = base.lastIndexOf(".");
  return dot > 0 ? base.slice(0, dot) : base;
}

function hexToBytes(hex) {
  const hx = String(hex ?? "").replace(/[^0-9a-fA-F]/g, "");
  if (!hx) return new Uint8Array(0);
  const pairs = hx.match(/.{2}/g) ?? [];
  return new Uint8Array(pairs.map((x) => parseInt(x, 16)));
}

/** MSVC link-time __security_cookie value ("cookie not initialized yet"). */
const GS_COOKIE_SENTINEL = 0x00002b992ddfa232n;
const U64 = (1n << 64n) - 1n;

/**
 * Re-key any MSVC GS-cookie sentinel left in the mapped image.
 *
 * On a real boot CRT init always replaces the link-time sentinel before any
 * /GS check executes, and loaders that map drivers manually (packers, cheat
 * mappers, legit installers) are expected to have done the same — several
 * treat "sentinel still present" as tampering and hit
 * __fastfail(FAST_FAIL_GS_COOKIE_INIT). TBMKD.sys does exactly this. Since a
 * genuine kernel never observes the sentinel, emulating the loader step here
 * is faithful, not permissive.
 */
function rekeySecurityCookie(kernel, mapped) {
  const mem = kernel.mem;
  const patched = [];
  for (let off = 0; off + 8 <= mapped.imageSize; off += 8) {
    const addr = mapped.base + BigInt(off);
    if (mem.u64(addr) !== GS_COOKIE_SENTINEL) continue;
    const fresh = (0x0000f1e2d3c4b5a6n ^ BigInt(off)) | 1n; // non-zero, non-sentinel, deterministic
    mem.w64(addr, fresh);
    if (off + 16 <= mapped.imageSize && mem.u64(addr + 8n) === (~GS_COOKIE_SENTINEL & U64)) {
      mem.w64(addr + 8n, ~fresh & U64); // keep __security_cookie_complement consistent
    }
    patched.push(`0x${off.toString(16)}`);
  }
  if (patched.length) {
    kernel.dbgLog.push(`[loader] re-keyed __security_cookie sentinel @ rva ${patched.join(", ")}`);
  }
}

/**
 * @param {Uint8Array} imageBytes raw PE32+ (.sys) file content
 * @param {object} [opts]
 *   name           driver name for DRIVER_OBJECT.DriverName + service RegistryPath
 *                  (default "uploaded.sys"; basename w/o ext seeds Services\<key>)
 *   backend        "js" | "unicorn" | "hybrid" | CpuBackend instance
 *   tables         StructTables instance
 *   bases          NtKernel base overrides
 *   carvedState    carve-dump.mjs JSON (genuine ntoskrnl pages) — loaded pre-boot
 *   registry       {path: {valueName: data}} seeds
 *   maxSteps       per-call instruction budget (default 20M)
 *   ioctls         [{code:number|string, input?:Uint8Array|hex, outputLen?, major?}]
 *   autoIrp        true | {maxCodes?, inputPatterns?, outputLen?} — lifecycle
 *                  majors + harvested CTL_CODEs driven automatically post-entry
 *   runUnload      invoke DriverUnload after IOCTLs when present
 *   paging         boot the kernel with guest paging enabled (JsInterpreter only)
 *   makeBackend    async (mem)=>CpuBackend factory override (browser unicorn path)
 * @returns {Promise<object>} report
 */
/**
 * Run a driver, automatically rescuing pure-JS runs that hit instructions the
 * interpreter refuses (SSE, etc.) by retrying once on the hybrid backend —
 * speakeasy-style "it just works" behavior. Disable with
 * opts.autoHybridFallback = false.
 */
export async function analyzeDriver(imageBytes, opts = {}) {
  const r = await analyzeDriverOnce(imageBytes, opts);
  if (opts.autoHybridFallback === false) return r;
  if (opts.makeBackend || opts.cpu) return r; // caller chose a backend explicitly
  if (opts.backend && opts.backend !== "js") return r;
  const err = `${r.entry?.error ?? ""} ${r.bugcheck ?? ""}`;
  if (!/unimplemented|unsupported|0f opcode/i.test(err)) return r;
  try {
    const { HybridCpuBackend } = await import("@kernelforge/ntsim-unicorn/src/hybrid.mjs");
    const retried = await analyzeDriverOnce(imageBytes, {
      ...opts,
      backendName: "hybrid",
      makeBackend: async () => HybridCpuBackend.create(null),
    });
    if (retried.entry?.status === "ok" || !/unimplemented/i.test(retried.entry?.error ?? "")) {
      retried.meta.fallbackFrom = "js";
      return retried;
    }
  } catch {
    /* unicorn unavailable in this environment — keep the JS report */
  }
  return r;
}

async function analyzeDriverOnce(imageBytes, opts = {}) {
  // One address space for guest + kernel model + CPU: adopt whatever backend
  // we get (or NtKernel's default JsInterpreter) and reuse its SparseMemory.
  let cpu;
  if (typeof opts.makeBackend === "function") cpu = await opts.makeBackend(null);
  else if (opts.cpu) cpu = opts.cpu;

  const kernel = new NtKernel({
    cpu,
    tables: opts.tables,
    bases: opts.bases,
    paging: opts.paging,
    heap: opts.heap,
  });
  const mem = kernel.mem;
  kernel.bootstrap();

  // genuine dump pages under the synthetic world (optional)
  if (opts.carvedState?.pages) {
    const { loadDumpState } = await import("@kernelforge/ntsim/src/dumpstate.mjs");
    const info = loadDumpState(mem, opts.carvedState);
    kernel.dumpSource = "carved";
    kernel.carvedModules = info.modules;
  }
  // makeBackend factories that need the real memory object get it now
  if (cpu && typeof cpu.attachMemory === "function") cpu.attachMemory(mem);

  if (opts.registry) {
    for (const [p, values] of Object.entries(opts.registry)) {
      kernel.registrySeed(p, values);
    }
  }

  const report = {
    meta: {
      size: imageBytes.length,
      engine: opts.backendName ?? (kernel.cpu.constructor.name),
      at: new Date().toISOString(),
    },
    load: null,
    entry: null,
    ioctls: [],
    autoIrps: null,
    harvestedIoctls: null,
    deferred: null,
    unload: null,
    dbgLog: [],
    apiTraceSummary: null,
    exceptions: [],
    irqlViolations: [],
    bugcheck: null,
  };

  // ------------------------------------------------------------- map
  const drvRec = createDriverObject(kernel, opts.name ?? "uploaded.sys", opts.driverObject ?? {});
  const pe = parsePe(imageBytes); // throws PeError on non-x64/non-PE32+
  const mapped = mapPe(imageBytes, mem, DEFAULT_DRIVER_BASE, (qualified) =>
    kernel.resolveImportProvisioned(qualified));
  const image = { base: mapped.base, bytes: imageBytes };
  initDriverObjectName(kernel, drvRec, opts.name ?? "uploaded.sys", mapped.base, mapped.imageSize);
  drvRec.image = image; // enable SEH dispatch for IOCTL/unload calls
  // Ensure the whole image extent is backed with Windows-accurate zero fill
  // (inter-section gaps + intra-section BSS beyond pe.mjs's own BSS fill).
  // Without this, Unicorn faults on #PF while JsInterpreter silently
  // succeeds due to SparseMemory read-as-zero semantics.
  try { kernel.materializeModuleRange(mapped.base, mapped.imageSize, { fill: 0x00 }); } catch { /* optional backend */ }

  report.load = {
    base: `0x${mapped.base.toString(16)}`,
    imageSize: mapped.imageSize,
    entryRva: pe.entryRva,
    relocated: mapped.relocated,
    imports: mapped.imports,
    unmodeledExports: [...kernel.unmodeledExports],
    sections: pe.sections.map((s) => ({
      name: s.name, rva: s.rva, vsize: s.virtualSize,
    })),
    driverObject: `0x${drvRec.va.toString(16)}`,
    heap: { aslr: !!kernel.heapConfig?.aslr, poolBase: `0x${kernel.bases.pool.toString(16)}` },
  };
  // Packer / encryption detection: UPX sections indicate compressed payload that
  // must be unpacked before code is valid. Surface as load.packed for UI.
  try {
    const upx = pe.sections.filter(s => s.name.startsWith(".UPX"));
    if (upx.length) {
      report.load.packed = `UPX (${upx.map(s=>s.name).join(",")})`;
      kernel.dbgLog.push(`[loader] detected packed image ${report.load.packed} — entry may require unpacking; emulation may fault`);
    }
    if (pe.imageBase !== 0x140000000n && pe.imageBase === 0x10000n) {
      report.load.packed = (report.load.packed ? report.load.packed + " " : "") + "non-canonical base 0x10000";
    }
  } catch {}

  const driverName = opts.name ?? "uploaded.sys";
  const regPath = `\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Services\\${serviceKeyOf(driverName)}`;
  report.load.registryPath = regPath;
  report.load.driverName = driverName;
  // Seed the driver's service key so ZwOpenKey for its own service succeeds.
  // Many drivers (f9dd...) abort DriverEntry if they cannot open their service key.
  try {
    const svcMap = new Map([["Start", { type: 4, data: Uint8Array.from([0x03,0x00,0x00,0x00]) }], ["Type", { type: 4, data: Uint8Array.from([0x01,0x00,0x00,0x00]) }], ["ErrorControl", { type: 4, data: Uint8Array.from([0x01,0x00,0x00,0x00]) }]]);
    kernel.registry.set(regPath, svcMap);
    kernel.registry.set(regPath + "\\Parameters", new Map([["Config", { type: 1, data: new TextEncoder().encode("default\0") }]]));
    kernel.dbgLog.push(`[kdemu] seeded service key ${regPath}`);
  } catch {}

  if (opts.rekeySecurityCookie !== false) rekeySecurityCookie(kernel, mapped);

  // DriverEntry second arg is PUNICODE_STRING RegistryPath, not PWSTR
  const regPathBuf = kernel.allocPool(0x10); // UNICODE_STRING
  const regPathStrBuf = kernel.allocPool(0x200);
  mem.writeUtf16(regPathStrBuf, regPath);
  mem.w16(regPathBuf, regPath.length * 2);
  mem.w16(regPathBuf + 2n, 0x200);
  mem.w64(regPathBuf + 8n, regPathStrBuf);

  // ------------------------------------------------------ DriverEntry
  kernel.tracePhase = "DriverEntry";
  const entryResult = kernel.callFunctionSeh(mapped.entry, [drvRec.va, regPathBuf], image);
  report.entry = summarizeCall(entryResult);
  report.dbgLog.push(...kernel.dbgLog.splice(0));
  report.exceptions.push(...kernel.exceptionTrace.splice(0));
  report.irqlViolations.push(...kernel.irqlViolations.splice(0));

  if (kernel.bugcheck || kernel.crash) report.bugcheck = kernel.bugcheck ?? kernel.crash;

  // ------------------------------------------------------- deferred work
  if (entryResult.status === "ok" && !report.bugcheck) {
    kernel.tracePhase = "deferred";
    report.deferred = kernel.drainDeferred();
    report.dbgLog.push(...kernel.dbgLog.splice(0));
    report.exceptions.push(...kernel.exceptionTrace.splice(0));
  }

  // ------------------------------------------------------------ IOCTLs
  // Drivers that never call IoCreateDevice still get a synthetic device so
  // scripted IOCTLs can reach MajorFunction — speakeasy-style harnessing.
  const device = drvRec.deviceList[0] ?? createDeviceObject(kernel, drvRec, {});
  if (device && entryResult.status === "ok" && !report.bugcheck) {
    // automatic driving first (lifecycle majors + harvested CTL_CODEs)
    if (opts.autoIrp) {
      const { harvestCtlCodes, autoDriveIrps } = await import("./autoirp.mjs");
      const cfg = typeof opts.autoIrp === "object" ? opts.autoIrp : {};
      const harvested = harvestCtlCodes(imageBytes, pe, {
        maxCodes: cfg.maxCodes ?? 32,
        maxScanBytes: cfg.maxScanBytes,
      });
      report.harvestedIoctls = harvested.map((h) => ({
        value: h.value,
        hex: `0x${h.value.toString(16).padStart(8, "0")}`,
        rva: `0x${h.rva.toString(16)}`,
      }));
      kernel.tracePhase = "auto-irp";
      report.autoIrps = await autoDriveIrps(kernel, device, {
        sendIrp,
        harvested,
        maxCodes: cfg.maxCodes ?? 32,
        inputPatterns: cfg.inputPatterns,
        outputLen: cfg.outputLen ?? 64,
        imageBase: mapped.base,
        imageSize: mapped.imageSize,
        fuzz: cfg.fuzz ?? null,
        concolic: cfg.concolic ?? null,
        onPhase: (label) => { kernel.tracePhase = label; },
      });
      report.dbgLog.push(...kernel.dbgLog.splice(0));
      report.exceptions.push(...kernel.exceptionTrace.splice(0));
      report.irqlViolations.push(...kernel.irqlViolations.splice(0));
      if (kernel.bugcheck || kernel.crash) report.bugcheck = kernel.bugcheck ?? kernel.crash;
    }

    for (const spec of opts.ioctls ?? []) {
      if (report.bugcheck) break;
      const codeBig = typeof spec.code === "string"
        ? BigInt(spec.code.replace(/^0x/i, ""))
        : BigInt(spec.code ?? 0);
      kernel.tracePhase = `ioctl 0x${codeBig.toString(16)}`;
      const r = await sendIrp(kernel, device, {
        major: spec.major ?? IRP_MJ.DEVICE_CONTROL,
        ioctl: codeBig,
        input: spec.input instanceof Uint8Array ? spec.input : hexToBytes(spec.inputHex ?? spec.input),
        outputLen: spec.outputLen ?? 0,
        minor: spec.minor,
      });
      report.ioctls.push({
        ...r,
        outputHex: r.outputHex ?? "",
        error: r.error ? String(r.error.message ?? r.error) : undefined,
      });
      report.dbgLog.push(...kernel.dbgLog.splice(0));
      report.exceptions.push(...kernel.exceptionTrace.splice(0));
      report.irqlViolations.push(...kernel.irqlViolations.splice(0));
      if (r.status !== "ok") break; // stop driving after first hard failure
    }
  }

  // ------------------------------------------------------------ unload
  if (opts.runUnload && entryResult.status === "ok" && !report.bugcheck) {
    kernel.tracePhase = "unload";
    report.unload = summarizeCall(await callDriverUnload(kernel, drvRec));
    report.dbgLog.push(...kernel.dbgLog.splice(0));
    report.exceptions.push(...kernel.exceptionTrace.splice(0));
  }

  // ------------------------------------------------------------ summary
  // chronological call trace (ktrace-style) over everything that ran
  {
    const { finalizeTrace } = await import("@kernelforge/ntsim/src/tracer.mjs");
    const modules = [
      { name: driverName, base: mapped.base, size: mapped.imageSize },
      ...(kernel.loadedModules ?? [])
        .filter((m) => m.base !== undefined)
        .map((m) => ({ name: m.name, base: BigInt(m.base), size: Number(m.imageSize ?? m.size ?? 0x1000) })),
    ];
    if (!opts.trace?.disable) {
      const { events, text } = finalizeTrace(kernel, modules);
      report.trace = events;
      report.traceText = text;
    }
    report.etw = kernel.etwLog ?? [];
    kernel.tracePhase = "idle";
  }
  report.apiTraceSummary = summarizeApiTrace(kernel.apiTrace);
  report.symbolicLinks = kernel.symbolicLinks ?? [];
  report.registryWrites = summarizeRegistryWrites(kernel);
  report.filesWritten = [...(kernel.fs ?? new Map()).entries()]
    .filter(([, b]) => b.length > 0)
    .map(([p, b]) => ({ path: p, size: b.length }));
  // Preserve count for backwards compat and add detailed addresses with
  // overlap diagnostics (callback inside DriverEntry's own image range).
  report.notifyRoutines = Object.fromEntries(
    Object.entries(kernel.notifyRoutines).map(([k2, arr]) => [k2, arr.length]),
  );
  try {
    const drvBase = mapped.base;
    const drvEnd = mapped.base + BigInt(mapped.imageSize);
    const detail = {};
    for (const [k2, arr] of Object.entries(kernel.notifyRoutines)) {
      detail[k2] = arr.map((va) => {
        const v = BigInt(va);
        const rva = v >= drvBase && v < drvEnd ? Number(v - drvBase) : null;
        const overlapsEntry = rva !== null ? (v >= mapped.entry && v < mapped.entry + 0x2000n) : false; // heuristic: entry ± 8k
        return {
          va: `0x${v.toString(16)}`,
          rva: rva !== null ? `0x${rva.toString(16)}` : null,
          inImage: rva !== null,
          // true when callback lies within the page of DriverEntry — often
          // just adjacent pdata function, not real overlap. Flag for review.
          nearEntry: overlapsEntry,
        };
      });
    }
    report.notifyRoutinesDetail = detail;
    // Dbg log warnings for callbacks that fall inside the image's .text but
    // very close to entry — the user-reported "overlap" case. These are
    // usually legitimate adjacent functions (see pdata) and not a loader bug.
    for (const [kind, entries] of Object.entries(detail)) {
      for (const e of entries) {
        if (e.inImage && e.nearEntry) {
          kernel.dbgLog.push(`[notify] ${kind} cb ${e.va} (rva ${e.rva}) near DriverEntry — adjacent pdata function, not overlap`);
        }
      }
    }
  } catch { /* best-effort diagnostics */ }
  // live session for interactive follow-ups (UI IOCTLs / unload). Not JSON.
  report.__session = {
    kernel,
    drvRec,
    device,
    image,
  };
  return report;
}

function summarizeCall(r) {
  if (!r) return null;
  const out = { status: r.status };
  if ("retval" in r) out.retval = `0x${BigInt.asUintN(32, r.retval).toString(16).padStart(8, "0")}`;
  if (r.sehHandled) out.sehHandled = true;
  if (r.sehDetail) out.sehDetail = r.sehDetail;
  if (r.error) out.error = String(r.error.message ?? r.error);
  if (r.rip !== undefined) out.rip = `0x${r.rip.toString(16)}`;
  return out;
}

function summarizeApiTrace(trace) {
  if (!trace.length) return null;
  const byName = new Map();
  for (const e of trace) {
    const rec = byName.get(e.name) ?? { count: 0, args: [] };
    rec.count++;
    if (rec.args.length < 3) {
      rec.args.push({
        args: e.args.slice(0, 4).map((a) => `0x${a.toString(16)}`),
        ret: e.ret === undefined ? null : `0x${e.ret.toString(16)}`,
      });
    }
    byName.set(e.name, rec);
  }
  return {
    totalCalls: trace.length,
    distinct: byName.size,
    byName: Object.fromEntries([...byName.entries()].slice(0, 256)),
  };
}

function summarizeRegistryWrites(kernel) {
  const out = [];
  for (const [path, values] of kernel.registry ?? []) {
    for (const [name, entry] of values) {
      out.push({ path, value: name, type: entry.type, bytes: entry.data.length });
    }
  }
  return out;
}
