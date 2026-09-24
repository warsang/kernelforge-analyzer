/**
 * @kernelforge/pe-runner — userland PE32+ harness.
 *
 * Maps an EXE with the same loader as the kernel harness (`mapPe`), resolves
 * every import to a modeled Win32 thunk, seeds a minimal TEB/PEB so MSVC CRT
 * entry points run, then calls the entry point on the JS interpreter and
 * records behavior: files, registry, network, processes, commands, mutexes.
 *
 * This is a behavioral *intent* harness (speakeasy-style), not a Windows
 * emulator: unknown APIs are recorded and fail open with 0.
 */

import { SparseMemory, JsInterpreter, M64, installUserlandCpu } from "@kernelforge/ntsim/src/index.mjs";
import { mapPe, parsePe, rekeySecurityCookie } from "@kernelforge/ntsim/src/pe.mjs";
import {
  parsePeStatic, ssdeep, scanRules, extractStackStrings, detectApiHashes,
  scanWithYaraX, normalizeYaraMatches, PE_USERLAND_RULES, PE_USERLAND_YARA,
} from "@kernelforge/triage";
import { createWin32Model, writeCString, writeUtf16 } from "./win32.mjs";
import { listPeExports, findPeExport, exportSpecOf } from "./pe-exports.mjs";
import { createSehHost, callWithSeh } from "./seh-host.mjs";
import { createWindowsSyscallHandler } from "./nt-syscalls.mjs";
import { createThreadManager } from "./threads.mjs";
import { MemoryManager, HeapAllocator, PROT } from "./memory.mjs";
import { createMemoryApiHandlers } from "./memory-api.mjs";
import { createModuleLoader } from "./loader.mjs";
import { formatPeTrace } from "./trace.mjs";

export { createWin32Model } from "./win32.mjs";
export { listPeExports, findPeExport, exportSpecOf, MAX_EXPORTS } from "./pe-exports.mjs";

/** Thunk region: every modeled API gets a 16-byte slot inside this range. */
export const THUNK_BASE = 0x0000000060000000n;
export const THUNK_SLOT = 0x10n;
export const THUNK_REGION = 0x10000n;

const HEAP_BASE = 0x0000000002000000n;
const STACK_BASE = 0x0000000010000000n;
const TEB_BASE = 0x0n;
const PEB_BASE = 0x1000n;
const PARAMS_BASE = 0x2000n;
const STRINGS_BASE = 0x2100n;
/** Unicorn backend ABI return-marker page (backend-internal, kept RW). */
const UNICORN_MARKER_PAGE = 0x000000000badf000n;

const safe = (fn, fallback = null) => {
  try { return fn(); } catch { return fallback; }
};

const safeAsync = async (fn, fallback = null) => {
  try { return await fn(); } catch { return fallback; }
};

/** True when a fault rip sits in the seeded TEB/PEB/params zero page. */
function inSeedZeroPage(rips) {
  const last = Array.isArray(rips) && rips.length ? BigInt(rips[rips.length - 1]) : null;
  return last !== null && last < 0x3000n;
}

/** Compact call result for the report (`entry`/`attach` fields). */
function summarizeCall(r) {
  if (!r) return null;
  const out = {
    status: r.status,
    retval: r.retval !== undefined ? `0x${BigInt.asUintN(64, r.retval).toString(16)}` : undefined,
    error: r.error ? String(r.error.message ?? r.error) : undefined,
  };
  if (r.sehHandled) out.sehHandled = true;
  if (r.sehDetail) out.sehDetail = r.sehDetail;
  if (Array.isArray(r.recentRips) && r.recentRips.length) {
    out.recentRips = r.recentRips.slice(-24).map((x) => `0x${BigInt.asUintN(64, x).toString(16)}`);
  }
  return out;
}

function seedTeb(mem, { imageBase, commandLine, imagePath }) {
  // TEB: [0x30]=Self, [0x60]=PEB. Segment overrides are not modeled, so
  // `gs:[0x60]` resolves to the literal address 0x60 — put the PEB pointer
  // there and the CRT gets what it expects.
  mem.w64(TEB_BASE + 0x30n, TEB_BASE);
  mem.w64(TEB_BASE + 0x60n, PEB_BASE);
  mem.w64(PEB_BASE + 0x10n, imageBase); // ImageBaseAddress
  mem.w64(PEB_BASE + 0x20n, PARAMS_BASE); // ProcessParameters

  let cursor = STRINGS_BASE;
  const put = (s) => {
    const va = cursor;
    writeUtf16(mem, va, s);
    cursor += BigInt(s.length * 2 + 2 + 15) & ~0xfn;
    return va;
  };
  const cmdVa = put(commandLine);
  const imgVa = put(imagePath);
  const envVa = put("");
  // RTL_USER_PROCESS_PARAMETERS (approximate but layout-compatible)
  mem.w32(PARAMS_BASE + 0x00n, 0x1000); // MaximumLength
  mem.w32(PARAMS_BASE + 0x04n, 0x800); // Length
  const ustr = (off, s, va) => {
    mem.w16(PARAMS_BASE + off, s.length * 2);
    mem.w16(PARAMS_BASE + off + 2n, s.length * 2 + 2);
    mem.w64(PARAMS_BASE + off + 8n, va);
  };
  ustr(0x38n, "C:\\kfsample", put("C:\\kfsample"));
  ustr(0x60n, imagePath, imgVa);
  ustr(0x70n, commandLine, cmdVa);
  ustr(0x80n, "", envVa);
  // std handles
  mem.w64(PARAMS_BASE + 0x100n, 0x10n);
  mem.w64(PARAMS_BASE + 0x108n, 0x11n);
  mem.w64(PARAMS_BASE + 0x110n, 0x12n);
  return { commandLine, imagePath };
}

/**
 * @param {Uint8Array} imageBytes PE32+ executable or DLL
 * @param {object} [opts]
 *   name        sample name for reports (default "sample.exe")
 *   maxSteps    instruction budget (default 4M)
 *   commandLine guest command line (default `C:\kfsample\<name>`)
 *   rules       rule pack override (default PE_USERLAND_RULES)
 *   seedTeb     false disables the TEB/PEB seed (for bare entry tests)
 *   systemRoot  { "kernel32.dll": Uint8Array } real DLL images the loader maps
 *               on LoadLibrary (Wine-derived roots welcome); see loader.mjs
 *   preload     module names to map before the entry point runs
 *   fs          { "C:\\path\\file": "content" | Uint8Array } virtual FS;
 *               files written at runtime are visible to later opens
 *   network     { "host:port": ["canned response", ...] | "default": [...] }
 *               scripted socket replies for connect/send/recv/WSASend/WSARecv
 *   backendName "js" | "hybrid" (default js, with auto-hybrid fallback).
 *               Pure "unicorn" is not supported for userland yet: API thunk
 *               hooks are installed before the unicorn engine starts, which
 *               currently faults in the WASM core (use "hybrid").
 *   makeBackend async () => CpuBackend override (browser unicorn/hybrid path)
 *   cpu         explicit backend instance
 *   extraYara   user-supplied YARA-X source (compiled alongside the pack)
 *
 * DLL options (ignored for EXEs):
 *   dllMode     "export" (default) | "attach" | "all"
 *   export      export name, "#ordinal" or bare ordinal (default: first named
 *               non-forwarder export)
 *   exportArgs  rundll32-style argument string (wide, passed as arg3)
 *   customArgs  [rcx, rdx, r8, r9] bigint/number overrides
 *   callDllMain false skips DllMain(DLL_PROCESS_ATTACH) (default true)
 *   callDetach  true calls DllMain(DLL_PROCESS_DETACH) after the export
 *   maxExports  cap for dllMode "all" (default 64)
 *   perExportSteps per-export instruction budget for dllMode "all" (default 200k)
 * @returns {Promise<object>} report
 */
export async function runUserlandPe(imageBytes, opts = {}) {
  const bytes = imageBytes instanceof Uint8Array ? imageBytes : Uint8Array.from(imageBytes);
  const name = opts.name ?? "sample.exe";
  const pe = parsePe(bytes); // throws PeError for non-PE32+
  const isDll = (pe.characteristics & 0x2000) !== 0;

  // Static analysis runs once and is shared by every export run.
  const staticFacts = safe(() => {
    const st = parsePeStatic(bytes, { strings: true, maxStrings: 256 });
    st.ssdeep = ssdeep(bytes);
    st.stackStrings = extractStackStrings(bytes, { minLength: 6, maxStrings: 64 }).strings.slice(0, 32);
    st.apiHashes = detectApiHashes(bytes, { maxHits: 64 }).hits;
    st.strings = st.strings
      ? { total: st.strings.total, interesting: st.strings.interesting.slice(0, 64) }
      : null;
    return st;
  });
  const rules = safe(() => scanRules(bytes, opts.rules ?? PE_USERLAND_RULES, { maxMatchesPerRule: 8 }));
  const exportList = safe(() => listPeExports(bytes), null) ?? { total: 0, moduleName: null, entries: [] };

  // YARA-X (built-in pack + optional user source, compiled separately so a
  // bad custom rule cannot break the built-ins).
  let yara = null;
  if (opts.yara !== false) {
    const matches = [];
    const errors = [];
    const builtin = await safeAsync(() => scanWithYaraX(bytes, opts.yaraRules ?? PE_USERLAND_YARA));
    if (builtin) { matches.push(...normalizeYaraMatches(builtin)); errors.push(...(builtin.errors ?? [])); }
    if (opts.extraYara && String(opts.extraYara).trim()) {
      const custom = await safeAsync(() => scanWithYaraX(bytes, opts.extraYara, { throwOnError: true }));
      if (custom) matches.push(...normalizeYaraMatches(custom));
    }
    yara = { matches, errors };
  }

  const specs = decideRunSpecs({ isDll, opts, exportList });
  const ctxBase = { pe, isDll, name, staticFacts, rules, yara, exportList };
  const runs = [];
  let primary = null;
  for (const spec of specs) {
    const runOpts = spec.perExportSteps ? { ...opts, maxSteps: Math.min(opts.maxSteps ?? Infinity, spec.perExportSteps) } : opts;
    let r = await runUserlandPeOnce(bytes, runOpts, { ...ctxBase, spec });

    // Auto-hybrid rescue (single-run modes only — a 64-export sweep must not
    // spin up 64 Unicorn instances).
    if (specs.length === 1 && opts.autoHybridFallback !== false && !opts.makeBackend && !opts.cpu && !(opts.backendName && opts.backendName !== "js")) {
      const err = `${r.entry?.error ?? ""}`;
      if (/unimplemented|unsupported|0f opcode|x87/i.test(err)) {
        try {
          const { HybridCpuBackend } = await import("@kernelforge/ntsim-unicorn/src/hybrid.mjs");
          const retried = await runUserlandPeOnce(bytes, {
            ...runOpts,
            backendName: "hybrid",
            makeBackend: async () => HybridCpuBackend.create(null),
          }, { ...ctxBase, spec });
          if (retried.entry?.status === "ok" || !/unimplemented/i.test(retried.entry?.error ?? "")) {
            retried.meta.fallbackFrom = "js";
            r = retried;
          }
        } catch { /* unicorn unavailable in this environment — keep the JS report */ }
      }
    }

    runs.push(summarizeRun(r, spec));
    if (!primary) primary = r;
  }

  primary.run = {
    mode: isDll && opts.dllMode === "all" ? "all" : specs[0].mode,
    export: specs[0].exportSpec ?? null,
    args: opts.exportArgs ?? null,
    dllMode: isDll ? (opts.dllMode ?? "export") : null,
  };
  primary.runs = runs;
  return primary;
}

/** Pick the run spec(s): EXE entry, DLL attach/export/all. */
function decideRunSpecs({ isDll, opts, exportList }) {
  if (!isDll) return [{ mode: "entry" }];
  const mode = opts.dllMode ?? "export";
  if (mode === "all") {
    const cap = Math.max(1, Number(opts.maxExports ?? 64));
    const perExportSteps = Number(opts.perExportSteps ?? 200_000);
    const specs = exportList.entries
      .filter((e) => !e.forwarder)
      .slice(0, cap)
      .map((e) => ({ mode: "export", exportEntry: e, exportSpec: exportSpecOf(e), perExportSteps }));
    return specs.length ? specs : [{ mode: "attach" }];
  }
  if (mode === "attach") return [{ mode: "attach" }];
  const entry = findPeExport(exportList.entries, opts.export ?? "")
    ?? exportList.entries.find((e) => !e.forwarder)
    ?? null;
  if (!entry) return [{ mode: "attach" }];
  const spec = { mode: "export", exportEntry: entry, exportSpec: exportSpecOf(entry) };
  if (entry.forwarder) spec.mode = "forwarder";
  return [spec];
}

function summarizeRun(r, spec) {
  return {
    mode: spec.mode,
    export: spec.exportSpec ?? null,
    ordinal: spec.exportEntry?.ordinal ?? null,
    status: r.entry?.status ?? "?",
    steps: r.entry?.steps,
    retval: r.entry?.retval,
    error: r.entry?.error,
    exited: r.exited,
    exitCode: r.exitCode,
    apiCalls: r.apiTrace?.totalCalls ?? 0,
    files: r.artifacts?.files?.length ?? 0,
    registry: r.artifacts?.registry?.length ?? 0,
    network: r.artifacts?.network?.length ?? 0,
  };
}

async function runUserlandPeOnce(imageBytes, opts = {}, ctx = {}) {
  const bytes = imageBytes instanceof Uint8Array ? imageBytes : Uint8Array.from(imageBytes);
  const name = opts.name ?? ctx.name ?? "sample.exe";
  const pe = ctx.pe ?? parsePe(bytes);
  const isDll = ctx.isDll ?? ((pe.characteristics & 0x2000) !== 0);
  const staticFacts = ctx.staticFacts;
  const rules = ctx.rules;
  const yara = ctx.yara ?? null;
  const exportList = ctx.exportList ?? { total: 0, entries: [] };
  const spec = ctx.spec ?? { mode: isDll ? "attach" : "entry" };

  // Protected memory facade + real heap (VirtualAlloc/protect/guard semantics;
  // write/fetch faults flow into SEH as #PF). Never-mapped reads stay zeros.
  const sparse = new SparseMemory();
  const mem = new MemoryManager(sparse, {
    // Unknown addresses keep read/write-as-zero (analysis pragmatism);
    // declared regions enforce their state/protection (guard/reserve/NX).
    strictWrites: opts.strictMemory === true,
    strictFetch: opts.strictMemory === true,
  });
  const kernelHeap = new HeapAllocator(mem, HEAP_BASE, 0x10000000n);
  mem.map(TEB_BASE, 0x3000n, { protect: PROT.READWRITE });              // TEB/PEB/strings
  mem.map(STACK_BASE, 0x40000n, { protect: PROT.READWRITE });
  mem.map(HEAP_BASE, 0x10000000n, { protect: PROT.READWRITE });
  mem.map(THUNK_BASE, THUNK_REGION, { protect: PROT.EXECUTE_READWRITE });
  mem.map(UNICORN_MARKER_PAGE, 0x1000n, { protect: PROT.READWRITE });   // ABI marker (unicorn)

  let cpu = null;
  if (typeof opts.makeBackend === "function") cpu = await opts.makeBackend(mem);
  else if (opts.cpu) cpu = opts.cpu;
  else cpu = new JsInterpreter(mem);
  if (typeof cpu.attachMemory === "function") {
    try { cpu.attachMemory(mem); } catch { /* already attached */ }
  }
  installUserlandCpu(cpu);
  // #PF records carry the faulting instruction address for the SEH walk.
  mem.faultRip = () => (cpu.opcodeStart ?? cpu.rip ?? 0n);
  const maxSteps = opts.maxSteps ?? 4_000_000;

  // Unicorn (and other native backends) need real mapped pages where the JS
  // interpreter reads as zero: thunks, stack, heap and the image extent.
  const materialize = (base, size, { fill = 0 } = {}) => {
    const pages = BigInt(size ?? 0);
    if (pages <= 0n) return;
    if (fill !== null) {
      const end = base + pages;
      for (let p = base & ~0xfffn; p < end; p += 0x1000n) {
        if (!mem.hasPage?.(p)) mem.write(p, new Uint8Array(0x1000).fill(fill));
      }
    }
    if (typeof cpu.mapRange === "function") {
      try { cpu.mapRange(base, pages); } catch { /* already mapped / optional */ }
    }
  };
  materialize(THUNK_BASE, THUNK_REGION, { fill: null });
  // Seed every thunk slot with `xor eax,eax; ret` (int3 padding between):
  // a missed hook must return 0, not run through zero bytes — and long
  // all-zero basic blocks break the vendored Unicorn's code-hook translation
  // (wasm "memory access out of bounds" before the hook can fire).
  {
    const slotBytes = Number(THUNK_SLOT);
    const region = new Uint8Array(Number(THUNK_REGION)).fill(0xcc);
    for (let at = 0; at < region.length; at += slotBytes) {
      region[at] = 0x31;     // xor eax, eax
      region[at + 1] = 0xc0;
      region[at + 2] = 0xc3; // ret
    }
    mem.write(THUNK_BASE, region);
  }
  materialize(STACK_BASE, 0x40000);
  materialize(HEAP_BASE, 0x800000, { fill: null });

  const origRun = cpu.run.bind(cpu);
  cpu.run = (n) => origRun(Math.min(opts.maxSteps ?? n ?? maxSteps, maxSteps));

  // guest heap (first-fit/coalescing allocator) + stack
  const alloc = (size) => kernelHeap.alloc(size, { zero: true });
  cpu.regs.rsp = STACK_BASE + 0x10000n;

  // thunks
  const thunkByVa = new Map();
  const thunkByName = new Map();
  let thunkCount = 0;
  const allocThunk = (rawName) => {
    const api = String(rawName).replace(/^.*!/, "").replace(/^(?:__imp_|_)/, "");
    if (thunkByName.has(api)) return thunkByName.get(api);
    const va = THUNK_BASE + BigInt(thunkCount++) * THUNK_SLOT;
    thunkByName.set(api, va);
    thunkByVa.set(va, api);
    return va;
  };

  const model = createWin32Model({ mem, cpu, alloc, fs: opts.fs ?? null, network: opts.network ?? null });
  model.resolveProc = (fn) => (model.dispatch ? allocThunk(fn) : 0n);
  model.mainModule = pe.imageBase;
  /** image descriptor shared with the SEH dispatcher (needs raw bytes + base) */
  const sehImage = { base: pe.imageBase, bytes };
  model.image = sehImage;
  /** SEH dispatch trace lines (`[seh] ...`), surfaced in the report */
  const sehLog = [];
  const sehHost = createSehHost({ mem, cpu, alloc, dbgLog: sehLog });

  // Native syscalls: a raw `syscall` (0F 05) is serviced by the NT model, so
  // direct-syscall samples / anti-cheat stubs run instead of faulting.
  const winSyscall = createWindowsSyscallHandler({ mem, cpu, model });
  try { cpu.onSyscall = (nr) => winSyscall(nr); } catch { /* backend without syscall surface */ }

  // Guest threads / sync objects / TLS-FLS / APCs (eager single-CPU scheduler).
  const threadMgr = createThreadManager({
    mem,
    cpu,
    model,
    alloc,
    call: (addr, args) => callWithSeh(sehHost, sehImage, addr, args),
    stackSize: opts.threadStackSize ?? 0x100000,
  });
  model.register(threadMgr.handlers);
  // Windows memory/heap API surface (VirtualAlloc states, protections, guard
  // pages, HeapAlloc/Rtl*Heap) backed by MemoryManager/HeapAllocator.
  model.register(createMemoryApiHandlers({ mm: mem, heap: kernelHeap }));
  const commandLine = opts.commandLine ?? `C:\\kfsample\\${name}`;
  const imagePath = `C:\\kfsample\\${name}`;
  if (opts.seedTeb !== false) seedTeb(mem, { imageBase: pe.imageBase, commandLine, imagePath });
  model.commandLineA = alloc(commandLine.length + 1);
  writeCString(mem, model.commandLineA, commandLine);
  model.commandLineW = alloc((commandLine.length + 1) * 2);
  writeUtf16(mem, model.commandLineW, commandLine);

  // Data exports: msvcrt globals like _wcmdln/_fmode are *variables*, not code.
  // The loader writes the IAT slot with the address of the variable and the CRT
  // dereferences it; mapping them to code thunks leaves the variable null
  // (calc.exe bails 0xFF right after initterm when _wcmdln == NULL).
  const dataCells = new Map();
  const DATA_EXPORTS = new Map([
    ["wcmdln", () => model.commandLineW],
    ["acmdln", () => model.commandLineA],
    ["pgmptr", () => model.commandLineA],
    ["wpgmptr", () => model.commandLineW],
    ["fmode", () => 0n],
    ["commode", () => 0x200n],
    ["argc", () => 1n],
    ["argv", () => model.argvPtr],
    ["environ", () => model.envBlockPtr],
    ["wenviron", () => model.envBlockPtr],
  ]);
  model.dataCells = dataCells;
  const resolveImport = (qualified) => {
    const symbol = String(qualified).replace(/^.*!/, "");
    const key = symbol.replace(/^(?:__imp_|_+)/, "").toLowerCase();
    if (DATA_EXPORTS.has(key)) {
      if (!dataCells.has(key)) {
        const va = alloc(8);
        mem.w64(va, BigInt(DATA_EXPORTS.get(key)()));
        dataCells.set(key, va);
      }
      return dataCells.get(key);
    }
    return allocThunk(qualified);
  };

  // Real module loading: `opts.systemRoot` maps DLL names to genuine PE images
  // (e.g. a Wine-derived root). LoadLibrary* maps them with the same manual
  // mapper, binds their imports against loaded modules (real EAT + forwarders)
  // or the modeled thunks, and registers them in PEB->Ldr.
  const loader = createModuleLoader({
    mem,
    mm: mem,
    model,
    alloc,
    resolveImport,
    systemRoot: opts.systemRoot ?? null,
    pebBase: PEB_BASE,
  });

  // Managed .NET assemblies carry a CLR header: the native entry would be the
  // DOS stub, which executes garbage. Refuse them (and any EXE with no entry
  // point) with a clear load error instead. DLLs may legitimately have
  // AddressOfEntryPoint=0 (no DllMain) — those run their export directly.
  const clrDir = pe.dirs?.[14];
  const hasClr = !!(clrDir && clrDir.rva);
  if (hasClr || (pe.entryRva === 0 && !isDll)) {
    const reason = hasClr
      ? "managed .NET assembly (CLR header present) — not supported by this harness"
      : "no entry point (AddressOfEntryPoint=0)";
    return {
      meta: { kind: "userland-pe", size: bytes.length, at: new Date().toISOString(), name },
      load: null,
      static: staticFacts,
      rules,
      yara,
      entry: { status: "load-error", error: reason },
      artifacts: model.artifacts,
      apiTrace: null,
      unmodeled: [],
    };
  }

  // map + import resolution (image registered RW for the loader phase; section
  // protections are applied after relocs/imports/GS re-keying)
  let mapped;
  try {
    mem.map(pe.imageBase, BigInt(pe.sizeOfImage), {
      protect: opts.sectionProtections === true ? PROT.READWRITE : PROT.EXECUTE_READWRITE,
    });
    mapped = mapPe(bytes, mem, pe.imageBase, resolveImport);
  } catch (e) {
    return {
      meta: { kind: "userland-pe", size: bytes.length, at: new Date().toISOString(), name },
      load: null,
      static: staticFacts,
      rules,
      entry: { status: "load-error", error: String(e?.message ?? e) },
      artifacts: model.artifacts,
      apiTrace: null,
      unmodeled: [],
    };
  }

  // Register the main image in PEB->Ldr and expose the loader's Win32 surface
  // (LoadLibrary/GetModuleHandle/GetProcAddress/GetModuleFileName).
  loader.registerMain({ name, base: pe.imageBase, imageSize: pe.sizeOfImage, entry: pe.imageBase + BigInt(pe.entryRva), bytes });
  model.register(loader.handlers);
  for (const pre of opts.preload ?? []) {
    try { loader.load(pre); } catch { /* optional preload */ }
  }

  // __fastfail terminates the process (abort/GS/security checks): record the
  // reason and stop cleanly instead of surfacing a bare interpreter fault.
  const FASTFAIL = {
    0: "legacy GS violation",
    1: "GS violation (stack cookie)",
    2: "invalid argument",
    3: "corrupted list",
    4: "incorrect stack",
    5: "invalid arg",
    7: "fatal app exit (abort)",
    8: "stack cookie init failure",
    9: "corrupted heap",
  };
  cpu.onFastfail = (code) => {
    model.exited = true;
    model.exitCode = code;
    model.exitReason = FASTFAIL[code] ?? `fastfail(${code})`;
    model.events.push({
      name: `[exit] __fastfail: ${model.exitReason}`,
      args: [],
      ret: undefined,
      retAddr: cpu.rip !== undefined ? BigInt(cpu.rip) : undefined,
    });
    return true;
  };

  // Image extent (sections are sparse-resident; map the whole range so native
  // backends can execute gaps/headers without faulting).
  if (typeof cpu.mapRange === "function") {
    try { cpu.mapRange(pe.imageBase, pe.sizeOfImage); } catch { /* optional */ }
  }

  // Loader step: re-key the MSVC GS cookie sentinel (see ntsim/pe.mjs) so
  // /GS checks in the CRT do not __fastfail before initialization.
  const rekeyed = rekeySecurityCookie(mem, pe.imageBase, pe.sizeOfImage);
  if (rekeyed.length) {
    model.events.push({ name: "[loader] rekeyed __security_cookie", args: [], ret: undefined });
  }

  // Loader step: apply real section protections — OPT-IN (`sectionProtections:
  // true`). Default off: analysis samples commonly self-modify .text without
  // VirtualProtect, and the corpus runs better when sections stay permissive.
  // VirtualAlloc/VirtualProtect regions always enforce their declared state.
  if (opts.sectionProtections === true) {
    try {
      mem.protect(pe.imageBase, BigInt(Math.min(pe.sizeOfHeaders, pe.sizeOfImage)), PROT.READONLY);
      for (const s of pe.sections) {
        const size = BigInt(Math.max(s.virtualSize, s.rawSize));
        if (size <= 0n) continue;
        const exec = (s.chars & 0x20000000) !== 0;
        const write = (s.chars & 0x80000000) !== 0;
        const prot = exec
          ? (write ? PROT.EXECUTE_READWRITE : PROT.EXECUTE_READ)
          : (write ? PROT.READWRITE : PROT.READONLY);
        mem.protect(pe.imageBase + BigInt(s.rva), size, prot);
      }
    } catch { /* protection bookkeeping is advisory if it fails */ }
  }

  // API dispatch hook over the thunk region
  const thunkHandler = (rip) => {
    const api = thunkByVa.get(rip);
    if (!api) return false;
    const rsp = cpu.regs.rsp;
    const args = [cpu.regs.rcx, cpu.regs.rdx, cpu.regs.r8, cpu.regs.r9];
    for (let j = 0; j < 8; j++) {
      try { args.push(mem.u64(rsp + 0x28n + BigInt(8 * j))); } catch { args.push(0n); }
    }
    const retAddr = safe(() => mem.u64(rsp), 0n);
    const ret = model.dispatch(api, args, { retAddr });
    if (ret !== undefined) cpu.regs.rax = BigInt.asUintN(64, ret);
    cpu.regs.rsp = (rsp + 8n) & M64;
    cpu.rip = retAddr;
    return true;
  };
  if (typeof cpu.addCodeHook === "function") {
    cpu.addCodeHook(thunkHandler, THUNK_BASE, THUNK_BASE + THUNK_REGION);
  } else {
    cpu.onCodeHook = thunkHandler;
  }

  // ---- invoke: EXE entry | DLL attach | DLL export (rundll32-style) ----
  const stepsBefore = cpu.steps ?? 0;
  const entryVa = pe.imageBase + BigInt(pe.entryRva);
  const callAttach = () => {
    if (pe.entryRva === 0 || opts.callDllMain === false) return null;
    const r = callWithSeh(sehHost, sehImage, entryVa, [pe.imageBase, 1n, 0n]);
    return { raw: r, rec: summarizeCall(r) };
  };

  let result;
  let attach = null;
  if (spec.mode === "forwarder") {
    result = { status: "forwarder", error: `export ${spec.exportSpec} forwards to ${spec.exportEntry?.forwarder ?? "?"}` };
  } else if (spec.mode === "export" && spec.exportEntry) {
    const ar = callAttach();
    if (ar) {
      attach = ar.rec;
      // Broken or terminating DllMain: report it instead of running the export.
      if (model.exited || (ar.raw.status !== "ok" && ar.raw.status !== "halted")) {
        result = ar.raw;
      }
    }
    if (!result) {
      const exportVa = pe.imageBase + BigInt(spec.exportEntry.rva);
      let args;
      if (Array.isArray(opts.customArgs) && opts.customArgs.length) {
        args = opts.customArgs.slice(0, 4).map((v) => BigInt.asUintN(64, BigInt(v ?? 0)));
      } else {
        const argsVa = STRINGS_BASE + 0x800n;
        writeUtf16(mem, argsVa, String(opts.exportArgs ?? ""));
        args = [0n, pe.imageBase, argsVa, 1n]; // rundll32: hwnd, hinst, cmdline, nCmdShow
      }
      result = callWithSeh(sehHost, sehImage, exportVa, args);
      if (opts.callDetach && pe.entryRva !== 0 && !model.exited && !cpu.halted) {
        safe(() => callWithSeh(sehHost, sehImage, entryVa, [pe.imageBase, 0n, 0n]));
      }
    }
  } else if (isDll) {
    const ar = callAttach();
    attach = ar?.rec ?? null;
    result = ar ? ar.raw : { status: "ok", retval: 0n, steps: 0 }; // DLL without DllMain
  } else {
    result = callWithSeh(sehHost, sehImage, entryVa, []);
  }
  const steps = (cpu.steps ?? 0) - stepsBefore;

  const byName = new Map();
  for (const e of model.events) {
    const rec = byName.get(e.name) ?? { count: 0, args: [] };
    rec.count++;
    if (rec.args.length < 2) {
      rec.args.push({ args: e.args.slice(0, 4).map((a) => `0x${a.toString(16)}`), ret: e.ret !== undefined ? `0x${e.ret.toString(16)}` : null });
    }
    byName.set(e.name, rec);
  }

  // ExitProcess halts the CPU; surface a clean process exit as ok.
  const status = result.status === "halted" && model.exited ? "ok" : result.status;
  const stalled = status === "timeout" || status === "debug-stop";
  const { trace, traceText, traceAbridgedText, traceAbridgedCount, traceTotalCount } = formatPeTrace(model.events, {
    mem, base: pe.imageBase, imageSize: pe.sizeOfImage, name,
  });
  return {
    meta: {
      kind: "userland-pe", size: bytes.length, at: new Date().toISOString(), name,
      engine: opts.backendName ?? (cpu.constructor?.name ?? "JsInterpreter"),
    },
    load: {
      base: `0x${pe.imageBase.toString(16)}`,
      imageSize: pe.sizeOfImage,
      entryRva: pe.entryRva,
      isDll,
      exportCount: exportList.total ?? 0,
      exports: (exportList.entries ?? []).slice(0, 256).map((e) => ({
        name: e.name, ordinal: e.ordinal, forwarder: e.forwarder ?? null,
      })),
      imports: mapped.imports,
      dataExports: [...dataCells.keys()],
      unsupportedRuntime: mapped.imports.some((i) => /^(msys-|cygwin1)/i.test(i))
        ? "msys2/cygwin POSIX runtime — imports are stubbed, execution will diverge"
        : null,
      relocated: mapped.relocated,
      modules: loader.list(),
      fsFiles: typeof model.vfs?.size === "function" ? model.vfs.size() : 0,
      subsystem: staticFacts?.subsystem ?? null,
      subsystemName: staticFacts?.subsystemName ?? null,
      machine: staticFacts?.machineName ?? null,
    },
    static: staticFacts,
    rules,
    yara,
    run: {
      mode: spec.mode,
      export: spec.exportSpec ?? null,
      args: opts.exportArgs ?? null,
      dllMode: isDll ? (opts.dllMode ?? "export") : null,
    },
    entry: {
      status,
      retval: result.retval !== undefined ? `0x${BigInt.asUintN(64, result.retval).toString(16)}` : undefined,
      error: result.error ? String(result.error.message ?? result.error) : undefined,
      steps,
      ...(result.sehHandled ? { sehHandled: true } : {}),
      ...(result.sehDetail ? { sehDetail: result.sehDetail } : {}),
      ...(status === "fault" && inSeedZeroPage(result.recentRips)
        ? { errorHint: "execution entered the TEB/PEB zero page — an indirect call went through a NULL vtable/function pointer (usually an unmodeled C++/framework import that returned 0)" }
        : {}),
      ...(Array.isArray(result.recentRips) && result.recentRips.length
        ? { recentRips: result.recentRips.slice(-160).map((x) => `0x${BigInt.asUintN(64, x).toString(16)}`) }
        : {}),
    },
    seh: sehLog.slice(0, 64),
    threads: typeof model.threadState === "function" ? model.threadState() : [],
    attach,
    stall: stalled
      ? {
        status,
        rip: result.rip !== undefined ? `0x${BigInt(result.rip).toString(16)}` : (cpu.rip !== undefined ? `0x${BigInt(cpu.rip).toString(16)}` : null),
        steps,
        lastEvents: model.events.slice(-10).map((e) => e.name),
      }
      : null,
    exited: model.exited,
    exitCode: model.exitCode,
    exitReason: model.exitReason ?? null,
    apiTrace: { totalCalls: model.events.length, distinct: byName.size, byName: Object.fromEntries([...byName.entries()].slice(0, 256)) },
    memoryFaults: mem.faults.slice(0, 32),
    artifacts: model.artifacts,
    unmodeled: [...model.unmodeled],
    trace,
    traceText,
    traceAbridgedText,
    traceAbridgedCount,
    traceTotalCount,
    events: model.events.slice(0, 2048),
  };
}
