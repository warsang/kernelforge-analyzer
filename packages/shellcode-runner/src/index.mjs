/**
 * index.mjs — @kernelforge/shellcode-runner: run raw x64 shellcode.
 *
 * Windows mode builds a walkable TEB/PEB/Ldr world with synthetic kernel32 /
 * ntdll images whose real (sorted) export tables resolve to either thunk
 * stubs (dispatched into the pe-runner Win32 model) or genuine
 * `mov r10,rcx; mov eax,SSN; syscall` stubs (dispatched through the fixed
 * SSN table — Hell's-Gate scraping works). Linux mode reuses the elf-runner
 * syscall model. Both record behavior, decode traces, run triage rules and
 * YARA, and diff the RWX code + heap before/after to surface unpacked
 * buffers (self-modifying decoders).
 */

import { SparseMemory, JsInterpreter, M64, installUserlandCpu } from "@kernelforge/ntsim/src/index.mjs";
import { createWin32Model, writeCString, writeUtf16 } from "@kernelforge/pe-runner/src/win32.mjs";
import { formatPeTrace } from "@kernelforge/pe-runner/src/trace.mjs";
import { createLinuxModel } from "@kernelforge/elf-runner/src/linux.mjs";
import { formatElfTrace } from "@kernelforge/elf-runner/src/trace.mjs";
import {
  shellcodeFacts, ssdeep, scanRules, scanWithYaraX, normalizeYaraMatches,
  SHELLCODE_RULES, SHELLCODE_YARA,
} from "@kernelforge/triage";
import {
  CODE_BASE, HEAP_BASE, HEAP_SIZE, STACK_BASE, STACK_SIZE,
  THUNK_BASE, THUNK_SLOT, THUNK_REGION, NT_DLL_BASE, K32_DLL_BASE,
  PARAMS_BASE, ARGV_STRINGS, ARGC_VA, TRAMP_VA,
  seedTebPebLdr, buildSyntheticDll, buildThunkStub, ntDllExports,
} from "./win/loader.mjs";
import { createWindowsSyscallHandler, readNtArgs } from "./win/syscalls.mjs";

export {
  CODE_BASE, HEAP_BASE, STACK_BASE, THUNK_BASE, NT_DLL_BASE, K32_DLL_BASE,
  PARAMS_BASE, seedTebPebLdr, buildSyntheticDll, buildThunkStub, buildNtStub,
} from "./win/loader.mjs";
export { NT_SSNS, createWindowsSyscallHandler } from "./win/syscalls.mjs";

const u64 = (v) => BigInt.asUintN(64, BigInt(v ?? 0n));
const safe = (fn, fallback = null) => { try { return fn(); } catch { return fallback; } };

const FASTFAIL = {
  0: "legacy GS violation", 1: "GS violation (stack cookie)", 2: "invalid argument",
  3: "corrupted list", 4: "incorrect stack", 5: "invalid arg", 7: "fatal app exit (abort)",
  8: "stack cookie init failure", 9: "corrupted heap",
};

/**
 * @param {Uint8Array} bytesIn raw x64 shellcode
 * @param {object} [opts]
 *   os           "win" (default) | "linux"
 *   convention   win: "raw"|"threadproc"|"function"; linux: "raw"|"argv"|"function"
 *   entryOffset  start offset inside the buffer (default 0)
 *   paramBytes   guest argument buffer (threadproc/function conventions)
 *   name         sample name (default "shellcode.bin")
 *   maxSteps     instruction budget (default 4M)
 *   backendName  "js" (default) | "hybrid" (auto-fallback on interpreter gaps)
 *   makeBackend  async () => CpuBackend override
 *   cpu          explicit backend instance
 *   extraYara    user-supplied YARA-X source (compiled alongside the pack)
 * @returns {Promise<object>} report (meta.kind === "shellcode")
 */
export async function runShellcode(bytesIn, opts = {}) {
  const r = await runShellcodeOnce(bytesIn, opts);
  if (opts.autoHybridFallback === false) return r;
  if (opts.makeBackend || opts.cpu) return r;
  if (opts.backendName && opts.backendName !== "js") return r;
  const err = `${r.entry?.error ?? ""}`;
  if (!/unimplemented|unsupported|0f opcode/i.test(err)) return r;
  try {
    const { HybridCpuBackend } = await import("@kernelforge/ntsim-unicorn/src/hybrid.mjs");
    const retried = await runShellcodeOnce(bytesIn, {
      ...opts,
      backendName: "hybrid",
      makeBackend: async () => HybridCpuBackend.create(null),
    });
    if (retried.entry?.status === "ok" || !/unimplemented/i.test(retried.entry?.error ?? "")) {
      retried.meta.fallbackFrom = "js";
      return retried;
    }
  } catch { /* unicorn unavailable — keep the JS report */ }
  return r;
}

function snapshot(mem, va, size) {
  return safe(() => Uint8Array.from(mem.read(va, size)), new Uint8Array(size));
}

function diffBuffers(before, after) {
  const ranges = [];
  let changedBytes = 0;
  let start = -1;
  for (let i = 0; i < before.length; i++) {
    const changed = before[i] !== after[i];
    if (changed && start < 0) start = i;
    if (!changed && start >= 0) {
      if (ranges.length < 256) ranges.push({ start, end: i });
      changedBytes += i - start;
      start = -1;
    }
  }
  if (start >= 0) {
    if (ranges.length < 256) ranges.push({ start, end: before.length });
    changedBytes += before.length - start;
  }
  return { changedBytes, ranges };
}

async function runShellcodeOnce(bytesIn, opts = {}) {
  const bytes = bytesIn instanceof Uint8Array ? bytesIn : Uint8Array.from(bytesIn);
  if (!bytes.length) throw new Error("empty buffer — nothing to emulate");
  const os = opts.os === "linux" ? "linux" : "win";
  const name = opts.name ?? "shellcode.bin";
  const convention = opts.convention ?? "raw";
  const entryOffset = Number(opts.entryOffset ?? 0);
  const maxSteps = opts.maxSteps ?? 4_000_000;

  // ---- static triage (before emulation) ----
  const facts = { ...shellcodeFacts(bytes), os };
  const staticFacts = {
    ...facts,
    ssdeep: safe(() => ssdeep(bytes), null),
  };
  const rules = safe(() => scanRules(bytes, opts.rules ?? SHELLCODE_RULES, { maxMatchesPerRule: 8 }), null);

  // ---- CPU + memory ----
  const mem = new SparseMemory();
  let cpu = null;
  if (typeof opts.makeBackend === "function") cpu = await opts.makeBackend(mem);
  else if (opts.cpu) cpu = opts.cpu;
  else cpu = new JsInterpreter(mem);
  if (typeof cpu.attachMemory === "function") {
    try { cpu.attachMemory(mem); } catch { /* already attached */ }
  }
  installUserlandCpu(cpu);
  // Cumulative step budget. Hybrid's callFunction drives its inner engines
  // directly (bypassing a wrapper on the hybrid itself), so cap every engine
  // and charge by cpu.steps deltas — the hybrid's step count is its engines'.
  let budget = Number(opts.maxSteps ?? maxSteps);
  const capRun = (engine) => {
    if (!engine || typeof engine.run !== "function" || engine.__kfBudgeted) return;
    engine.__kfBudgeted = true;
    const orig = engine.run.bind(engine);
    engine.run = (n) => {
      const before = cpu.steps ?? 0;
      const want = Math.max(0, Math.min(n ?? budget, budget));
      const res = orig(want);
      budget -= Math.max(0, (cpu.steps ?? 0) - before);
      return res;
    };
  };
  if (cpu.js || cpu.uc) { capRun(cpu.js); capRun(cpu.uc); } else capRun(cpu);

  const materialize = (base, size, { fill = 0 } = {}) => {
    if (size <= 0n) return;
    if (fill !== null) {
      for (let p = base & ~0xfffn; p < base + size; p += 0x1000n) {
        if (!mem.hasPage?.(p)) mem.write(p, new Uint8Array(0x1000).fill(fill));
      }
    }
    if (typeof cpu.mapRange === "function") {
      try { cpu.mapRange(base, size); } catch { /* already mapped */ }
    }
  };
  materialize(STACK_BASE, STACK_SIZE, { fill: null });
  materialize(HEAP_BASE, HEAP_SIZE, { fill: null });
  cpu.regs.rsp = STACK_BASE + 0x18000n;

  let heapPtr = HEAP_BASE;
  const alloc = (size) => {
    const va = heapPtr;
    heapPtr += BigInt(Math.max(16, (Number(size) + 15) & ~15));
    return va;
  };

  // ---- OS world ----
  const model = os === "win"
    ? createWin32Model({ mem, cpu, alloc })
    : createLinuxModel({ mem, cpu, alloc });
  const events = model.events;
  let thunkByVa = new Map();
  let winSyscall = null;

  if (os === "win") {
    let thunkCount = 0;
    const thunkByName = new Map();
    const allocThunk = (rawName) => {
      const api = String(rawName).replace(/^.*!/, "").replace(/^(?:__imp_|_)/, "");
      if (thunkByName.has(api)) return thunkByName.get(api);
      const va = THUNK_BASE + BigInt(thunkCount++) * THUNK_SLOT;
      thunkByName.set(api, va);
      thunkByVa.set(va, api);
      return va;
    };
    model.resolveProc = (fn) => allocThunk(fn);
    model.mainModule = CODE_BASE;

    const apiNames = model.apiNames ?? [];
    const ntStyle = /^(?:Nt|Zw|Rtl)/;
    const k32Exports = apiNames
      .filter((n) => !ntStyle.test(n))
      .map((name) => ({ name, stub: buildThunkStub(allocThunk(name)) }));
    const ntExports = ntDllExports(allocThunk);
    for (const n of apiNames.filter((n) => ntStyle.test(n))) {
      if (!ntExports.some((e) => e.name === n)) {
        ntExports.push({ name: n, stub: buildThunkStub(allocThunk(n)) });
      }
    }
    const ntdll = buildSyntheticDll(mem, { base: NT_DLL_BASE, dllName: "ntdll.dll", exports: ntExports });
    const kernel32 = buildSyntheticDll(mem, { base: K32_DLL_BASE, dllName: "kernel32.dll", exports: k32Exports });
    seedTebPebLdr(mem, [
      { name: name.slice(-12) || "sample.bin", full: `C:\\kfsample\\${name}`, base: CODE_BASE, size: 0x10000n },
      { name: "ntdll.dll", full: "C:\\Windows\\System32\\ntdll.dll", base: ntdll.base, size: ntdll.size },
      { name: "kernel32.dll", full: "C:\\Windows\\System32\\kernel32.dll", base: kernel32.base, size: kernel32.size },
    ]);

    winSyscall = createWindowsSyscallHandler({ mem, cpu, model });

    // Thunk bodies live in the code hook, but the region must be mapped —
    // unicorn faults on fetch before hooks fire — and int3-filled so a
    // missed slot clean-stops instead of executing zeros.
    materialize(THUNK_BASE, THUNK_REGION, { fill: 0xcc });

    // thunk dispatch (same shape as pe-runner)
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
      if (ret !== undefined) cpu.regs.rax = u64(ret);
      cpu.regs.rsp = (rsp + 8n) & M64;
      cpu.rip = retAddr;
      return true;
    };
    if (typeof cpu.addCodeHook === "function") {
      cpu.addCodeHook(thunkHandler, THUNK_BASE, THUNK_BASE + THUNK_REGION);
    } else {
      cpu.onCodeHook = thunkHandler;
    }

    cpu.onFastfail = (code) => {
      model.exited = true;
      model.exitCode = code;
      model.exitReason = FASTFAIL[code] ?? `fastfail(${code})`;
      model.stopReason = `int 29 fastfail: ${model.exitReason}`;
      events.push({ name: `[stop] ${model.stopReason}`, args: [], ret: undefined });
      return true;
    };
  } else {
    cpu.onSyscall = (nr, args) => {
      const ret = model.dispatch(nr, args);
      const ev = events[events.length - 1];
      if (ev && ev.retAddr === undefined && cpu.rip !== undefined) ev.retAddr = u64(cpu.rip);
      return ret;
    };
  }

  // ---- trap / syscall interception (both OSes) ----
  // The JS interpreter throws CpuError on `int 2e`, `sysenter` and `ud2`, and
  // treats int3/int 2d as skippable breakpoints — shellcode semantics want
  // Windows SSN dispatch (syscall/sysenter/int 2e) and clean stops with a
  // reason (int3 / ud2 / int 2d / hlt). Intercept before the interpreter.
  const cleanStop = (rip, len, reason) => {
    model.exited = true;
    model.stopReason = reason;
    model.exitReason = reason;
    events.push({ name: `[stop] ${reason}`, args: [], ret: undefined, retAddr: rip });
    cpu.rip = (rip + BigInt(len)) & M64;
    cpu.halted = true;
    return true;
  };
  const winNativeSyscall = (rip, kind) => {
    const ssn = cpu.regs.rax & 0xffffffffn;
    const ret = winSyscall(ssn, readNtArgs(cpu, mem));
    events.push({ name: `[${kind}] Nt#${Number(ssn)}`, args: [], ret: u64(ret), retAddr: rip });
    cpu.regs.rax = u64(ret);
    cpu.rip = (rip + 2n) & M64;
    return true;
  };
  // Linux `syscall` must not reach the CPU backend either (unicorn has no
  // syscall hook) — dispatch nr=rax with the linux ABI regs, then step over
  // the 2-byte instruction. execve is terminal (it replaces the image).
  const linuxNativeSyscall = (rip) => {
    const args = [cpu.regs.rdi, cpu.regs.rsi, cpu.regs.rdx, cpu.regs.r10, cpu.regs.r8, cpu.regs.r9].map(u64);
    const ret = model.dispatch(cpu.regs.rax, args);
    const ev = events[events.length - 1];
    if (ev && ev.retAddr === undefined) ev.retAddr = u64(rip + 2n);
    if (ret !== undefined && ret !== null) cpu.regs.rax = u64(ret);
    cpu.rip = (rip + 2n) & M64;
    if (ev && (ev.name === "execve" || ev.name === "execveat")) {
      model.exited = true;
      model.exitReason = `${ev.name} (image replaced)`;
      model.stopReason = model.exitReason;
      cpu.halted = true;
    }
    return true;
  };
  const trapHook = (rip) => {
    const at = safe(() => mem.read(rip, 2), null);
    if (!at) return false;
    const b0 = at[0], b1 = at[1];
    if (b0 === 0x0f && b1 === 0x05) { // syscall
      return os === "win" ? winNativeSyscall(rip, "syscall") : linuxNativeSyscall(rip);
    }
    if (b0 === 0x0f && b1 === 0x34) { // sysenter
      return os === "win" ? winNativeSyscall(rip, "sysenter") : cleanStop(rip, 2, "sysenter (Windows-only)");
    }
    if (b0 === 0xcd && b1 === 0x2e) { // int 2e — legacy NT call (EDX=argptr)
      if (os !== "win") return cleanStop(rip, 2, "int 2e (Windows-only)");
      const ssn = cpu.regs.rax & 0xffffffffn;
      let args = null;
      const edxPtr = u64(cpu.regs.rdx);
      if (edxPtr !== 0n) {
        args = safe(() => [0, 1, 2, 3].map((i) => mem.u64(edxPtr + BigInt(i * 8))), null) ?? readNtArgs(cpu, mem);
      } else {
        args = readNtArgs(cpu, mem);
      }
      const ret = winSyscall(ssn, args);
      events.push({ name: `[int 2e] Nt#${Number(ssn)}`, args: [], ret: u64(ret), retAddr: rip });
      cpu.regs.rax = u64(ret);
      cpu.rip = (rip + 2n) & M64;
      return true;
    }
    if (b0 === 0xcd && b1 === 0x2d) return cleanStop(rip, 2, "int 2d (anti-debug)");
    if (b0 === 0xcc) return cleanStop(rip, 1, "int3");
    if (b0 === 0x0f && b1 === 0x0b) return cleanStop(rip, 2, "ud2");
    return false;
  };
  if (typeof cpu.addCodeHook === "function") cpu.addCodeHook(trapHook, 0n, M64);
  else if (os === "win") cpu.onCodeHook = trapHook;

  // ---- map the buffer (RWX) + params ----
  const codeSize = BigInt(Math.max(0x2000, (bytes.length + 0x1fff) & ~0xfff));
  // 0xCC padding: running past the buffer clean-stops on int3. A payload's
  // tail call may leave an unbalanced stack (shadow space unpopped), so a
  // ret into the padding would go wild — int3 is the safe end-of-buffer.
  materialize(CODE_BASE, codeSize, { fill: 0xcc });
  mem.write(CODE_BASE, bytes);
  const paramBytes = opts.paramBytes ? Uint8Array.from(opts.paramBytes) : new Uint8Array(0);
  if (paramBytes.length) mem.write(PARAMS_BASE, paramBytes);

  // ---- before/after snapshots for the unpacked-buffer diff ----
  const codeBefore = snapshot(mem, CODE_BASE, Number(codeSize));
  const heapBefore = snapshot(mem, HEAP_BASE, 0x80000);

  // ---- entry conventions ----
  const entryVa = CODE_BASE + BigInt(entryOffset);
  let result;
  if (os === "win") {
    if (convention === "threadproc") {
      result = cpu.callFunction(entryVa, [PARAMS_BASE]);
    } else if (convention === "function") {
      result = cpu.callFunction(entryVa, [PARAMS_BASE, BigInt(paramBytes.length), 0n, 0n]);
    } else {
      result = cpu.callFunction(entryVa, []);
    }
  } else if (convention === "argv") {
    // _start layout: [argc][argv…][0][envp…][0][auxv…]; callFunction's frame
    // sits 48 bytes below argc and the trampoline pops it before jumping.
    let strVa = ARGV_STRINGS;
    const argv = opts.argv ?? [`/kfsample/${name}`];
    const envp = opts.envp ?? ["PATH=/usr/bin:/bin"];
    const putStr = (s) => {
      const b = new TextEncoder().encode(s + "\0");
      mem.write(strVa, b);
      const va = strVa;
      strVa += BigInt((b.length + 15) & ~15);
      return va;
    };
    const argvPtrs = argv.map(putStr);
    const envpPtrs = envp.map(putStr);
    let p = ARGC_VA;
    const wq = (v) => { mem.w64(p, u64(v)); p += 8n; };
    wq(argv.length); // argc
    for (const va of argvPtrs) wq(va);
    wq(0n);
    for (const va of envpPtrs) wq(va);
    wq(0n);
    wq(9n); wq(entryVa); // AT_ENTRY
    wq(6n); wq(4096n); // AT_PAGESZ
    wq(0n); wq(0n); // AT_NULL
    // trampoline: add rsp, 48 ; jmp entry (undo callFunction's frame)
    const tramp = new Uint8Array([
      0x48, 0x83, 0xc4, 0x30,
      0x48, 0xb8, ...le64(entryVa),
      0xff, 0xe0,
    ]);
    mem.write(TRAMP_VA, tramp);
    cpu.regs.rsp = ARGC_VA;
    result = cpu.callFunction(TRAMP_VA, []);
  } else if (convention === "function") {
    cpu.regs.rdi = PARAMS_BASE;
    cpu.regs.rsi = BigInt(paramBytes.length);
    result = cpu.callFunction(entryVa, []);
  } else {
    result = cpu.callFunction(entryVa, []);
  }

  // ---- unpacked-buffer diffs ----
  const codeAfter = snapshot(mem, CODE_BASE, Number(codeSize));
  const heapAfter = snapshot(mem, HEAP_BASE, 0x80000);
  const codeDiff = diffBuffers(codeBefore, codeAfter);
  const heapDiff = diffBuffers(heapBefore, heapAfter);

  // ---- status mapping ----
  const stopReason = model.stopReason ?? null;
  let status = result.status;
  if (status === "halted") {
    status = stopReason ? "stopped" : (model.exited ? "ok" : "stopped");
  }
  const stalled = status === "timeout" || status === "debug-stop" || status === "breakpoint";

  // ---- YARA (built-in + optional user source) ----
  let yara = null;
  if (opts.yara !== false) {
    const matches = [];
    const errors = [];
    const builtin = await safeAsync(() => scanWithYaraX(bytes, opts.yaraRules ?? SHELLCODE_YARA));
    if (builtin) { matches.push(...normalizeYaraMatches(builtin)); errors.push(...(builtin.errors ?? [])); }
    if (opts.extraYara && String(opts.extraYara).trim()) {
      const custom = await safeAsync(() => scanWithYaraX(bytes, opts.extraYara, { throwOnError: true }));
      if (custom) matches.push(...normalizeYaraMatches(custom));
    }
    yara = { matches, errors };
  }

  // ---- traces ----
  const traceCtx = { mem, moduleBase: CODE_BASE, base: CODE_BASE, moduleSize: Number(codeSize), imageSize: Number(codeSize), name };
  const { trace, traceText, traceAbridgedText, traceAbridgedCount, traceTotalCount } = os === "win"
    ? formatPeTrace(events, traceCtx)
    : formatElfTrace(events, traceCtx);

  const byName = new Map();
  for (const e of events) {
    const rec = byName.get(e.name) ?? { count: 0, args: [] };
    rec.count++;
    if (rec.args.length < 2) {
      rec.args.push({ args: (e.args ?? []).slice(0, 4).map((a) => `0x${u64(a).toString(16)}`), ret: e.ret !== undefined ? `0x${u64(e.ret).toString(16)}` : null });
    }
    byName.set(e.name, rec);
  }

  const shellcodeReport = {
    ...facts,
    unpackedBytes: codeDiff.changedBytes + heapDiff.changedBytes,
  };

  return {
    meta: {
      kind: "shellcode", os, convention, entryOffset, size: bytes.length, at: new Date().toISOString(),
      name, engine: opts.backendName ?? (cpu.constructor?.name ?? "JsInterpreter"),
    },
    load: {
      codeBase: `0x${CODE_BASE.toString(16)}`,
      codeSize: Number(codeSize),
      modules: os === "win"
        ? [
          { name: "sample.bin", base: `0x${CODE_BASE.toString(16)}` },
          { name: "ntdll.dll", base: `0x${NT_DLL_BASE.toString(16)}` },
          { name: "kernel32.dll", base: `0x${K32_DLL_BASE.toString(16)}` },
        ]
        : [{ name: "shellcode", base: `0x${CODE_BASE.toString(16)}` }],
    },
    static: staticFacts,
    shellcode: shellcodeReport,
    rules,
    yara,
    entry: {
      status,
      retval: result.retval !== undefined ? `0x${u64(result.retval).toString(16)}` : undefined,
      error: result.error ? String(result.error.message ?? result.error) : undefined,
      steps: (cpu.steps ?? 0),
      stopReason,
    },
    stall: stalled
      ? {
        status,
        rip: result.rip !== undefined ? `0x${u64(result.rip).toString(16)}` : (cpu.rip !== undefined ? `0x${u64(cpu.rip).toString(16)}` : null),
        steps: (cpu.steps ?? 0),
        lastEvents: events.slice(-10).map((e) => e.name),
      }
      : null,
    exited: model.exited,
    exitCode: model.exitCode,
    exitReason: model.exitReason ?? null,
    apiTrace: os === "win"
      ? { totalCalls: events.length, distinct: byName.size, byName: Object.fromEntries([...byName.entries()].slice(0, 256)) }
      : undefined,
    syscalls: os === "linux"
      ? {
        total: events.filter((e) => !e.name.startsWith("[")).length,
        byName: Object.fromEntries([...byName.entries()].filter(([k]) => !k.startsWith("[")).slice(0, 256)),
      }
      : undefined,
    artifacts: model.artifacts,
    unmodeled: [...model.unmodeled],
    unpacked: {
      base: `0x${CODE_BASE.toString(16)}`,
      size: Number(codeSize),
      changedBytes: codeDiff.changedBytes,
      ranges: codeDiff.ranges,
      buffer: codeAfter,
    },
    unpackedHeap: heapDiff.changedBytes
      ? {
        base: `0x${HEAP_BASE.toString(16)}`,
        size: 0x80000,
        changedBytes: heapDiff.changedBytes,
        ranges: heapDiff.ranges,
        buffer: heapAfter,
      }
      : null,
    trace,
    traceText,
    traceAbridgedText,
    traceAbridgedCount,
    traceTotalCount,
    events: events.slice(0, 2048),
  };
}

async function safeAsync(fn, fallback = null) {
  try { return await fn(); } catch { return fallback; }
}

function le64(v) {
  const out = [];
  let x = u64(v);
  for (let i = 0; i < 8; i++) { out.push(Number(x & 0xffn)); x >>= 8n; }
  return out;
}
