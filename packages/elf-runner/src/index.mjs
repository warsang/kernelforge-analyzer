/**
 * @kernelforge/elf-runner — userland ELF64 (x86-64) harness.
 *
 * Maps PT_LOAD segments, resolves imports (libc wrappers -> syscall
 * trampolines, common libc helpers -> native handlers), seeds an initial
 * process stack (argc/argv/envp/auxv) and runs the entry point on the JS
 * interpreter with a Tier-1 Linux syscall model.
 *
 * Not modeled: ld.so, threads, signal delivery, seccomp, namespaces.
 */

import { SparseMemory, JsInterpreter, M64, installUserlandCpu } from "@kernelforge/ntsim/src/index.mjs";
import {
  parseElf64, parseElfStatic, scanRules, extractStackStrings, detectApiHashes,
  scanWithYaraX, normalizeYaraMatches, ELF_USERLAND_RULES, ELF_USERLAND_YARA,
} from "@kernelforge/triage";
import { createLinuxModel, SYSCALLS } from "./linux.mjs";
import { formatElfTrace } from "./trace.mjs";

export { parseElf64, parseElfStatic } from "@kernelforge/triage";
export { createLinuxModel, SYSCALLS } from "./linux.mjs";

const STACK_TOP = 0x00007ffffff00000n;
const LIBC_BASE = 0x0000000050000000n;
const TRAMP_BASE = 0x0000000051000000n;
const PIE_BIAS = 0x0000000000400000n;

const M64MASK = M64;

/** libc function name -> syscall number (wrappers get a syscall trampoline). */
const LIBC_SYSCALLS = {
  read: 0, write: 1, open: 2, close: 3, stat: 4, fstat: 5, lstat: 6, lseek: 8,
  mmap: 9, mprotect: 10, munmap: 11, ioctl: 16, access: 21, pipe: 22, dup: 32, dup2: 33,
  nanosleep: 35, getpid: 39, socket: 41, connect: 42, accept: 43, sendto: 44, recvfrom: 45,
  send: 44, recv: 45, bind: 49, listen: 50, clone: 56, fork: 57, execve: 59, exit: 60,
  wait4: 61, kill: 62, uname: 63, fcntl: 72, getcwd: 79, chdir: 80, rename: 82, mkdir: 83,
  rmdir: 84, creat: 85, unlink: 87, readlink: 89, chmod: 90, gettimeofday: 96, ptrace: 101,
  getuid: 102, getgid: 104, geteuid: 107, getppid: 110, statfs: 137, arch_prctl: 158,
  gettid: 186, getdents64: 217, openat: 257, newfstatat: 262, unlinkat: 263, renameat: 264,
  prlimit64: 302, getrandom: 318, execveat: 322, poll: 7, select: 23, madvise: 28,
  socketpair: 53, shutdown: 48, getsockopt: 55, setsockopt: 54, futex: 202, kill_: 62,
  epoll_create1: 291, epoll_ctl: 233, epoll_wait: 232, sched_yield: 24, getdents: 78,
  clock_gettime: 228, getrlimit: 97, sysinfo: 99, sigaltstack: 131, mremap: 25,
};

const safe = (fn, fallback = null) => {
  try { return fn(); } catch { return fallback; }
};

const safeAsync = async (fn, fallback = null) => {
  try { return await fn(); } catch { return fallback; }
};

/**
 * @param {Uint8Array} imageBytes ELF64 x86-64 (ET_EXEC or ET_DYN)
 * @param {object} [opts]
 *   name      sample name (default "sample.elf")
 *   maxSteps  instruction budget (default 4M)
 *   argv      guest argv (default ["/kfsample/<name>"])
 *   envp      guest envp (default ["PATH=/usr/bin:/bin"])
 *   bias      override load bias for ET_DYN
 * @returns {Promise<object>} report
 */
/**
 * Run an ELF64 x86-64 image, retrying once on the hybrid (JS + Unicorn) backend
 * when the deterministic interpreter refuses an instruction (x87/SSE gap).
 * Mirrors the PE harness: "it just works" for real-world binaries.
 */
export async function runElf(imageBytes, opts = {}) {
  const r = await runElfOnce(imageBytes, opts);
  if (opts.autoHybridFallback === false) return r;
  if (opts.makeBackend || opts.cpu) return r; // caller chose a backend
  if (opts.backendName && opts.backendName !== "js") return r;
  const err = `${r.entry?.error ?? ""} ${r.bugcheck ?? ""}`;
  if (!/unimplemented|unsupported|0f opcode|x87/i.test(err)) return r;
  try {
    const { HybridCpuBackend } = await import("@kernelforge/ntsim-unicorn/src/hybrid.mjs");
    const retried = await runElfOnce(imageBytes, {
      ...opts,
      backendName: "hybrid",
      makeBackend: async () => HybridCpuBackend.create(null),
    });
    if (retried.entry?.status === "ok" || !/unimplemented|unicorn engine error/i.test(retried.entry?.error ?? "")) {
      retried.meta.fallbackFrom = "js";
      return retried;
    }
  } catch { /* unicorn unavailable in this environment — keep the JS report */ }
  return r;
}

async function runElfOnce(imageBytes, opts = {}) {
  const bytes = imageBytes instanceof Uint8Array ? imageBytes : Uint8Array.from(imageBytes);
  const name = opts.name ?? "sample.elf";
  const elf = parseElf64(bytes);
  if (elf.type === 1) {
    throw new Error("ET_REL relocatable object (kernel module) — use the Linux Driver Analyzer (.ko)");
  }
  const staticFacts = safe(() => {
    const st = parseElfStatic(bytes, { strings: true, maxStrings: 256 });
    st.stackStrings = extractStackStrings(bytes, { minLength: 6, maxStrings: 64 }).strings.slice(0, 32);
    st.apiHashes = detectApiHashes(bytes, { maxHits: 64 }).hits;
    return st;
  });
  const rules = safe(() => scanRules(bytes, opts.rules ?? ELF_USERLAND_RULES, { maxMatchesPerRule: 8 }));
  const bias = elf.type === 3 ? (opts.bias ?? PIE_BIAS) : 0n;

  const mem = new SparseMemory();
  let cpu;
  if (typeof opts.makeBackend === "function") cpu = await opts.makeBackend(mem);
  else if (opts.cpu) cpu = opts.cpu;
  else cpu = new JsInterpreter(mem);
  if (typeof cpu.attachMemory === "function") {
    try { cpu.attachMemory(mem); } catch { /* already attached */ }
  }
  installUserlandCpu(cpu);
  const maxSteps = opts.maxSteps ?? 4_000_000;
  const origRun = cpu.run.bind(cpu);
  cpu.run = (n) => origRun(Math.min(opts.maxSteps ?? n ?? maxSteps, maxSteps));

  // ---- map PT_LOAD ----
  for (const p of elf.loads) {
    const dst = bias + p.vaddr;
    const fileSize = Number(p.filesz);
    if (fileSize > 0) {
      mem.write(dst, bytes.subarray(Number(p.offset), Number(p.offset) + fileSize));
    }
    const memSize = Number(p.memsz);
    if (memSize > fileSize) {
      mem.write(dst + BigInt(fileSize), new Uint8Array(memSize - fileSize));
    }
  }

  // ---- guest heap ----
  let heapPtr = 0x0000000004000000n;
  const alloc = (size) => {
    const va = heapPtr;
    heapPtr += BigInt(Math.max(16, (Number(size) + 15) & ~15));
    return va;
  };
  const model = createLinuxModel({ mem, cpu, alloc });

  // ---- libc resolution: native handlers + syscall trampolines ----
  const nativeByVa = new Map();
  const nativeByName = new Map();
  let nativeCount = 0;
  let trampCount = 0;
  const resolveLibc = (fnName) => {
    const fn = String(fnName);
    if (LIBC_SYSCALLS[fn] !== undefined) {
      const nr = LIBC_SYSCALLS[fn];
      const va = TRAMP_BASE + BigInt(trampCount++) * 0x20n;
      // mov r10, rcx ; mov rax, nr ; syscall ; ret
      const code = new Uint8Array([
        0x49, 0x89, 0xCA,
        0x48, 0xC7, 0xC0, nr & 0xff, (nr >> 8) & 0xff, (nr >> 16) & 0xff, (nr >> 24) & 0xff,
        0x0F, 0x05, 0xC3,
      ]);
      mem.write(va, code);
      return va;
    }
    if (nativeByName.has(fn)) return nativeByName.get(fn);
    const va = LIBC_BASE + BigInt(nativeCount++) * 0x10n;
    nativeByName.set(fn, va);
    nativeByVa.set(va, fn);
    return va;
  };
  for (const imp of elf.imports) {
    if (!imp.name || !imp.got) continue;
    const va = resolveLibc(imp.name);
    safe(() => mem.w64(bias + imp.offset, va));
  }

  // ---- initial stack: argc/argv/envp/auxv ----
  const argv = opts.argv ?? [`/kfsample/${name}`];
  const envp = opts.envp ?? ["PATH=/usr/bin:/bin"];
  let sp = STACK_TOP;
  const pushStr = (s) => {
    const buf = new TextEncoder().encode(s + "\0");
    sp -= BigInt(buf.length);
    mem.write(sp, buf);
    return sp;
  };
  const argvPtrs = argv.map(pushStr);
  const envpPtrs = envp.map(pushStr);
  const argv0 = argvPtrs[0];
  // auxv (16-byte entries: type, value)
  const auxv = [
    [9n, bias + elf.entry], // AT_ENTRY
    [3n, bias + (elf.phdrs[0] ? 0x40n : 0x40n)], // AT_PHDR (header is at offset 0x40)
    [4n, 56n], // AT_PHENT
    [5n, BigInt(elf.phdrs.length)], // AT_PHNUM
    [6n, 4096n], // AT_PAGESZ
    [7n, 0n], // AT_BASE
    [31n, argv0], // AT_EXECFN
    [0n, 0n], // AT_NULL
  ];
  sp &= ~0xfn;
  sp -= BigInt((auxv.length) * 16);
  auxv.forEach(([t, v], i) => {
    mem.w64(sp + BigInt(i * 16), t);
    mem.w64(sp + BigInt(i * 16 + 8), v);
  });
  sp -= 8n;
  mem.w64(sp, 0n); // envp NULL terminator
  for (let i = envpPtrs.length - 1; i >= 0; i--) { sp -= 8n; mem.w64(sp, envpPtrs[i]); }
  sp -= 8n;
  mem.w64(sp, 0n); // argv NULL terminator
  for (let i = argvPtrs.length - 1; i >= 0; i--) { sp -= 8n; mem.w64(sp, argvPtrs[i]); }
  sp -= 8n;
  mem.w64(sp, BigInt(argv.length));
  cpu.regs.rsp = sp;
  cpu.regs.rdx = 0n; // rtld_fini

  // ---- libc native handlers ----
  const nativeHandlers = {
    malloc: (_m, [size]) => alloc(size),
    calloc: (_m, [n, size]) => {
      const total = Number(u64(n)) * Number(u64(size)) || 16;
      const va = alloc(total);
      mem.write(va, new Uint8Array(total));
      return va;
    },
    realloc: (_m, [_p, size]) => alloc(size),
    free: () => 0n,
    memcpy: (_m, [dst, src, n]) => {
      safe(() => mem.write(u64(dst), Uint8Array.from(mem.read(u64(src), Math.min(Number(u64(n)), 1 << 16)))));
      return u64(dst);
    },
    memmove: (_m, [dst, src, n]) => nativeHandlers.memcpy(null, [dst, src, n]),
    memset: (_m, [dst, val, n]) => {
      const len = Math.min(Number(u64(n)), 1 << 20);
      mem.write(u64(dst), new Uint8Array(len).fill(Number(u64(val)) & 0xff));
      return u64(dst);
    },
    memcmp: () => 0n,
    strlen: (_m, [s]) => {
      let n = 0;
      while (n < 4096) { let b; try { b = mem.u8(u64(s) + BigInt(n)); } catch { break; } if (b === 0) break; n++; }
      return BigInt(n);
    },
    strcmp: () => 0n,
    strncmp: () => 0n,
    strcpy: (_m, [dst, src]) => nativeHandlers.memcpy(null, [dst, src, nativeHandlers.strlen(null, [src])]),
    strncpy: (_m, [dst, src, n]) => nativeHandlers.memcpy(null, [dst, src, n]),
    strcat: () => 0n,
    strstr: () => 0n,
    strchr: () => 0n,
    strdup: (_m, [s]) => {
      const n = Number(nativeHandlers.strlen(null, [s]));
      const va = alloc(n + 1);
      nativeHandlers.memcpy(null, [va, s, BigInt(n)]);
      return va;
    },
    atoi: () => 0n,
    strtol: () => 0n,
    printf: (_m, [fmt]) => {
      const s = safe(() => readCStringLocal(mem, fmt), "");
      model.artifacts.stdout.push({ text: s });
      return BigInt(s.length);
    },
    puts: (_m, [s]) => {
      model.artifacts.stdout.push({ text: safe(() => readCStringLocal(mem, s), "") });
      return 0n;
    },
    putchar: () => 0n,
    fwrite: () => 0n,
    fflush: () => 0n,
    __errno_location: () => alloc(8),
    __stack_chk_fail: () => 0n,
    __cxa_atexit: () => 0n,
    __assert_fail: () => 0n,
    abort: () => { model.exited = true; cpu.halted = true; return undefined; },
    _exit: (_m, [code]) => {
      model.exited = true;
      model.exitCode = Number(i64Local(code));
      cpu.halted = true;
      return undefined;
    },
    exit: (_m, [code]) => {
      model.exited = true;
      model.exitCode = Number(i64Local(code));
      cpu.halted = true;
      return undefined;
    },
    __libc_start_main: (_m, [mainVa, argcVa, argvVa, _init, _fini, _rtld, stackEnd]) => {
      // Run the real main(argc, argv, envp) so the sample's logic executes.
      const argv2 = argvVa || 0n;
      void argcVa; void stackEnd;
      const envpVa = (() => {
        let p = argv2;
        for (let i = 0; i < 64; i++) {
          let v;
          try { v = mem.u64(p); } catch { return 0n; }
          p += 8n;
          if (v === 0n) return p;
        }
        return 0n;
      })();
      const r = safe(() => cpu.callFunction(u64(mainVa), [BigInt(argv.length), argv2, envpVa]), null);
      if (r?.retval !== undefined) model.exitCode = Number(i64Local(r.retval));
      model.exited = true;
      cpu.halted = true;
      return undefined;
    },
  };
  const libcHook = (rip) => {
    const fn = nativeByVa.get(rip);
    if (!fn) return false;
    const rsp = cpu.regs.rsp;
    const args = [cpu.regs.rdi, cpu.regs.rsi, cpu.regs.rdx, cpu.regs.rcx, cpu.regs.r8, cpu.regs.r9];
    const retAddr = safe(() => mem.u64(rsp), 0n);
    const handler = nativeHandlers[fn];
    let ret;
    if (!handler) {
      model.unmodeled.add(`libc:${fn}`);
      ret = 0n;
    } else {
      ret = safe(() => handler(model, args), 0n);
    }
    model.events.push({ name: `libc:${fn}`, args: args.slice(0, 6).map((a) => u64(a)), ret: ret === undefined ? undefined : u64(ret), retAddr });
    if (ret !== undefined) cpu.regs.rax = BigInt.asUintN(64, ret);
    cpu.regs.rsp = (rsp + 8n) & M64MASK;
    cpu.rip = retAddr;
    return true;
  };
  cpu.addCodeHook(libcHook, LIBC_BASE, LIBC_BASE + 0x10000n);

  cpu.onFastfail = () => { model.exited = true; return true; };

  // ---- syscalls ----
  cpu.onSyscall = (nr, args) => {
    const ret = model.dispatch(nr, args);
    // annotate the just-recorded event with the call site (rip already points
    // past the 2-byte syscall instruction) for the trace
    const ev = model.events[model.events.length - 1];
    if (ev && ev.retAddr === undefined && cpu.rip !== undefined) ev.retAddr = BigInt(cpu.rip);
    return ret;
  };

  // ---- YARA-X (built-in + optional user source, compiled separately) ----
  let yara = null;
  if (opts.yara !== false) {
    const matches = [];
    const errors = [];
    const builtin = await safeAsync(() => scanWithYaraX(bytes, opts.yaraRules ?? ELF_USERLAND_YARA));
    if (builtin) { matches.push(...normalizeYaraMatches(builtin)); errors.push(...(builtin.errors ?? [])); }
    if (opts.extraYara && String(opts.extraYara).trim()) {
      const custom = await safeAsync(() => scanWithYaraX(bytes, opts.extraYara, { throwOnError: true }));
      if (custom) matches.push(...normalizeYaraMatches(custom));
    }
    yara = { matches, errors };
  }

  // ---- run ----
  const stepsBefore = cpu.steps ?? 0;
  const entryVa = bias + elf.entry;
  const result = cpu.callFunction(entryVa, []);
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
  // A clean exit is `halted` from the CPU's perspective; surface it as ok.
  const status = result.status === "halted" && model.exited ? "ok" : result.status;
  const moduleBase = bias + elf.loads.reduce((a, p) => (p.vaddr < a ? p.vaddr : a), elf.loads[0].vaddr);
  const moduleEnd = elf.loads.reduce((a, p) => {
    const end = p.vaddr + p.memsz;
    return end > a ? end : a;
  }, 0n);
  const { trace, traceText, traceAbridgedText, traceAbridgedCount, traceTotalCount } = formatElfTrace(model.events, {
    mem, moduleBase, moduleSize: Number(moduleEnd - (moduleBase - bias)), name,
  });
  const stalled = status === "timeout" || status === "debug-stop";
  const output = model.artifacts.stdout.map((x) => x.text).join("").slice(0, 8192);

  return {
    meta: { kind: "userland-elf", size: bytes.length, at: new Date().toISOString(), name, engine: opts.backendName ?? (cpu.constructor?.name ?? "JsInterpreter") },
    load: {
      type: elf.typeName,
      isPie: elf.isPie,
      interp: elf.interp,
      base: `0x${bias.toString(16)}`,
      entry: `0x${entryVa.toString(16)}`,
      segments: elf.loads.map((p) => ({
        vaddr: `0x${(bias + p.vaddr).toString(16)}`,
        filesz: Number(p.filesz),
        memsz: Number(p.memsz),
        flags: p.flags,
      })),
      needed: elf.needed,
      imports: elf.importNames,
      rwxSegments: elf.rwxSegments,
      execStack: elf.execStack,
    },
    static: staticFacts ?? {
      format: "elf",
      type: elf.typeName,
      machine: elf.machineName,
      isPie: elf.isPie,
      importCount: elf.importNames.length,
    },
    rules,
    yara,
    entry: {
      status,
      retval: result.retval !== undefined ? `0x${BigInt.asUintN(64, result.retval).toString(16)}` : undefined,
      error: result.error ? String(result.error.message ?? result.error) : undefined,
      steps,
    },
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
    output,
    syscalls: {
      total: model.events.filter((e) => !e.name.startsWith("libc:")).length,
      byName: Object.fromEntries(
        [...byName.entries()].filter(([k]) => !k.startsWith("libc:")).slice(0, 256)),
    },
    libcCalls: Object.fromEntries([...byName.entries()].filter(([k]) => k.startsWith("libc:")).slice(0, 256)),
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

function readCStringLocal(mem, va, max = 512) {
  let s = "";
  for (let i = 0; i < max; i++) {
    const b = mem.u8(BigInt.asUintN(64, BigInt(va)) + BigInt(i));
    if (b === 0) break;
    s += String.fromCharCode(b);
  }
  return s;
}

const u64 = (v) => BigInt.asUintN(64, BigInt(v ?? 0));
const i64Local = (v) => BigInt.asIntN(64, BigInt(v ?? 0));
