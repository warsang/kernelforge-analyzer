/**
 * win32.mjs — Tier-1 Win32 API model for the userland PE harness.
 *
 * Every handler records what the sample *tried to do* (path, registry key,
 * host, command line, ...) into bounded artifact lists, then returns a
 * plausible success value so execution continues. This is the speakeasy
 * philosophy: model behavior, not the OS.
 *
 * Handlers are deliberately permissive (fail-open): the goal is to keep the
 * sample running long enough to observe intent, not to emulate Windows.
 */

const M64 = (1n << 64n) - 1n;
const u64 = (v) => BigInt.asUintN(64, BigInt(v ?? 0));

export function readCString(mem, va, max = 1024) {
  const out = [];
  for (let i = 0; i < max; i++) {
    let b;
    try { b = mem.u8(va + BigInt(i)); } catch { break; }
    if (b === 0) break;
    out.push(b);
  }
  return String.fromCharCode(...out);
}

export function writeCString(mem, va, s) {
  const bytes = new Uint8Array(s.length + 1);
  for (let i = 0; i < s.length; i++) bytes[i] = s.charCodeAt(i) & 0xff;
  mem.write(va, bytes);
}

export function readUtf16(mem, va, max = 1024) {
  let s = "";
  for (let i = 0; i < max; i++) {
    let lo;
    try { lo = mem.u8(va + BigInt(i * 2)); } catch { break; }
    if (lo === 0) break;
    s += String.fromCharCode(lo);
  }
  return s;
}

export function writeUtf16(mem, va, s) {
  const bytes = new Uint8Array(s.length * 2 + 2);
  for (let i = 0; i < s.length; i++) {
    bytes[i * 2] = s.charCodeAt(i) & 0xff;
    bytes[i * 2 + 1] = (s.charCodeAt(i) >> 8) & 0xff;
  }
  mem.write(va, bytes);
}

const FILE_SHARE_ALL = 0x7;
const GENERIC_WRITE = 0x40000000;
const CREATE_ALWAYS = 2;
const CREATE_NEW = 1;

/**
 * Create the API model.
 * @param {{mem:object, cpu:object, alloc:(size:number, opts?:object)=>bigint, onApi?:(name:string,args:bigint[],ret:bigint|undefined)=>void}} env
 */
export function createWin32Model(env) {
  const { mem, cpu, alloc } = env;
  const events = [];
  const MAX_EVENTS = 4096;
  const MAX_ARTIFACTS = 256;
  const artifacts = {
    files: [],
    registry: [],
    network: [],
    processes: [],
    commands: [],
    modules: [],
    mutexes: [],
    debugStrings: [],
    stdout: [],
  };
  const handles = new Map();
  let nextHandle = 0x100n;
  let lastError = 0;
  let tick = 0x1000;
  let pid = 4242n;
  const push = (list, item) => { if (list.length < MAX_ARTIFACTS) list.push(item); };

  const model = {
    artifacts,
    events,
    get lastError() { return lastError; },
    unmodeled: new Set(),
    exited: false,
    exitCode: null,
  };

  const record = (name, args, ret, meta = null) => {
    if (events.length < MAX_EVENTS) {
      events.push({
        name,
        args: args.slice(0, 8).map((a) => u64(a)),
        ret: ret === undefined ? undefined : u64(ret),
        retAddr: meta?.retAddr !== undefined ? u64(meta.retAddr) : undefined,
      });
    }
    try { env.onApi?.(name, args, ret); } catch { /* listener error */ }
  };

  const newHandle = (obj) => {
    const h = nextHandle;
    nextHandle += 4n;
    handles.set(h, obj);
    return h;
  };
  const getHandle = (h) => handles.get(u64(h));

  const safe = (fn, fallback = null) => {
    try { return fn(); } catch { return fallback; }
  };
  const safeU64 = (fn) => safe(fn, 0n);
  const readVarargs = (listVa, count = 12) => {
    const out = [];
    if (!listVa || u64(listVa) === 0n) return out;
    for (let i = 0; i < count; i++) {
      const v = safe(() => mem.u64(u64(listVa) + BigInt(i * 8)), null);
      if (v === null) break;
      out.push(v);
    }
    return out;
  };
  const cstrLocal = (m, va) => {
    try { return readCString(m, u64(va)); } catch { return ""; }
  };
  const hexFn = (v) => `0x${BigInt(v).toString(16)}`;
  /** Minimal printf formatter: %s %S %ls %d %i %u %x %X %p %c %% (width ignored). */
  const formatPrintf = (fmt, args, startIndex = 0) => {
    let out = "";
    let ai = startIndex;
    for (let i = 0; i < fmt.length; i++) {
      const ch = fmt[i];
      if (ch !== "%") { out += ch; continue; }
      const spec = fmt[i + 1];
      if (spec === undefined) break;
      i++;
      switch (spec) {
        case "%": out += "%"; break;
        case "s": {
          const a = args[ai++];
          out += a !== undefined ? cstrLocal(mem, a) : "(null)";
          break;
        }
        case "S": {
          const a = args[ai++];
          out += a !== undefined ? wstr(a) : "(null)";
          break;
        }
        case "l": {
          const sub = fmt[i + 1];
          if (sub === "s") { i++; const a = args[ai++]; out += a !== undefined ? wstr(a) : "(null)"; }
          else if (sub === "d" || sub === "i") { i++; out += String(BigInt.asIntN(64, BigInt(args[ai++] ?? 0n))); }
          else if (sub === "u") { i++; out += BigInt.asUintN(64, BigInt(args[ai++] ?? 0n)).toString(); }
          else if (sub === "x" || sub === "X") { i++; out += BigInt.asUintN(64, BigInt(args[ai++] ?? 0n)).toString(16); }
          else out += "%l";
          break;
        }
        case "d": case "i": out += String(Number(BigInt.asIntN(32, BigInt(args[ai++] ?? 0n)))); break;
        case "u": out += String(Number(BigInt.asUintN(32, BigInt(args[ai++] ?? 0n)))); break;
        case "x": out += Number(BigInt.asUintN(32, BigInt(args[ai++] ?? 0n))).toString(16); break;
        case "X": out += Number(BigInt.asUintN(32, BigInt(args[ai++] ?? 0n))).toString(16).toUpperCase(); break;
        case "p": out += `0x${BigInt.asUintN(64, BigInt(args[ai++] ?? 0n)).toString(16)}`; break;
        case "c": out += String.fromCharCode(Number(BigInt.asUintN(8, BigInt(args[ai++] ?? 0n)))); break;
        default: out += `%${spec}`;
      }
      if (out.length > 4096) break;
    }
    return out.slice(0, 4096);
  };

  const str = (va) => {
    try { return readCString(mem, u64(va)); } catch { return ""; }
  };
  const wstr = (va) => {
    try { return readUtf16(mem, u64(va)); } catch { return ""; }
  };

  // deterministic pseudo-random-ish allocator for guest buffers
  let bump = 0n;
  const guestAlloc = (size, { zero = true } = {}) => {
    const sz = Math.max(16, (Number(size) + 15) & ~15);
    const va = alloc(sz);
    if (zero) mem.write(va, new Uint8Array(sz));
    return va;
  };

  // ---- CRT data exports ----------------------------------------------------
  // msvcrt exports a handful of *variables* (not functions) that legacy CRT
  // startups dereference directly, e.g. calc.exe does:
  //   mov rax, [IAT _wcmdln] ; mov rcx, [rax] ; test rcx, rcx ; jz exit(0xFF)
  // The runner maps those imports to real data cells (see index.mjs); these
  // helpers keep the cells in sync when a modeled API mutates the variable.
  const setDataCell = (key, value) => {
    const cell = model.dataCells?.get(key);
    if (cell !== undefined) mem.w64(cell, u64(value));
  };

  /** Fill the caller's argc/argv/wargv/envp and the msvcrt command-line globals. */
  const fillMainArgs = (argcOut, argvOut, wargvOut, envpOut) => {
    const cmd = str(model.commandLineA ?? 0n) || "C:\\kfsample\\sample.exe";
    const parts = cmd.split(/\s+/).filter(Boolean);
    const argc = Math.max(1, parts.length);
    const build = (wide) => {
      const arr = guestAlloc(BigInt((argc + 1) * 8));
      for (let i = 0; i < argc; i++) {
        const s = parts[i] ?? cmd;
        const va = wide ? guestAlloc(BigInt(s.length * 2 + 2)) : guestAlloc(BigInt(s.length + 1));
        if (wide) writeUtf16(mem, va, s); else writeCString(mem, va, s);
        mem.w64(arr + BigInt(i * 8), va);
      }
      mem.w64(arr + BigInt(argc * 8), 0n);
      return arr;
    };
    const argv = build(false);
    const wargv = build(true);
    const envp = guestAlloc(8);
    if (u64(argcOut)) mem.w32(u64(argcOut), argc);
    if (u64(argvOut)) mem.w64(u64(argvOut), argv);
    if (u64(wargvOut)) mem.w64(u64(wargvOut), wargv);
    if (u64(envpOut)) mem.w64(u64(envpOut), envp);
    setDataCell("wcmdln", model.commandLineW ?? 0n);
    setDataCell("acmdln", model.commandLineA ?? 0n);
    setDataCell("fmode", 0n);
    setDataCell("commode", 0x200n);
    if (model.argcPtr) mem.w32(model.argcPtr, argc);
    if (model.argvPtr) { mem.w64(model.argvPtr, argv); mem.w64(model.argvPtr + 8n, envp); }
    if (model.envBlockPtr) mem.w64(model.envBlockPtr, envp);
    return 0n;
  };

  const handlers = {
    // ---- memory ----
    VirtualAlloc: (_c, [addr, size, type, protect]) => {
      const va = addr && u64(addr) !== 0n ? u64(addr) : guestAlloc(size);
      const n = Math.min(Number(size) || 0x1000, 1 << 20);
      mem.write(va, new Uint8Array(n));
      return va;
    },
    VirtualProtect: () => 1n,
    VirtualFree: () => 1n,
    VirtualQuery: (_c, [addr, buf, len]) => {
      if (u64(buf) && u64(len) >= 48n) {
        mem.w64(u64(buf), u64(addr));
        mem.w64(u64(buf) + 8n, 0n);
        mem.w32(u64(buf) + 16n, 0x1000);
        mem.w32(u64(buf) + 20n, 0x04); // MEM_COMMIT
        mem.w32(u64(buf) + 24n, 0x40); // PAGE_EXECUTE_READWRITE
      }
      return 48n;
    },
    // ---- heap ----
    HeapCreate: () => newHandle({ kind: "heap" }),
    HeapAlloc: (_c, [_h, _flags, size]) => guestAlloc(size),
    HeapFree: () => 1n,
    HeapSetInformation: () => 1n,
    GlobalAlloc: (_c, [_flags, size]) => guestAlloc(size),
    GlobalFree: () => 0n,
    LocalAlloc: (_c, [_flags, size]) => guestAlloc(size),
    LocalFree: () => 0n,
    // ---- modules ----
    GetModuleHandleA: () => model.mainModule,
    GetModuleHandleW: () => model.mainModule,
    GetModuleHandleExA: (_c, [_flags, _name, out]) => {
      if (u64(out)) mem.w64(u64(out), model.mainModule);
      return 1n;
    },
    GetModuleHandleExW: (_c, [_flags, _name, out]) => {
      if (u64(out)) mem.w64(u64(out), model.mainModule);
      return 1n;
    },
    DisableThreadLibraryCalls: () => 1n,
    LoadLibraryA: (_c, [name]) => {
      const path = str(name);
      push(artifacts.modules, { action: "load", name: path });
      return newHandle({ kind: "module", name: path });
    },
    LoadLibraryW: (_c, [name]) => {
      const path = wstr(name);
      push(artifacts.modules, { action: "load", name: path });
      return newHandle({ kind: "module", name: path });
    },
    LoadLibraryExA: (_c, [name]) => {
      const path = str(name);
      push(artifacts.modules, { action: "load", name: path });
      return newHandle({ kind: "module", name: path });
    },
    GetProcAddress: (_c, [_h, name]) => {
      const fn = str(name);
      return model.resolveProc ? model.resolveProc(fn) : 0n;
    },
    FreeLibrary: () => 1n,
    FreeLibraryAndExitThread: () => {
      model.exited = true;
      model.exitReason = "FreeLibraryAndExitThread";
      cpu.halted = true;
      return undefined;
    },
    GetModuleFileNameA: (_c, [_h, buf, size]) => {
      const path = "C:\\kfsample\\sample.exe";
      if (u64(buf)) writeCString(mem, u64(buf), path.slice(0, Number(size) - 1));
      return BigInt(path.length);
    },
    GetModuleFileNameW: (_c, [_h, buf, size]) => {
      const path = "C:\\kfsample\\sample.exe";
      if (u64(buf)) writeUtf16(mem, u64(buf), path.slice(0, Number(size) - 1));
      return BigInt(path.length);
    },
    // ---- files ----
    CreateFileA: (_c, [pathVa, access, _share, _sa, disposition]) => {
      const path = str(pathVa);
      const accessN = Number(u64(access));
      const disp = Number(u64(disposition));
      push(artifacts.files, { action: disp === CREATE_ALWAYS || disp === CREATE_NEW ? "create" : "open", path, write: (accessN & 0x40000000) !== 0 });
      return newHandle({ kind: "file", path, write: (accessN & GENERIC_WRITE) !== 0, data: new Uint8Array(0) });
    },
    CreateFileW: (_c, [pathVa, access, _share, _sa, disposition]) => {
      const path = wstr(pathVa);
      const accessN = Number(u64(access));
      const disp = Number(u64(disposition));
      push(artifacts.files, { action: disp === CREATE_ALWAYS || disp === CREATE_NEW ? "create" : "open", path, write: (accessN & 0x40000000) !== 0 });
      return newHandle({ kind: "file", path, write: (accessN & GENERIC_WRITE) !== 0, data: new Uint8Array(0) });
    },
    ReadFile: (_c, [h, buf, size, readPtr]) => {
      const f = getHandle(h);
      const n = Math.min(Number(size) || 0, 4096);
      if (u64(buf)) mem.write(u64(buf), new Uint8Array(n));
      if (u64(readPtr)) mem.w32(u64(readPtr), n);
      if (f) push(artifacts.files, { action: "read", path: f.path, bytes: n });
      return 1n;
    },
    WriteFile: (_c, [h, buf, size, writtenPtr]) => {
      const f = getHandle(h);
      const n = Math.min(Number(size) || 0, 1 << 20);
      let data = new Uint8Array(0);
      try { data = Uint8Array.from(mem.read(u64(buf), n)); } catch { /* unreadable */ }
      if (u64(writtenPtr)) mem.w32(u64(writtenPtr), n);
      if (f?.kind === "file") {
        f.data = Uint8Array.from([...f.data, ...data]).slice(0, 1 << 20);
        push(artifacts.files, { action: "write", path: f.path, bytes: n });
      } else {
        push(artifacts.files, { action: "write", path: "<handle>", bytes: n });
      }
      return 1n;
    },
    CloseHandle: () => 1n,
    DeleteFileA: (_c, [pathVa]) => {
      push(artifacts.files, { action: "delete", path: str(pathVa) });
      return 1n;
    },
    DeleteFileW: (_c, [pathVa]) => {
      push(artifacts.files, { action: "delete", path: wstr(pathVa) });
      return 1n;
    },
    CopyFileA: (_c, [from, to]) => {
      push(artifacts.files, { action: "copy", path: str(to), from: str(from) });
      return 1n;
    },
    MoveFileA: (_c, [from, to]) => {
      push(artifacts.files, { action: "move", path: str(to), from: str(from) });
      return 1n;
    },
    CreateDirectoryA: (_c, [pathVa]) => {
      push(artifacts.files, { action: "mkdir", path: str(pathVa) });
      return 1n;
    },
    GetFileSize: () => 0x1000n,
    SetFilePointer: () => 0n,
    FindFirstFileA: () => M64, // INVALID_HANDLE_VALUE
    FindFirstFileW: () => M64,
    FindNextFileA: () => 0n,
    FindClose: () => 1n,
    GetTempPathA: (_c, [_n, buf]) => {
      const p = "C:\\Users\\kf\\AppData\\Local\\Temp\\";
      if (u64(buf)) writeCString(mem, u64(buf), p);
      return BigInt(p.length);
    },
    GetTempPathW: (_c, [_n, buf]) => {
      const p = "C:\\Users\\kf\\AppData\\Local\\Temp\\";
      if (u64(buf)) writeUtf16(mem, u64(buf), p);
      return BigInt(p.length);
    },
    GetSystemDirectoryA: (_c, [buf]) => {
      const p = "C:\\Windows\\System32";
      if (u64(buf)) writeCString(mem, u64(buf), p);
      return BigInt(p.length);
    },
    GetWindowsDirectoryA: (_c, [buf]) => {
      const p = "C:\\Windows";
      if (u64(buf)) writeCString(mem, u64(buf), p);
      return BigInt(p.length);
    },
    // ---- registry ----
    RegOpenKeyExA: (_c, [hive, subkey, _opts, _sam, out]) => {
      const path = str(subkey);
      push(artifacts.registry, { action: "open", path: `${registryRoot(hive)}\\${path}` });
      const h = newHandle({ kind: "reg", path });
      if (u64(out)) mem.w64(u64(out), h);
      return 0n;
    },
    RegOpenKeyExW: (_c, [hive, subkey, _opts, _sam, out]) => {
      const path = wstr(subkey);
      push(artifacts.registry, { action: "open", path: `${registryRoot(hive)}\\${path}` });
      const h = newHandle({ kind: "reg", path });
      if (u64(out)) mem.w64(u64(out), h);
      return 0n;
    },
    RegCreateKeyExA: (_c, [hive, subkey, _res, _class, _opts, _sam, _sa, out, disp]) => {
      const path = str(subkey);
      push(artifacts.registry, { action: "create", path: `${registryRoot(hive)}\\${path}` });
      const h = newHandle({ kind: "reg", path });
      if (u64(out)) mem.w64(u64(out), h);
      if (u64(disp)) mem.w32(u64(disp), 1);
      return 0n;
    },
    RegCreateKeyExW: (_c, [hive, subkey, _res, _class, _opts, _sam, _sa, out, disp]) => {
      const path = wstr(subkey);
      push(artifacts.registry, { action: "create", path: `${registryRoot(hive)}\\${path}` });
      const h = newHandle({ kind: "reg", path });
      if (u64(out)) mem.w64(u64(out), h);
      if (u64(disp)) mem.w32(u64(disp), 1);
      return 0n;
    },
    RegSetValueExA: (_c, [h, nameVa, _res, type, dataVa, size]) => {
      const key = getHandle(h);
      const name = str(nameVa);
      const n = Math.min(Number(size) || 0, 256);
      let data = "";
      try { data = readCString(mem, u64(dataVa), n); } catch { /* unreadable */ }
      push(artifacts.registry, { action: "set", path: key?.path ?? "<hive>", value: name, type: Number(u64(type)), data });
      return 0n;
    },
    RegSetValueExW: (_c, [h, nameVa, _res, type, dataVa, size]) => {
      const key = getHandle(h);
      const name = wstr(nameVa);
      const n = Math.min(Number(size) || 0, 256);
      let data = "";
      try { data = readUtf16(mem, u64(dataVa), Math.max(1, n / 2)); } catch { /* unreadable */ }
      push(artifacts.registry, { action: "set", path: key?.path ?? "<hive>", value: name, type: Number(u64(type)), data });
      return 0n;
    },
    RegQueryValueExA: () => 2n, // ERROR_FILE_NOT_FOUND
    RegQueryValueExW: () => 2n,
    // Subkey/value enumeration is not modeled: must report ERROR_NO_MORE_ITEMS
    // (259), not success — apps that enumerate in a do/while loop (idapyswitch)
    // otherwise spin to the step cap.
    RegEnumKeyExA: () => 259n,
    RegEnumKeyExW: () => 259n,
    RegEnumValueA: () => 259n,
    RegEnumValueW: () => 259n,
    RegDeleteValueA: (_c, [h, nameVa]) => {
      const key = getHandle(h);
      push(artifacts.registry, { action: "delete", path: key?.path ?? "<hive>", value: str(nameVa) });
      return 0n;
    },
    RegDeleteKeyA: (_c, [hive, subkey]) => {
      push(artifacts.registry, { action: "delete-key", path: `${registryRoot(hive)}\\${str(subkey)}` });
      return 0n;
    },
    RegCloseKey: () => 0n,
    // ---- processes / threads ----
    CreateProcessA: (_c, [app, cmd, _pa, _ta, _inh, _flags, _env, _dir, si, pi]) => createProcess(app, cmd, si, pi),
    CreateProcessW: (_c, [app, cmd, _pa, _ta, _inh, _flags, _env, _dir, si, pi]) => createProcess(app, cmd, si, pi),
    WinExec: (_c, [cmdVa, _show]) => {
      const cmd = str(cmdVa);
      push(artifacts.commands, { api: "WinExec", command: cmd });
      return 33n;
    },
    ShellExecuteA: (_c, [_hwnd, _op, file, _params, _dir, _show]) => {
      push(artifacts.commands, { api: "ShellExecuteA", command: str(file) });
      return 42n;
    },
    OpenProcess: () => newHandle({ kind: "process" }),
    TerminateProcess: (_c, [h, code]) => {
      const p = getHandle(h);
      push(artifacts.processes, { action: "terminate", handle: u64(h).toString(16), code: Number(u64(code)) });
      void p;
      return 1n;
    },
    ReadProcessMemory: () => 0n,
    WriteProcessMemory: () => 0n,
    CreateToolhelp32Snapshot: () => M64,
    Process32First: () => 0n,
    Process32Next: () => 0n,
    CreateThread: () => newHandle({ kind: "thread" }),
    CreateRemoteThread: (_c, [h, _sa, _start, _param, _flags, tid]) => {
      const p = getHandle(h);
      push(artifacts.processes, { action: "remote-thread", target: p ? u64(h).toString(16) : "?" });
      if (u64(tid)) mem.w32(u64(tid), 6001);
      return newHandle({ kind: "thread" });
    },
    WaitForSingleObject: () => 0n,
    Sleep: () => undefined,
    GetCurrentProcess: () => 0xffffffffffffffffn,
    GetCurrentProcessId: () => pid,
    GetCurrentThreadId: () => 0x1b2cn,
    ExitProcess: (_c, [code]) => {
      model.exited = true;
      model.exitCode = Number(u64(code));
      cpu.halted = true;
      return undefined;
    },
    ExitThread: () => {
      cpu.halted = true;
      return undefined;
    },
    // CRT exit aliases (both spellings; normalization also catches _exit/_Exit)
    exit: (_c, [code]) => {
      model.exited = true;
      model.exitCode = Number(u64(code));
      model.exitReason = model.exitReason ?? "exit";
      cpu.halted = true;
      return undefined;
    },
    _exit: (_c, [code]) => {
      model.exited = true;
      model.exitCode = Number(u64(code));
      model.exitReason = model.exitReason ?? "exit";
      cpu.halted = true;
      return undefined;
    },
    _Exit: (_c, [code]) => {
      model.exited = true;
      model.exitCode = Number(u64(code));
      model.exitReason = model.exitReason ?? "exit";
      cpu.halted = true;
      return undefined;
    },
    // ---- network ----
    WSAStartup: (_c, [_ver, data]) => {
      if (u64(data)) mem.write(u64(data), new Uint8Array(400));
      return 0n;
    },
    socket: () => newHandle({ kind: "socket" }),
    connect: (_c, [h, name, _len]) => {
      const sock = getHandle(h);
      let host = "";
      let port = 0;
      try {
        port = (mem.u8(u64(name) + 2n) << 8) | mem.u8(u64(name) + 3n);
        host = readCString(mem, u64(name) + 4n, 256);
      } catch { /* unreadable */ }
      push(artifacts.network, { action: "connect", host, port, proto: "tcp" });
      void sock;
      return 0n;
    },
    send: (_c, [_h, buf, len]) => BigInt(Math.min(Number(u64(len)) || 0, 4096)),
    recv: () => 0n,
    closesocket: () => 0n,
    gethostbyname: () => 0n,
    inet_addr: (_c, [ipVa]) => {
      const ip = str(ipVa);
      const parts = ip.split(".").map(Number);
      if (parts.length !== 4) return 0n;
      return BigInt(((parts[0] | (parts[1] << 8) | (parts[2] << 16) | (parts[3] << 24)) >>> 0));
    },
    InternetOpenA: (_c, [_agent]) => newHandle({ kind: "inet" }),
    InternetOpenW: () => newHandle({ kind: "inet" }),
    InternetConnectA: (_c, [_h, hostVa, port]) => {
      const host = str(hostVa);
      push(artifacts.network, { action: "http-connect", host, port: Number(u64(port)) });
      return newHandle({ kind: "inet", host });
    },
    HttpOpenRequestA: () => newHandle({ kind: "http" }),
    HttpSendRequestA: () => 1n,
    InternetReadFile: (_c, [_h, buf, size, readPtr]) => {
      if (u64(readPtr)) mem.w32(u64(readPtr), 0);
      if (u64(buf)) mem.write(u64(buf), new Uint8Array(Math.min(Number(u64(size)) || 0, 64)));
      return 1n;
    },
    URLDownloadToFileA: (_c, [_caller, urlVa, pathVa]) => {
      const url = str(urlVa);
      const path = str(pathVa);
      push(artifacts.network, { action: "download", url, path });
      push(artifacts.files, { action: "create", path, write: true, download: url });
      return 0n;
    },
    // ---- anti-analysis / environment ----
    IsDebuggerPresent: () => 0n,
    CheckRemoteDebuggerPresent: (_c, [_h, out]) => {
      if (u64(out)) mem.w32(u64(out), 0);
      return 1n;
    },
    OutputDebugStringA: (_c, [sVa]) => {
      push(artifacts.debugStrings, { text: str(sVa).slice(0, 256) });
      return undefined;
    },
    OutputDebugStringW: (_c, [sVa]) => {
      push(artifacts.debugStrings, { text: wstr(sVa).slice(0, 256) });
      return undefined;
    },
    GetTickCount: () => (tick += 0x10, BigInt(tick)),
    GetTickCount64: () => (tick += 0x10, BigInt(tick)),
    QueryPerformanceCounter: (_c, [out]) => {
      tick += 1;
      if (u64(out)) mem.w64(u64(out), BigInt(tick));
      return 1n;
    },
    GetSystemTimeAsFileTime: (_c, [out]) => {
      if (u64(out)) mem.w64(u64(out), 0x01d7000000000000n);
      return undefined;
    },
    GetSystemTime: (_c, [out]) => {
      if (u64(out)) mem.write(u64(out), new Uint8Array(16));
      return undefined;
    },
    GetVersionExA: (_c, [out]) => {
      if (u64(out) && u64(out) !== 0n) {
        mem.w32(u64(out), 284);
        mem.w32(u64(out) + 4n, 6);
        mem.w32(u64(out) + 8n, 2);
        mem.w32(u64(out) + 12n, 19041);
      }
      return 1n;
    },
    GetSystemInfo: (_c, [out]) => {
      if (u64(out)) {
        mem.write(u64(out), new Uint8Array(48));
        mem.w32(u64(out), 0);
        mem.w32(u64(out) + 4n, 0x1000);
        mem.w64(u64(out) + 24n, 0x7fffffffffffn);
      }
      return undefined;
    },
    GetComputerNameA: (_c, [buf, sizePtr]) => {
      const name = "KFPC";
      if (u64(buf)) writeCString(mem, u64(buf), name);
      if (u64(sizePtr)) mem.w32(u64(sizePtr), name.length);
      return 1n;
    },
    GetUserNameA: (_c, [buf, sizePtr]) => {
      const name = "kfuser";
      if (u64(buf)) writeCString(mem, u64(buf), name);
      if (u64(sizePtr)) mem.w32(u64(sizePtr), name.length);
      return 1n;
    },
    GetEnvironmentVariableA: () => 0n,
    GetEnvironmentStringsA: () => model.envBlockA,
    GetEnvironmentStringsW: () => model.envBlockW,
    ExpandEnvironmentStringsA: (_c, [srcVa, dstVa, size]) => {
      const src = str(srcVa);
      const expanded = src
        .replace(/%TEMP%/gi, "C:\\Users\\kf\\AppData\\Local\\Temp")
        .replace(/%TMP%/gi, "C:\\Users\\kf\\AppData\\Local\\Temp")
        .replace(/%APPDATA%/gi, "C:\\Users\\kf\\AppData\\Roaming")
        .replace(/%SYSTEMROOT%/gi, "C:\\Windows")
        .replace(/%WINDIR%/gi, "C:\\Windows")
        .replace(/%USERPROFILE%/gi, "C:\\Users\\kf");
      if (u64(dstVa)) writeCString(mem, u64(dstVa), expanded.slice(0, Number(size) - 1));
      return BigInt(expanded.length + 1);
    },
    // ---- strings / conversion ----
    lstrlenA: (_c, [sVa]) => BigInt(str(sVa).length),
    lstrlenW: (_c, [sVa]) => BigInt(wstr(sVa).length),
    lstrcpyA: (_c, [dst, src]) => {
      const s = str(src);
      if (u64(dst)) writeCString(mem, u64(dst), s);
      return u64(dst);
    },
    lstrcatA: (_c, [dst, src]) => {
      const base = str(dst);
      if (u64(dst)) writeCString(mem, u64(dst), base + str(src));
      return u64(dst);
    },
    MultiByteToWideChar: (_c, [_cp, _flags, src, _cb, dst, cch]) => {
      const s = str(src).slice(0, Math.max(0, Number(u64(cch)) - 1));
      if (u64(dst)) writeUtf16(mem, u64(dst), s);
      return BigInt(s.length + 1);
    },
    WideCharToMultiByte: (_c, [_cp, _flags, src, _cch, dst, cb]) => {
      const s = wstr(src).slice(0, Math.max(0, Number(u64(cb)) - 1));
      if (u64(dst)) writeCString(mem, u64(dst), s);
      return BigInt(s.length + 1);
    },
    // ---- CRT stdio (format and record; no real FILE*) ----
    _stdio_common_vfprintf: (_c, [_opts, _stream, fmtVa, _locale, argListVa]) => {
      const fmt = str(fmtVa);
      const args = readVarargs(argListVa);
      const text = formatPrintf(fmt, args);
      push(artifacts.stdout, { text });
      return BigInt(text.length);
    },
    _stdio_common_vsprintf: (_c, [_opts, dst, _size, fmtVa, _locale, argListVa]) => {
      const text = formatPrintf(str(fmtVa), readVarargs(argListVa));
      if (u64(dst)) writeCString(mem, u64(dst), text);
      return BigInt(text.length);
    },
    _stdio_common_vsprintf_s: (_c, [_opts, dst, _size, fmtVa, _locale, argListVa]) => {
      const text = formatPrintf(str(fmtVa), readVarargs(argListVa));
      if (u64(dst)) writeCString(mem, u64(dst), text);
      return BigInt(text.length);
    },
    _stdio_common_vsnprintf_s: (_c, [_opts, dst, size, _count, fmtVa, _locale, argListVa]) => {
      const text = formatPrintf(str(fmtVa), readVarargs(argListVa)).slice(0, Math.max(0, Number(u64(size)) - 1));
      if (u64(dst)) writeCString(mem, u64(dst), text);
      return BigInt(text.length);
    },
    _stdio_common_vfscanf: () => 0n,
    _stdio_common_vsscanf: () => 0n,
    fputs: (_c, [sVa]) => {
      push(artifacts.stdout, { text: cstrLocal(mem, sVa) });
      return 0n;
    },
    fputc: (_c, [ch]) => {
      push(artifacts.stdout, { text: String.fromCharCode(Number(u64(ch)) & 0xff) });
      return u64(ch);
    },
    fprintf: (_c, [_stream, fmtVa, ...rest]) => {
      const text = formatPrintf(str(fmtVa), rest);
      push(artifacts.stdout, { text });
      return BigInt(text.length);
    },
    _initialize_onexit_table: () => 0n,
    _register_onexit_function: () => 0n,
    _execute_onexit_table: () => 0n,
    _onexit: () => 0n,
    onexit: () => 0n,
    _crt_atexit: () => 0n,
    __cxa_atexit: () => 0n,
    _cxa_atexit: () => 0n,

    // ---- CRT startup helpers ----
    // _initterm[_e](start, end): call every non-null function pointer in the
    // range. This is how MSVC runs C/C++ static initializers; returning 0
    // without calling them silently skips the sample's constructors.
    _initterm: (_c, [start, end]) => {
      for (let p = u64(start); p < u64(end); p += 8n) {
        const fn = safeU64(() => mem.u64(p));
        if (fn) safe(() => cpu.callFunction(fn, []));
      }
      return 0n;
    },
    _initterm_e: (_c, [start, end]) => {
      for (let p = u64(start); p < u64(end); p += 8n) {
        const fn = safeU64(() => mem.u64(p));
        if (!fn) continue;
        const r = safe(() => cpu.callFunction(fn, []), null);
        if (r && r.status !== "ok") {
          push(artifacts.debugStrings, { text: `[crt] initializer ${hex(fn)} ${r.status}: ${String(r.error?.message ?? r.error ?? "").slice(0, 120)}` });
        }
        const v = r?.retval !== undefined ? Number(BigInt.asIntN(32, r.retval)) : 0;
        if (v !== 0) {
          push(artifacts.debugStrings, { text: `[crt] initializer ${hex(fn)} returned ${v} -> CRT aborts` });
          return BigInt(v);
        }
      }
      return 0n;
    },
    // Legacy msvcrt entry helpers. calc.exe's startup wrapper calls
    // __wgetmainargs and its CRT then requires _wcmdln (a data export) to be
    // non-null; without this it returns 0xFF before main/WinMain ever runs.
    __wgetmainargs: (_c, [argcOut, argvOut, wargvOut, _wild, _si]) => fillMainArgs(argcOut, argvOut, wargvOut, 0n),
    _wgetmainargs: (_c, [argcOut, argvOut, wargvOut, _wild, _si]) => fillMainArgs(argcOut, argvOut, wargvOut, 0n),
    __getmainargs: (_c, [argcOut, argvOut, envpOut, _wild, _si]) => fillMainArgs(argcOut, argvOut, 0n, envpOut),
    _getmainargs: (_c, [argcOut, argvOut, envpOut, _wild, _si]) => fillMainArgs(argcOut, argvOut, 0n, envpOut),
    // Cygwin/MSYS2 runtime entries: without the POSIX runtime these can never
    // make progress (all msys-2.0 imports are stubs); stop with a classified
    // reason instead of spinning to the step cap.
    cygwin_internal: () => { model.exited = true; model.exitReason = "cygwin/msys runtime not modeled"; cpu.halted = true; return 0n; },
    dll_crt0: () => { model.exited = true; model.exitReason = "cygwin/msys runtime not modeled"; cpu.halted = true; return 0n; },
    _get_initial_narrow_environment: () => model.envBlockA,
    _initialize_narrow_environment: () => 0n,
    __initialize_narrow_environment: () => 0n,
    _get_initial_wide_environment: () => model.envBlockW,
    __p___argc: () => model.argcPtr,
    __p___argv: () => model.argvPtr,
    __p__environ: () => model.argvPtr,
    _environ: () => model.envBlockPtr,
    _set_app_type: () => undefined,
    _configure_narrow_argv: () => 0n,
    _configure_wide_argv: () => 0n,
    _configthreadlocale: () => 0n,
    __setusermatherr: () => undefined,
    _set_fmode: (_c, [mode]) => { setDataCell("fmode", u64(mode)); return 0n; },
    _crt_atexit: () => 0n,
    atexit: () => 0n,
    _cexit: () => { model.exited = true; cpu.halted = true; return undefined; },
    _c_exit: () => { model.exited = true; cpu.halted = true; return undefined; },
    quick_exit: (_c, [code]) => {
      model.exited = true;
      model.exitCode = Number(u64(code));
      cpu.halted = true;
      return undefined;
    },
    _amsg_exit: () => { model.exited = true; cpu.halted = true; return undefined; },
    _invalid_parameter_noinfo_noreturn: () => { model.exited = true; cpu.halted = true; return undefined; },
    _invoke_watson: () => { model.exited = true; cpu.halted = true; return undefined; },
    terminate: () => { model.exited = true; cpu.halted = true; return undefined; },
    _lock_file: () => 0n,
    _unlock_file: () => 0n,
    __acrt_iob_func: (_c, [idx]) => (u64(idx) === 1n ? 0x11n : u64(idx) === 2n ? 0x12n : 0x10n),
    _fileno: () => 1n,
    _isatty: () => 1n,
    signal: () => 0n,
    _get_daylight: (_c, [out]) => { if (u64(out)) mem.w32(u64(out), 0); return 0n; },
    _get_timezone: (_c, [out]) => { if (u64(out)) mem.w32(u64(out), 0); return 0n; },
    _get_dstbias: (_c, [out]) => { if (u64(out)) mem.w32(u64(out), 0); return 0n; },
    wcslen: (_c, [sVa]) => BigInt(wstr(sVa).length),
    wcscpy: (_c, [dst, src]) => {
      const s = wstr(src);
      if (u64(dst)) writeUtf16(mem, u64(dst), s);
      return u64(dst);
    },
    memcpy_s: (_c, [dst, _dstSize, src, count]) => {
      const n = Math.min(Number(u64(count)) || 0, 1 << 16);
      try { mem.write(u64(dst), Uint8Array.from(mem.read(u64(src), n))); } catch { /* unreadable */ }
      return 0n;
    },
    memmove_s: (_c, [dst, _dstSize, src, count]) => {
      const n = Math.min(Number(u64(count)) || 0, 1 << 16);
      try { mem.write(u64(dst), Uint8Array.from(mem.read(u64(src), n))); } catch { /* unreadable */ }
      return 0n;
    },
    strcpy_s: (_c, [_dst, _size, src]) => {
      const s = cstrLocal(mem, src);
      return BigInt(s.length);
    },
    sprintf: (_c, [dst, fmt]) => {
      const f = str(fmt);
      if (u64(dst)) writeCString(mem, u64(dst), f.replace(/%[sdifuxX]/g, "0"));
      return BigInt(f.length);
    },
    _snprintf: (_c, [dst, size, fmt]) => {
      const f = str(fmt);
      if (u64(dst)) writeCString(mem, u64(dst), f.slice(0, Math.max(0, Number(u64(size)) - 1)));
      return BigInt(f.length);
    },
    strerror: (_c, [code]) => {
      const va = model.errStr ?? (model.errStr = alloc(32));
      writeCString(mem, va, `error ${Number(u64(code))}`);
      return va;
    },
    _errno: () => model.errnoPtr ?? (model.errnoPtr = alloc(4)),

    // ---- CRT memory/string (MSVC imports these unprefixed) ----
    malloc: (_c, [size]) => guestAlloc(size),
    calloc: (_c, [n, size]) => {
      const total = Math.max(16, (Number(u64(n)) || 1) * (Number(u64(size)) || 1));
      const va = guestAlloc(total);
      mem.write(va, new Uint8Array(total));
      return va;
    },
    realloc: (_c, [_p, size]) => guestAlloc(size),
    free: () => 0n,
    memcpy: (_c, [dst, src, n]) => {
      const len = Math.min(Number(u64(n)) || 0, 1 << 20);
      try { mem.write(u64(dst), Uint8Array.from(mem.read(u64(src), len))); } catch { /* unreadable */ }
      return u64(dst);
    },
    memmove: (_c, [dst, src, n]) => {
      const len = Math.min(Number(u64(n)) || 0, 1 << 20);
      let data = new Uint8Array(0);
      try { data = Uint8Array.from(mem.read(u64(src), len)); } catch { /* unreadable */ }
      try { mem.write(u64(dst), data); } catch { /* unwritable */ }
      return u64(dst);
    },
    memset: (_c, [dst, val, n]) => {
      const len = Math.min(Number(u64(n)) || 0, 1 << 20);
      mem.write(u64(dst), new Uint8Array(len).fill(Number(u64(val)) & 0xff));
      return u64(dst);
    },
    memcmp: (_c, [a, b, n]) => {
      const len = Math.min(Number(u64(n)) || 0, 1 << 16);
      let av = new Uint8Array(0), bv = new Uint8Array(0);
      try { av = Uint8Array.from(mem.read(u64(a), len)); } catch { /* unreadable */ }
      try { bv = Uint8Array.from(mem.read(u64(b), len)); } catch { /* unreadable */ }
      for (let i = 0; i < len; i++) if (av[i] !== bv[i]) return BigInt(av[i] - bv[i]);
      return 0n;
    },
    RtlCopyMemory: (_c, [dst, src, n]) => handlers.memcpy?.(null, [dst, src, n]) ?? u64(dst),
    RtlMoveMemory: (_c, [dst, src, n]) => handlers.memmove?.(null, [dst, src, n]) ?? u64(dst),
    RtlZeroMemory: (_c, [dst, n]) => handlers.memset?.(null, [dst, 0n, n]) ?? u64(dst),
    strlen: (_c, [sVa]) => BigInt(cstrLocal(mem, sVa).length),
    strcmp: (_c, [a, b]) => {
      const av = cstrLocal(mem, a), bv = cstrLocal(mem, b);
      return BigInt(av < bv ? -1 : av > bv ? 1 : 0);
    },
    strncmp: (_c, [a, b, n]) => {
      const len = Number(u64(n)) || 0;
      const av = cstrLocal(mem, a).slice(0, len), bv = cstrLocal(mem, b).slice(0, len);
      return BigInt(av < bv ? -1 : av > bv ? 1 : 0);
    },
    strcpy: (_c, [dst, src]) => {
      writeCString(mem, u64(dst), cstrLocal(mem, src));
      return u64(dst);
    },
    strncpy: (_c, [dst, src, n]) => {
      const len = Number(u64(n)) || 0;
      writeCString(mem, u64(dst), cstrLocal(mem, src).slice(0, len));
      return u64(dst);
    },
    strcat: (_c, [dst, src]) => {
      writeCString(mem, u64(dst), cstrLocal(mem, dst) + cstrLocal(mem, src));
      return u64(dst);
    },
    strchr: (_c, [sVa, ch]) => {
      const str2 = cstrLocal(mem, sVa);
      const idx = str2.indexOf(String.fromCharCode(Number(u64(ch)) & 0xff));
      return idx < 0 ? 0n : u64(sVa) + BigInt(idx);
    },
    strstr: (_c, [hayVa, needleVa]) => {
      const hay = cstrLocal(mem, hayVa), needle = cstrLocal(mem, needleVa);
      const idx = needle ? hay.indexOf(needle) : 0;
      return idx < 0 ? 0n : u64(hayVa) + BigInt(idx);
    },
    atoi: (_c, [sVa]) => BigInt(parseInt(cstrLocal(mem, sVa), 10) || 0),
    atol: (_c, [sVa]) => BigInt(parseInt(cstrLocal(mem, sVa), 10) || 0),
    _p__commode: () => model.commodePtr ?? (model.commodePtr = alloc(4)),
    _p___mb_cur_max: () => model.mbCurMaxPtr ?? (model.mbCurMaxPtr = alloc(4)),
    set_new_mode: () => 0n,
    callnewh: () => 0n,
    _get_narrow_winmain_command_line: () => model.commandLineA,
    get_narrow_winmain_command_line: () => model.commandLineA,
    _get_wide_winmain_command_line: () => model.commandLineW,
    InitializeSListHead: (_c, [head]) => {
      if (u64(head)) mem.write(u64(head), new Uint8Array(16));
      return undefined;
    },
    _CxxThrowException: () => {
      // Unwinding is not modeled; returning would make a noreturn caller run
      // into garbage (or spin retrying). Stop with a classified reason.
      push(artifacts.debugStrings, { text: "[crt] C++ exception thrown (unwinding not modeled)" });
      model.exited = true;
      model.exitReason = "C++ exception (unwinding not modeled)";
      cpu.halted = true;
      return 0n;
    },
    _cxa_allocate_exception: (_c, [size]) => guestAlloc(size),
    __cxa_allocate_exception: (_c, [size]) => guestAlloc(size),
    __cxa_throw: () => { model.exited = true; model.exitReason = "C++ exception (unwinding not modeled)"; cpu.halted = true; return 0n; },
    _cxa_throw: () => { model.exited = true; model.exitReason = "C++ exception (unwinding not modeled)"; cpu.halted = true; return 0n; },
    _Unwind_RaiseException: () => { model.exited = true; model.exitReason = "C++ exception (unwinding not modeled)"; cpu.halted = true; return 0n; },
    RtlDeleteCriticalSection: () => undefined,
    RtlEnterCriticalSection: () => undefined,
    RtlLeaveCriticalSection: () => undefined,
    RtlInitializeCriticalSection: () => undefined,
    RtlInitializeCriticalSectionAndSpinCount: () => 0n,

    // ---- ntdll heap / virtual memory (out-params matter: callers read them) ----
    RtlCreateHeap: () => newHandle({ kind: "heap" }),
    RtlDestroyHeap: () => 0n,
    RtlAllocateHeap: (_c, [_h, _flags, size]) => guestAlloc(size),
    RtlReAllocateHeap: (_c, [_h, _flags, _ptr, size]) => guestAlloc(size),
    RtlFreeHeap: () => 1n,
    RtlSizeHeap: () => 0n,
    NtAllocateVirtualMemory: (_c, [_h, basePtr, _zeroBits, sizePtr, _type, _prot]) => {
      const size = Math.min(Number(safeU64(() => mem.u32(u64(sizePtr)))) || 0x1000, 1 << 24);
      const va = guestAlloc(size);
      if (u64(basePtr)) mem.w64(u64(basePtr), va);
      if (u64(sizePtr)) mem.w32(u64(sizePtr), size);
      return 0n;
    },
    NtFreeVirtualMemory: (_c, [_h, basePtr, sizePtr]) => {
      if (u64(basePtr)) mem.w64(u64(basePtr), 0n);
      if (u64(sizePtr)) mem.w32(u64(sizePtr), 0);
      return 0n;
    },
    NtProtectVirtualMemory: (_c, [_h, _basePtr, _sizePtr, _prot, oldPtr]) => {
      if (u64(oldPtr)) mem.w32(u64(oldPtr), 0x40);
      return 0n;
    },
    NtQueryVirtualMemory: (_c, [_h, _addr, _class, buf, len, retPtr]) => {
      const n = Math.min(Number(u64(len)) || 48, 4096);
      if (u64(buf)) mem.write(u64(buf), new Uint8Array(n));
      if (u64(retPtr)) mem.w64(u64(retPtr), BigInt(n));
      return 0n;
    },
    NtQueryInformationProcess: (_c, [_h, _class, buf, len, retPtr]) => {
      const n = Math.min(Number(u64(len)) || 64, 4096);
      if (u64(buf)) mem.write(u64(buf), new Uint8Array(n));
      if (u64(retPtr)) mem.w32(u64(retPtr), n);
      return 0n;
    },
    NtQueryInformationThread: (_c, [_h, _class, buf, len, retPtr]) => {
      const n = Math.min(Number(u64(len)) || 64, 4096);
      if (u64(buf)) mem.write(u64(buf), new Uint8Array(n));
      if (u64(retPtr)) mem.w32(u64(retPtr), n);
      return 0n;
    },
    NtSetInformationProcess: () => 0n,
    NtSetInformationThread: () => 0n,
    NtQuerySystemInformation: () => 0xc0000003n, // STATUS_INVALID_INFO_CLASS
    NtQuerySystemTime: (_c, [out]) => {
      if (u64(out)) mem.w64(u64(out), 0x01d7000000000000n);
      return 0n;
    },
    NtQueryPerformanceCounter: (_c, [out]) => {
      tick += 1;
      if (u64(out)) mem.w64(u64(out), BigInt(tick));
      return 0n;
    },
    NtClose: () => 0n,
    NtWaitForSingleObject: () => 0n,
    NtWaitForMultipleObjects: () => 0n,
    NtTestAlert: () => 0n,
    NtYieldExecution: () => 0n,
    NtDelayExecution: () => 0n,
    RtlGetVersion: (_c, [out]) => {
      if (u64(out)) {
        mem.write(u64(out), new Uint8Array(284));
        mem.w32(u64(out), 284);
        mem.w32(u64(out) + 4n, 6);
        mem.w32(u64(out) + 8n, 2);
        mem.w32(u64(out) + 12n, 19041);
      }
      return 0n;
    },
    RtlInitUnicodeString: (_c, [dest, src]) => {
      if (u64(dest)) {
        const s = wstr(src);
        mem.w16(u64(dest), s.length * 2);
        mem.w16(u64(dest) + 2n, s.length * 2 + 2);
        mem.w64(u64(dest) + 8n, u64(src));
      }
      return undefined;
    },
    RtlFreeUnicodeString: () => undefined,
    RtlCreateUnicodeString: () => 1n,
    RtlEqualUnicodeString: () => 1n,
    RtlCompareUnicodeString: () => 0n,
    RtlUpcaseUnicodeString: () => 0n,

    // ---- CRT / runtime (success-path stubs; real apps treat failures as fatal) ----
    InitializeCriticalSectionEx: () => 1n,
    InitializeCriticalSectionAndSpinCount: () => 1n,
    GetEnabledXStateFeatures: () => 1n,
    IsProcessorFeaturePresent: () => 1n,
    FlsAlloc: () => 0n,
    FlsFree: () => 1n,
    FlsGetValue: () => 0n,
    FlsSetValue: () => 1n,
    GetStringTypeW: () => 1n,
    GetStringTypeA: () => 1n,
    LCMapStringW: () => 0n,
    LCMapStringEx: () => 0n,
    FormatMessageW: () => 0n,
    FormatMessageA: () => 0n,
    EnumSystemLocalesW: () => 1n,
    IsValidLocale: () => 1n,
    IsValidCodePage: () => 1n,
    GetUserDefaultLCID: () => 0x409n,
    GetSystemDefaultLCID: () => 0x409n,
    GetLocaleInfoW: () => 0n,
    GetLocaleInfoEx: () => 0n,
    GetNumberFormatEx: () => 0n,
    GetDateFormatEx: () => 0n,
    GetTimeFormatEx: () => 0n,
    SearchPathW: () => 0n,
    MulDiv: (_c, [a, b, c]) => {
      const den = Number(u64(c));
      return den ? BigInt(Math.floor((Number(u64(a)) * Number(u64(b))) / den)) : 0n;
    },
    SystemTimeToTzSpecificLocalTime: (_c, [_tz, _in, out]) => {
      if (u64(out)) mem.write(u64(out), new Uint8Array(16));
      return 1n;
    },
    RtlQueryPerformanceCounter: (_c, [out]) => {
      tick += 1;
      if (u64(out)) mem.w64(u64(out), BigInt(tick));
      return 1n;
    },
    RtlNtStatusToDosErrorNoTeb: () => 0n,
    RtlNtStatusToDosError: () => 0n,
    RaiseException: () => { model.exited = true; model.exitReason = "raise-exception"; cpu.halted = true; return undefined; },
    GetCurrentPackageFullName: () => 15700n, // APPMODEL_ERROR_NO_PACKAGE

    // ---- console ----
    AllocConsole: () => 1n,
    FreeConsole: () => 1n,
    GetConsoleWindow: () => 0n,
    SetConsoleOutputCP: () => 1n,
    SetConsoleCP: () => 1n,
    SetConsoleCtrlHandler: () => 1n,
    GetConsoleMode: (_c, [_h, out]) => {
      if (u64(out)) mem.w32(u64(out), 3);
      return 1n;
    },
    WriteConsoleW: (_c, [_h, _buf, len, written]) => {
      if (u64(written)) mem.w32(u64(written), Number(u64(len)) || 0);
      return 1n;
    },
    ReadConsoleW: (_c, [_h, _buf, _len, readPtr]) => {
      if (u64(readPtr)) mem.w32(u64(readPtr), 0);
      return 1n;
    },
    SetStdHandle: () => 1n,

    // ---- user32 (GUI apps: keep the message path alive) ----
    RegisterClassExW: (_c, [out]) => {
      if (u64(out)) mem.write(u64(out), new Uint8Array(16));
      return 1n;
    },
    RegisterClassExA: () => 1n,
    CreateWindowExW: () => 0x100n,
    CreateWindowExA: () => 0x100n,
    DestroyWindow: () => 1n,
    ShowWindow: () => 1n,
    UpdateWindow: () => 1n,
    GetMessageW: (_c, [msg]) => {
      // WM_QUIT -> the standard message loop exits; record it as an exit.
      if (u64(msg)) mem.w32(u64(msg), 0x0012);
      model.exited = true;
      model.exitReason = model.exitReason ?? "message-loop-exit";
      cpu.halted = true;
      return 0n;
    },
    GetMessageA: (_c, [msg]) => handlers.GetMessageW?.(null, [msg]) ?? 0n,
    PeekMessageW: (_c, [msg]) => {
      if (u64(msg)) mem.w32(u64(msg), 0);
      return 0n;
    },
    TranslateMessage: () => 0n,
    DispatchMessageW: () => 0n,
    DispatchMessageA: () => 0n,
    DefWindowProcW: () => 0n,
    DefWindowProcA: () => 0n,
    PostQuitMessage: () => undefined,
    PostMessageW: () => 1n,
    SendMessageW: () => 0n,
    MessageBoxW: () => 1n,
    MessageBoxA: () => 1n,
    LoadCursorW: () => 0n,
    LoadIconW: () => 0n,
    LoadImageW: () => 0n,
    SetWindowLongPtrW: () => 0n,
    SetWindowLongW: () => 0n,
    GetWindowLongPtrW: () => 0n,
    GetClientRect: (_c, [_h, rect]) => {
      if (u64(rect)) mem.write(u64(rect), new Uint8Array(16));
      return 1n;
    },
    GetWindowRect: (_c, [_h, rect]) => {
      if (u64(rect)) mem.write(u64(rect), new Uint8Array(16));
      return 1n;
    },
    BeginPaint: () => 0n,
    EndPaint: () => 1n,
    CreateMenu: () => 0n,
    CreatePopupMenu: () => 0n,
    DestroyMenu: () => 1n,
    AppendMenuW: () => 1n,
    GetSystemMetrics: () => 1920n,
    AdjustWindowRectEx: () => 1n,
    SetWindowPos: () => 1n,
    IsWindowVisible: () => 0n,
    GetDesktopWindow: () => 0n,
    MonitorFromWindow: () => 0n,
    GetMonitorInfoW: () => 0n,
    EnumWindows: () => 1n,
    GetWindowThreadProcessId: (_c, [_h, pidOut]) => {
      if (u64(pidOut)) mem.w32(u64(pidOut), Number(pid));
      return 1n;
    },
    GetForegroundWindow: () => 0n,
    SetForegroundWindow: () => 1n,
    GetDC: () => 0n,
    ReleaseDC: () => 1n,
    InvalidateRect: () => 1n,
    SetTimer: () => 1n,
    KillTimer: () => 1n,
    SetWindowTextW: () => 1n,
    GetWindowTextW: () => 0n,
    SetWindowTextA: () => 1n,
    GetWindowTextA: () => 0n,

    // ---- startup / misc ----
    GetCommandLineA: () => model.commandLineA,
    GetCommandLineW: () => model.commandLineW,
    GetStartupInfoA: (_c, [out]) => {
      if (u64(out)) mem.write(u64(out), new Uint8Array(104));
      return undefined;
    },
    GetStartupInfoW: (_c, [out]) => {
      if (u64(out)) mem.write(u64(out), new Uint8Array(104));
      return undefined;
    },
    GetStdHandle: (_c, [which]) => (u64(which) === 0xfffffff6n ? 0x10n : u64(which) === 0xfffffff5n ? 0x11n : 0x12n),
    SetUnhandledExceptionFilter: () => 0n,
    UnhandledExceptionFilter: () => 1n,
    InitializeCriticalSection: () => undefined,
    DeleteCriticalSection: () => undefined,
    EnterCriticalSection: () => undefined,
    LeaveCriticalSection: () => undefined,
    InitializeCriticalSectionAndSpinCount: () => 1n,
    TlsAlloc: () => 0n,
    TlsFree: () => 1n,
    TlsGetValue: () => 0n,
    TlsSetValue: () => 1n,
    EncodePointer: (_c, [p]) => u64(p),
    DecodePointer: (_c, [p]) => u64(p),
    GetLastError: () => BigInt(lastError),
    SetLastError: (_c, [code]) => {
      lastError = Number(u64(code));
      return undefined;
    },
    CreateMutexA: (_c, [_sa, _own, nameVa]) => {
      const name = str(nameVa);
      push(artifacts.mutexes, { action: "create", name });
      return newHandle({ kind: "mutex", name });
    },
    CreateMutexW: (_c, [_sa, _own, nameVa]) => {
      const name = wstr(nameVa);
      push(artifacts.mutexes, { action: "create", name });
      return newHandle({ kind: "mutex", name });
    },
    OpenMutexA: () => newHandle({ kind: "mutex" }),
    ReleaseMutex: () => 1n,
    GetProcessHeap: () => 0x30n,
    GetACP: () => 1252n,
    GetOEMCP: () => 437n,
    GetCPInfo: () => 1n,
    GetFileType: () => 1n,
    FlushFileBuffers: () => 1n,
    SetEndOfFile: () => 1n,
  };

  function createProcess(appVa, cmdVa, si, pi) {
    const app = typeof appVa === "bigint" ? str(appVa) : "";
    const cmd = str(cmdVa);
    push(artifacts.processes, { action: "create", path: app || cmd.split(" ")[0], cmdline: cmd });
    pid += 4n;
    if (u64(si)) mem.write(u64(si), new Uint8Array(104));
    if (u64(pi)) {
      mem.w64(u64(pi), 0x200n);
      mem.w64(u64(pi) + 8n, 0x300n);
      mem.w32(u64(pi) + 16n, Number(pid));
      mem.w32(u64(pi) + 20n, 0x3004);
    }
    return 1n;
  }

  function registryRoot(hive) {
    const h = u64(hive);
    if (h === 0x80000001n) return "HKCU";
    if (h === 0x80000002n) return "HKLM";
    return `HK${h.toString(16)}`;
  }

  /**
   * Dispatch one API by name. Unknown names are recorded as unmodeled and
   * return 0 (fail-open).
   */
  // MSVC decorates CRT imports inconsistently (`_initterm` vs `initterm`,
  // `__p___argv` vs `_p___argv`); normalize leading underscores for lookup.
  const normalizeApi = (n) => String(n).replace(/^_+/, "").toLowerCase();
  const byNormalized = new Map();
  for (const [apiName, impl] of Object.entries(handlers)) {
    const key = normalizeApi(apiName);
    if (!byNormalized.has(key)) byNormalized.set(key, impl);
  }
  // Modeled API names — consumed by the shellcode harness to build synthetic
  // kernel32/ntdll export tables with zero drift from this handler set.
  model.apiNames = Object.keys(handlers).sort();

  model.dispatch = (name, args, meta = null) => {
    let fn = handlers[name];
    if (!fn) fn = byNormalized.get(normalizeApi(name));
    if (!fn) {
      model.unmodeled.add(name);
      record(name, args, 0n, meta);
      return 0n;
    }
    let ret;
    try {
      ret = fn(model, args);
    } catch {
      ret = 0n;
    }
    record(name, args, ret, meta);
    return ret === undefined ? undefined : u64(ret);
  };

  // CRT argv/env pointers (filled by the runner once the guest stack exists)
  model.envBlockA = alloc(4);
  model.envBlockW = alloc(4);
  model.argcPtr = alloc(8);
  model.argvPtr = alloc(16);
  model.envBlockPtr = alloc(8);
  mem.write(model.envBlockA, new Uint8Array(2));
  mem.write(model.envBlockW, new Uint8Array(4));

  model.guestAlloc = guestAlloc;
  model.str = str;
  model.wstr = wstr;
  return model;
}

