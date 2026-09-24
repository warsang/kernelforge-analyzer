/**
 * trace.mjs — decode recorded Win32 API events into a chronological trace.
 *
 * The model records raw register/stack args; this module turns them into
 * human-readable lines (paths, URLs, registry keys, commands, buffer
 * previews) with the caller's module+RVA. Guest memory is still live when
 * the trace is built, so pointers can be dereferenced.
 *
 *   [0001] sample.exe+0x1a3f  CreateFileA("C:\temp\x.bin", 0x40000000, 0x0, 0x0, 0x2, 0x0, 0x0) -> 0x104
 */

const M64 = (1n << 64n) - 1n;

function cstr(mem, va, max = 160) {
  if (va === 0n) return null;
  try {
    let s = "";
    for (let i = 0; i < max; i++) {
      const b = mem.u8(va + BigInt(i));
      if (b === 0) break;
      if (b < 0x09 || (b > 0x0d && b < 0x20) || b > 0x7e) return null;
      s += String.fromCharCode(b);
    }
    return s.length >= 2 ? s : null;
  } catch {
    return null;
  }
}

function wstr(mem, va, max = 160) {
  if (va === 0n) return null;
  try {
    let s = "";
    for (let i = 0; i < max; i++) {
      const lo = mem.u8(va + BigInt(i * 2));
      const hi = mem.u8(va + BigInt(i * 2 + 1));
      if (lo === 0 && hi === 0) break;
      if (hi !== 0 || lo < 0x09 || (lo > 0x0d && lo < 0x20) || lo > 0x7e) return null;
      s += String.fromCharCode(lo);
    }
    return s.length >= 2 ? s : null;
  } catch {
    return null;
  }
}

const hex = (v) => `0x${BigInt.asUintN(64, BigInt(v ?? 0)).toString(16)}`;
const quoted = (s) => (s === null ? null : JSON.stringify(s));

/**
 * Abridged-trace filter: behavior-relevant APIs only (file/registry/network/
 * process/memory/hooking). Timing, CRT, heap and lock noise is dropped; the
 * full trace is still available via traceText.
 */
const INTERESTING = new Set([
  "CreateFileA", "CreateFileW", "WriteFile", "ReadFile", "DeleteFileA", "DeleteFileW",
  "CopyFileA", "MoveFileA", "CreateDirectoryA", "SetFilePointer", "GetFileSize",
  "RegOpenKeyExA", "RegOpenKeyExW", "RegCreateKeyExA", "RegCreateKeyExW",
  "RegSetValueExA", "RegSetValueExW", "RegDeleteValueA", "RegDeleteKeyA",
  "CreateProcessA", "CreateProcessW", "WinExec", "ShellExecuteA", "ShellExecuteExA",
  "CreateRemoteThread", "CreateRemoteThreadEx", "WriteProcessMemory", "ReadProcessMemory",
  "OpenProcess", "OpenThread", "TerminateProcess", "QueueUserAPC", "SetThreadContext",
  "GetThreadContext", "SuspendThread", "ResumeThread", "VirtualAlloc", "VirtualAllocEx",
  "VirtualProtect", "VirtualProtectEx", "VirtualFree", "VirtualQuery",
  "LoadLibraryA", "LoadLibraryW", "LoadLibraryExA", "LoadLibraryExW", "GetProcAddress",
  "GetModuleFileNameA", "GetModuleFileNameW", "URLDownloadToFileA", "InternetOpenA",
  "InternetOpenW", "InternetConnectA", "HttpOpenRequestA", "HttpSendRequestA",
  "InternetReadFile", "WinHttpOpen", "WinHttpConnect", "WinHttpSendRequest",
  "WinHttpReceiveResponse", "WinHttpReadData", "socket", "connect", "send", "recv",
  "sendto", "bind", "listen", "accept", "closesocket", "gethostbyname", "inet_addr",
  "OutputDebugStringA", "OutputDebugStringW", "CreateMutexA", "CreateMutexW",
  "OpenMutexA", "SetWindowsHookExA", "SetWindowsHookExW", "GetAsyncKeyState",
  "GetForegroundWindow", "BitBlt", "GetDC", "MiniDumpWriteDump", "ExpandEnvironmentStringsA",
  "GetTempPathA", "GetTempPathW", "SetUnhandledExceptionFilter", "IsDebuggerPresent",
  "CheckRemoteDebuggerPresent", "EnumDeviceDrivers", "GetSystemFirmwareTable",
]);

/** True when an event belongs in the abridged trace. */
export function isInterestingPeCall(name) {
  if (INTERESTING.has(name)) return true;
  if (/^(?:Nt|Zw)[A-Z]/.test(name)) return true;              // ntdll syscalls
  if (/^(?:Create|Open|Write|Read|Delete|Copy|Move|Load|Find)[A-Z]/.test(name)) return true;
  if (/^(?:Reg|Internet|WinHttp|Http)[A-Z]/.test(name)) return true;
  if (/Thread|Process|Inject|Apc|Hook/.test(name)) return true;
  return false;
}

/** API -> [arg indexes that are ASCII strings, arg indexes that are wide strings]. */
const ARG_STRINGS = {
  CreateFileA: [[0], []], CreateFileW: [[], [0]],
  DeleteFileA: [[0], []], DeleteFileW: [[], [0]],
  CreateDirectoryA: [[0], []],
  CopyFileA: [[0, 1], []], MoveFileA: [[0, 1], []],
  LoadLibraryA: [[0], []], LoadLibraryW: [[], [0]], LoadLibraryExA: [[0], []],
  GetModuleHandleA: [[0], []], GetModuleHandleW: [[], [0]],
  RegOpenKeyExA: [[1], []], RegOpenKeyExW: [[], [1]],
  RegCreateKeyExA: [[1], []], RegCreateKeyExW: [[], [1]],
  RegSetValueExA: [[1], []], RegSetValueExW: [[], [1]],
  RegDeleteValueA: [[1], []],
  WinExec: [[0], []],
  ShellExecuteA: [[2], []],
  CreateProcessA: [[0, 1], []], CreateProcessW: [[], [0, 1]],
  InternetConnectA: [[1], []],
  URLDownloadToFileA: [[1, 2], []],
  OutputDebugStringA: [[0], []], OutputDebugStringW: [[], [0]],
  CreateMutexA: [[2], []], CreateMutexW: [[], [2]],
  GetCommandLineA: [[], []],
  gethostbyname: [[0], []],
  inet_addr: [[0], []],
  ExpandEnvironmentStringsA: [[0], []],
  CreateRemoteThread: [[], []],
};

/** Args that are pointers to buffers (shown as a bounded hex/ascii preview). */
const ARG_BUFFERS = {
  WriteFile: [1], send: [1], sendto: [1], InternetReadFile: [1], ReadFile: [1],
  MultiByteToWideChar: [2], WideCharToMultiByte: [2],
};

function bufferPreview(mem, va, len) {
  if (va === 0n || !len) return null;
  const n = Math.min(Number(len) || 0, 48);
  if (n <= 0) return null;
  try {
    const bytes = Uint8Array.from(mem.read(va, n));
    let printable = 0;
    for (const b of bytes) if (b >= 0x20 && b <= 0x7e) printable++;
    if (printable / bytes.length > 0.75) return quoted(String.fromCharCode(...bytes));
    return `${n}B[${[...bytes.slice(0, 12)].map((b) => b.toString(16).padStart(2, "0")).join(" ")}${n > 12 ? " …" : ""}]`;
  } catch {
    return null;
  }
}

function decodeSockaddr(mem, va) {
  if (va === 0n) return null;
  try {
    const family = mem.u16(va);
    if (family !== 2) return null;
    const port = (mem.u8(va + 2n) << 8) | mem.u8(va + 3n);
    const ip = [0, 1, 2, 3].map((i) => mem.u8(va + 4n + BigInt(i))).join(".");
    return `${ip}:${port}`;
  } catch {
    return null;
  }
}

function decodeArgs(mem, name, args) {
  const [ascii, wide] = ARG_STRINGS[name] ?? [[], []];
  const out = args.map((a) => hex(a));
  for (const i of ascii) {
    if (i >= args.length) continue;
    const s = cstr(mem, args[i]);
    if (s !== null) out[i] = quoted(s);
  }
  for (const i of wide) {
    if (i >= args.length) continue;
    const s = wstr(mem, args[i]);
    if (s !== null) out[i] = quoted(s);
  }
  for (const i of ARG_BUFFERS[name] ?? []) {
    if (i >= args.length) continue;
    const len = args[i + 1] !== undefined ? args[i + 1] : 0n;
    const preview = bufferPreview(mem, args[i], len);
    if (preview) out[i] = preview;
  }
  if (name === "connect" || name === "bind") {
    const sa = decodeSockaddr(mem, args[1]);
    if (sa) out[1] = quoted(sa);
  }
  // generic fallback: pointers that happen to point at readable strings
  for (let i = 0; i < out.length; i++) {
    if (out[i] !== hex(args[i])) continue;
    const a = args[i];
    if (a < 0x10000n) continue;
    const s = cstr(mem, a, 64);
    if (s !== null && s.length >= 5 && /[a-z]/i.test(s)) out[i] = `${hex(a)} ${quoted(s)}`;
  }
  return out;
}

/**
 * @param {Array} events model events ({name,args,ret,retAddr})
 * @param {{mem:object, base:bigint, imageSize:number, name:string}} ctx
 * @returns {{trace:Array, traceText:string}}
 */
export function formatPeTrace(events, { mem, base, imageSize, name, maxStructured = 20000 }) {
  const lines = [];
  const abridged = [];
  const structured = [];
  for (let i = 0; i < events.length; i++) {
    const e = events[i];
    const caller = (() => {
      if (e.retAddr === undefined) return null;
      const ra = BigInt(e.retAddr);
      if (ra >= base && ra < base + BigInt(imageSize)) return `${name}+0x${(ra - base).toString(16)}`;
      return hex(ra);
    })();
    const args = decodeArgs(mem, e.name, e.args ?? []);
    const ret = e.ret !== undefined ? ` -> ${hex(e.ret)}` : "";
    const line = `[${String(i + 1).padStart(4, "0")}] ${caller ? caller.padEnd(28) : "".padEnd(28)} ${e.name}(${args.join(", ")})${ret}`;
    lines.push(line);
    if (isInterestingPeCall(e.name)) abridged.push(line);
    if (structured.length < maxStructured) {
      structured.push({
        seq: i + 1,
        name: e.name,
        caller,
        args: args.map((a, idx) => ({ raw: hex((e.args ?? [])[idx]), decoded: a })),
        ret: e.ret !== undefined ? hex(e.ret) : null,
        text: line,
      });
    }
  }
  return {
    trace: structured,
    traceText: lines.join("\n"),
    traceAbridgedText: abridged.join("\n"),
    traceAbridgedCount: abridged.length,
    traceTotalCount: lines.length,
  };
}
