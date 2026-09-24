/**
 * trace.mjs — decode recorded syscall/libc events into a chronological trace.
 *
 *   [0001] sample.elf+0x12a4  openat(AT_FDCWD, "/etc/passwd", 0x0) -> 0x3
 *   [0002] sample.elf+0x12c0  write(0x1, "hello", 0x5) -> 0x5
 */

const AT_FDCWD = -100n;
const hex = (v) => `0x${BigInt.asUintN(64, BigInt(v ?? 0)).toString(16)}`;
const quoted = (s) => (s === null ? null : JSON.stringify(s));

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
    return s.length >= 1 ? s : null;
  } catch {
    return null;
  }
}

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
    const port = (mem.u8(va + 2n) << 8) | mem.u8(va + 3n);
    if (family === 2) {
      const ip = [0, 1, 2, 3].map((i) => mem.u8(va + 4n + BigInt(i))).join(".");
      return `${ip}:${port}`;
    }
    if (family === 10) return `[inet6]:${port}`;
    return null;
  } catch {
    return null;
  }
}

/** Syscall arity: trailing register garbage is not part of the call. */
const ARITY = {
  read: 3, write: 3, open: 3, close: 1, stat: 2, fstat: 2, lstat: 2, lseek: 3,
  mmap: 6, mprotect: 3, munmap: 2, brk: 1, ioctl: 3, access: 2, pipe: 1, dup: 1, dup2: 2,
  nanosleep: 2, getpid: 0, socket: 3, connect: 3, accept: 3, sendto: 6, recvfrom: 6,
  send: 4, recv: 4, bind: 3, listen: 2, clone: 5, fork: 0, execve: 3, execveat: 5,
  exit: 1, exit_group: 1, wait4: 4, kill: 2, uname: 1, fcntl: 3, getcwd: 2, chdir: 1,
  rename: 2, mkdir: 2, rmdir: 1, creat: 1, unlink: 1, readlink: 3, chmod: 2,
  gettimeofday: 2, ptrace: 4, getuid: 0, getgid: 0, geteuid: 0, getppid: 0,
  arch_prctl: 2, gettid: 0, getdents64: 3, openat: 4, mkdirat: 3, newfstatat: 4,
  unlinkat: 3, renameat: 4, set_robust_list: 2, prlimit64: 4, getrandom: 3, memfd_create: 2,
  epoll_create1: 1, epoll_ctl: 4, epoll_wait: 4, futex: 6, madvise: 3, sched_yield: 0,
  rt_sigaction: 3, rt_sigprocmask: 4, sigaltstack: 2, set_tid_address: 1, sysinfo: 1,
  clock_gettime: 2, getrlimit: 2, statfs: 2, mremap: 5, socketpair: 4, shutdown: 2,
  setsockopt: 5, getsockopt: 5, membarrier: 3, rseq: 4, clone3: 2, poll: 3, select: 5,
};
const LIBC_ARITY = {
  malloc: 1, calloc: 2, realloc: 2, free: 1, memcpy: 3, memmove: 3, memset: 3, memcmp: 3,
  strlen: 1, strcmp: 2, strncmp: 3, strcpy: 2, strncpy: 3, strcat: 2, strstr: 2, strchr: 2,
  strdup: 1, atoi: 1, strtol: 3, printf: 1, puts: 1, putchar: 1, fwrite: 4, fflush: 1,
  __errno_location: 0, __stack_chk_fail: 0, __cxa_atexit: 3, __assert_fail: 4,
  abort: 0, _exit: 1, exit: 1, __libc_start_main: 7,
};

/** Abridged filter: file/network/process/privilege syscalls only. */
const INTERESTING = new Set([
  "open", "openat", "creat", "unlink", "unlinkat", "rename", "renameat", "mkdir", "mkdirat",
  "rmdir", "readlink", "readlinkat", "chmod", "fchmodat", "chown", "truncate", "link", "symlink",
  "execve", "execveat", "clone", "clone3", "fork", "vfork", "kill", "ptrace", "memfd_create",
  "socket", "connect", "bind", "listen", "accept", "accept4", "sendto", "sendmsg", "recvfrom",
  "recvmsg", "setsockopt", "shutdown", "mount", "umount2", "unshare", "setns", "chroot",
  "setuid", "setgid", "setreuid", "capset", "prctl", "seccomp", "ioctl",
]);

export function isInterestingElfCall(name, args) {
  const base = name.startsWith("libc:") ? name.slice(5) : name;
  if (INTERESTING.has(base)) return true;
  // file writes (skip stdout/stderr chatter)
  if (base === "write" || base === "writev") {
    const fd = Number(args?.[0] ?? 0n);
    return fd > 2;
  }
  return false;
}

const PATH_ARG = {
  open: 0, openat: 1, creat: 0, access: 0, unlink: 0, unlinkat: 1, mkdir: 0, rmdir: 0,
  chdir: 0, stat: 0, lstat: 0, readlink: 0, execve: 0, execveat: 1, rename: 0,
  libc: 0,
};

const PATH_ARG2 = { rename: 1, openat: 1 };

const BUFFER_ARG = { write: 1, read: 1, sendto: 1, recvfrom: 1, send: 1, recv: 1, getrandom: 0 };

function readArgv(mem, va) {
  const argv = [];
  if (va === 0n) return argv;
  for (let i = 0; i < 12; i++) {
    let p;
    try { p = mem.u64(va + BigInt(i * 8)); } catch { break; }
    if (p === 0n) break;
    const s = cstr(mem, p, 64);
    if (s === null) break;
    argv.push(s);
  }
  return argv;
}

function decodeArgs(mem, name, args) {
  const out = args.map((a) => (name === "openat" && args.indexOf(a) === 0 && a === 0xffffffffffffff9cn ? "AT_FDCWD" : hex(a)));
  const pathIdx = PATH_ARG[name];
  if (pathIdx !== undefined && pathIdx < args.length) {
    const s = cstr(mem, args[pathIdx]);
    if (s !== null) out[pathIdx] = quoted(s);
  }
  if (name === "rename" && args.length > 1) {
    const s = cstr(mem, args[1]);
    if (s !== null) out[1] = quoted(s);
  }
  const bufIdx = BUFFER_ARG[name];
  if (bufIdx !== undefined && bufIdx < args.length) {
    const len = args[bufIdx + 1] ?? 0n;
    const preview = bufferPreview(mem, args[bufIdx], len);
    if (preview) out[bufIdx] = preview;
  }
  if (name === "connect" || name === "bind") {
    const sa = decodeSockaddr(mem, args[1]);
    if (sa) out[1] = quoted(sa);
  }
  if ((name === "execve" || name === "execveat") && args.length > 1) {
    const argvIdx = name === "execve" ? 1 : 2;
    if (argvIdx < args.length) {
      const argv = readArgv(mem, args[argvIdx]);
      if (argv.length) out[argvIdx] = `[${argv.map((a) => quoted(a)).join(", ")}]`;
    }
  }
  if (name === "ptrace" && args.length) {
    const req = BigInt.asIntN(64, BigInt(args[0] ?? 0n));
    const names = { 0n: "PTRACE_TRACEME", 1n: "PTRACE_PEEKTEXT", 16n: "PTRACE_ATTACH", 17n: "PTRACE_DETACH" };
    if (names[req]) out[0] = `${hex(args[0])} ${names[req]}`;
  }
  return out;
}

/**
 * @param {Array} events model events ({name,args,ret,retAddr})
 * @param {{mem:object, bias:bigint, imageSize:number, name:string}} ctx
 */
export function formatElfTrace(events, { mem, moduleBase = 0n, moduleSize = 0, name, maxStructured = 20000 }) {
  const lines = [];
  const abridged = [];
  const structured = [];
  for (let i = 0; i < events.length; i++) {
    const e = events[i];
    const caller = (() => {
      if (e.retAddr === undefined) return null;
      const ra = BigInt(e.retAddr);
      if (ra >= moduleBase && ra < moduleBase + BigInt(moduleSize || 0)) return `${name}+0x${(ra - moduleBase).toString(16)}`;
      return hex(ra);
    })();
    const arity = e.name.startsWith("libc:")
      ? LIBC_ARITY[e.name.slice(5)]
      : ARITY[e.name];
    const rawArgs = (e.args ?? []).slice(0, arity === undefined ? e.args?.length ?? 0 : arity);
    const args = decodeArgs(mem, e.name, rawArgs);
    const ret = e.ret !== undefined ? ` -> ${hex(e.ret)}` : "";
    const line = `[${String(i + 1).padStart(4, "0")}] ${caller ? caller.padEnd(28) : "".padEnd(28)} ${e.name}(${args.join(", ")})${ret}`;
    lines.push(line);
    if (isInterestingElfCall(e.name, rawArgs)) abridged.push(line);
    if (structured.length < maxStructured) {
      structured.push({
        seq: i + 1,
        name: e.name,
        caller,
        args: args.map((a, idx) => ({ raw: hex(rawArgs[idx]), decoded: a })),
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
