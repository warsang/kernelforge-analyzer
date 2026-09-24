/**
 * linux.mjs — Tier-1 x86-64 Linux syscall model.
 *
 * Records intent (files, sockets, processes, ptrace, mmap) and returns
 * plausible results so the sample keeps running. Unknown syscalls are
 * recorded as unmodeled and return -ENOSYS (fail-open for triage).
 */

const M64 = (1n << 64n) - 1n;
const u64 = (v) => BigInt.asUintN(64, BigInt(v ?? 0));
const i64 = (v) => BigInt.asIntN(64, BigInt(v ?? 0));

/** x86-64 syscall numbers used by the model. */
export const SYSCALLS = {
  0: "read", 1: "write", 2: "open", 3: "close", 4: "stat", 5: "fstat", 6: "lstat",
  7: "poll", 8: "lseek", 9: "mmap", 10: "mprotect", 11: "munmap", 12: "brk",
  13: "rt_sigaction", 14: "rt_sigprocmask", 16: "ioctl", 17: "pread64", 18: "pwrite64",
  20: "writev", 21: "access", 22: "pipe", 23: "select", 24: "sched_yield",
  25: "mremap", 28: "madvise", 32: "dup", 33: "dup2", 35: "nanosleep",
  39: "getpid", 41: "socket", 42: "connect", 43: "accept", 44: "sendto",
  45: "recvfrom", 46: "sendmsg", 47: "recvmsg", 48: "shutdown", 49: "bind",
  50: "listen", 51: "getsockname", 52: "getpeername", 53: "socketpair",
  54: "setsockopt", 55: "getsockopt", 56: "clone", 57: "fork", 58: "vfork",
  59: "execve", 60: "exit", 61: "wait4", 62: "kill", 63: "uname",
  72: "fcntl", 73: "flock", 74: "fsync", 78: "getdents", 79: "getcwd",
  80: "chdir", 82: "rename", 83: "mkdir", 84: "rmdir", 85: "creat", 86: "link",
  87: "unlink", 88: "symlink", 89: "readlink", 90: "chmod", 92: "chown",
  95: "umask", 96: "gettimeofday", 97: "getrlimit", 99: "sysinfo",
  101: "ptrace", 102: "getuid", 104: "getgid", 107: "geteuid", 108: "getegid",
  110: "getppid", 111: "getpgrp", 112: "setsid", 113: "setreuid",
  131: "sigaltstack", 137: "statfs", 158: "arch_prctl", 186: "gettid",
  202: "futex", 217: "getdents64", 218: "set_tid_address", 228: "clock_gettime",
  231: "exit_group", 232: "epoll_wait", 233: "epoll_ctl", 257: "openat",
  258: "mkdirat", 262: "newfstatat", 263: "unlinkat", 264: "renameat",
  273: "set_robust_list", 281: "epoll_pwait", 288: "accept4", 291: "epoll_create1",
  293: "pipe2", 302: "prlimit64", 318: "getrandom", 319: "memfd_create",
  322: "execveat", 324: "membarrier", 334: "rseq", 435: "clone3",
};

const SOCK = { AF_INET: 2, AF_INET6: 10 };

export function createLinuxModel({ mem, cpu, alloc }) {
  const artifacts = {
    files: [],
    network: [],
    processes: [],
    commands: [],
    ptrace: [],
    mmaps: [],
    stdout: [],
    debug: [],
  };
  const MAX = 256;
  const push = (list, item) => { if (list.length < MAX) list.push(item); };
  const events = [];
  const MAX_EVENTS = 4096;
  const fds = new Map([[0, { kind: "stdin" }], [1, { kind: "stdout" }], [2, { kind: "stderr" }]]);
  let nextFd = 3;
  let nextMmap = 0x0000000001000000n;
  let brk = 0x0000000003000000n;
  let sockId = 0;
  const model = { artifacts, events, unmodeled: new Set(), exited: false, exitCode: null };

  const cstr = (va, max = 512) => {
    let s = "";
    for (let i = 0; i < max; i++) {
      let b;
      try { b = mem.u8(u64(va) + BigInt(i)); } catch { break; }
      if (b === 0) break;
      s += String.fromCharCode(b);
    }
    return s;
  };
  const readBytes = (va, len) => {
    try { return Uint8Array.from(mem.read(u64(va), Math.min(Number(len) || 0, 4096))); } catch { return new Uint8Array(0); }
  };
  const allocFd = (obj) => { const fd = nextFd++; fds.set(fd, obj); return fd; };

  const record = (name, args, ret) => {
    if (events.length < MAX_EVENTS) {
      events.push({ name, args: args.slice(0, 6).map((a) => u64(a)), ret: ret === undefined ? undefined : i64(ret) });
    }
  };

  const handlers = {
    write: (_c, [fd, buf, len]) => {
      const f = fds.get(Number(u64(fd)));
      const n = Math.min(Number(u64(len)) || 0, 4096);
      const data = readBytes(buf, n);
      if (f?.kind === "stdout" || f?.kind === "stderr") {
        push(artifacts.stdout, { text: String.fromCharCode(...data).replace(/\0/g, "") });
      } else if (f?.kind === "file") {
        f.data = Uint8Array.from([...(f.data ?? []), ...data]).slice(0, 1 << 20);
        push(artifacts.files, { action: "write", path: f.path, bytes: n });
      }
      return BigInt(n);
    },
    read: (_c, [fd, buf, len]) => {
      const f = fds.get(Number(u64(fd)));
      const n = Math.min(Number(u64(len)) || 0, 4096);
      if (f?.kind === "file" && f.data?.length) {
        const chunk = f.data.slice(0, n);
        if (u64(buf)) mem.write(u64(buf), chunk);
        f.data = f.data.slice(chunk.length);
        return BigInt(chunk.length);
      }
      return 0n; // EOF
    },
    open: (_c, [pathVa, flags]) => openFile(cstr(pathVa), flags),
    openat: (_c, [_dirfd, pathVa, flags]) => openFile(cstr(pathVa), flags),
    creat: (_c, [pathVa]) => openFile(cstr(pathVa), 0x41),
    close: (_c, [fd]) => { fds.delete(Number(u64(fd))); return 0n; },
    access: (_c, [pathVa]) => {
      push(artifacts.files, { action: "access", path: cstr(pathVa) });
      return 0n;
    },
    unlink: (_c, [pathVa]) => {
      push(artifacts.files, { action: "delete", path: cstr(pathVa) });
      return 0n;
    },
    unlinkat: (_c, [_d, pathVa]) => {
      push(artifacts.files, { action: "delete", path: cstr(pathVa) });
      return 0n;
    },
    rename: (_c, [from, to]) => {
      push(artifacts.files, { action: "move", path: cstr(to), from: cstr(from) });
      return 0n;
    },
    mkdir: (_c, [pathVa]) => {
      push(artifacts.files, { action: "mkdir", path: cstr(pathVa) });
      return 0n;
    },
    mmap: (_c, [addr, len, _prot, _flags, _fd, _off]) => {
      const size = Number(u64(len)) || 0x1000;
      const va = u64(addr) !== 0n ? u64(addr) : nextMmap;
      nextMmap += BigInt((size + 0xfff) & ~0xfff);
      push(artifacts.mmaps, { addr: `0x${va.toString(16)}`, size, prot: Number(u64(_prot)) });
      return va;
    },
    mprotect: () => 0n,
    munmap: () => 0n,
    brk: (_c, [addr]) => {
      if (u64(addr) !== 0n) brk = u64(addr);
      return brk;
    },
    socket: (_c, [domain, type, _proto]) => {
      sockId++;
      return BigInt(allocFd({ kind: "socket", domain: Number(u64(domain)), type: Number(u64(type)) }));
    },
    connect: (_c, [fd, addrVa, addrlen]) => {
      const info = parseSockaddr(addrVa, addrlen);
      push(artifacts.network, { action: "connect", fd: Number(u64(fd)), ...info });
      return 0n;
    },
    bind: (_c, [fd, addrVa, addrlen]) => {
      const info = parseSockaddr(addrVa, addrlen);
      push(artifacts.network, { action: "bind", fd: Number(u64(fd)), ...info });
      return 0n;
    },
    listen: () => 0n,
    accept: () => BigInt(allocFd({ kind: "socket" })),
    accept4: () => BigInt(allocFd({ kind: "socket" })),
    sendto: (_c, [fd, _buf, len]) => {
      push(artifacts.network, { action: "send", fd: Number(u64(fd)), bytes: Math.min(Number(u64(len)) || 0, 4096) });
      return BigInt(Math.min(Number(u64(len)) || 0, 4096));
    },
    recvfrom: () => 0n,
    sendmsg: () => 0n,
    recvmsg: () => 0n,
    execve: (_c, [pathVa, argvVa]) => {
      const path = cstr(pathVa);
      const argv = readArgv(argvVa);
      push(artifacts.processes, { action: "execve", path, argv });
      push(artifacts.commands, { api: "execve", command: [path, ...argv].join(" ") });
      return 0n;
    },
    execveat: (_c, [_fd, pathVa, argvVa]) => {
      const path = cstr(pathVa);
      push(artifacts.processes, { action: "execveat", path, argv: readArgv(argvVa) });
      return 0n;
    },
    clone: () => 0x200n,
    clone3: () => 0x200n,
    fork: () => 0x200n,
    vfork: () => 0x200n,
    ptrace: (_c, [request, _pid, _addr, _data]) => {
      push(artifacts.ptrace, { request: Number(u64(request)) });
      return 0n;
    },
    getrandom: (_c, [buf, len]) => {
      const n = Math.min(Number(u64(len)) || 0, 256);
      if (u64(buf)) mem.write(u64(buf), Uint8Array.from({ length: n }, (_, i) => (i * 37 + 11) & 0xff));
      return BigInt(n);
    },
    uname: (_c, [buf]) => {
      if (u64(buf)) {
        mem.write(u64(buf), new Uint8Array(390));
        const s = "Linux";
        for (let i = 0; i < s.length; i++) mem.w8(u64(buf) + 260n + BigInt(i), s.charCodeAt(i));
      }
      return 0n;
    },
    fstat: (_c, [_fd, buf]) => fillStat(buf),
    newfstatat: (_c, [_d, _path, buf, _flags]) => fillStat(buf),
    stat: (_c, [_path, buf]) => fillStat(buf),
    lstat: (_c, [_path, buf]) => fillStat(buf),
    lseek: () => 0n,
    fcntl: () => 0n,
    ioctl: () => 0n,
    dup: (_c, [fd]) => BigInt(allocFd({ ...(fds.get(Number(u64(fd))) ?? {}) })),
    dup2: (_c, [_a, b]) => u64(b),
    pipe: (_c, [fdsVa]) => {
      if (u64(fdsVa)) { mem.w32(u64(fdsVa), 10); mem.w32(u64(fdsVa) + 4n, 11); }
      return 0n;
    },
    pipe2: (_c, [fdsVa]) => handlers.pipe(null, [fdsVa]),
    getpid: () => 4242n,
    getppid: () => 1n,
    gettid: () => 4243n,
    getuid: () => 1000n,
    geteuid: () => 1000n,
    getgid: () => 1000n,
    getegid: () => 1000n,
    nanosleep: () => 0n,
    clock_gettime: (_c, [_clock, buf]) => {
      if (u64(buf)) { mem.w64(u64(buf), 1700000000n); mem.w64(u64(buf) + 8n, 0n); }
      return 0n;
    },
    gettimeofday: (_c, [buf]) => {
      if (u64(buf)) { mem.w64(u64(buf), 1700000000n); mem.w64(u64(buf) + 8n, 0n); }
      return 0n;
    },
    getcwd: (_c, [buf, size]) => {
      const p = "/home/kf";
      if (u64(buf)) {
        for (let i = 0; i < p.length; i++) mem.w8(u64(buf) + BigInt(i), p.charCodeAt(i));
        mem.w8(u64(buf) + BigInt(p.length), 0);
      }
      void size;
      return u64(buf);
    },
    chdir: () => 0n,
    rt_sigaction: () => 0n,
    rt_sigprocmask: () => 0n,
    sigaltstack: () => 0n,
    set_tid_address: () => 4243n,
    set_robust_list: () => 0n,
    prlimit64: () => 0n,
    arch_prctl: () => 0n,
    membarrier: () => 0n,
    rseq: () => 0n,
    futex: () => 0n,
    sched_yield: () => 0n,
    madvise: () => 0n,
    mremap: () => 0n,
    kill: () => 0n,
    wait4: () => 0n,
    epoll_create1: () => BigInt(allocFd({ kind: "epoll" })),
    epoll_ctl: () => 0n,
    epoll_wait: () => 0n,
    epoll_pwait: () => 0n,
    getdents: () => 0n,
    getdents64: () => 0n,
    getrlimit: (_c, [_res, buf]) => {
      if (u64(buf)) { mem.w64(u64(buf), M64); mem.w64(u64(buf) + 8n, M64); }
      return 0n;
    },
    sysinfo: (_c, [buf]) => {
      if (u64(buf)) mem.write(u64(buf), new Uint8Array(112));
      return 0n;
    },
    exit: (_c, [code]) => exitProcess(code),
    exit_group: (_c, [code]) => exitProcess(code),
  };

  function exitProcess(code) {
    model.exited = true;
    model.exitCode = Number(i64(code));
    cpu.halted = true;
    return undefined;
  }
  function openFile(path, flags) {
    const fd = allocFd({ kind: "file", path, write: (Number(u64(flags)) & 0x3) !== 0, data: new Uint8Array(0) });
    push(artifacts.files, { action: (Number(u64(flags)) & 0x40) ? "create" : "open", path, fd });
    return BigInt(fd);
  }
  function fillStat(buf) {
    if (u64(buf)) {
      mem.write(u64(buf), new Uint8Array(144));
      mem.w32(u64(buf) + 24n, 0x81a4); // S_IFREG | 0644
      mem.w64(u64(buf) + 48n, 4096);
    }
    return 0n;
  }
  function readArgv(argvVa) {
    const argv = [];
    if (u64(argvVa) === 0n) return argv;
    for (let i = 0; i < 16; i++) {
      let p;
      try { p = mem.u64(u64(argvVa) + BigInt(i * 8)); } catch { break; }
      if (p === 0n) break;
      argv.push(cstr(p, 256));
    }
    return argv;
  }
  function parseSockaddr(addrVa, addrlen) {
    try {
      const family = mem.u16(u64(addrVa));
      if (family === SOCK.AF_INET) {
        const port = (mem.u8(u64(addrVa) + 2n) << 8) | mem.u8(u64(addrVa) + 3n);
        const ip = [0, 1, 2, 3].map((i) => mem.u8(u64(addrVa) + 4n + BigInt(i))).join(".");
        return { family: "AF_INET", host: ip, port };
      }
      if (family === SOCK.AF_INET6) {
        return { family: "AF_INET6", host: "<inet6>", port: (mem.u8(u64(addrVa) + 2n) << 8) | mem.u8(u64(addrVa) + 3n) };
      }
      return { family: `0x${family.toString(16)}`, addrlen: Number(u64(addrlen)) || 0 };
    } catch {
      return { family: "unknown" };
    }
  }

  model.dispatch = (nr, args) => {
    const name = SYSCALLS[Number(nr)] ?? `syscall_${nr}`;
    const fn = handlers[name];
    let ret;
    if (!fn) {
      model.unmodeled.add(name);
      ret = -38n; // -ENOSYS
    } else {
      try { ret = fn(model, args); } catch { ret = 0n; }
    }
    record(name, args, ret);
    return ret === undefined ? undefined : u64(ret);
  };
  return model;
}
