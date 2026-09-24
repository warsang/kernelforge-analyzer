/**
 * threads.mjs — guest threads, synchronization objects, TLS/FLS and APCs for
 * the userland PE harness.
 *
 * Determinism model (single CPU, eager scheduling): `CreateThread` runs the
 * thread routine to completion on its own stack before returning, so
 * "spawn a worker + wait for it" patterns behave predictably; a thread that
 * never returns is bounded by the global instruction budget. Objects
 * (events/mutexes) carry honest signalled/owned state, and alertable waits
 * drain queued APCs. Registered into the Win32 model via `model.register()`.
 */

const CALLEE_SAVED = ["rbx", "rbp", "rsi", "rdi", "r12", "r13", "r14", "r15"];
const INFINITE = 0xffffffff;
const WAIT_OBJECT_0 = 0n;
const WAIT_TIMEOUT = 0x102n;
const WAIT_IO_COMPLETION = 0xc0n;
const STILL_ACTIVE = 0x103n;

const u64 = (v) => BigInt.asUintN(64, BigInt(v ?? 0n));
const u32 = (v) => Number(u64(v) & 0xffffffffn);

/**
 * @param {{mem:object, cpu:object, model:object, alloc:(n:number)=>bigint,
 *   call:(addr:bigint, args:bigint[])=>object, stackSize?:number}} env
 * @returns {{handlers:Record<string,Function>, threads:object[], state:object}}
 */
export function createThreadManager({ mem, cpu, model, alloc, call, stackSize = 0x100000 }) {
  const threads = new Map();   // handle -> {handle, tid, stack, status, retval, exited}
  const events = new Map();    // handle -> {handle, manual, signalled, name}
  const mutexes = new Map();   // handle -> {handle, owner, name}
  const tlsSlots = new Map();  // index -> Map(tid -> value)
  const flsSlots = new Map();
  const apcs = new Map();      // tid -> [{fn, param, done}]
  const names = new Map();     // "event:name" / "mutex:name" -> handle

  let handleSeq = 0x300n;
  let tidSeq = 0x600n;
  const mainTid = 0x4b0n;
  let currentTid = mainTid;
  const nextHandle = () => (handleSeq += 4n);

  const pushDebug = (text) => {
    try { model.artifacts?.debugStrings?.push?.({ text }); } catch { /* optional */ }
  };

  function runThread(rec, startRoutine, param) {
    const savedRegs = {};
    for (const r of CALLEE_SAVED) savedRegs[r] = cpu.regs[r];
    const savedRsp = cpu.regs.rsp;
    const prevTid = currentTid;
    currentTid = rec.tid;
    try {
      cpu.regs.rsp = (rec.stack + BigInt(stackSize) - 0x100n) & ~0xfn;
      const r = call(startRoutine, [param]);
      rec.status = r?.status ?? "?";
      rec.retval = r?.retval ?? 0n;
      rec.error = r?.error ? String(r.error.message ?? r.error) : undefined;
    } catch (e) {
      rec.status = "fault";
      rec.error = String(e?.message ?? e);
    } finally {
      for (const r of CALLEE_SAVED) cpu.regs[r] = savedRegs[r];
      cpu.regs.rsp = savedRsp;
      cpu.halted = false; // a thread calling ExitThread must not kill the world
      currentTid = prevTid;
      rec.exited = true;
    }
    model.events.push({
      name: `[thread] tid 0x${rec.tid.toString(16)} ${rec.status}`,
      args: [],
      ret: rec.retval,
    });
  }

  function makeThread(startRoutine, param, tidOut) {
    const rec = {
      handle: nextHandle(),
      tid: (tidSeq += 4n),
      stack: alloc(stackSize),
      status: null,
      retval: 0n,
      exited: false,
    };
    try { mem.write(rec.stack, new Uint8Array(0x100)); } catch { /* optional */ }
    threads.set(rec.handle, rec);
    if (u64(tidOut)) { try { mem.w32(u64(tidOut), u32(rec.tid)); } catch { /* optional */ } }
    runThread(rec, startRoutine, param);
    return rec.handle;
  }

  function isSignalled(handle) {
    const h = u64(handle);
    if (threads.has(h)) return threads.get(h).exited;
    if (events.has(h)) return events.get(h).signalled;
    if (mutexes.has(h)) return true; // owned by the (single) running thread
    return true;                      // pseudo handles (-1/-2) / unknown: signalled
  }

  function drainApcs() {
    const list = apcs.get(currentTid);
    if (!list?.length) return 0;
    let ran = 0;
    while (list.length) {
      const a = list.shift();
      if (a.done) continue;
      a.done = true;
      ran++;
      try { call(u64(a.fn), [u64(a.param)]); } catch (e) {
        pushDebug(`[apc] routine 0x${u64(a.fn).toString(16)} faulted: ${String(e?.message ?? e)}`);
      }
    }
    return ran;
  }

  const handlers = {
    // ---- threads ---------------------------------------------------------
    CreateThread: (_c, [sa, size, start, param, flags, tidOut]) => {
      void sa; void size; void flags;
      model.artifacts?.processes?.push?.({ action: "create-thread", target: `0x${u64(start).toString(16)}` });
      return makeThread(u64(start), u64(param), tidOut);
    },
    CreateRemoteThread: (_c, [proc, sa, size, start, param, flags, tidOut]) => {
      void proc; void sa; void size; void flags;
      pushDebug(`[thread] CreateRemoteThread -> same-process (start 0x${u64(start).toString(16)})`);
      return makeThread(u64(start), u64(param), tidOut);
    },
    CreateRemoteThreadEx: (_c, a) => handlers.CreateRemoteThread(null, a),
    QueueUserWorkItem: (_c, [fn, ctx, _flags]) => {
      makeThread(u64(fn), u64(ctx), 0n);
      return 1n;
    },
    ExitThread: (_c, [code]) => {
      model.threadExit = u32(code);
      cpu.halted = true;
      return undefined;
    },
    GetExitCodeThread: (_c, [h, out]) => {
      const t = threads.get(u64(h));
      if (u64(out)) { try { mem.w32(u64(out), t?.exited ? u32(t.retval) : u32(STILL_ACTIVE)); } catch { /* optional */ } }
      return 1n;
    },
    GetCurrentThreadId: () => currentTid,
    GetCurrentThread: () => 0xfffffffffffffffen, // pseudo handle -2
    GetCurrentProcessId: () => 0x4b0n,
    TlsAlloc: () => {
      const idx = tlsSlots.size;
      tlsSlots.set(idx, new Map());
      return BigInt(idx);
    },
    TlsSetValue: (_c, [idx, val]) => {
      const slot = tlsSlots.get(Number(u64(idx)));
      if (!slot) return 0n;
      slot.set(currentTid, u64(val));
      return 1n;
    },
    TlsGetValue: (_c, [idx]) => tlsSlots.get(Number(u64(idx)))?.get(currentTid) ?? 0n,
    TlsFree: (_c, [idx]) => { tlsSlots.delete(Number(u64(idx))); return 1n; },
    FlsAlloc: (_c, [_cb]) => {
      const idx = flsSlots.size;
      flsSlots.set(idx, new Map());
      return BigInt(idx);
    },
    FlsSetValue: (_c, [idx, val]) => {
      const slot = flsSlots.get(Number(u64(idx)));
      if (!slot) return 0n;
      slot.set(currentTid, u64(val));
      return 1n;
    },
    FlsGetValue: (_c, [idx]) => flsSlots.get(Number(u64(idx)))?.get(currentTid) ?? 0n,
    FlsFree: (_c, [idx]) => { flsSlots.delete(Number(u64(idx))); return 1n; },

    // ---- synchronization -------------------------------------------------
    CreateEventA: (_c, [_sa, manual, initial, nameVa]) => handlers.CreateEventW(null, [0n, manual, initial, nameVa]),
    CreateEventW: (_c, [_sa, manual, initial, nameVa]) => {
      let name = "";
      try {
        const len = Number(u64(nameVa));
        if (len) name = ""; // narrow/wide name best-effort below
      } catch { /* optional */ }
      if (nameVa) {
        try { name = String.fromCharCode(...mem.read(u64(nameVa), 64)).split("\0")[0]; } catch { /* optional */ }
      }
      const key = name ? `event:${name}` : null;
      if (key && names.has(key)) return names.get(key);
      const rec = { handle: nextHandle(), manual: u64(manual) !== 0n, signalled: u64(initial) !== 0n, name };
      events.set(rec.handle, rec);
      if (key) names.set(key, rec.handle);
      return rec.handle;
    },
    OpenEventA: (_c, [_access, _inherit, nameVa]) => handlers.OpenEventW(null, [0n, 0n, nameVa]),
    OpenEventW: (_c, a) => handlers.CreateEventW(null, [0n, 0n, 0n, a[2]]),
    SetEvent: (_c, [h]) => {
      const e = events.get(u64(h));
      if (e) { e.signalled = true; return 1n; }
      return 1n;
    },
    ResetEvent: (_c, [h]) => {
      const e = events.get(u64(h));
      if (e) e.signalled = false;
      return 1n;
    },
    PulseEvent: (_c, [h]) => {
      const e = events.get(u64(h));
      if (e) e.signalled = false;
      return 1n;
    },
    CreateMutexA: (_c, [_sa, owner, nameVa]) => handlers.CreateMutexW(null, [0n, owner, nameVa]),
    CreateMutexW: (_c, [_sa, owner, nameVa]) => {
      const rec = { handle: nextHandle(), owner: u64(owner) !== 0n ? currentTid : null };
      mutexes.set(rec.handle, rec);
      if (nameVa) {
        try { const n = String.fromCharCode(...mem.read(u64(nameVa), 64)).split("\0")[0]; if (n) names.set(`mutex:${n}`, rec.handle); } catch { /* optional */ }
      }
      return rec.handle;
    },
    OpenMutexA: (_c, [_access, _inherit, nameVa]) => handlers.CreateMutexW(null, [0n, 0n, nameVa]),
    OpenMutexW: (_c, [_access, _inherit, nameVa]) => handlers.CreateMutexW(null, [0n, 0n, nameVa]),
    ReleaseMutex: (_c, [h]) => {
      const m = mutexes.get(u64(h));
      if (m) m.owner = null;
      return 1n;
    },
    WaitForSingleObject: (_c, [h, ms]) => {
      if (isSignalled(h)) return WAIT_OBJECT_0;
      return u64(ms) === BigInt(INFINITE) ? WAIT_OBJECT_0 : WAIT_TIMEOUT;
    },
    WaitForSingleObjectEx: (_c, [h, ms, alertable]) => {
      if (u64(alertable) && drainApcs() > 0) return WAIT_IO_COMPLETION;
      return handlers.WaitForSingleObject(null, [h, ms]);
    },
    WaitForMultipleObjects: (_c, [count, ptr, waitAll, ms]) => {
      const n = Math.min(Number(u64(count)) || 0, 64);
      const handles = [];
      for (let i = 0; i < n; i++) {
        try { handles.push(mem.u64(u64(ptr) + BigInt(i * 8))); } catch { handles.push(0n); }
      }
      const sig = handles.map((x) => isSignalled(x));
      if (u64(waitAll) ? sig.every(Boolean) : sig.some(Boolean)) return WAIT_OBJECT_0;
      return u64(ms) === BigInt(INFINITE) ? WAIT_OBJECT_0 : WAIT_TIMEOUT;
    },
    WaitForMultipleObjectsEx: (_c, [count, ptr, waitAll, ms, alertable]) => {
      if (u64(alertable) && drainApcs() > 0) return WAIT_IO_COMPLETION;
      return handlers.WaitForMultipleObjects(null, [count, ptr, waitAll, ms]);
    },
    Sleep: (_c, [ms]) => {
      model.tick = (model.tick ?? 0) + Number(u64(ms));
      return undefined;
    },
    SleepEx: (_c, [ms, alertable]) => {
      model.tick = (model.tick ?? 0) + Number(u64(ms));
      if (u64(alertable) && drainApcs() > 0) return 0x192n; // WAIT_IO_COMPLETION (SleepEx)
      return 0n;
    },
    QueueUserAPC: (_c, [fn, hThread, param]) => {
      const t = threads.get(u64(hThread));
      const tid = t?.tid ?? currentTid;
      const list = apcs.get(tid) ?? [];
      list.push({ fn: u64(fn), param: u64(param), done: false });
      apcs.set(tid, list);
      pushDebug(`[apc] queued 0x${u64(fn).toString(16)} for tid 0x${tid.toString(16)}`);
      return 1n;
    },
  };

  model.threads = threads;
  model.threadState = () => [...threads.values()].map((t) => ({
    tid: `0x${t.tid.toString(16)}`,
    status: t.status,
    retval: `0x${t.retval.toString(16)}`,
    exited: t.exited,
    error: t.error,
  }));

  return { handlers, threads, state: { events, mutexes, tlsSlots, flsSlots, apcs } };
}
