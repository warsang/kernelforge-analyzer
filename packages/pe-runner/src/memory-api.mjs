/**
 * memory-api.mjs — Windows memory/heap API surface backed by MemoryManager and
 * HeapAllocator (VirtualAlloc state machine, protections, guard pages, heap).
 */

import { PROT, MEM } from "./memory.mjs";

const u64 = (v) => BigInt.asUintN(64, BigInt(v ?? 0n));
const align4k = (v) => BigInt(v) & ~0xfffn;
const MEM_ZERO = 0x8; // HEAP_ZERO_MEMORY
const PROCESS_HEAP = 0x100n;

export function createMemoryApiHandlers({ mm, heap }) {
  let nextVa = 0x0000000200000000n; // scratch VA window for addr=0 allocations

  const reserveAt = (size, hint) => {
    const base = hint ? align4k(hint) : nextVa;
    if (!hint) nextVa = (nextVa + size + 0xffffn) & ~0xffffn;
    return base;
  };

  const doAlloc = (addr, size, type, protect) => {
    const sz = align4k(u64(size) || 0x1000n);
    if (sz <= 0n) return 0n;
    const t = Number(u64(type));
    const base = reserveAt(sz, u64(addr));
    const state = (t & MEM.COMMIT) ? "commit" : "reserve";
    const prot = Number(u64(protect)) || PROT.READWRITE;
    // Commit on top of an existing reservation extends it.
    const existing = mm.find(base);
    if (t === MEM.COMMIT && existing) {
      existing.state = "commit";
      existing.protect = prot;
      mm.write(base, new Uint8Array(Number(sz)));
      return base;
    }
    mm.map(base, sz, { protect: prot, state });
    return base;
  };

  const handlers = {
    // ---- virtual memory --------------------------------------------------
    VirtualAlloc: (_c, [addr, size, type, protect]) => doAlloc(addr, size, type, protect),
    VirtualAllocEx: (_c, [_p, addr, size, type, protect]) => doAlloc(addr, size, type, protect),
    VirtualFree: (_c, [addr, size, type]) => {
      const t = Number(u64(type));
      if (t & MEM.RELEASE) return mm.free(addr, size, MEM.RELEASE);
      if (t & MEM.DECOMMIT) return mm.free(addr, size, MEM.DECOMMIT);
      return 1n;
    },
    VirtualFreeEx: (_c, [_p, addr, size, type]) => handlers.VirtualFree(null, [addr, size, type]),
    VirtualProtect: (_c, [addr, size, newProtect, oldPtr]) => {
      const old = mm.protect(addr, size, Number(u64(newProtect)));
      if (u64(oldPtr)) { try { mm.w32(u64(oldPtr), old); } catch { /* optional */ } }
      return 1n;
    },
    VirtualProtectEx: (_c, [_p, addr, size, newProtect, oldPtr]) => handlers.VirtualProtect(null, [addr, size, newProtect, oldPtr]),
    VirtualQuery: (_c, [addr, buf, len]) => {
      if (!u64(buf) || u64(len) < 48n) return 0n;
      const q = mm.query(addr);
      const b = u64(buf);
      mm.w64(b, q.base);
      mm.w64(b + 8n, q.base);
      mm.w32(b + 16n, q.protect);
      mm.w64(b + 24n, q.size);
      mm.w32(b + 32n, q.state);
      mm.w32(b + 36n, q.protect);
      mm.w32(b + 40n, q.type);
      return 48n;
    },
    VirtualQueryEx: (_c, [_p, addr, buf, len]) => handlers.VirtualQuery(null, [addr, buf, len]),
    VirtualLock: () => 1n,
    VirtualUnlock: () => 1n,

    // ---- heap ------------------------------------------------------------
    GetProcessHeap: () => PROCESS_HEAP,
    HeapCreate: () => PROCESS_HEAP,
    HeapDestroy: () => 1n,
    HeapAlloc: (_c, [_h, flags, size]) => heap.alloc(u64(size) || 1n, { zero: (Number(u64(flags)) & MEM_ZERO) !== 0 }),
    HeapFree: (_c, [_h, _flags, p]) => (heap.free(u64(p)) ? 1n : 0n),
    HeapReAlloc: (_c, [_h, flags, p, size]) => heap.realloc(u64(p), u64(size) || 1n),
    HeapSize: (_c, [_h, _flags, p]) => heap.size(u64(p)),
    HeapValidate: (_c, [_h, _flags, _p]) => (heap.validate() ? 1n : 0n),
    RtlAllocateHeap: (_c, [_h, flags, size]) => handlers.HeapAlloc(null, [0n, flags, size]),
    RtlFreeHeap: (_c, [_h, _flags, p]) => handlers.HeapFree(null, [0n, 0n, p]),
    RtlReAllocateHeap: (_c, [_h, flags, p, size]) => handlers.HeapReAlloc(null, [0n, flags, p, size]),
    RtlSizeHeap: (_c, [_h, _flags, p]) => heap.size(u64(p)),
    LocalAlloc: (_c, [_flags, size]) => heap.alloc(u64(size) || 1n),
    LocalFree: () => 0n,
    GlobalAlloc: (_c, [_flags, size]) => heap.alloc(u64(size) || 1n),
    GlobalFree: () => 0n,
  };

  return handlers;
}
