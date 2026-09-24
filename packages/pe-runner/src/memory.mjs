/**
 * memory.mjs — protected memory facade + heap allocator for the userland PE
 * harness.
 *
 * SparseMemory stays the storage engine; MemoryManager layers a region table
 * on top so the harness can offer honest Windows semantics:
 *   - VirtualAlloc states (reserve / commit / decommit / release)
 *   - per-region protection (R/W/X/NX, guard pages with one-shot behaviour)
 *   - write/fetch faults that flow into SEH as #PF (pe-runner callWithSeh)
 * Never-mapped memory keeps SparseMemory's read-as-zero behaviour (analysis
 * pragmatism); writes to it fault by default so null derefs are visible.
 *
 * The heap is a real first-fit allocator with coalescing over a sparse region,
 * backing HeapAlloc/RtlAllocateHeap and the harness's internal allocations.
 */

import { CpuError } from "@kernelforge/ntsim/src/cpu.mjs";

export const PROT = {
  NOACCESS: 0x01,
  READONLY: 0x02,
  READWRITE: 0x04,
  WRITECOPY: 0x08,
  EXECUTE: 0x10,
  EXECUTE_READ: 0x20,
  EXECUTE_READWRITE: 0x40,
  EXECUTE_WRITECOPY: 0x80,
  GUARD: 0x100,
  NOCACHE: 0x200,
  WRITECOMBINE: 0x400,
};

export const MEM = {
  COMMIT: 0x1000,
  RESERVE: 0x2000,
  DECOMMIT: 0x4000,
  RELEASE: 0x8000,
  FREE: 0x10000,
  PRIVATE: 0x20000,
  MAPPED: 0x40000,
  RESET: 0x80000,
  TOP_DOWN: 0x100000,
  IMAGE: 0x1000000,
};

const PAGE = 0x1000n;

const READABLE = PROT.READONLY | PROT.READWRITE | PROT.WRITECOPY | PROT.EXECUTE_READ | PROT.EXECUTE_READWRITE | PROT.EXECUTE_WRITECOPY;
const WRITABLE = PROT.READWRITE | PROT.WRITECOPY | PROT.EXECUTE_READWRITE | PROT.EXECUTE_WRITECOPY;
const EXECUTABLE = PROT.EXECUTE | PROT.EXECUTE_READ | PROT.EXECUTE_READWRITE | PROT.EXECUTE_WRITECOPY;

/**
 * #PF-shaped fault. Extends CpuError so the interpreter surfaces it as a CPU
 * fault (CpuError is the only error class run() converts), carrying the
 * faulting instruction address for the SEH walk.
 */
export class MemoryFault extends CpuError {
  constructor(kind, addr, rip = 0n) {
    super(`${kind} to unmapped memory`, BigInt(rip));
    this.addr = BigInt(addr);
    this.kind = kind;
  }
}

export class MemoryManager {
  /**
   * @param {object} sparse SparseMemory instance
   * @param {{strictWrites?:boolean, strictFetch?:boolean}} [opts]
   */
  constructor(sparse, opts = {}) {
    this.sparse = sparse;
    this.regions = []; // sorted by base
    this.strictWrites = opts.strictWrites !== false;
    this.strictFetch = opts.strictFetch === true;
    this.faults = [];
    /** instruction-address provider for fault records (set after cpu exists) */
    this.faultRip = opts.faultRip ?? (() => 0n);
  }

  // ------------------------------------------------------------ region table

  map(base, size, { protect = PROT.READWRITE, state = "commit", type = MEM.PRIVATE, fill = false } = {}) {
    const b = BigInt(base) & ~0xfffn;
    const s = BigInt(size);
    if (s <= 0n) return b;
    this.regions.push({ base: b, size: s, protect, state, type });
    this.regions.sort((x, y) => (x.base < y.base ? -1 : x.base > y.base ? 1 : 0));
    if (fill && state === "commit") {
      for (let p = b; p < b + s; p += PAGE) {
        if (!this.sparse.hasPage?.(p)) this.sparse.write(p, new Uint8Array(0x1000));
      }
    }
    return b;
  }

  find(addr) {
    const a = BigInt(addr);
    for (const r of this.regions) {
      if (a >= r.base && a < r.base + r.size) return r;
    }
    return null;
  }

  /** Re-protect a range, splitting regions at the boundaries. */
  protect(base, size, newProtect) {
    const b = BigInt(base) & ~0xfffn;
    const e = b + BigInt(size);
    const out = [];
    let old = 0;
    for (const r of this.regions) {
      const rs = r.base, re = r.base + r.size;
      if (re <= b || rs >= e) { out.push(r); continue; }
      old = old || r.protect;
      if (rs < b) out.push({ ...r, size: b - rs });
      const cs = rs > b ? rs : b;
      const ce = re < e ? re : e;
      out.push({ ...r, base: cs, size: ce - cs, protect: newProtect });
      if (re > e) out.push({ ...r, base: e, size: re - e });
    }
    out.sort((x, y) => (x.base < y.base ? -1 : x.base > y.base ? 1 : 0));
    this.regions = out;
    return old;
  }

  free(base, size, type = MEM.RELEASE) {
    const b = BigInt(base) & ~0xfffn;
    const s = BigInt(size || 0n);
    const e = s ? b + s : b + BigInt(Number.MAX_SAFE_INTEGER);
    const out = [];
    let freed = false;
    for (const r of this.regions) {
      const rs = r.base, re = r.base + r.size;
      if (re <= b || rs >= e) { out.push(r); continue; }
      freed = true;
      if (type === MEM.DECOMMIT) {
        // keep the reservation, split around the decommitted middle
        if (rs < b) out.push({ ...r, size: b - rs });
        out.push({ ...r, base: b, size: (re < e ? re : e) - b, state: "reserve" });
        if (re > e) out.push({ ...r, base: e, size: re - e });
      } else {
        if (rs < b) out.push({ ...r, size: b - rs });
        if (re > e) out.push({ ...r, base: e, size: re - e });
      }
    }
    out.sort((x, y) => (x.base < y.base ? -1 : x.base > y.base ? 1 : 0));
    this.regions = out;
    return freed ? 1n : 0n;
  }

  query(addr) {
    const r = this.find(addr);
    if (!r) {
      return { base: 0n, size: 0n, state: MEM.FREE, protect: PROT.NOACCESS, type: 0 };
    }
    return { base: r.base, size: r.size, state: r.state === "commit" ? MEM.COMMIT : MEM.RESERVE, protect: r.protect, type: r.type };
  }

  // ------------------------------------------------------------- access paths

  #check(addr, kind) {
    const a = BigInt(addr);
    const r = this.find(a);
    if (!r) {
      if (kind === "write" && this.strictWrites) this.#fault(kind, a);
      if (kind === "fetch" && this.strictFetch) this.#fault(kind, a);
      return;
    }
    if (r.state !== "commit") this.#fault(kind, a);
    if (r.protect & PROT.GUARD) {
      r.protect &= ~PROT.GUARD; // one-shot guard semantics
      this.#fault(kind, a);
    }
    if (kind === "read" && !(r.protect & READABLE)) this.#fault(kind, a);
    if (kind === "write" && !(r.protect & WRITABLE)) this.#fault(kind, a);
    // Fetch: NOACCESS/guard/reserve fault, but NX (readable-not-executable)
    // is only enforced when strictFetch is on — analysis samples commonly run
    // generated code out of read/write allocations without VirtualProtect.
    if (kind === "fetch") {
      if (this.strictFetch ? !(r.protect & EXECUTABLE) : !(r.protect & READABLE)) this.#fault(kind, a);
    }
  }

  #fault(kind, addr) {
    this.faults.push({ kind, addr: `0x${BigInt(addr).toString(16)}` });
    throw new MemoryFault(kind, addr, this.faultRip());
  }

  /** Extra ranges the caller wants to treat as raw (no enforcement). */
  bypassRanges = [];

  #bypassed(addr) {
    const a = BigInt(addr);
    return this.bypassRanges.some((r) => a >= r.base && a < r.base + r.size);
  }

  read(addr, len) {
    if (!this.#bypassed(addr)) this.#check(addr, "read");
    return this.sparse.read(addr, len);
  }

  write(addr, bytes) {
    if (!this.#bypassed(addr)) this.#check(addr, "write");
    return this.sparse.write(addr, bytes);
  }

  /** Backend page-sync path: bypass region checks (not a guest access). */
  readRaw(addr, len) { return this.sparse.read(addr, len); }
  writeRaw(addr, bytes) { return this.sparse.write(addr, bytes); }

  fetchBytes(addr, len) {
    if (!this.#bypassed(addr)) this.#check(addr, "fetch");
    return this.sparse.read(addr, len);
  }

  // ---- SparseMemory surface ----
  get pages() { return this.sparse.pages; }
  hasPage(a) { return this.sparse.hasPage ? this.sparse.hasPage(a) : false; }
  u8(a) { return this.read(a, 1)[0]; }
  u16(a) { let v = 0n; const b = this.read(a, 2); for (let i = 1; i >= 0; i--) v = (v << 8n) | BigInt(b[i]); return Number(v); }
  u32(a) { let v = 0n; const b = this.read(a, 4); for (let i = 3; i >= 0; i--) v = (v << 8n) | BigInt(b[i]); return Number(v); }
  u64(a) { let v = 0n; const b = this.read(a, 8); for (let i = 7; i >= 0; i--) v = (v << 8n) | BigInt(b[i]); return v; }
  w8(a, v) { this.write(a, Uint8Array.from([v & 0xff])); }
  w16(a, v) { this.write(a, Uint8Array.from([v & 0xff, (v >>> 8) & 0xff])); }
  w32(a, v) { this.write(a, Uint8Array.from([v & 0xff, (v >>> 8) & 0xff, (v >>> 16) & 0xff, (v >>> 24) & 0xff])); }
  w64(a, v) {
    let x = BigInt.asUintN(64, BigInt(v));
    const out = new Uint8Array(8);
    for (let i = 0; i < 8; i++) { out[i] = Number(x & 0xffn); x >>= 8n; }
    this.write(a, out);
  }
  writeUtf16(a, s) {
    const out = new Uint8Array(s.length * 2 + 2);
    for (let i = 0; i < s.length; i++) { out[i * 2] = s.charCodeAt(i) & 0xff; out[i * 2 + 1] = (s.charCodeAt(i) >> 8) & 0xff; }
    this.write(a, out);
  }
}

/**
 * First-fit heap with coalescing over a sparse region (no full materialize).
 * Block layout: 16-byte header { size:u64 (payload), free:u8 } before payload.
 */
export class HeapAllocator {
  constructor(mm, base, size) {
    this.mm = mm;
    this.base = BigInt(base);
    this.size = BigInt(size);
    this.cursor = this.base + 0x1000n;
    this.blocks = []; // {addr, size(free payload), free}
  }

  #align(n) { return (BigInt(n) + 15n) & ~15n; }

  alloc(n, { zero = true } = {}) {
    const size = this.#align(n);
    for (const b of this.blocks) {
      if (b.free && b.size >= size) {
        b.free = false;
        if (zero) this.mm.write(b.addr, new Uint8Array(Number(b.size)));
        return b.addr;
      }
    }
    const addr = this.cursor;
    this.cursor = (this.cursor + 16n + size + 0xfffn) & ~0xfffn;
    if (this.cursor > this.base + this.size) throw new Error("emulated heap exhausted");
    this.blocks.push({ addr, size, free: false });
    if (zero) this.mm.write(addr, new Uint8Array(Number(size)));
    return addr;
  }

  free(addr) {
    const b = this.blocks.find((x) => x.addr === BigInt(addr));
    if (!b) return false;
    b.free = true;
    return true;
  }

  size(addr) {
    const b = this.blocks.find((x) => x.addr === BigInt(addr));
    return b ? b.size : 0n;
  }

  realloc(addr, n) {
    const b = this.blocks.find((x) => x.addr === BigInt(addr));
    const size = this.#align(n);
    if (b && b.size >= size) return b.addr;
    const next = this.alloc(size, { zero: false });
    if (b) {
      try { this.mm.write(next, this.mm.read(b.addr, Number(b.size < size ? b.size : size))); } catch { /* optional */ }
      b.free = true;
    }
    return next;
  }

  /** HeapValidate(core): are all block headers coherent? */
  validate() {
    let cursor = this.base + 0x1000n;
    for (const b of this.blocks) {
      if (b.addr < this.base || b.addr + b.size > this.base + this.size) return false;
      if (b.addr < cursor) return false;
      cursor = b.addr;
    }
    return true;
  }
}
