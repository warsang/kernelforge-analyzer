/**
 * taint.mjs — per-byte taint tracking for Find Bugs
 * One taint ID per byte, not per word, to catch sub-field granularity.
 * Shared propagation hooks with concolic symbolic layer.
 */

const PAGE_SHIFT = 12n;
const PAGE_SIZE = 4096;

export class TaintState {
  constructor() {
    /** Map<pageKey, Uint32Array> taint IDs per byte; 0 = untainted */
    this.pages = new Map();
    /** Map<regName, Uint32Array(8)?? or Set> — per-register byte taint: we store per 64-bit register as 8 byte IDs (low→high) */
    this.regs = new Map();
    /** flag taints: boolean per flag derived from tainted ALU */
    this.flags = { zf: false, cf: false, sf: false, of: false };
    /** read tracking for double-fetch: Map<addr, {count, pcs:Set}> */
    this.reads = new Map();
    /** source counter */
    this.nextId = 1;
    /** whether to keep comparison-bound taint (do not clear on cmp) */
    this.keepBoundCheckTaint = true;
  }

  _pageKey(addr) { return (BigInt(addr) & ~0xfffn).toString(16); }
  _offset(addr) { return Number(BigInt(addr) & 0xfffn); }

  ensurePage(key) {
    let arr = this.pages.get(key);
    if (!arr) { arr = new Uint32Array(PAGE_SIZE); this.pages.set(key, arr); }
    return arr;
  }

  taintRange(base, len, baseId = null) {
    // assign sequential IDs per byte starting at baseId or auto increment
    for (let i = 0; i < len; i++) {
      const addr = BigInt(base) + BigInt(i);
      const key = this._pageKey(addr);
      const off = this._offset(addr);
      const arr = this.ensurePage(key);
      const id = baseId !== null ? baseId + i : this.nextId++;
      arr[off] = id;
    }
    if (baseId === null) this.nextId += len - 1;
    // return first id for caller tracking
  }

  clearRange(base, len) {
    for (let i = 0; i < len; i++) {
      const addr = BigInt(base) + BigInt(i);
      const key = this._pageKey(addr);
      const arr = this.pages.get(key);
      if (arr) arr[this._offset(addr)] = 0;
    }
  }

  getByteTaint(addr) {
    const key = this._pageKey(addr);
    const arr = this.pages.get(key);
    if (!arr) return 0;
    return arr[this._offset(addr)] | 0;
  }

  setByteTaint(addr, id) {
    const key = this._pageKey(addr);
    const arr = this.ensurePage(key);
    arr[this._offset(addr)] = id | 0;
  }

  // multi-byte query
  getRangeTaint(addr, size) {
    const ids = [];
    let any = false;
    for (let i = 0; i < size; i++) {
      const id = this.getByteTaint(BigInt(addr) + BigInt(i));
      ids.push(id);
      if (id) any = true;
    }
    return { any, ids };
  }

  // register taint: store 8 byte IDs per reg (little endian)
  setRegTaint(name, byteIds) {
    // byteIds: Array(8) of ids (0 = clean) or single id replicated?
    if (!byteIds) { this.regs.delete(name); return; }
    if (Array.isArray(byteIds)) {
      this.regs.set(name, Uint32Array.from(byteIds));
    } else {
      // single int id -> replicate to low bytes according to size? keep as array
      const arr = new Uint32Array(8);
      arr[0] = byteIds;
      this.regs.set(name, arr);
    }
  }

  getRegTaint(name, size = 8) {
    const arr = this.regs.get(name);
    if (!arr) return { any: false, ids: [] };
    const ids = [];
    let any = false;
    for (let i = 0; i < size; i++) {
      const id = arr[i] || 0;
      ids.push(id);
      if (id) any = true;
    }
    return { any, ids };
  }

  clearReg(name) { this.regs.delete(name); }

  // propagate taint through ALU/data op: result tainted if any input byte tainted
  // for pointer arithmetic, track bounded flag: if base untainted and offset tainted -> bounded
  propagateBinop(aIds, bIds, size, op) {
    // aIds, bIds: arrays length size
    const resIds = new Uint32Array(size);
    let any = false;
    for (let i = 0; i < size; i++) {
      const ta = aIds[i] || 0, tb = bIds[i] || 0;
      if (ta || tb) { resIds[i] = ta || tb; any = true; }
    }
    // for address vs data distinction, caller will check if resulting register used as address
    return { any, ids: Array.from(resIds) };
  }

  // track double-fetch reads
  recordRead(addr, rip) {
    const key = BigInt(addr).toString(16);
    let rec = this.reads.get(key);
    if (!rec) { rec = { count: 0, pcs: new Set(), addrs: [] }; this.reads.set(key, rec); }
    rec.count++;
    rec.pcs.add(rip.toString(16));
  }

  reset() {
    this.pages.clear();
    this.regs.clear();
    this.reads.clear();
    this.flags.zf = this.flags.cf = this.flags.sf = this.flags.of = false;
  }

  // serialization for worker transfer
  dump() {
    const pages = [];
    for (const [k, v] of this.pages) pages.push([k, Array.from(v)]);
    const regs = [];
    for (const [k, v] of this.regs) regs.push([k, Array.from(v)]);
    return { pages, regs, nextId: this.nextId };
  }
  restore(d) {
    this.pages.clear(); for (const [k, arr] of d.pages) this.pages.set(k, Uint32Array.from(arr));
    this.regs.clear(); for (const [k, arr] of d.regs) this.regs.set(k, Uint32Array.from(arr));
    this.nextId = d.nextId;
  }
}
