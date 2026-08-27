/**
 * shadow.mjs — symbolic shadow state for concolic execution.
 *
 * Maps concrete byte addresses and registers to symbolic Expr nodes.
 */

import { mkSym } from "./expr.mjs";

export class ShadowState {
  constructor() {
    /** @type {Map<string, object>} key = "addrHex" -> Expr */
    this.mem = new Map();
    /** @type {Map<string, object>} regName -> Expr */
    this.regs = new Map();
    /** flag shadows: {zfSym, cfSym, sfSym, ofSym, df} */
    this.flags = { zfSym: null, cfSym: null, sfSym: null, ofSym: null };
    /** symbolic byte count cap */
    this.symCount = 0;
  }

  /** Mark SystemBuffer bytes as symbolic, each byte gets SymByte{id}. */
  taintRange(base, len, concreteBytes) {
    for (let i=0;i<len;i++) {
      const addr = (BigInt(base) + BigInt(i)).toString(16);
      const conc = concreteBytes ? BigInt(concreteBytes[i] ?? 0) : 0n;
      const sym = mkSym(i, conc, 8);
      this.mem.set(addr, sym);
    }
    this.symCount = len;
  }

  memGet(addr) {
    return this.mem.get(BigInt(addr).toString(16)) ?? null;
  }
  memSet(addr, expr) {
    const k = BigInt(addr).toString(16);
    if (expr) this.mem.set(k, expr);
    else this.mem.delete(k);
  }

  // For multi-byte loads, try to compose Concat of per-byte shadows if all bytes symbolic
  // otherwise return single derived expr if any part symbolic (handled by caller)
  memLoadShadow(addr, size) {
    // if single byte, direct
    if (size===1) return this.memGet(addr);
    // check if any byte tainted
    let any = false;
    for (let i=0;i<size;i++) if (this.memGet(BigInt(addr)+BigInt(i))) { any=true; break; }
    if (!any) return null;
    return { kind:"memload", addr: BigInt(addr), size, any: true }; // placeholder — caller builds Concat
  }

  regGet(name) { return this.regs.get(name) ?? null; }
  regSet(name, expr) {
    if (expr) this.regs.set(name, expr);
    else this.regs.delete(name);
  }

  clear() {
    this.mem.clear();
    this.regs.clear();
    this.flags = { zfSym:null, cfSym:null, sfSym:null, ofSym:null };
    this.symCount = 0;
  }
}
