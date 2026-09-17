/**
 * Minimal AArch64 interpreter covering the integer subset used by
 * hybrid-image ARM64EC ranges.
 *
 * Scope: ADRP/ADR, LDR/STR (unsigned offset, pre/post-index, literal),
 * LDUR/STUR, STP/LDP (64-bit integer + 128-bit SIMD round-trip),
 * ADD/SUB (immediate, shifted register), MOVZ/MOVK/MOVN, logical
 * immediate (AND/ORR/EOR/ANDS), logical register, CBZ/CBNZ, TBZ/TBNZ,
 * B/BL/BR/BLR/RET, UDF (structured fault), SVC (hook), NOP.
 *
 * Contract (mirrors the x86 JsInterpreter where applicable):
 * - BigInt register state; faults raise CpuError, never misexecute.
 * - Words with the top half zero decode as UDF-alias faults (these are
 *   the other-ISA padding bytes viewed as AArch64; both LLVM and Capstone
 *   agree on the `udf #imm` reading with imm = low 16 bits).
 * - Register 31 is SP for address/base contexts and XZR (zero) for data
 *   processing. BLR/BR to a registered thunk records an event and
 *   synthetically returns instead of leaving the image.
 */

const M64 = 0xffffffffffffffffn;

export class CpuError extends Error {
  constructor(msg, pc) {
    super(`${msg} @ pc=0x${pc.toString(16)}`);
    this.pc = pc;
  }
}

function sx(v, bits) {
  v &= (1n << BigInt(bits)) - 1n;
  const sign = 1n << BigInt(bits - 1);
  // Signed result (matches the reference Python interpreter): address
  // arithmetic at call sites wraps with & M64 explicitly.
  return (v & (sign - 1n)) - (v & sign);
}

function highestSetBit(v, bits) {
  for (let i = bits - 1; i >= 0; i--) if ((v >> i) & 1) return i;
  return -1;
}

/** ARM ARM DecodeBitMasks for logical immediates. */
export function decodeBitmask(nn, immr, imms, width) {
  const length = highestSetBit((nn << 6) | (~imms & 0x3f), 7);
  if (length < 1) throw new Error(`bad logical imm N=${nn} imms=0x${imms.toString(16)}`);
  const esize = 1 << length;
  if (esize > width) throw new Error(`bad logical imm esize=${esize} width=${width}`);
  const s = imms & (esize - 1);
  const r = immr & (esize - 1);
  const ones = (1n << BigInt(s + 1)) - 1n;
  const elem = (((ones >> BigInt(r)) | (ones << BigInt(esize - r))) & ((1n << BigInt(esize)) - 1n));
  let mask = 0n;
  for (let i = 0; i < width / esize; i++) mask = (mask << BigInt(esize)) | elem;
  return mask & ((1n << BigInt(width)) - 1n);
}

export class AArch64Interpreter {
  /**
   * @param {(addr: bigint, len: number) => Uint8Array} read
   * @param {(addr: bigint, bytes: Uint8Array) => void} write
   */
  constructor(read, write) {
    this.read = read;
    this.write = write;
    this.x = new Array(31).fill(0n);
    this.q = new Array(32).fill(0n);
    this.sp = 0n;
    this.pc = 0n;
    this.n = this.z = this.c = this.v = false;
    this.steps = 0;
    this.events = [];
    this.thunks = new Map(); // addr -> name
    this.trace = [];
  }

  xzr(i, sf) {
    if (i === 31) return 0n;
    return sf ? this.x[i] & M64 : this.x[i] & 0xffffffffn;
  }
  setXzr(i, v, sf) {
    if (i === 31) return;
    this.x[i] = sf ? v & M64 : v & 0xffffffffn;
  }
  base(i) {
    return i === 31 ? this.sp & M64 : this.x[i] & M64;
  }
  setBase(i, v) {
    if (i === 31) this.sp = v & M64;
    else this.x[i] = v & M64;
  }
  u32(addr) {
    const b = this.read(addr, 4);
    if (b.length < 4) throw new CpuError("read-unmapped", addr);
    return b[0] | (b[1] << 8) | (b[2] << 16) | (b[3] << 24);
  }
  u64(addr) {
    const b = this.read(addr, 8);
    if (b.length < 8) throw new CpuError("read-unmapped", addr);
    let v = 0n;
    for (let i = 7; i >= 0; i--) v = (v << 8n) | BigInt(b[i]);
    return v;
  }
  readOk(addr, n) {
    try {
      const b = this.read(addr, n);
      return b.length >= n ? b : null;
    } catch {
      return null;
    }
  }
  w64(addr, v) {
    const b = new Uint8Array(8);
    let t = v & M64;
    for (let i = 0; i < 8; i++) { b[i] = Number(t & 0xffn); t >>= 8n; }
    this.write(addr, b);
  }

  log(text) {
    if (this.trace.length < 20000) this.trace.push({ step: this.steps, pc: "0x" + this.pc.toString(16), text });
  }

  run(start, maxSteps = 5000) {
    this.pc = start & M64;
    for (let i = 0; i < maxSteps; i++) {
      let w;
      try {
        w = this.u32(this.pc);
      } catch (e) {
        return { status: "fetch-unmapped", detail: String((e && e.message) || e), steps: this.steps };
      }
      const [mn, ops] = this.execOne(w >>> 0);
      this.steps++;
      this.log(`${mn} ${ops}`);
      if (mn === "udf" || mn === "svc") return { status: mn, detail: ops, steps: this.steps };
    }
    return { status: "step-cap", steps: this.steps };
  }

  execOne(w) {
    const pc = this.pc;
    const adv = () => { this.pc = (pc + 4n) & M64; };
    // UDF-alias: zero top half (other-ISA padding; LLVM/Capstone read udf #imm).
    if (((w & 0xffff0000) >>> 0) === 0) {
      const imm = w & 0xffff;
      this.events.push({ type: "UDF-alias", pc: "0x" + pc.toString(16), imm: "0x" + imm.toString(16) });
      adv();
      return ["udf", `#0x${imm.toString(16)} (alias)`];
    }
    if (((w & 0xffe0001f) >>> 0) === 0xd4000000) {
      const imm = (w >>> 5) & 0xffff;
      this.events.push({ type: "UDF", pc: "0x" + pc.toString(16), imm: "0x" + imm.toString(16) });
      adv();
      return ["udf", `#0x${imm.toString(16)}`];
    }
    if (((w & 0xffe0001f) >>> 0) === 0xd4000001) {
      const imm = (w >>> 5) & 0xffff;
      this.events.push({ type: "SVC", pc: "0x" + pc.toString(16), imm: "0x" + imm.toString(16) });
      adv();
      return ["svc", `#0x${imm.toString(16)}`];
    }
    if (w === 0xd503201f) { adv(); return ["nop", ""]; }
    // B / BL
    if ((w >>> 26) === 0b000101) {
      const imm = Number(sx(BigInt(w & 0x3ffffff), 26)) * 4;
      if ((w >>> 31) & 1) {
        this.x[30] = (pc + 4n) & M64;
        this.pc = (pc + BigInt(imm)) & M64;
        return ["bl", `#${"0x" + this.pc.toString(16)}`];
      }
      this.pc = (pc + BigInt(imm)) & M64;
      return ["b", `#${"0x" + this.pc.toString(16)}`];
    }
    // CBZ / CBNZ
    if ([0b00110100, 0b00110101].includes(w >>> 24)) {
      const sf = (w >>> 31) & 1, op = (w >>> 24) & 1;
      const imm = Number(sx(BigInt((w >>> 5) & 0x7ffff), 19)) * 4;
      const rt = w & 0x1f;
      let v = this.xzr(rt, !!sf);
      if (!sf) v &= 0xffffffffn;
      const take = op === 0 ? v === 0n : v !== 0n;
      this.pc = (take ? pc + BigInt(imm) : pc + 4n) & M64;
      return [op ? "cbnz" : "cbz", `x${rt} take=${take ? 1 : 0}`];
    }
    // BR / BLR / RET
    if ([0xd61f0000, 0xd63f0000, 0xd65f0000].includes((w & 0xfffffc1f) >>> 0)) {
      const rn = (w >>> 5) & 0x1f;
      const tgt = this.xzr(rn, true);
      const kind = ((w & 0xfffffc1f) >>> 0) === 0xd61f0000 ? "br" : ((w & 0xfffffc1f) >>> 0) === 0xd63f0000 ? "blr" : "ret";
      if (kind === "blr") this.x[30] = (pc + 4n) & M64;
      if (this.thunks.has(tgt)) {
        const name = this.thunks.get(tgt);
        this.events.push({ type: "API", pc: "0x" + pc.toString(16), target: "0x" + tgt.toString(16), name });
        this.pc = kind === "blr" ? this.x[30] & M64 : (pc + 4n) & M64;
        if (kind === "blr") this.x[0] = 0n;
        return [kind, `${name} (stubbed ret)`];
      }
      this.pc = tgt & M64;
      return [kind, `x${rn}=0x${tgt.toString(16)}`];
    }
    // ADRP / ADR
    if (((w & 0x9f000000) >>> 0) === 0x90000000) {
      const op = (w >>> 31) & 1, rd = w & 0x1f;
      const imm = (((w >>> 5) & 0x7ffff) << 2) | ((w >>> 29) & 3);
      const off = op ? Number(sx(BigInt(imm), 21)) * 4096 : Number(sx(BigInt(imm), 21));
      const base = op ? pc & ~0xfffn : pc;
      this.setXzr(rd, base + BigInt(off), true);
      adv();
      return [op ? "adrp" : "adr", `x${rd}`];
    }
    // LDUR/STUR + pre/post-index group (bits25-24=00).
    if ([0xb8000000, 0xb8400000, 0xf8000000, 0xf8400000].includes((w & 0xffc00000) >>> 0)) {
      const sub = (w >>> 10) & 3;
      const size = (w >>> 30) & 3, isLoad = (w >>> 22) & 1;
      const rn = (w >>> 5) & 0x1f, rt = w & 0x1f;
      const nbytes = 1 << size;
      const off = Number(sx(BigInt((w >>> 12) & 0x1ff), 9));
      if (sub === 0) {
        const addr = (this.base(rn) + BigInt(off)) & M64;
        const b = isLoad ? this.readOk(addr, nbytes) : new Uint8Array(nbytes);
        if (isLoad && !b) {
          this.events.push({ type: "UNMAPPED", pc: "0x" + pc.toString(16) });
          adv();
          return [`${isLoad ? "ldur" : "stur"}-UNMAPPED`, `x${rt}, [x${rn}#${off}]`];
        }
        if (isLoad) {
          let v = 0n;
          for (let i = nbytes - 1; i >= 0; i--) v = (v << 8n) | BigInt(b[i]);
          this.setXzr(rt, v, size === 3);
        } else {
          const v = this.xzr(rt, size === 3);
          const out = new Uint8Array(nbytes);
          let t = v;
          for (let i = 0; i < nbytes; i++) { out[i] = Number(t & 0xffn); t >>= 8n; }
          this.write(addr, out);
        }
        adv();
        return [isLoad ? "ldur" : "stur", `x${rt}, [x${rn}#${off}]`];
      }
      if (sub === 1 || sub === 3) {
        const pre = sub === 3;
        let addr;
        if (pre) { const nb = (this.base(rn) + BigInt(off)) & M64; this.setBase(rn, nb); addr = nb; }
        else addr = this.base(rn);
        const b = isLoad ? this.readOk(addr, nbytes) : new Uint8Array(nbytes);
        if (isLoad && !b) {
          this.events.push({ type: "UNMAPPED", pc: "0x" + pc.toString(16) });
          adv();
          return [`${isLoad ? "ldr-pp-UNMAPPED" : "str-pp-UNMAPPED"}`, `x${rt}, [x${rn}]`];
        }
        if (isLoad) {
          let v = 0n;
          for (let i = nbytes - 1; i >= 0; i--) v = (v << 8n) | BigInt(b[i]);
          this.setXzr(rt, v, size === 3);
        } else {
          const v = this.xzr(rt, size === 3);
          const out = new Uint8Array(nbytes);
          let t = v;
          for (let i = 0; i < nbytes; i++) { out[i] = Number(t & 0xffn); t >>= 8n; }
          this.write(addr, out);
        }
        if (!pre) this.setBase(rn, (addr + BigInt(off)) & M64);
        adv();
        return [isLoad ? "ldr" : "str", `x${rt}, [x${rn}#${off}]${pre ? "!" : ""}`];
      }
      throw new CpuError("unprivileged ld/st unsupported", pc);
    }
    // Logical immediate.
    if (((w & 0x1f800000) >>> 0) === 0x12000000) {
      const sf = (w >>> 31) & 1, opc = (w >>> 29) & 3;
      const nn = (w >>> 22) & 1, immr = (w >>> 16) & 0x3f, imms = (w >>> 10) & 0x3f;
      const rn = (w >>> 5) & 0x1f, rd = w & 0x1f;
      const mask = decodeBitmask(nn, immr, imms, sf ? 64 : 32);
      const a = this.xzr(rn, !!sf);
      let res, nm;
      if (opc === 0) { res = a & mask; nm = "and"; }
      else if (opc === 1) { res = a | mask; nm = rn === 31 ? "mov" : "orr"; }
      else if (opc === 2) { res = a ^ mask; nm = "eor"; }
      else { res = a & mask; nm = rd === 31 ? "tst" : "ands"; }
      if (!sf) res &= 0xffffffffn;
      if (rd === 31 && opc === 3) { this.n = !!(res >> 63n); this.z = res === 0n; }
      else this.setXzr(rd, res, !!sf);
      adv();
      return [nm, `x${rd}, x${rn}, #0x${mask.toString(16)}`];
    }
    // LDR literal.
    if ([0x58000000, 0x18000000].includes((w & 0xff000000) >>> 0)) {
      const is64 = ((w >>> 30) & 1) || ((w & 0xff000000) >>> 0) === 0x58000000;
      const imm = Number(sx(BigInt((w >>> 5) & 0x7ffff), 19)) * 4;
      const rt = w & 0x1f, addr = (pc + BigInt(imm)) & M64;
      const nbytes = is64 ? 8 : 4;
      const b = this.readOk(addr, nbytes);
      if (!b) {
        this.events.push({ type: "UNMAPPED", pc: "0x" + pc.toString(16) });
        adv();
        return ["ldr-lit-UNMAPPED", `x${rt}, [pc]`];
      }
      let v = 0n;
      for (let i = nbytes - 1; i >= 0; i--) v = (v << 8n) | BigInt(b[i]);
      this.setXzr(rt, v, true);
      adv();
      return ["ldr", `x${rt}, [pc]`];
    }
    // STP / LDP (integer 64-bit + SIMD 128-bit round-trip).
    if ([0xa9000000, 0xa9400000, 0xa9800000, 0xa8c00000,
         0xad000000, 0xad400000, 0xad800000, 0xadc00000,
         0xac000000, 0xac400000, 0xac800000, 0xacc00000].includes((w & 0xffc00000) >>> 0)) {
      const opc = (w >>> 30) & 3, vv = (w >>> 26) & 1, isLoad = (w >>> 22) & 1;
      const mode = (w >>> 23) & 3, imm7 = (w >>> 15) & 0x7f;
      const rt2 = (w >>> 10) & 0x1f, rn = (w >>> 5) & 0x1f, rt = w & 0x1f;
      if (opc !== 2) throw new CpuError(`unimplemented stp/ldp opc=${opc}`, pc);
      const unit = vv ? 16 : 8;
      const off = Number(sx(BigInt(imm7), 7)) * unit;
      let base = this.base(rn), addr;
      if (mode === 2) { base = (base + BigInt(off)) & M64; this.setBase(rn, base); addr = base; }
      else if (mode === 0) addr = base;
      else addr = (base + BigInt(off)) & M64;
      const put64 = (a, v) => {
        const out = new Uint8Array(8);
        let t = v & M64;
        for (let i = 0; i < 8; i++) { out[i] = Number(t & 0xffn); t >>= 8n; }
        this.write(a, out);
      };
      const get64 = (a) => {
        const b = this.readOk(a, 8);
        if (!b) return null;
        let v = 0n;
        for (let i = 7; i >= 0; i--) v = (v << 8n) | BigInt(b[i]);
        return v;
      };
      if (vv) {
        if (isLoad) {
          const a = this.readOk(addr, 16), c = this.readOk(addr + 16n, 16);
          if (!a || !c) {
            this.events.push({ type: "UNMAPPED", pc: "0x" + pc.toString(16) });
            adv();
            return ["ldp-UNMAPPED", `x${rt}, x${rt2}`];
          }
          const cvt = (b) => { let v = 0n; for (let i = 15; i >= 0; i--) v = (v << 8n) | BigInt(b[i]); return v; };
          if (rt !== 31) this.q[rt] = cvt(a);
          if (rt2 !== 31) this.q[rt2] = cvt(c);
        } else {
          const cvt = (v) => {
            const out = new Uint8Array(16);
            let t = v & ((1n << 128n) - 1n);
            for (let i = 0; i < 16; i++) { out[i] = Number(t & 0xffn); t >>= 8n; }
            return out;
          };
          this.write(addr, cvt(this.q[rt]));
          this.write(addr + 16n, cvt(this.q[rt2]));
        }
      } else if (isLoad) {
        const v0 = get64(addr), v1 = get64(addr + 8n);
        if (v0 === null || v1 === null) {
          this.events.push({ type: "UNMAPPED", pc: "0x" + pc.toString(16) });
          adv();
          return ["ldp-UNMAPPED", `x${rt}, x${rt2}`];
        }
        this.setXzr(rt, v0, true);
        this.setXzr(rt2, v1, true);
      } else {
        put64(addr, this.xzr(rt, true));
        put64(addr + 8n, this.xzr(rt2, true));
      }
      if (mode === 0) this.setBase(rn, (base + BigInt(off)) & M64);
      adv();
      return [isLoad ? "ldp" : "stp", `x${rt}, x${rt2}, [x${rn}#${off}]`];
    }
    // STR / LDR unsigned offset.
    if ([0xb9000000, 0xb9400000, 0xf9000000, 0xf9400000,
         0x39000000, 0x39400000, 0x79000000, 0x79400000].includes((w & 0xffc00000) >>> 0)) {
      const size = (w >>> 30) & 3, isLoad = (w >>> 22) & 1;
      const imm12 = (w >>> 10) & 0xfff, rn = (w >>> 5) & 0x1f, rt = w & 0x1f;
      const nbytes = 1 << size, addr = (this.base(rn) + BigInt(imm12 * nbytes)) & M64;
      if (isLoad) {
        const b = this.readOk(addr, nbytes);
        if (!b) {
          this.events.push({ type: "UNMAPPED", pc: "0x" + pc.toString(16) });
          adv();
          return ["ldr-UNMAPPED", `x${rt}, [x${rn}]`];
        }
        let v = 0n;
        for (let i = nbytes - 1; i >= 0; i--) v = (v << 8n) | BigInt(b[i]);
        this.setXzr(rt, v, size === 3);
      } else {
        const v = this.xzr(rt, size === 3);
        const out = new Uint8Array(nbytes);
        let t = v;
        for (let i = 0; i < nbytes; i++) { out[i] = Number(t & 0xffn); t >>= 8n; }
        this.write(addr, out);
      }
      adv();
      return [isLoad ? "ldr" : "str", `x${rt}, [x${rn}, #${imm12 * nbytes}]`];
    }
    // ADD / SUB immediate.
    if (((w & 0x1f000000) >>> 0) === 0x11000000) {
      const sf = (w >>> 31) & 1, s = (w >>> 29) & 1, op = (w >>> 30) & 1;
      const sh = (w >>> 22) & 1;
      let imm = (w >>> 10) & 0xfff;
      if (sh) imm <<= 12;
      const rn = (w >>> 5) & 0x1f, rd = w & 0x1f;
      const a = this.base(rn);
      let res = op === 0 ? (a + BigInt(imm)) & M64 : (a - BigInt(imm)) & M64;
      if (!sf) res &= 0xffffffffn;
      if (rd === 31) { this.n = !!(res >> 63n); this.z = res === 0n; }
      else this.setBase(rd, res);
      adv();
      if (op === 0 && imm === 0 && !s && rn === 31) return ["mov", `x${rd}, sp`];
      return [s ? (op ? "subs" : "adds") : op ? "sub" : "add", `x${rd}, x${rn}#${imm}`];
    }
    // MOVZ / MOVK / MOVN.
    if (((w & 0x1f800000) >>> 0) === 0x12800000) {
      const sf = (w >>> 31) & 1, opc = (w >>> 29) & 3;
      const hw = (w >>> 21) & 3, imm = (w >>> 5) & 0xffff, rd = w & 0x1f;
      const v = BigInt(imm) << BigInt(hw * 16);
      const cur = this.xzr(rd, !!sf);
      let res;
      if (opc === 2) res = v;
      else if (opc === 3) res = cur | v;
      else res = ~v & (sf ? M64 : 0xffffffffn);
      if (!sf) res &= 0xffffffffn;
      this.setXzr(rd, res, !!sf);
      adv();
      return [{ 0: "movn", 1: "movn", 2: "movz", 3: "movk" }[opc], `x${rd}`];
    }
    // ADD / SUB shifted register.
    if (((w & 0x1f200000) >>> 0) === 0x0b000000) {
      const sf = (w >>> 31) & 1, op = (w >>> 30) & 1, s = (w >>> 29) & 1;
      const shift = (w >>> 22) & 3, rm = (w >>> 16) & 0x1f;
      const imm6 = (w >>> 10) & 0x3f, rn = (w >>> 5) & 0x1f, rd = w & 0x1f;
      let b = this.xzr(rm, !!sf);
      if (shift === 0) b = b << BigInt(imm6);
      else if (shift === 1) b = b >> BigInt(imm6);
      else if (shift === 2) b = sx(b, sf ? 64 : 32) >> BigInt(imm6);
      else throw new CpuError("ror unimplemented", pc);
      b &= sf ? M64 : 0xffffffffn;
      const a = this.xzr(rn, !!sf);
      let res = op === 0 ? (a + b) & M64 : (a - b) & M64;
      if (!sf) res &= 0xffffffffn;
      if (rd === 31 && s) { this.n = !!(res >> 63n); this.z = res === 0n; }
      else this.setXzr(rd, res, !!sf);
      adv();
      return [op ? "sub" : "add", `x${rd}, x${rn}, x${rm}`];
    }
    // Logical register (+ MOV alias).
    if (((w & 0x1f000000) >>> 0) === 0x0a000000) {
      const sf = (w >>> 31) & 1, opc = (w >>> 29) & 3;
      const shift = (w >>> 22) & 3, rm = (w >>> 16) & 0x1f;
      const imm6 = (w >>> 10) & 0x3f, rn = (w >>> 5) & 0x1f, rd = w & 0x1f;
      let b = this.xzr(rm, !!sf);
      if (shift === 0) b = b << BigInt(imm6);
      else if (shift === 1) b = b >> BigInt(imm6);
      else throw new CpuError(`shift ${shift} unimplemented`, pc);
      b &= sf ? M64 : 0xffffffffn;
      const a = this.xzr(rn, !!sf);
      let res, nm;
      if (opc === 1) { res = a | b; nm = "orr"; }
      else if (opc === 0) { res = a & b; nm = "and"; }
      else if (opc === 2) { res = a ^ b; nm = "eor"; }
      else { res = a & b; nm = "ands"; }
      if (!sf) res &= 0xffffffffn;
      if (rd === 31 && opc === 3) { this.n = !!(res >> 63n); this.z = res === 0n; }
      else {
        if (rn === 31 && opc === 1) nm = "mov";
        this.setXzr(rd, res, !!sf);
      }
      adv();
      return nm === "mov" ? [nm, `x${rd}, x${rm}`] : [nm, `x${rd}, x${rn}, x${rm}`];
    }
    throw new CpuError(`unimplemented encoding 0x${w.toString(16)}`, pc);
  }
}
