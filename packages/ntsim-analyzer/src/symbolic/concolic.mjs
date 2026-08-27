/**
 * concolic.mjs — concolic execution for IOCTL SystemBuffer magic-value discovery.
 *
 * Approach: ConcolicJsInterpreter extends JsInterpreter with shadow taint.
 * Every byte in SystemBuffer is SymByte{id, concrete}. Concrete execution
 * proceeds normally (required for control flow); symbolic expressions are
 * bookkeeping until a comparison against tainted data hits a Jcc.
 *
 * Constraint collection at each conditional branch where predicate is tainted,
 * then solve negated prefix via Z3 (or heuristic fallback) with per-query
 * timeout and re-run concretely to confirm.
 */

import { JsInterpreter, M64 } from "@kernelforge/ntsim/src/cpu.mjs";
import { ShadowState } from "./shadow.mjs";
import { mkConst, mkBinop, mkCmp, mkNot, mkExtract, mkConcat, isSymbolic } from "./expr.mjs";
import { solveConstraints } from "./solver.mjs";
import { captureSnapshot, restoreSnapshot } from "../snapshot.mjs";
import { CoverageTracker } from "../coverage.mjs";

const R64 = ["rax","rcx","rdx","rbx","rsp","rbp","rsi","rdi","r8","r9","r10","r11","r12","r13","r14","r15"];
const REG_INDEX = Object.fromEntries(R64.map((n,i)=>[n,i]));

// Wrap helper to mask value per bits
function mask(v, bits) {
  if (bits>=64) return BigInt(v) & M64;
  return BigInt(v) & ((1n<<BigInt(bits))-1n);
}

export class ConcolicJsInterpreter extends JsInterpreter {
  constructor(mem) {
    super(mem);
    this.shadow = new ShadowState();
    this.pathConstraints = []; // [{pred, taken, rip, bits}]
    this._taintBase = null;
    this._taintLen = 0;
    this._concolicEnabled = false;
  }

  enableConcolic(base, len, concreteBytes) {
    this.shadow.clear();
    this.pathConstraints = [];
    this._taintBase = BigInt(base);
    this._taintLen = len;
    this.shadow.taintRange(base, len, concreteBytes);
    this._concolicEnabled = true;
  }
  disableConcolic() {
    this._concolicEnabled = false;
    this.pathConstraints = [];
    // keep shadow for post-run inspection but not needed
  }

  // ---- overrides -------------------------------------------------------

  // Override readReg to propagate shadow if present
  readReg(idx, size) {
    const v = super.readReg(idx, size);
    // shadow propagation for reads handled via stored expr; caller (loadOp, alu) will fetch shadow via regGet
    return v;
  }

  writeReg(idx, size, val) {
    // if concolic disabled, just do normal
    if (!this._concolicEnabled) return super.writeReg(idx, size, val);
    const regName = R64[idx];
    // incoming symbolic? If caller set shadow via alu path, it's already in this._pendingWriteSym
    // For direct writes (mov reg, imm), we clear unless pending sym was set
    const pending = this._pendingSym;
    this._pendingSym = null;
    super.writeReg(idx, size, val);
    if (pending && isSymbolic(pending)) {
      // size-aware: if pending bits != size*8, extract/truncate
      let expr = pending;
      if (expr.bits !== size*8) {
        // need extract low bits
        if (expr.bits > size*8) {
          expr = mkExtract(pending, size*8-1, 0, mask(val, size*8));
        } else {
          // zero-extend? For 32->64 writes, x86 zero-extends on 32-bit writes
          // we model as concat zeros
          // simplify: keep as is but mask
        }
      }
      this.shadow.regSet(regName, expr);
    } else {
      // check if any source was symbolic for size-changing writes: 4-byte write zero-extends -> if old 64-bit sym, clear upper?
      // For now, clear shadow for this reg when writing concrete
      this.shadow.regSet(regName, null);
    }
  }

  // Wrap loadMem to return concrete but also track shadow per address
  loadMem(addr, size) {
    const v = super.loadMem(addr, size);
    if (!this._concolicEnabled) return v;
    // if loading from tainted range, create symbolic concat
    let any = false;
    const byteSyms = [];
    for (let i=0;i<size;i++) {
      const sym = this.shadow.memGet(BigInt(addr)+BigInt(i));
      if (sym) { any=true; byteSyms.push(sym); } else byteSyms.push(null);
    }
    if (!any) {
      // load from non-tainted but maybe value came from symbolic reg store earlier? Already handled via storeMem spreading.
      // So no shadow.
      this._lastLoadSym = null;
      return v;
    }
    // build concat little-endian: byte0 is low
    // For size==1, sym directly
    if (size===1) {
      this._lastLoadSym = byteSyms[0];
    } else {
      // create concat of bytes high to low? Little endian concat: high byte first
      const parts = [];
      for (let i=size-1;i>=0;i--) {
        if (byteSyms[i]) parts.push(byteSyms[i]);
        else parts.push(mkConst((v >> BigInt(i*8)) & 0xffn, 8));
      }
      // concat args: high .. low
      this._lastLoadSym = mkConcat(parts, size*8, v);
      // If not all bytes symbolic, this concat mixes sym+const which is okay
    }
    return v;
  }

  storeMem(addr, size, val) {
    // need to propagate symbolic if val has shadow pending
    let sym = this._pendingSym;
    // also check if _lastLoadSym corresponds to this store? Not generic.
    super.storeMem(addr, size, val);
    if (!this._concolicEnabled) { this._pendingSym=null; this._lastLoadSym=null; return; }
    if (sym && isSymbolic(sym)) {
      // spread sym's bytes into per-byte shadows
      // sym may be concat or single byte; extract each byte
      for (let i=0;i<size;i++) {
        const byteVal = (BigInt(val) >> BigInt(i*8)) & 0xffn;
        let byteSym;
        if (sym.bits === 8 && size===1) byteSym = sym;
        else if (sym.kind==="concat") {
          // crude: if concat of size bytes, pick appropriate part index
          // parts were high..low, need reverse
          // For now, create extract
          byteSym = mkExtract(sym, i*8+7, i*8, byteVal);
        } else {
          byteSym = mkExtract(sym, i*8+7, i*8, byteVal);
        }
        this.shadow.memSet(BigInt(addr)+BigInt(i), byteSym);
      }
    } else {
      // storing concrete value clears taint for those bytes
      for (let i=0;i<size;i++) this.shadow.memSet(BigInt(addr)+BigInt(i), null);
    }
    this._pendingSym=null;
    this._lastLoadSym=null;
  }

  // Helper to get shadow for a loadOp result
  loadOp(rm, size) {
    const v = super.loadOp(rm, size);
    if (!this._concolicEnabled) return v;
    // super.loadOp already called loadMem/readReg which set _lastLoadSym / reg shadow
    if (rm.kind==="reg") {
      const name = R64[rm.reg ?? 0];
      const rsym = this.shadow.regGet(name);
      if (rsym) {
        // size adjust
        if (rsym.bits !== size*8) {
          if (rsym.bits > size*8) {
            this._lastLoadSym = mkExtract(rsym, size*8-1, 0, mask(v, size*8));
          } else {
            this._lastLoadSym = rsym; // zero-extend case—keep but note bits diff
          }
        } else this._lastLoadSym = rsym;
      } else this._lastLoadSym = null;
    } // else mem case already set _lastLoadSym via loadMem
    // expose for caller
    this._pendingSym = this._lastLoadSym;
    return v;
  }

  storeOp(rm, size, val) {
    // need pending sym for store
    const sym = this._pendingSym;
    super.storeOp(rm, size, val);
    if (!this._concolicEnabled) { this._pendingSym=null; return; }
    if (rm.kind==="reg") {
      const name = R64[rm.reg ?? 0];
      if (sym && isSymbolic(sym)) {
        let expr = sym;
        if (expr.bits !== size*8) {
          if (expr.bits > size*8) expr = mkExtract(expr, size*8-1, 0, mask(val, size*8));
        }
        this.shadow.regSet(name, expr);
      } else this.shadow.regSet(name, null);
    } else {
      // mem case already handled via storeMem spreading if sym present; but need to handle direct storeOp mem path where _pendingSym is used in storeMem?
      // storeMem already cleared or set.
    }
    this._pendingSym=null;
  }

  // ALU with symbolic propagation
  alu(op, a, b, size) {
    // capture incoming shadows before super
    let aSym=null, bSym=null;
    if (this._concolicEnabled) {
      aSym = this._pendingASym ?? this._lastLoadSym ?? null;
      // bSym is trickier: many ALU paths read second operand via readReg directly not via loadOp
      // We try to get from last reg shadow if b came from register
      // For now, heuristic: if instruction's second operand was register, bSym is that reg's shadow
      // We'll rely on dispatch to set _pendingB sym before calling alu; patch dispatch call sites by overriding alu wrapper that inspects recent shadows
      // Simpler: check _pendingBSym if set
      bSym = this._pendingBSym ?? null;
      // fallback: if aSym from mem but b from const, keep null
    }
    const r = super.alu(op, a, b, size);
    if (!this._concolicEnabled) return r;
    // Determine shadows for a,b for this alu invocation
    // If instruction was like "cmp r/m, imm" then b is imm const (no sym)
    // For "cmp r/m, r" we have a from r/m (_lastLoadSym), b from reg
    // To propagate, we need both; we attempt to infer from current shadow state at alu entry

    // Heuristic: use _lastLoadSym and recent reg shadows
    // Since we don't have clean operand shadow routing, we store a shadow stack per dispatch
    // Instead, we patch dispatch to set _pendingASym/_pendingBSym before alu call. For now, if both null, try to look at reg shadows of typical sources?
    // Simpler: if any of aSym/bSym symbolic, derive
    let derived = null;
    const hasA = aSym && isSymbolic(aSym);
    const hasB = bSym && isSymbolic(bSym);
    if (hasA || hasB) {
      const aNode = hasA ? aSym : mkConst(a, size*8);
      const bNode = hasB ? bSym : mkConst(b, size*8);
      let kind = op;
      if (op==="cmp" || op==="test") kind = op; // cmp/test still produce flags via sub/and
      // map op to expr kind
      const binMap = { add:"add", sub:"sub", and:"and", or:"or", xor:"xor", adc:"add", sbb:"sub", cmp:"sub", test:"and" };
      const ekind = binMap[op] ?? op;
      if (["add","sub","and","or","xor"].includes(ekind)) {
        derived = mkBinop(ekind, aNode, bNode, size*8, r);
      } else derived = mkBinop(ekind, aNode, bNode, size*8, r);
      // flags: derive symbolic flags
      // zf = derived == 0
      const zero = mkConst(0, size*8);
      this.shadow.flags.zfSym = mkCmp("eq", derived, zero, r===0n);
      // cf per op
      if (op==="add" || op==="adc") this.shadow.flags.cfSym = mkCmp("ult", derived, aNode, (a+b) > ((1n<<BigInt(size*8))-1n));
      else if (op==="sub"||op==="cmp"||op==="sbb") this.shadow.flags.cfSym = mkCmp("ult", aNode, bNode, a < b);
      else if (op==="and"||op==="or"||op==="xor"||op==="test") this.shadow.flags.cfSym = mkConst(0,1); // not symbolic
      else this.shadow.flags.cfSym = null;
      // sf = msb of derived
      const msb = size*8-1;
      const signBit = mkExtract(derived, msb, msb, (r>>BigInt(msb)) & 1n);
      this.shadow.flags.sfSym = mkCmp("ne", signBit, mkConst(0,1), ((r>>BigInt(msb))&1n)!==0n);
      // of crude: derived overflow — keep symbolic as not simple
      this.shadow.flags.ofSym = null;
      this._pendingSym = derived;
    } else {
      // concrete — clear flag shadows if derived was concrete
      if (op==="cmp"||op==="test"||op==="and"||op==="or"||op==="xor"||op==="add"||op==="sub") {
        this.shadow.flags.zfSym = null;
        this.shadow.flags.cfSym = null;
        this.shadow.flags.sfSym = null;
        this.shadow.flags.ofSym = null;
      }
      this._pendingSym = null;
    }
    // cleanup per-alu pending
    this._pendingASym=null; this._pendingBSym=null; this._lastLoadSym=null;
    return r;
  }

  cond(cc) {
    const concrete = super.cond(cc);
    if (!this._concolicEnabled) return concrete;
    // map cc to flag predicate
    let pred = null;
    const zf = this.shadow.flags.zfSym, cf = this.shadow.flags.cfSym, sf = this.shadow.flags.sfSym, of = this.shadow.flags.ofSym;
    const hasAnySym = zf || cf || sf || of;
    if (!hasAnySym) return concrete;
    switch(cc) {
      case 0x4: pred = zf; break; // e
      case 0x5: pred = zf ? mkCmp(predNegKind(zf), zf.left ?? zf, zf.right ?? mkConst(0,1), !concrete) : null; 
        // instead simpler: if zf sym then ne is not(eq). For ne we want not(zf)
        if (zf) pred = { kind:"not", bits:1, arg: zf, concrete: !concrete }; // not eq
        break;
      case 0x2: pred = cf; break;
      case 0x3: pred = cf ? { kind:"not", bits:1, arg: cf, concrete: !concrete } : null; break;
      case 0x6: {
        // be = cf || zf
        if (cf && zf) pred = mkBinop("or", cf, zf, 1, concrete?1:0);
        else pred = cf ?? zf;
        break;
      }
      case 0x7: {
        if (cf || zf) {
          const cfOrZf = (cf && zf) ? mkBinop("or", cf, zf, 1, concrete?0:0) : (cf??zf);
          pred = { kind:"not", bits:1, arg: cfOrZf, concrete };
        }
        break;
      }
      case 0x0: pred = of; break;
      case 0x1: pred = of ? { kind:"not", bits:1, arg: of, concrete } : null; break;
      case 0x8: pred = sf; break;
      case 0x9: pred = sf ? { kind:"not", bits:1, arg: sf, concrete } : null; break;
      case 0xc: // le
      case 0xe: {
        // zf || sf!=of -> need of/sf
        if (zf) pred = zf; // approx: only track zf part; sf/of often null
        else pred = null;
        break;
      }
      case 0xd: // g
      case 0xf: {
        if (zf) pred = { kind:"not", bits:1, arg: zf, concrete };
        break;
      }
    }
    // For cmp-derived zf, pred will be eq(derived,0); which maps to a==b when derived = a-b
    // So eq(a-b,0) is equivalent to a==b — that's useful for solver

    if (pred && isSymbolic(pred)) {
      // Record path constraint
      // Transform top-level not handling already
      // Ensure pred is boolean BV (1-bit) comparison
      this.pathConstraints.push({ pred, taken: concrete, cc, rip: this.opcodeStart ?? this.rip });
    }
    return concrete;
  }
}

function predNegKind(expr) {
  // helper for negating cmp
  return expr?.kind==="eq" ? "ne" : expr?.kind==="ne" ? "eq" : "ne";
}

// ------------------------------------------------------------------ driver

/**
 * Concolic campaign for a single IOCTL code.
 * @param {object} kernel NtKernel (with JsInterpreter)
 * @param {object} device
 * @param {number} ctlCode
 * @param {object} opts {iterations, maxSymBytes, solverTimeoutMs, maxQueries, inputLen, outputLen, sendIrp, imageBase, imageSize, onProgress, corpus}
 */
export async function concolicCampaign(kernel, device, ctlCode, opts={}) {
  const maxSymBytes = opts.maxSymBytes ?? 64;
  const solverTimeoutMs = opts.solverTimeoutMs ?? 500;
  const maxQueries = opts.maxQueries ?? 8;
  const inputLen = opts.inputLen ?? 16;
  const outputLen = opts.outputLen ?? 64;
  const sendIrp = opts.sendIrp;
  const base = opts.imageBase, size = opts.imageSize;
  if (!sendIrp) throw new Error("concolicCampaign: sendIrp required");

  // Ensure we have JsInterpreter; if Hybrid/Unicorn, clone to JS
  let concolicKernel = kernel;
  let concolicCpu = kernel.cpu;
  let isCloned = false;
  const isJs = concolicCpu.constructor?.name === "JsInterpreter";
  const isHybrid = concolicCpu.constructor?.name === "HybridCpuBackend";
  if (!isJs) {
    // For Hybrid, force active js by capturing its js engine. For Unicorn, create fresh JsInterpreter that shares memory via copy? Instead create new NtKernel clone?
    // Simpler: if hybrid, use its js engine directly
    if (isHybrid && concolicCpu.js) {
      concolicCpu = concolicCpu.js;
      concolicKernel = kernel; // but cpu swapped? We'll install concolic wrapper over that js engine
      // We'll wrap the hybrid's js interpreter but keep kernel.cpu as hybrid? Need to temporarily swap?
      // Instead we create a ConcolicJsInterpreter that shares mem
      const mem = kernel.mem;
      const c = new ConcolicJsInterpreter(mem);
      // copy regs state from js engine before swapping? Will be snapshotted anyway per run
      c.regs = concolicCpu.regs; // share? Actually need independent copy; we'll replace
      // Swap kernel.cpu to concolic for campaign duration, then restore
      concolicKernel._savedCpu = kernel.cpu;
      concolicKernel.cpu = c;
      c.mem = mem;
      concolicCpu = c;
      isCloned = true;
    } else {
      // Unicorn-only: instantiate concolic interpreter sharing same mem pages (copy-on)
      const mem = kernel.mem;
      const c = new ConcolicJsInterpreter(mem);
      concolicKernel._savedCpu = kernel.cpu;
      concolicKernel.cpu = c;
      concolicCpu = c;
      isCloned = true;
    }
  } else {
    // wrap existing JsInterpreter in concolic subclass by monkey-patching? Instead replace with instance that copies state
    const mem = kernel.mem;
    const c = new ConcolicJsInterpreter(mem);
    // copy current regs/flags etc
    for (const r of R64) c.regs[r] = kernel.cpu.regs[r];
    c.rip = kernel.cpu.rip;
    for (const f of ["cf","zf","sf","of","df","tf","iflag","inhibitWindow"]) if (f in kernel.cpu) c[f]=kernel.cpu[f];
    concolicKernel._savedCpu = kernel.cpu;
    concolicKernel.cpu = c;
    concolicCpu = c;
    isCloned = true;
  }

  const tracker = new CoverageTracker(concolicKernel, base, size);
  tracker.install();
  const corpus = opts.corpus ? [...opts.corpus] : [];
  const globalSeen = new Set();
  for (const e of corpus) for (const b of e.coverage?.blocks??[]) globalSeen.add(b);

  // helper to run concolically and collect constraints+coverage
  async function runConcolic(buf) {
    const snap = captureSnapshot(concolicKernel);
    // need to set taint for expected systemBuffer allocation
    // We'll intercept allocPool for IrpB to taint after its allocation inside sendIrp
    // So we monkey-patch kernel.allocPool temporarily
    const origAlloc = concolicKernel.allocPool.bind(concolicKernel);
    let taintedBase = null;
    concolicKernel.allocPool = function(size, tag) {
      const addr = origAlloc(size, tag);
      if (tag==="IrpB" && taintedBase===null && size >= Math.max(buf.length, outputLen)) {
        taintedBase = addr;
        // enable taint inside cpu
        const concrete = buf;
        const len = Math.min(buf.length, maxSymBytes);
        // only first maxSymBytes
        concolicCpu.enableConcolic(taintedBase, len, concrete.slice(0,len));
      }
      return addr;
    };

    tracker.reset(); tracker.resume();
    concolicCpu.pathConstraints = [];

    let res;
    try {
      res = await sendIrp(concolicKernel, device, {
        major: 0x0e, ioctl: BigInt(ctlCode>>>0), input: buf, outputLen,
      });
    } catch(e) { res = { status:"fault", error:e }; }

    tracker.pause();
    const coverage = { blocks: new Set(tracker.blocks), edges: new Set(tracker.edges) };
    const constraints = [...concolicCpu.pathConstraints];
    const symCount = concolicCpu.shadow?.symCount ?? Math.min(buf.length, maxSymBytes);
    // cleanup
    concolicCpu.disableConcolic();
    concolicKernel.allocPool = origAlloc;
    tracker.reset();
    restoreSnapshot(concolicKernel, snap);
    // ensure cpu's concolic disabled cleared shadow
    if (concolicCpu.shadow) concolicCpu.shadow.clear();
    return { res, coverage, constraints, symCount, taintedBase };
  }

  // BFS concolic: queue of seeds to explore, each popped runs once and pushes witnesses back
  let seedQueue = corpus.length ? corpus.map(c=>c.buf) : [new Uint8Array(inputLen)];
  if (!seedQueue.length) seedQueue = [new Uint8Array(inputLen)];
  // cap initial seeds to 4 to bound work
  seedQueue = seedQueue.slice(0, 4);
  const results = [];
  let queriesDone = 0;
  let iterations = 0;
  const visitedHex = new Set(seedQueue.map(b=> [...b].join(",")));

  while (seedQueue.length && queriesDone < maxQueries) {
    const seed = seedQueue.shift();
    const { res, coverage, constraints, symCount } = await runConcolic(seed);
    iterations++;
    for (const b of coverage.blocks) globalSeen.add(b);
    results.push({ seed, res, coverage, constraints, symCount });
    if (opts.onProgress) opts.onProgress({ phase:"concolic-seed", buf: seed, coverage, constraints, res });
    if (concolicKernel.bugcheck || concolicKernel.crash) break;
    if (!constraints.length) continue;
    // attempt to flip each constraint (BFS near-start priority = reverse order, per prompt near start)
    // we iterate in order from 0..n-1 to prioritize early branches, but cap by remaining queries
    const order = [...constraints.keys()]; // forward: near start first
    for (const idx of order) {
      if (queriesDone >= maxQueries) break;
      const prefix = constraints.slice(0, idx).map(c=> ({pred:c.pred, taken:c.taken}));
      const target = constraints[idx];
      const negated = { pred: target.pred, taken: !target.taken };
      const query = [...prefix, negated];
      const { sat, model, smt2, fallback } = await solveConstraints(query, symCount, { timeoutMs: solverTimeoutMs });
      queriesDone++;
      if (!sat || !model) {
        if (opts.onProgress) opts.onProgress({ phase:"concolic-query", idx, sat:false, smt2 });
        continue;
      }
      const child = new Uint8Array(seed);
      for (let i=0;i<Math.min(symCount, child.length);i++) {
        if (model[i] !== null && model[i] !== undefined) child[i]= model[i] & 0xff;
      }
      // re-run concretely on original backend (kernel that was saved) to confirm
      // For isCloned case, we need to run on original cpu (saved) not concolic. Use original kernel's sendIrp after restoring?
      // We already restored snapshot; run via runConcolic's concrete re-run path using same runConcolic but disable tracking? Simpler: run via ordinary sendIrp on concolicKernel (which now has original cpu restored? Not yet). We'll temporarily disable concolic and run ordinary coverage run.

      // So we re-run using ordinary fuzz-style run without taint to verify branch flip
      const snap2 = captureSnapshot(concolicKernel);
      // run ordinary (no taint) using concolicKernel's current cpu (which is concolic but disabled)
      tracker.reset(); tracker.resume();
      let confirmRes;
      try {
        // ensure concolic disabled so shadow not interfering
        concolicCpu.disableConcolic();
        confirmRes = await sendIrp(concolicKernel, device, { major:0x0e, ioctl: BigInt(ctlCode>>>0), input: child, outputLen });
      } catch(e){ confirmRes={status:"fault",error:e}; }
      tracker.pause();
      const confirmCov = new Set(tracker.blocks);
      restoreSnapshot(concolicKernel, snap2);
      tracker.reset();
      if (opts.onProgress) opts.onProgress({ phase:"concolic-witness", idx, child, confirmRes, sat, fallback, smt2 });

      // check novelty
      const newBlocks = [...confirmCov].filter(b=>!globalSeen.has(b));
      if (newBlocks.length>0 || confirmRes?.ntstatus===0n) {
        for (const b of confirmCov) globalSeen.add(b);
        corpus.push({ buf: child, coverage: { blocks: confirmCov, edges: new Set() }, res: confirmRes, witness: true, pred: target.pred });
        results.push({ child, confirmRes, coverage: { blocks: confirmCov }, constraints: query });
        // BFS: explore witnesses that gave new coverage
        if (newBlocks.length>0 && queriesDone < maxQueries) {
          const hex = [...child].join(",");
          if (!visitedHex.has(hex)) { visitedHex.add(hex); seedQueue.push(child); }
        }
        if (confirmRes?.ntstatus===0n) {
          // keep going to find more, but prioritize
        }
      }
    }
  }

  // restore original cpu if cloned
  if (isCloned && concolicKernel._savedCpu) {
    concolicKernel.cpu = concolicKernel._savedCpu;
    delete concolicKernel._savedCpu;
  }
  tracker.dispose();

  return { corpus, globalSeen, queriesDone, iterations, results };
}
