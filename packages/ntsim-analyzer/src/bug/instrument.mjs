/**
 * instrument.mjs — shared taint+symbolic instrumentation for Find Bugs
 * Wraps JsInterpreter with per-byte taint and sink checks.
 */

import { JsInterpreter, M64 } from "@kernelforge/ntsim/src/cpu.mjs";
import { TaintState } from "./taint.mjs";
import { SINK_CATALOG, sinksForApi } from "./sinks.mjs";
import { makeBug } from "./bugdb.mjs";

const R64 = ["rax","rcx","rdx","rbx","rsp","rbp","rsi","rdi","r8","r9","r10","r11","r12","r13","r14","r15"];

function mask(v,bits){ return bits>=64 ? BigInt(v)&M64 : BigInt(v) & ((1n<<BigInt(bits))-1n); }

export class BugFindingInterpreter extends JsInterpreter {
  constructor(mem, opts={}) {
    super(mem);
    this.taint = new TaintState();
    this.bugs = []; // per-run bugs
    this.mode = opts.mode || "TAINT_ONLY"; // or TAINT_AND_SYMBOLIC
    this.systemBuffer = null;
    this.systemBufferLen = 0;
    this.inputBufferLengthAddr = null; // for tainting InputBufferLength
    this.probeDone = false; // track ProbeForRead called
    this.readAddrs = new Map(); // for double-fetch
    this.allocSites = []; // for pool overflow tracking
    this.sinkHits = [];
    this._pendingTaint = null; // per-op taint
    this._lastLoadTaint = null;
  }

  enableTaintForIrp(systemBuffer, len, inputLen, outputLen, ioctlCode) {
    this.taint.reset();
    this.bugs = [];
    this.probeDone = false;
    this.systemBuffer = BigInt(systemBuffer);
    this.systemBufferLen = len;
    // taint every byte of SystemBuffer with distinct IDs (per-byte source)
    if (systemBuffer && len) {
      this.taint.taintRange(systemBuffer, Math.min(len, 256));
    }
    // also taint InputBufferLength/OutputBufferLength as attacker-controlled distinct IDs
    // we use high IDs to distinguish from buffer bytes: use nextId offset
    // For now, we treat lengths as tainted single values (their taint will propagate via stack location reads)
    // We will taint the stack slot where those lengths live when we know its VA; otherwise we conservatively treat any length arg that equals inputLen as tainted in API checks
    this._inputLenTainted = true;
    this._outputLenTainted = true;
    this._ioctlCode = ioctlCode;
  }

  // ---- taint propagation helpers ----

  // propagate taint for register write
  writeReg(idx, size, val) {
    if (!this.taint) return super.writeReg(idx, size, val);
    const pending = this._pendingTaint;
    this._pendingTaint = null;
    super.writeReg(idx, size, val);
    const name = R64[idx];
    if (pending && pending.any) {
      // size-aware: if pending ids length != size, slice/extend
      const ids = pending.ids.slice(0, size);
      // pad to 8
      const full = new Array(8).fill(0);
      for (let i=0;i<Math.min(ids.length, size);i++) full[i]=ids[i]||0;
      this.taint.setRegTaint(name, full);
    } else {
      this.taint.clearReg(name);
    }
  }

  loadMem(addr, size) {
    const val = super.loadMem(addr, size);
    // check for arbitrary read: if addr is tainted, that's a sink
    const addrTaint = this._addrTaintForLoadStore(addr);
    if (addrTaint?.any) {
      this._reportMemSink("ARBITRARY_READ_DEREF", addr, size, addrTaint, "read");
    }
    // double-fetch tracking
    if (this.taint.getRangeTaint(addr, size).any) {
      // reading tainted memory location — record
      const key = BigInt(addr).toString(16);
      const rec = this.taint.reads.get(key) || {count:0, pcs: new Set()};
      rec.count++; rec.pcs.add(this.opcodeStart?.toString(16) || this.rip.toString(16));
      this.taint.reads.set(key, rec);
      if (rec.count > 1) {
        // flag double-fetch if reads >1 and first read was a validation (we approximate)
        // we will emit bug if count==2 and within same handler run
        if (rec.count===2) {
          this._reportMemSink("DOUBLE_FETCH", addr, size, {any:true, ids:[1]}, "double_fetch");
        }
      }
    }
    // missing probe check: if addr points into tainted SystemBuffer region and probe not done, flag
    if (this._isTaintedUserPointer(addr) && !this.probeDone) {
      // check if this load is dereferencing a pointer that itself came from tainted buffer
      // For now, if addr is within SystemBuffer and that buffer byte is tainted as pointer, flag
      // Simplified: if addrTaint.any and not probeDone, flag MISSING_PROBE
      if (addrTaint?.any) {
        // already flagged as arbitrary read, but also missing probe is separate
      } else {
        // check if the value being loaded is a pointer taken from tainted buffer? Hard to know
        // We approximate: any load of size 8 from tainted buffer that yields an address later used as addr
        // For now, we track that SystemBuffer bytes are tainted; if we load an 8-byte value from there, that value's taint propagates to register, then later used as addr -> arbitrary read/write
        // So missing probe is essentially same as arbitrary read/write with extra condition
      }
    }

    // propagate taint from memory to register (for loadOp)
    const memTaint = this.taint.getRangeTaint(addr, size);
    if (memTaint.any) {
      this._lastLoadTaint = memTaint;
    } else {
      this._lastLoadTaint = null;
    }
    return val;
  }

  storeMem(addr, size, val) {
    const addrTaint = this._addrTaintForLoadStore(addr);
    if (addrTaint?.any) {
      // distinguish bounded vs full
      const degree = this._controlDegree(addrTaint, addr);
      this._reportMemSink("ARBITRARY_WRITE_DEREF", addr, size, addrTaint, "write", degree);
    }
    // stack overflow: tainted length written to stack (e.g., memcpy to local buffer with tainted len)
    // check if dst is stack and len tainted (pending taint contains len)
    // For now, approximate: if store to stack and pending taint any and size tainted, flag
    if (this._isStackAddr(addr) && this._pendingTaint?.any) {
      // Only flag if this store is part of a larger copy with tainted length (heuristic)
      // We skip to avoid false positives from arbitrary writes that happen to land near stack
    }
    // check for info-leak? store to SystemBuffer that is partially uninitialized is not detectable here

    // propagate taint from register to memory
    const pending = this._pendingTaint;
    super.storeMem(addr, size, val);
    if (pending && pending.any) {
      // spread per-byte taint to memory
      for (let i=0;i<size;i++) {
        const id = pending.ids[i] || 0;
        if (id) this.taint.setByteTaint(BigInt(addr)+BigInt(i), id);
        else this.taint.setByteTaint(BigInt(addr)+BigInt(i), 0);
      }
    } else {
      // storing concrete clears taint
      for (let i=0;i<size;i++) this.taint.setByteTaint(BigInt(addr)+BigInt(i), 0);
    }
    this._pendingTaint = null;
    this._lastLoadTaint = null;
  }

  loadOp(rm, size) {
    const v = super.loadOp(rm, size);
    // rm.kind reg -> taint from reg
    if (rm.kind==="reg") {
      const name = R64[rm.reg ?? 0];
      const t = this.taint.getRegTaint(name, size);
      this._lastLoadTaint = t.any ? t : null;
    }
    // mem already set via loadMem
    this._pendingTaint = this._lastLoadTaint;
    return v;
  }

  storeOp(rm, size, val) {
    const pending = this._pendingTaint;
    super.storeOp(rm, size, val);
    if (rm.kind==="reg") {
      const name = R64[rm.reg ?? 0];
      if (pending && pending.any) {
        const full = new Array(8).fill(0);
        for(let i=0;i<Math.min(pending.ids.length,size);i++) full[i]=pending.ids[i];
        this.taint.setRegTaint(name, full);
      } else {
        this.taint.clearReg(name);
      }
    }
    this._pendingTaint = null;
  }

  alu(op, a, b, size) {
    // capture taint before super
    let aTaint = this._lastLoadTaint || {any:false, ids:[]};
    // b taint often from reg; try to get from pending b
    let bTaint = this._pendingBTaint || {any:false, ids:[]};
    // also try to infer b from reg taint if b came from register not via loadOp
    // For ops like add r/m, r : a is mem/reg m, b is reg
    // For ops like add r, r/m : a is reg, b is mem
    // Our capture is incomplete; fallback: if aTaint empty and bTaint empty, check regs for likely sources
    const r = super.alu(op, a, b, size);
    // propagate
    let resIds = new Array(size).fill(0);
    let any = false;
    // simple: if either operand tainted, result tainted with union
    const aIds = aTaint.ids || [], bIds = bTaint.ids || [];
    for(let i=0;i<size;i++){
      const ta = aIds[i]||0, tb = bIds[i]||0;
      if(ta||tb){ resIds[i]= ta||tb; any=true; }
    }
    // for cmp/test, result not stored but flags tainted
    if (op==="cmp" || op==="test") {
      // flags taint
      if (any) {
        this.taint.flags.zf = true;
        this.taint.flags.cf = true;
      } else {
        this.taint.flags.zf = false;
        this.taint.flags.cf = false;
      }
      this._pendingTaint = any ? {any, ids: resIds} : null;
    } else {
      this._pendingTaint = any ? {any, ids: resIds} : null;
      // clear load taint
      if (!any) {
        this.taint.flags.zf = false; this.taint.flags.cf = false;
      } else {
        this.taint.flags.zf = true;
      }
    }
    this._lastLoadTaint = null;
    this._pendingBTaint = null;
    return r;
  }

  // hooks for port/MSR/CR
  // These will be wired via onPortRead/onPortWrite and cr0 etc from kernel

  _addrTaintForLoadStore(addr) {
    // check if address computation involved tainted register
    // We approximate by checking if any reg that was recently used to compute addr is tainted
    // For simplicity, check if addr value itself is within tainted SystemBuffer range? No, addr is VA, not value
    // We need to know if the register holding addr is tainted
    // Our loadMem/storeMem is called with concrete addr, but we can check if that addr's low bytes match tainted SystemBuffer content?
    // Instead, we check if the address was derived from tainted data via taint on the register that held it before the mem op
    // We have not tracked which reg was used for addr; we can check all regs taint: if any reg taint any and its concrete value equals addr & ... that's heuristic
    // For now, we check if the addr bytes themselves are tainted in memory? No.
    // Simpler: if the address is user-controlled (i.e., tainted value used as address), then the address value itself would be tainted as data
    // But our taint tracks data flow, so if SystemBuffer[0..7] is tainted as pointer, then after `mov rax, [rcx]` where rcx is SystemBuffer and rax gets tainted pointer, then `mov rbx, [rax]` will have addr = rax concrete = tainted pointer value, and rax reg is tainted. So at that second deref, we can detect that the base register (rax) is tainted
    // So at storeMem/loadMem, we should check if any reg's tainted value equals addr (or close)
    // For now, brute check: iterate regs, if reg tainted and reg value == addr, then addr is tainted
    for (const name of R64) {
      const t = this.taint.getRegTaint(name, 8);
      if (t.any) {
        try {
          const rv = this.regs[name];
          if (rv === (BigInt(addr) & M64)) {
            return t;
          }
          // also check bounded: addr == base + tainted_offset
          // if tainted offset is e.g., low 4 bytes of reg, then addr = fixed_base + offset
          // we can detect if addr - base == offset and offset tainted
          // For simplicity, if reg tainted and addr is within 0x1000 of some fixed base? Hard
          // We'll just return t if any reg tainted and its value is close
          if ((rv & 0xffffffffn) === (BigInt(addr) & 0xffffffffn) && t.any) {
            return t;
          }
        } catch {}
      }
    }
    // also check if addr itself was tainted as memory address (unlikely)
    return {any:false, ids:[]};
  }

  _isTaintedUserPointer(addr) {
    // check if the 8-byte value at addr (if addr is within SystemBuffer) is tainted?
    // Simplified: if addr within SystemBuffer range, then its content is tainted
    if (this.systemBuffer && BigInt(addr) >= this.systemBuffer && BigInt(addr) < this.systemBuffer + BigInt(this.systemBufferLen)) {
      const t = this.taint.getRangeTaint(addr, 8);
      return t.any;
    }
    return false;
  }

  _isStackAddr(addr) {
    const rsp = this.regs.rsp;
    // stack is within 0x1000 of rsp
    const diff = BigInt(addr) > rsp ? BigInt(addr)-rsp : rsp-BigInt(addr);
    return diff < 0x2000n;
  }

  _controlDegree(addrTaint, addr) {
    // heuristic: if taint covers all 8 bytes -> full
    // if taint covers 1-4 low bytes -> bounded
    const taintedBytes = addrTaint.ids.filter(id=>id).length;
    if (taintedBytes >= 6) return "full";
    if (taintedBytes >=1 && taintedBytes <=4) return "bounded";
    return "influenced";
  }

  _reportMemSink(id, addr, size, taint, access, degree) {
    const cfg = SINK_CATALOG.find(s=>s.id===id);
    if (!cfg) return;
    const bug = makeBug({
      sinkType: cfg.id,
      sinkApi: null,
      sinkLocation: `0x${this.rip.toString(16)}`,
      taintedOperands: [{role: access, addr:`0x${addr.toString(16)}`, size, taintIds: taint.ids}],
      controlDegree: degree || (taint.any ? "full" : "influenced"),
      witnessInput: null,
      coverageDelta: null,
      severity: cfg.severity,
      rip: this.rip,
      taintFlows: [`addr tainted ${taint.ids.join(",")}`],
    });
    this.bugs.push(bug);
  }

  // API sink check called from kernel wrapper
  checkApiSink(apiName, args) {
    const sinks = sinksForApi(apiName);
    for (const sink of sinks) {
      for (const p of sink.params || []) {
        const argVal = args[p.idx] ?? 0n;
        // check taint of this arg
        // args are BigInt values from regs/stack
        // we need to know if that arg's value is tainted (i.e., came from SystemBuffer)
        // We check if any reg taint corresponds to this arg's value
        // For simplicity, check if argVal's low bytes match any tainted reg or if the SystemBuffer taint includes the stack slot for this arg
        let isTainted = false;
        let taintIds = [];
        // check regs: rcx, rdx, r8, r9, stack args
        const regMap = ["rcx","rdx","r8","r9"];
        if (p.idx < 4) {
          const r = regMap[p.idx];
          const t = this.taint.getRegTaint(r, 8);
          if (t.any) { isTainted = true; taintIds = t.ids; }
        } else {
          // stack arg: need to check memory at rsp+0x28 + (idx-4)*8
          // we can check taint of that stack slot via memory taint
          const slotAddr = this.regs.rsp + 0x28n + BigInt((p.idx-4)*8);
          const t = this.taint.getRangeTaint(slotAddr, 8);
          if (t.any) { isTainted = true; taintIds = t.ids; }
        }
        // also check if argVal points into tainted buffer (for dstAddr case, dst may be SystemBuffer itself? but SystemBuffer is not tainted as address, it's fixed)
        // For len case, isTainted if length value equals inputLen and we marked inputLen tainted
        if (p.role==="length" && this._inputLenTainted) {
          // if argVal == input length (attacker-controlled), consider tainted
          // we conservatively flag if len is small and taint any
          // For now, if not already tainted, check if len bytes include tainted SystemBuffer length field? Hard
          // We will flag len tainted if any SystemBuffer byte tainted (since len is attacker-controlled independent of content)
          // So we treat InputBufferLength as tainted by definition
          isTainted = true;
          if (!taintIds.length) taintIds = [9999];
        }
        if (isTainted) {
          const degree = p.role==="dstAddr" || p.role==="physAddr" ? "full" : p.role==="length" || p.role==="size" ? "bounded" : "influenced";
          const bug = makeBug({
            sinkType: sink.id,
            sinkApi: apiName,
            sinkLocation: `0x${this.rip.toString(16)}`,
            taintedOperands: [{pos:p.idx, role:p.role, value:`0x${argVal.toString(16)}`, taintIds}],
            controlDegree: degree,
            severity: sink.severity,
            rip: this.rip,
          });
          this.bugs.push(bug);
        }
      }
    }
    // special handling for Probe tracking
    if (apiName==="ProbeForRead" || apiName==="ProbeForWrite") {
      this.probeDone = true;
    }
  }

  // MSR/CR/port hooks
  checkMsr(msr, value, isWrite) {
    const t = this.taint.getRegTaint("rcx", 4) || this.taint.getRegTaint("rdx", 4);
    // msr index in rcx, value in rdx:rax
    // check if msr tainted
    const msrTaint = this.taint.getRegTaint("rcx", 4);
    if (msrTaint.any) {
      const bug = makeBug({ sinkType:"WRMSR_TAINTED", sinkApi: isWrite?"WRMSR":"RDMSR", sinkLocation:`0x${this.rip.toString(16)}`, taintedOperands:[{role:"msr", value:msr.toString(16)}], controlDegree:"full", severity:8, rip:this.rip });
      this.bugs.push(bug);
    }
  }
  checkCrWrite(cr, value) {
    const t = this.taint.getRegTaint("rcx",8) || this.taint.getRegTaint("rdx",8);
    // if value tainted
    // we check if any reg tainted
    let any=false;
    for(const r of R64){ if(this.taint.getRegTaint(r,8).any){ any=true; break; }}
    if (any) {
      const bug=makeBug({sinkType:"MOV_CR_TAINTED", sinkApi:`MOV CR${cr}`, sinkLocation:`0x${this.rip.toString(16)}`, controlDegree:"full", severity:8, rip:this.rip});
      this.bugs.push(bug);
    }
  }
}
