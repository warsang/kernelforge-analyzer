/**
 * bug/engine.mjs — orchestrates Find Bugs campaign (directed fuzz + taint + bug DB)
 */

import { CoverageTracker } from "../coverage.mjs";
import { captureSnapshot, restoreSnapshot } from "../snapshot.mjs";
import { BugFindingInterpreter } from "./instrument.mjs";
import { BugDB, makeBug } from "./bugdb.mjs";
import { DynamicCFG } from "./cfg.mjs";
import { computeDistances, distanceForTrace } from "./distance.mjs";
import { SINK_CATALOG } from "./sinks.mjs";

const R64 = ["rax","rcx","rdx","rbx","rsp","rbp","rsi","rdi","r8","r9","r10","r11","r12","r13","r14","r15"];

export async function findBugsCampaign(kernel, device, ctlCode, opts={}) {
  const {
    sendIrp, imageBase, imageSize,
    iterations = 128, corpusCap = 16,
    maxSymBytes = 32, inputLen = 16, outputLen = 64,
    onProgress, driverHash,
  } = opts;

  // Ensure we have a BugFindingInterpreter (JS only)
  let bugKernel = kernel;
  let bugCpu = kernel.cpu;
  let savedCpu = null;
  const isJs = bugCpu.constructor?.name === "JsInterpreter";
  const isHybrid = bugCpu.constructor?.name === "HybridCpuBackend";
  if (!isJs) {
    // For Hybrid/Unicorn, fallback to JS shadow with replay
    const mem = kernel.mem;
    const c = new BugFindingInterpreter(mem, {mode:"TAINT_ONLY"});
    if (isHybrid && bugCpu.js) {
      // copy regs from active js engine
      for (const r of R64) try{ c.regs[r]=bugCpu.js.regs[r]; }catch{}
      try{ c.rip=bugCpu.js.rip; }catch{}
    } else {
      for (const r of R64) try{ c.regs[r]=bugCpu.regs[r]; }catch{}
      try{ c.rip=bugCpu.rip; }catch{}
    }
    savedCpu = kernel.cpu;
    kernel.cpu = c;
    bugCpu = c;
    bugKernel = kernel;
  } else {
    // wrap existing JsInterpreter
    const mem = kernel.mem;
    const c = new BugFindingInterpreter(mem, {mode:"TAINT_ONLY"});
    for (const r of R64) try{ c.regs[r]=kernel.cpu.regs[r]; }catch{}
    try{ c.rip=kernel.cpu.rip; }catch{}
    for (const f of ["cf","zf","sf","of","df","tf","iflag","inhibitWindow"]) if (f in kernel.cpu) c[f]=kernel.cpu[f];
    savedCpu = kernel.cpu;
    kernel.cpu = c;
    bugCpu = c;
  }

  // Patch API sinks: wrap kernel.defineApi / existing impls to check taint before execution
  const origImpls = new Map(kernel.apiImpls);
  const wrapped = new Map();
  for (const [name, addr] of kernel.apiThunks) {
    const sinkCheck = () => {
      // check at call time via hook, not here
    };
  }
  // Instead, install a code hook for thunk range that checks taint on entry
  // We will addCodeHook for the thunk range that inspects args taint via bugCpu.taint
  // Simpler: monkey-patch kernel.apiImpls to wrap each impl
  for (const [name, impl] of kernel.apiImpls) {
    const orig = impl;
    const wrappedFn = function(...args) {
      // args are BigInt values from kernel's hook (rcx,rdx,...)
      try {
        // call bugCpu check
        if (bugCpu && typeof bugCpu.checkApiSink==="function") {
          bugCpu.checkApiSink(name, args);
        }
      } catch(e){ /* ignore */ }
      return orig.apply(this, args);
    };
    kernel.apiImpls.set(name, wrappedFn);
    wrapped.set(name, orig);
  }

  // Hook port/MSR/CR via cpu callbacks
  const origPortWrite = bugCpu.onPortWrite;
  const origPortRead = bugCpu.onPortRead;
  bugCpu.onPortWrite = (port, value, size) => {
    // check taint
    const t = bugCpu.taint.getRegTaint("rdx",2) || bugCpu.taint.getRegTaint("rcx",2);
    if (t.any) {
      const bug = makeBug({ sinkType:"PORT_IO_TAINTED", sinkApi:`OUT 0x${port.toString(16)}`, sinkLocation:`0x${bugCpu.rip.toString(16)}`, controlDegree:"full", severity:5, rip:bugCpu.rip });
      bugCpu.bugs.push(bug);
    }
    if (origPortWrite) return origPortWrite(port, value, size);
  };
  bugCpu.onPortRead = (port, size) => {
    // port read taint? less relevant
    if (origPortRead) return origPortRead(port, size);
    return 0xffffffffn;
  };
  // CR writes via kernel.writeCr0 already logs; we add check in bugCpu.checkCrWrite called from where? We can monkey-patch kernel.writeCr0
  const origWriteCr0 = kernel.writeCr0.bind(kernel);
  kernel.writeCr0 = function(v){
    try{ bugCpu.checkCrWrite(0, v); }catch{}
    return origWriteCr0(v);
  };

  const bugDB = new BugDB();
  const cfg = new DynamicCFG(imageBase);
  const tracker = new CoverageTracker(bugKernel, imageBase, imageSize);
  tracker.install();

  // heuristic sink locations for distance: we don't know static rip for each sink, so we treat any API sink address as potential target
  // For distance, we use the set of observed API thunk addresses that are sinks
  const sinkApiAddrs = new Set();
  for (const [name, addr] of kernel.apiThunks) {
    if (SINK_CATALOG.some(s=> s.apis?.includes(name))) sinkApiAddrs.add("0x"+addr.toString(16));
  }
  // Also for mem sinks, distance is to any block that is near handler entry (fallback)

  let seedPatterns = opts.seedPatterns || [
    new Uint8Array(inputLen),
    Uint8Array.from({length:inputLen},()=>0xff),
    Uint8Array.from({length:inputLen},(_,i)=>i),
  ];

  const snap0 = captureSnapshot(bugKernel);
  const globalSeen = new Set();
  let corpus = seedPatterns.map(b=> ({buf:b, coverage:{blocks:new Set()}, bugs:[]}));
  let globalHits = new Map();

  function buildGlobalHits(corpus) {
    const m=new Map();
    for(const e of corpus) for(const b of e.coverage.blocks) m.set(b,(m.get(b)||0)+1);
    return m;
  }
  function pickParent(corpus, hits, distMap, rngVal) {
    if (!corpus.length) return corpus[0];
    // score = distance weight + rarity
    const scored = corpus.map(e=>{
      const blocks = e.coverage.blocks;
      const dist = distanceForTrace(blocks, distMap);
      const rarity = [...blocks].reduce((s,b)=> s + (hits.get(b)||1), 0) / (blocks.size||1);
      // AFLGo annealing: early prefer rarity, later prefer distance
      // For now fixed blend 0.5
      const score = (dist===Infinity? 10 : dist*0.7) + rarity*0.3;
      return {e, score};
    });
    scored.sort((a,b)=> a.score - b.score);
    const top = scored.slice(0, Math.max(1, Math.ceil(scored.length/3)));
    return top[Math.floor(rngVal * top.length) % top.length].e;
  }

  function xorshift32(s){ s^=s<<13; s^=s>>>17; s^=s<<5; return s>>>0; }
  let rngState = 0x9e3779b1 ^ (ctlCode>>>0);
  const rng = ()=> { rngState = xorshift32(rngState); return rngState / 0xffffffff; };

  // helper to run one input with taint and collect bugs+coverage
  async function runWithBugs(buf) {
    const snap = captureSnapshot(bugKernel);
    // enable taint for this IRP's SystemBuffer
    // we need to intercept allocPool to know systemBuffer VA
    const origAlloc = bugKernel.allocPool.bind(bugKernel);
    let taintedBase = null;
    bugKernel.allocPool = function(size, tag){
      const addr = origAlloc(size, tag);
      if (tag==="IrpB" && taintedBase===null && size >= Math.max(buf.length, outputLen)) {
        taintedBase = addr;
        bugCpu.enableTaintForIrp(addr, Math.min(buf.length, 256), buf.length, outputLen, ctlCode);
        bugCpu.bugs = [];
        bugCpu.taint.reads.clear();
      }
      return addr;
    };
    tracker.reset(); tracker.resume();
    let res;
    try {
      res = await sendIrp(bugKernel, device, { major:0x0e, ioctl: BigInt(ctlCode>>>0), input: buf, outputLen });
    } catch(e){ res={status:"fault", error:e}; }
    tracker.pause();
    const coverage = { blocks:new Set(tracker.blocks), edges:new Set(tracker.edges) };
    // collect bugs from this run
    const bugs = [...bugCpu.bugs];
    // check for uninitialized leak / null deref
    if (res.status==="fault") {
      const bug = makeBug({ sinkType:"NULL_DEREF", sinkApi:null, sinkLocation:`0x${bugCpu.rip.toString(16)}`, severity:1, rip:bugCpu.rip, controlDegree:"influenced", taintedOperands:[]});
      bugs.push(bug);
    }
    // info leak: if res output not fully initialized? Check if outputHex has uninitialized bytes (we can't easily know, approximate)
    // we skip for v1

    // update CFG with this trace
    cfg.addTrace(coverage.edges);
    // compute distances
    const distMap = computeDistances(cfg, sinkApiAddrs);

    bugKernel.allocPool = origAlloc;
    bugCpu.taint.reset();
    // clear bugs for next run
    bugCpu.bugs = [];
    restoreSnapshot(bugKernel, snap);
    tracker.reset();
    return { res, coverage, bugs, distMap };
  }

  // initial corpus evaluation
  let bestBugs = 0;
  for (const entry of corpus.slice(0, Math.min(corpus.length, 8))) {
    const { res, coverage, bugs } = await runWithBugs(entry.buf);
    entry.coverage = coverage;
    entry.res = res;
    for(const b of bugs){
      b.witnessInput = [...entry.buf].map(x=>x.toString(16).padStart(2,"0")).join("");
      b.ioctlCode = ctlCode;
      b.driverHash = driverHash || "unknown";
      b.coverageDelta = {blocks: coverage.blocks.size};
      if (bugDB.add(b)) {
        bestBugs++;
        if (onProgress) onProgress({phase:"bug-found", bug:b});
      }
    }
    for(const b of coverage.blocks) globalSeen.add(b);
  }
  globalHits = buildGlobalHits(corpus);

  let iterationsDone = 0;
  // main directed fuzz loop
  for(let iter=0; iter<iterations; iter++){
    if (bugKernel.bugcheck || bugKernel.crash) break;
    iterationsDone = iter+1;
    // compute current dist map for scheduling
    const distMap = computeDistances(cfg, sinkApiAddrs);
    const parent = pickParent(corpus, globalHits, distMap, rng());
    if (!parent) break;
    // mutate to create child (reuse fuzz mutation logic simple)
    let child;
    // simple random byte mutation
    {
      child = new Uint8Array(parent.buf);
      const idx = Math.floor(rng()*child.length);
      child[idx] = Math.floor(rng()*256);
      // occasionally splice interesting
      if (rng()<0.2) {
        const interesting = [0x00,0xff,0x41,0x42,0x7f,0x80];
        child[Math.floor(rng()*child.length)] = interesting[Math.floor(rng()*interesting.length)];
      }
    }
    const { res, coverage, bugs } = await runWithBugs(child);
    const newBlocks = [...coverage.blocks].filter(b=> !globalSeen.has(b));
    const isNewCoverage = newBlocks.length>0;
    const hasBugs = bugs.length>0;
    // directed: if close to sink (distance < 3) but not yet reached, hand to concolic slice
    const dist = distanceForTrace(coverage.blocks, distMap);
    let concolicBugs = [];
    if (dist < 3 && dist !== Infinity && !hasBugs && parent) {
      // attempt concolic slice to sink (simplified: just try to solve next branch)
      // For v1, we will reuse existing concolicCampaign for this input (one query)
      // To avoid heavy solver per iter, only do every 16 iters
      if (iter % 16 === 0) {
        try {
          const { concolicCampaign } = await import("../symbolic/concolic.mjs");
          const conc = await concolicCampaign(bugKernel, device, ctlCode, {
            sendIrp, imageBase, imageSize,
            maxSymBytes: Math.min(child.length, 16),
            solverTimeoutMs: 300, maxQueries: 2,
            inputLen: child.length, outputLen,
            corpus: [{buf: child, coverage}],
            onProgress: ()=>{},
          });
          for(const c of conc.corpus){
            if (c.buf.join(",") !== child.join(",")) {
              const { res: cres, coverage: ccov, bugs: cbugs } = await runWithBugs(c.buf);
              if (cbugs.length) concolicBugs.push(...cbugs.map(b=> ({...b, witnessInput: [...c.buf].map(x=>x.toString(16).padStart(2,"0")).join("") })));
              // add to corpus if new
              if ([...ccov.blocks].some(b=>!globalSeen.has(b))) {
                for(const b of ccov.blocks) globalSeen.add(b);
                corpus.push({buf:c.buf, coverage:ccov, res:cres});
              }
            }
          }
        } catch(e){ /* ignore */ }
      }
    }

    if (isNewCoverage || hasBugs || concolicBugs.length) {
      for(const b of coverage.blocks) globalSeen.add(b);
      const entry = { buf: child, coverage, res, bugs: [...bugs, ...concolicBugs] };
      corpus.push(entry);
      if (corpus.length > corpusCap) {
        // evict most common
        const scored = corpus.map(e=>{
          let sum=0; for(const b of e.coverage.blocks) sum+= globalHits.get(b)||1;
          return {e, score: e.coverage.blocks.size ? sum/e.coverage.blocks.size : 0};
        });
        scored.sort((a,b)=> b.score - a.score);
        const worst = scored[0].e;
        const idx = corpus.indexOf(worst);
        if(idx>=0) corpus.splice(idx,1);
      }
      globalHits = buildGlobalHits(corpus);
      for(const b of [...bugs, ...concolicBugs]){
        b.witnessInput = [...child].map(x=>x.toString(16).padStart(2,"0")).join("");
        b.ioctlCode = ctlCode;
        b.driverHash = driverHash || "unknown";
        b.coverageDelta = {blocks: coverage.blocks.size};
        if (bugDB.add(b)) {
          if (onProgress) onProgress({phase:"bug-found", bug:b});
        }
      }
      if (onProgress && (hasBugs || concolicBugs.length)) {
        onProgress({phase:"fuzz-bug", iter, child, bugs});
      }
    }
    if (onProgress && iter % 32 === 0) onProgress({phase:"fuzz", iter, coverage: coverage.blocks.size, dist, corpus: corpus.length});
  }

  // restore original cpu and api impls
  if (savedCpu) {
    bugKernel.cpu = savedCpu;
  }
  for(const [name, orig] of wrapped) bugKernel.apiImpls.set(name, orig);
  bugKernel.writeCr0 = origWriteCr0;

  restoreSnapshot(bugKernel, snap0);
  tracker.dispose();

  return { corpus, bugDB, cfg, iterations: iterationsDone };
}
