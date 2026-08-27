/**
 * linux-engine.mjs — directed fuzz + taint for .ko
 * Clone of bug/engine.mjs but targeting LinuxKernel + sendFileOp + Linux sinks
 */
import { CoverageTracker } from "@kernelforge/ntsim-analyzer/src/coverage.mjs";
import { captureSnapshot, restoreSnapshot } from "@kernelforge/ntsim-analyzer/src/snapshot.mjs";
import { BugFindingInterpreter } from "@kernelforge/ntsim-analyzer/src/bug/instrument.mjs";
import { BugDB, makeBug } from "@kernelforge/ntsim-analyzer/src/bug/bugdb.mjs";
import { DynamicCFG } from "@kernelforge/ntsim-analyzer/src/bug/cfg.mjs";
import { computeDistances, distanceForTrace } from "@kernelforge/ntsim-analyzer/src/bug/distance.mjs";
import { LINUX_SINK_CATALOG } from "./linux-sinks.mjs";

const R64=["rax","rcx","rdx","rbx","rsp","rbp","rsi","rdi","r8","r9","r10","r11","r12","r13","r14","r15"];

export async function findLinuxBugsCampaign(kernel, device, op, opts={}){
  const {
    sendFileOp, imageBase, imageSize,
    iterations=128, corpusCap=16,
    inputLen=16, outputLen=64,
    onProgress, driverHash,
    cmd=0,
  } = opts;

  let bugKernel=kernel;
  let bugCpu=kernel.cpu;
  let savedCpu=null;
  const isJs=bugCpu.constructor?.name==="JsInterpreter";
  const isHybrid=bugCpu.constructor?.name==="HybridCpuBackend";
  if(!isJs){
    const mem=kernel.mem;
    const c=new BugFindingInterpreter(mem, {mode:"TAINT_ONLY"});
    if(isHybrid && bugCpu.js){
      for(const r of R64) try{ c.regs[r]=bugCpu.js.regs[r]; }catch{}
      try{ c.rip=bugCpu.js.rip; }catch{}
    } else {
      for(const r of R64) try{ c.regs[r]=bugCpu.regs[r]; }catch{}
      try{ c.rip=bugCpu.rip; }catch{}
    }
    savedCpu=kernel.cpu;
    kernel.cpu=c;
    bugCpu=c;
    if(typeof kernel.reinstallHooks==="function") kernel.reinstallHooks();
  } else {
    const mem=kernel.mem;
    const c=new BugFindingInterpreter(mem, {mode:"TAINT_ONLY"});
    for(const r of R64) try{ c.regs[r]=kernel.cpu.regs[r]; }catch{}
    try{ c.rip=kernel.cpu.rip; }catch{}
    for(const f of ["cf","zf","sf","of","df","tf","iflag","inhibitWindow"]) if(f in kernel.cpu) c[f]=kernel.cpu[f];
    savedCpu=kernel.cpu;
    kernel.cpu=c;
    bugCpu=c;
    if(typeof kernel.reinstallHooks==="function") kernel.reinstallHooks();
  }

  // patch api impls + taint propagation for user copies + Linux SysV checks
  const origImpls=new Map(kernel.apiImpls);
  const sysvRegs=["rdi","rsi","rdx","rcx","r8","r9"];
  const STUB_FUZZABLES=["filp_open","kern_path","notify_change","call_usermodehelper","copy_to_user","kmalloc"];
  function isTaintedSysv(idx){
    if(idx<6) return bugCpu.taint.getRegTaint(sysvRegs[idx],8).any;
    const slotAddr = bugCpu.regs.rsp + 8n + BigInt((idx-6)*8);
    return bugCpu.taint.getRangeTaint(slotAddr,8).any;
  }
  function applyStubPolicyFromBuf(buf){
    // success-by-default, but byte 0 bit 0 flips filp_open, bit1 kern_path, etc.
    // This makes stub outcome fuzz-configurable per call without hardcoding
    try{
      const b0=buf[0]??0;
      const b1=buf[1]??0;
      kernel.stubPolicy.set("filp_open", {mode:(b0 & 1)?"err":"success", errCode:-2});
      kernel.stubPolicy.set("kern_path", {mode:(b0 & 2)?"err":"success", errCode:-2});
      kernel.stubPolicy.set("notify_change", {mode:(b0 & 4)?"err":"success", errCode:-1});
      kernel.stubPolicy.set("call_usermodehelper", {mode:(b0 & 8)?"err":"success"});
      // use b1 for kmalloc etc
      kernel.stubPolicy.set("kmalloc", {mode:(b1 & 1)?"err":"success"});
      kernel.stubPolicy.set("copy_to_user", {mode:(b1 & 2)?"err":"success"});
    }catch{}
  }
  for(const [name,impl] of kernel.apiImpls){
    const orig=impl;
    const wrapped=function(...args){
      try{ if(bugCpu && typeof bugCpu.checkApiSink==="function") bugCpu.checkApiSink(name, args); }catch{}
      try{
        if(name==="copy_to_user"||name==="_copy_to_user"||name==="__copy_to_user"||name==="copy_from_user"||name==="_copy_from_user"){
          const dstTainted=isTaintedSysv(0);
          const lenTainted=isTaintedSysv(2);
          if(dstTainted){
            const bug=makeBug({sinkType:"COPY_TO_USER_TAINTED_PTR_OR_LEN", sinkApi:name, sinkLocation:`0x${bugCpu.rip.toString(16)}`, taintedOperands:[{pos:0, role:"dst", value:`0x${args[0].toString(16)}`}], controlDegree:"full", severity:10, rip:bugCpu.rip});
            bugCpu.bugs.push(bug);
          }
          if(lenTainted){
            const bug=makeBug({sinkType:"COPY_TO_USER_TAINTED_PTR_OR_LEN", sinkApi:name, sinkLocation:`0x${bugCpu.rip.toString(16)}`, taintedOperands:[{pos:2, role:"len", value:`0x${args[2].toString(16)}`}], controlDegree:"bounded", severity:8, rip:bugCpu.rip});
            bugCpu.bugs.push(bug);
          }
        }
        if(name==="kmalloc"||name==="kzalloc"||name==="__kmalloc"||name==="vmalloc"){
          if(isTaintedSysv(0)){
            const bug=makeBug({sinkType:"KMALLOC_TAINTED_SIZE", sinkApi:name, sinkLocation:`0x${bugCpu.rip.toString(16)}`, taintedOperands:[{pos:0, role:"size", value:`0x${args[0].toString(16)}`}], controlDegree:"bounded", severity:8, rip:bugCpu.rip});
            bugCpu.bugs.push(bug);
          }
        }
        if(name==="commit_creds"){
          // Flag any commit_creds reachable from fileop, tainted or not (classic cred escalation)
          const isTainted=isTaintedSysv(0);
          const bug=makeBug({sinkType: isTainted?"COMMIT_CREDS_TAINTED":"COMMIT_CREDS_TAINTED", sinkApi:name, sinkLocation:`0x${bugCpu.rip.toString(16)}`, taintedOperands:[{pos:0, role:"cred", value:`0x${args[0].toString(16)}`}], controlDegree:isTainted?"full":"full", severity:10, rip:bugCpu.rip});
          bugCpu.bugs.push(bug);
        }
        if(name==="prepare_kernel_cred"){
          // Also flag prepare_kernel_cred(0) as potential
          if(Number(args[0])===0){
            const bug=makeBug({sinkType:"PREPARE_KERNEL_CRED_NULL", sinkApi:name, sinkLocation:`0x${bugCpu.rip.toString(16)}`, taintedOperands:[{pos:0, role:"daemon", value:`0x${args[0].toString(16)}`}], controlDegree:"full", severity:10, rip:bugCpu.rip});
            bugCpu.bugs.push(bug);
          }
        }
      }catch{}
      const ret=orig.apply(this,args);
      try{
        if(name==="copy_from_user"||name==="_copy_from_user"||name==="__copy_from_user"){
          const to=args[0], from=args[1];
          const n=Number(args[2] ?? 0);
          if(to && from && n>0 && n<4096){
            const src=bugCpu.taint.getRangeTaint(from, n);
            if(src.any){
              for(let i=0;i<n;i++){
                const id=src.ids[i]||0;
                if(id) bugCpu.taint.setByteTaint(BigInt(to)+BigInt(i), id);
                else bugCpu.taint.setByteTaint(BigInt(to)+BigInt(i), 0);
              }
            } else {
              for(let i=0;i<n;i++) bugCpu.taint.setByteTaint(BigInt(to)+BigInt(i), 0);
            }
          }
        } else if(name==="copy_to_user"||name==="_copy_to_user"||name==="__copy_to_user"){
        } else if(name==="kmalloc"||name==="kzalloc"||name==="__kmalloc"){
        }
      }catch{}
      return ret;
    };
    kernel.apiImpls.set(name,wrapped);
  }
  // port/cr hooks
  const origPortWrite=bugCpu.onPortWrite;
  bugCpu.onPortWrite=(port,value,size)=>{
    const t = bugCpu.taint.getRegTaint("rdx",2) || bugCpu.taint.getRegTaint("rcx",2);
    if(t.any){
      const bug=makeBug({sinkType:"PORT_IO_TAINTED", sinkApi:`OUT 0x${port.toString(16)}`, sinkLocation:`0x${bugCpu.rip.toString(16)}`, controlDegree:"full", severity:5, rip: bugCpu.rip});
      bugCpu.bugs.push(bug);
    }
    if(origPortWrite) return origPortWrite(port,value,size);
  };
  const origWriteCr0 = kernel.writeCr0 ? kernel.writeCr0.bind(kernel) : null;
  // LinuxKernel doesn't have writeCr0 directly but define via api; we monkey patch api wrapper for write_cr0
  // Instead patch checkCr
  const origCheck = bugCpu.checkCrWrite;
  // We'll keep.

  const bugDB=new BugDB();
  const cfg=new DynamicCFG(imageBase);
  const tracker=new CoverageTracker(bugKernel, imageBase, imageSize);
  tracker.install();

  const sinkApiAddrs=new Set();
  for(const [name,addr] of kernel.apiThunks){
    if(LINUX_SINK_CATALOG.some(s=> s.apis?.includes(name))) sinkApiAddrs.add("0x"+addr.toString(16));
  }

  let seedPatterns = opts.seedPatterns || [
    new Uint8Array(inputLen),
    Uint8Array.from({length:inputLen},()=>0xff),
    Uint8Array.from({length:inputLen},(_,i)=>i),
  ];

  const snap0=captureSnapshot(bugKernel);
  const globalSeen=new Set();
  let corpus=seedPatterns.map(b=> ({buf:b, coverage:{blocks:new Set()}, bugs:[]}));
  let globalHits=new Map();
  function buildGlobalHits(corpus){
    const m=new Map();
    for(const e of corpus) for(const b of e.coverage.blocks) m.set(b,(m.get(b)||0)+1);
    return m;
  }
  function pickParent(corpus, hits, distMap, rngVal){
    if(!corpus.length) return corpus[0];
    const scored=corpus.map(e=>{
      const blocks=e.coverage.blocks;
      const dist=distanceForTrace(blocks, distMap);
      const rarity=[...blocks].reduce((s,b)=> s + (hits.get(b)||1),0) / (blocks.size||1);
      const score=(dist===Infinity?10:dist*0.7)+rarity*0.3;
      return {e, score};
    });
    scored.sort((a,b)=>a.score-b.score);
    const top=scored.slice(0, Math.max(1, Math.ceil(scored.length/3)));
    return top[Math.floor(rngVal*top.length)%top.length].e;
  }
  function xorshift32(s){ s^=s<<13; s^=s>>>17; s^=s<<5; return s>>>0; }
  let rngState=0x9e3779b1 ^ (Number(cmd)>>>0);
  const rng=()=>{ rngState=xorshift32(rngState); return rngState/0xffffffff; };

  async function runWithBugs(buf){
    const snap=captureSnapshot(bugKernel);
    const stubSnap=new Map(kernel.stubPolicy);
    applyStubPolicyFromBuf(buf);
    // intercept slub alloc for UArg
    const origAlloc=bugKernel.allocSlub ? bugKernel.allocSlub.bind(bugKernel) : bugKernel.allocPool.bind(bugKernel);
    let taintedBase=null;
    const patchAlloc = function(size, tag){
      const addr=origAlloc(size,tag);
      if(tag==="UArg" && taintedBase===null && size>=Math.max(buf.length, outputLen)){
        taintedBase=addr;
        bugCpu.enableTaintForIrp(addr, Math.min(buf.length,256), buf.length, outputLen, Number(cmd));
        bugCpu.bugs=[];
        bugCpu.taint.reads.clear();
      }
      return addr;
    };
    // Patch both alloc entry points
    const origAllocPool=bugKernel.allocPool.bind(bugKernel);
    const origAllocSlub=bugKernel.allocSlub ? bugKernel.allocSlub.bind(bugKernel) : origAllocPool;
    bugKernel.allocPool=patchAlloc;
    if(bugKernel.allocSlub) bugKernel.allocSlub=patchAlloc;
    tracker.reset(); tracker.resume();
    let res;
    try{
      res=await sendFileOp(bugKernel, device, { op, cmd, input: buf, outputLen });
    } catch(e){ res={status:"fault", error:e}; }
    tracker.pause();
    const coverage={blocks:new Set(tracker.blocks), edges:new Set(tracker.edges)};
    const bugs=[...bugCpu.bugs];
    if(res.status==="fault"){
      const bug=makeBug({sinkType:"NULL_DEREF", sinkApi:null, sinkLocation:`0x${bugCpu.rip.toString(16)}`, severity:1, rip: bugCpu.rip, controlDegree:"influenced", taintedOperands:[]});
      bugs.push(bug);
    }
    cfg.addTrace(coverage.edges);
    const distMap=computeDistances(cfg, sinkApiAddrs);
    bugKernel.allocPool=origAllocPool;
    if(bugKernel.allocSlub) bugKernel.allocSlub=origAllocSlub;
    // restore stub policy
    kernel.stubPolicy.clear();
    for(const [k,v] of stubSnap) kernel.stubPolicy.set(k,v);
    bugCpu.taint.reset();
    bugCpu.bugs=[];
    restoreSnapshot(bugKernel, snap);
    tracker.reset();
    return {res, coverage, bugs, distMap};
  }

  let bestBugs=0;
  for(const entry of corpus.slice(0, Math.min(corpus.length,8))){
    const {res, coverage, bugs}=await runWithBugs(entry.buf);
    entry.coverage=coverage; entry.res=res;
    for(const b of bugs){
      b.witnessInput=[...entry.buf].map(x=>x.toString(16).padStart(2,"0")).join("");
      b.ioctlCode=`0x${cmd.toString(16)}`;
      b.driverHash=driverHash||"unknown";
      if(bugDB.add(b)){
        bestBugs++;
        if(onProgress) onProgress({phase:"bug-found", bug:b});
      }
    }
    for(const b of coverage.blocks) globalSeen.add(b);
  }
  globalHits=buildGlobalHits(corpus);
  let iterationsDone=0;
  for(let iter=0; iter<iterations; iter++){
    if(bugKernel.bugcheck || bugKernel.crash) break;
    iterationsDone=iter+1;
    const distMap=computeDistances(cfg, sinkApiAddrs);
    const parent=pickParent(corpus, globalHits, distMap, rng());
    if(!parent) break;
    let child=new Uint8Array(parent.buf);
    const idx=Math.floor(rng()*child.length);
    child[idx]=Math.floor(rng()*256);
    if(rng()<0.2){
      const interesting=[0x00,0xff,0x41,0x42,0x7f,0x80];
      child[Math.floor(rng()*child.length)]=interesting[Math.floor(rng()*interesting.length)];
    }
    const {res, coverage, bugs}=await runWithBugs(child);
    const newBlocks=[...coverage.blocks].filter(b=>!globalSeen.has(b));
    const isNewCoverage=newBlocks.length>0;
    const hasBugs=bugs.length>0;
    const dist=distanceForTrace(coverage.blocks, distMap);
    let concolicBugs=[];
    if(dist<3 && dist!==Infinity && !hasBugs && parent){
      if(iter%16===0){
        try{
          const { concolicCampaign } = await import("@kernelforge/ntsim-analyzer/src/symbolic/concolic.mjs");
          // reuse generic concolic but adapt sendIrp shim to sendFileOp
          // Wrap sendFileOp as sendIrp for campaign
          const conc = await concolicCampaign(bugKernel, device, Number(cmd), {
            sendIrp: async (k,dev,spec)=> {
              // spec.input is Uint8Array, spec.ioctl is BigInt cmd
              return sendFileOp(k, dev, {op, cmd: spec.ioctl, input: spec.input, outputLen});
            },
            imageBase, imageSize,
            maxSymBytes: Math.min(child.length,16),
            solverTimeoutMs:300, maxQueries:2,
            inputLen: child.length, outputLen,
            corpus: [{buf:child, coverage}],
            onProgress:()=>{},
          });
          for(const c of conc.corpus){
            if(c.buf.join(",")!==child.join(",")){
              const {res:cres, coverage:ccov, bugs:cbugs}=await runWithBugs(c.buf);
              if(cbugs.length) concolicBugs.push(...cbugs.map(b=> ({...b, witnessInput:[...c.buf].map(x=>x.toString(16).padStart(2,"0")).join("")})));
              if([...ccov.blocks].some(b=>!globalSeen.has(b))){
                for(const b of ccov.blocks) globalSeen.add(b);
                corpus.push({buf:c.buf, coverage:ccov, res:cres});
              }
            }
          }
        }catch(e){ }
      }
    }
    if(isNewCoverage || hasBugs || concolicBugs.length){
      for(const b of coverage.blocks) globalSeen.add(b);
      const entry={buf:child, coverage, res, bugs:[...bugs,...concolicBugs]};
      corpus.push(entry);
      if(corpus.length>corpusCap){
        const scored=corpus.map(e=>{
          let sum=0; for(const b of e.coverage.blocks) sum+= globalHits.get(b)||1;
          return {e, score: e.coverage.blocks.size? sum/e.coverage.blocks.size:0};
        });
        scored.sort((a,b)=> b.score - a.score);
        const worst=scored[0].e;
        const idx=corpus.indexOf(worst);
        if(idx>=0) corpus.splice(idx,1);
      }
      globalHits=buildGlobalHits(corpus);
      for(const b of [...bugs, ...concolicBugs]){
        b.witnessInput=[...child].map(x=>x.toString(16).padStart(2,"0")).join("");
        b.ioctlCode=`0x${cmd.toString(16)}`;
        b.driverHash=driverHash||"unknown";
        if(bugDB.add(b)){
          if(onProgress) onProgress({phase:"bug-found", bug:b});
        }
      }
      if(onProgress && (hasBugs||concolicBugs.length)){
        onProgress({phase:"fuzz-bug", iter, child, bugs});
      }
    }
    if(onProgress && iter%32===0) onProgress({phase:"fuzz", iter, coverage: coverage.blocks.size, dist, corpus: corpus.length});
  }

  if(savedCpu){
    bugKernel.cpu=savedCpu;
  }
  for(const [name,orig] of origImpls) bugKernel.apiImpls.set(name,orig);
  restoreSnapshot(bugKernel, snap0);
  tracker.dispose();
  return {corpus, bugDB, cfg, iterations: iterationsDone};
}
