/**
 * concolic-ops.mjs — concolic campaign for Linux fileops
 * Wraps generic concolicCampaign with fileop adapter
 */
import { CoverageTracker } from "@kernelforge/ntsim-analyzer/src/coverage.mjs";
import { captureSnapshot, restoreSnapshot } from "@kernelforge/ntsim-analyzer/src/snapshot.mjs";
import { ConcolicJsInterpreter } from "@kernelforge/ntsim-analyzer/src/symbolic/concolic.mjs";
import { solveConstraints } from "@kernelforge/ntsim-analyzer/src/symbolic/solver.mjs";

const R64=["rax","rcx","rdx","rbx","rsp","rbp","rsi","rdi","r8","r9","r10","r11","r12","r13","r14","r15"];

export async function concolicFileOp(kernel, device, opName, opts={}){
  const maxSymBytes=opts.maxSymBytes??64;
  const solverTimeoutMs=opts.solverTimeoutMs??500;
  const maxQueries=opts.maxQueries??8;
  const inputLen=opts.inputLen??16;
  const outputLen=opts.outputLen??64;
  const cmd=opts.cmd??0x222000;
  const sendFileOp=opts.sendFileOp;
  const base=opts.imageBase, size=opts.imageSize;
  if(!sendFileOp) throw new Error("concolicFileOp: sendFileOp required");

  // Ensure JsInterpreter concolic path (like concolicCampaign does)
  let concolicKernel=kernel;
  let concolicCpu=kernel.cpu;
  let isCloned=false;
  const isJs=concolicCpu.constructor?.name==="JsInterpreter";
  const isHybrid=concolicCpu.constructor?.name==="HybridCpuBackend";
  if(!isJs){
    if(isHybrid && concolicCpu.js){
      const mem=kernel.mem;
      const c=new ConcolicJsInterpreter(mem);
      concolicKernel._savedCpu=kernel.cpu;
      concolicKernel.cpu=c;
      concolicCpu=c;
      isCloned=true;
    } else {
      const mem=kernel.mem;
      const c=new ConcolicJsInterpreter(mem);
      concolicKernel._savedCpu=kernel.cpu;
      concolicKernel.cpu=c;
      concolicCpu=c;
      isCloned=true;
    }
  } else {
    const mem=kernel.mem;
    const c=new ConcolicJsInterpreter(mem);
    for(const r of R64) c.regs[r]=kernel.cpu.regs[r];
    c.rip=kernel.cpu.rip;
    for(const f of ["cf","zf","sf","of","df","tf","iflag","inhibitWindow"]) if(f in kernel.cpu) c[f]=kernel.cpu[f];
    concolicKernel._savedCpu=kernel.cpu;
    concolicKernel.cpu=c;
    concolicCpu=c;
    isCloned=true;
  }

  const tracker=new CoverageTracker(concolicKernel, base, size);
  tracker.install();
  const corpus=opts.corpus ? [...opts.corpus] : [];
  const globalSeen=new Set();
  for(const e of corpus) for(const b of e.coverage?.blocks??[]) globalSeen.add(b);

  async function runConcolic(buf){
    const snap=captureSnapshot(concolicKernel);
    const origAlloc=concolicKernel.allocPool.bind(concolicKernel);
    let taintedBase=null;
    concolicKernel.allocPool=function(size, tag){
      const addr=origAlloc(size, tag);
      if(tag==="UArg" && taintedBase===null && size >= Math.max(buf.length, outputLen)){
        taintedBase=addr;
        const len=Math.min(buf.length, maxSymBytes);
        concolicCpu.enableConcolic(taintedBase, len, buf.slice(0,len));
      }
      return addr;
    };
    // also patch allocSlub if present
    const origSlub=concolicKernel.allocSlub?.bind(concolicKernel);
    if(origSlub) concolicKernel.allocSlub=concolicKernel.allocPool;
    tracker.reset(); tracker.resume();
    concolicCpu.pathConstraints=[];
    let res;
    try{
      res=await sendFileOp(concolicKernel, device, {op:opName, cmd: BigInt(cmd>>>0), input: buf, outputLen});
    } catch(e){ res={status:"fault", error:e}; }
    tracker.pause();
    const coverage={blocks:new Set(tracker.blocks), edges:new Set(tracker.edges)};
    const constraints=[...concolicCpu.pathConstraints];
    const symCount=concolicCpu.shadow?.symCount ?? Math.min(buf.length, maxSymBytes);
    concolicCpu.disableConcolic();
    concolicKernel.allocPool=origAlloc;
    if(origSlub) concolicKernel.allocSlub=origSlub;
    tracker.reset();
    restoreSnapshot(concolicKernel, snap);
    if(concolicCpu.shadow) concolicCpu.shadow.clear();
    return {res, coverage, constraints, symCount, taintedBase};
  }

  let seedQueue=corpus.length ? corpus.map(c=>c.buf) : [new Uint8Array(inputLen)];
  if(!seedQueue.length) seedQueue=[new Uint8Array(inputLen)];
  seedQueue=seedQueue.slice(0,4);
  const results=[];
  let queriesDone=0;
  let iterations=0;
  const visitedHex=new Set(seedQueue.map(b=> [...b].join(",")));

  while(seedQueue.length && queriesDone < maxQueries){
    const seed=seedQueue.shift();
    const {res, coverage, constraints, symCount}=await runConcolic(seed);
    iterations++;
    for(const b of coverage.blocks) globalSeen.add(b);
    results.push({seed, res, coverage, constraints, symCount});
    if(opts.onProgress) opts.onProgress({phase:"concolic-seed", buf:seed, coverage, constraints, res});
    if(concolicKernel.bugcheck||concolicKernel.crash) break;
    if(!constraints.length) continue;
    const order=[...constraints.keys()];
    for(const idx of order){
      if(queriesDone>=maxQueries) break;
      const prefix=constraints.slice(0,idx).map(c=>({pred:c.pred, taken:c.taken}));
      const target=constraints[idx];
      const query=[...prefix, {pred: target.pred, taken: !target.taken}];
      const {sat, model, smt2} = await solveConstraints(query, symCount, {timeoutMs: solverTimeoutMs});
      queriesDone++;
      if(!sat || !model){
        if(opts.onProgress) opts.onProgress({phase:"concolic-query", idx, sat:false, smt2});
        continue;
      }
      const child=new Uint8Array(seed);
      for(let i=0;i<Math.min(symCount, child.length);i++){
        if(model[i]!==null && model[i]!==undefined) child[i]=model[i]&0xff;
      }
      const snap2=captureSnapshot(concolicKernel);
      tracker.reset(); tracker.resume();
      let confirmRes;
      try{
        concolicCpu.disableConcolic();
        confirmRes=await sendFileOp(concolicKernel, device, {op:opName, cmd: BigInt(cmd>>>0), input: child, outputLen});
      } catch(e){ confirmRes={status:"fault", error:e}; }
      tracker.pause();
      const confirmCov=new Set(tracker.blocks);
      restoreSnapshot(concolicKernel, snap2);
      tracker.reset();
      if(opts.onProgress) opts.onProgress({phase:"concolic-witness", idx, child, confirmRes, sat, smt2});
      const newBlocks=[...confirmCov].filter(b=>!globalSeen.has(b));
      if(newBlocks.length>0 || confirmRes?.ntstatus===0n){
        for(const b of confirmCov) globalSeen.add(b);
        corpus.push({buf:child, coverage:{blocks:confirmCov, edges:new Set()}, res:confirmRes, witness:true, pred: target.pred});
        results.push({child, confirmRes, coverage:{blocks:confirmCov}, constraints:query});
        if(newBlocks.length>0 && queriesDone<maxQueries){
          const hex=[...child].join(",");
          if(!visitedHex.has(hex)){ visitedHex.add(hex); seedQueue.push(child); }
        }
      }
    }
  }

  if(isCloned && concolicKernel._savedCpu){
    concolicKernel.cpu=concolicKernel._savedCpu;
    delete concolicKernel._savedCpu;
  }
  tracker.dispose();
  return {corpus, globalSeen, queriesDone, iterations, results};
}
