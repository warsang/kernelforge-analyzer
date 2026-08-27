/**
 * autoops.mjs — automatic file_operations driving (equivalent to autoirp.mjs)
 * Drives open + per-op fuzz/concolic + release
 */
import { sendFileOp, getHarvestedOps } from "@kernelforge/linux-sim/src/file-ops.mjs";
import { FILE_OPS_OFF } from "@kernelforge/linux-sim/src/file-ops.mjs";

export function harvestFromKernel(kernel){
  return getHarvestedOps(kernel);
}

// Simple canned input patterns like autoirp
function inputPatterns(opts){
  if(opts.inputPatterns?.length) return opts.inputPatterns;
  return [
    new Uint8Array(16),
    Uint8Array.from({length:16},()=>0xff),
    Uint8Array.from({length:16},(_,i)=>i),
  ];
}
function toHex(buf){ return [...buf].map(b=>b.toString(16).padStart(2,"0")).join(""); }

/**
 * Auto-drive file_operations similar to autoDriveIrps
 * @param {LinuxKernel} kernel
 * @param {object} device one device entry (or null for first)
 * @param {object} cfg {sendFileOp, harvested?, maxOps?, fuzz?, concolic?, imageBase,imageSize, outputLen, onPhase}
 */
export async function autoDriveFileOps(kernel, device, cfg){
  const send = cfg.sendFileOp || sendFileOp;
  const onPhase=cfg.onPhase ?? (()=>{});
  const results=[];
  const push = async (spec, phase)=>{
    if(phase) onPhase(phase);
    const r=await send(kernel, device, spec);
    results.push({...r, outputHex: r.outputHex??"", error: r.error ? String(r.error.message??r.error):undefined});
    return r;
  };
  // open
  await push({op:"open", outputLen: 0}, "fileop OPEN");
  if(results.at(-1).status!=="ok" && results.at(-1).status!=="no_handler"){
    // continue even if open no handler
  }

  const fuzzEnabled=!!cfg.fuzz;
  const concEnabled=!!cfg.concolic;
  const useAdvanced = fuzzEnabled || concEnabled;
  const imageBase = cfg.imageBase!=null ? BigInt(cfg.imageBase) : null;
  const imageSize = cfg.imageSize!=null ? BigInt(cfg.imageSize) : null;
  const canAdvanced = useAdvanced && imageBase!==null && imageSize!==null;

  const harvested = cfg.harvested ?? harvestFromKernel(kernel);
  // Dedupe by op+va
  const uniq=[];
  const seen=new Set();
  for(const h of harvested.slice(0, cfg.maxOps??32)){
    const key=`${h.op}:${h.va.toString(16)}`;
    if(seen.has(key)) continue;
    seen.add(key);
    uniq.push(h);
  }

  if(useAdvanced && !canAdvanced){
    console.warn("[autoDrive] advanced requested but imageBase/size missing — fallback to canned");
  }

  if(canAdvanced){
    const baseOpts={ sendFileOp: send, imageBase, imageSize, outputLen: cfg.outputLen??64 };
    for(const entry of uniq){
      if(kernel.bugcheck||kernel.crash) break;
      const opName=entry.op;
      onPhase(`fileop ${opName} (advanced)`);
      if(fuzzEnabled && concEnabled){
        const { fuzzFileOp } = await import("./fuzz-ops.mjs");
        const fuzzRes=await fuzzFileOp(kernel, device, opName, {
          ...baseOpts,
          cmd: 0x222000,
          iterations: cfg.fuzz.iterations??256,
          corpusCap: cfg.fuzz.corpusCap??32,
          inputLen: cfg.fuzz.inputLen??16,
          outputLen: cfg.outputLen??64,
          seedPatterns: inputPatterns(cfg),
          onProgress: (evt)=> onPhase(`fuzz ${opName} ${evt.iter??evt.phase}`),
        });
        const seedsFromFuzz=fuzzRes.corpus.map(c=>c.buf);
        const { concolicFileOp } = await import("./concolic-ops.mjs");
        const concRes=await concolicFileOp(kernel, device, opName, {
          ...baseOpts,
          cmd: 0x222000,
          maxSymBytes: cfg.concolic.maxSymBytes??64,
          solverTimeoutMs: cfg.concolic.solverTimeoutMs??500,
          maxQueries: cfg.concolic.maxQueries??8,
          inputLen: cfg.fuzz.inputLen??16,
          outputLen: cfg.outputLen??64,
          corpus: fuzzRes.corpus,
          onProgress: (evt)=> onPhase(`concolic ${opName} ${evt.phase}`),
        });
        const seenHex=new Set();
        const merged=[];
        for(const c of [...fuzzRes.corpus, ...concRes.corpus]){
          const h=toHex(c.buf);
          if(seenHex.has(h)) continue;
          seenHex.add(h);
          merged.push(c);
        }
        for(const e of merged.slice(0,64)){
          const r=e.res ?? e.confirmRes;
          if(!r) continue;
          results.push({...r, outputHex:r.outputHex??"", error:r.error? String(r.error.message??r.error):undefined, ioctl: 0x222000n, majorName: opName.toUpperCase(), inputHex: toHex(e.buf), coverage: e.coverage? {blocks:e.coverage.blocks?.size??0, edges:e.coverage.edges?.size??0}:undefined, source: e.witness?"concolic":"fuzz"});
          if(kernel.bugcheck||kernel.crash) break;
        }
        if(!merged.length){
          for(const input of inputPatterns(cfg)){
            const r=await push({op:opName, input, outputLen: cfg.outputLen??64}, `fileop ${opName} canned`);
            if(r.status!=="ok") break;
            if(kernel.bugcheck||kernel.crash) break;
          }
        }
      } else if(fuzzEnabled){
        const { fuzzFileOp } = await import("./fuzz-ops.mjs");
        const fuzzRes=await fuzzFileOp(kernel, device, opName, {
          ...baseOpts,
          cmd: 0x222000,
          iterations: cfg.fuzz.iterations??256,
          corpusCap: cfg.fuzz.corpusCap??32,
          inputLen: cfg.fuzz.inputLen??16,
          outputLen: cfg.outputLen??64,
          seedPatterns: inputPatterns(cfg),
          onProgress: (evt)=>{ if(evt.phase==="fuzz") onPhase(`fuzz ${opName} iter ${evt.iter}`); },
        });
        for(const entry of fuzzRes.corpus.slice(0,64)){
          const r=entry.res;
          results.push({...r, outputHex:r.outputHex??"", error:r.error? String(r.error.message??r.error):undefined, ioctl:0x222000n, majorName:opName.toUpperCase(), inputHex: toHex(entry.buf), coverage:{blocks:entry.coverage.blocks.size, edges:entry.coverage.edges.size}, source:"fuzz"});
          if(kernel.bugcheck||kernel.crash) break;
        }
        if(!fuzzRes.corpus.length){
          for(const input of inputPatterns(cfg)){
            const r=await push({op:opName, input, outputLen: cfg.outputLen??64}, `fileop ${opName} fuzz-fallback`);
            if(r.status!=="ok") break;
            if(kernel.bugcheck||kernel.crash) break;
          }
        }
        results.push({status:"ok", ntstatus:0n, majorName:"__fuzz_summary", ioctl:0x222000n, outputHex:"", coverage:{corpus:fuzzRes.corpus.length, globalBlocks:fuzzRes.globalSeen.size, iterations:fuzzRes.iterations}});
      } else if(concEnabled){
        const { concolicFileOp } = await import("./concolic-ops.mjs");
        const concRes=await concolicFileOp(kernel, device, opName, {
          ...baseOpts,
          maxSymBytes: cfg.concolic.maxSymBytes??64,
          solverTimeoutMs: cfg.concolic.solverTimeoutMs??500,
          maxQueries: cfg.concolic.maxQueries??8,
          inputLen: cfg.concolic.inputLen??16,
          outputLen: cfg.outputLen??64,
          corpus: inputPatterns(cfg).map(buf=>({buf, coverage:{blocks:new Set(), edges:new Set()}})),
          onProgress: (evt)=> onPhase(`concolic ${opName} ${evt.phase}`),
        });
        for(const e of concRes.corpus.slice(0,64)){
          const r=e.res ?? e.confirmRes;
          if(!r) continue;
          results.push({...r, outputHex:r.outputHex??"", error:r.error? String(r.error.message??r.error):undefined, ioctl:0x222000n, majorName:opName.toUpperCase(), inputHex: toHex(e.buf), coverage: e.coverage? {blocks:e.coverage.blocks?.size??0}:undefined, source: e.witness?"concolic":"seed", smt2: e.smt2});
          if(kernel.bugcheck||kernel.crash) break;
        }
        if(!concRes.corpus.length){
          for(const input of inputPatterns(cfg)){
            const r=await push({op:opName, input, outputLen: cfg.outputLen??64}, `fileop ${opName} concolic-fallback`);
            if(r.status!=="ok") break;
            if(kernel.bugcheck||kernel.crash) break;
          }
        }
      }
    }
  } else {
    for(const entry of uniq){
      let hardFail=false;
      let i=0;
      for(const input of inputPatterns(cfg)){
        const r=await push({op:entry.op, input, outputLen: cfg.outputLen??64}, `fileop ${entry.op} #${++i}`);
        if(r.status!=="ok" && r.status!=="no_handler") { hardFail=true; break; }
        if(kernel.bugcheck||kernel.crash) return results;
      }
      if(hardFail) break;
    }
  }

  await push({op:"release", outputLen:0}, "fileop RELEASE");
  return results;
}
