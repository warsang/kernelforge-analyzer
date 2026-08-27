/**
 * linux-analyzer/src/index.mjs — analyzeKo pipeline (Linux analog of ntsim-analyzer/index.mjs)
 */
import { LinuxKernel } from "@kernelforge/linux-sim/src/linux-kernel.mjs";
import { parseElfKo, mapModule } from "@kernelforge/linux-sim/src/module-loader.mjs";
import { sendFileOp, getHarvestedOps } from "@kernelforge/linux-sim/src/file-ops.mjs";
import { harvestFileOpsStatic } from "./harvest.mjs";

const DEFAULT_MODULE_BASE = 0xffffffffc0000000n;

function serviceKeyOf(name){
  const base=String(name??"uploaded.ko").split(/[\\/]/).pop()||"uploaded.ko";
  const dot=base.lastIndexOf(".");
  return dot>0 ? base.slice(0,dot) : base;
}

function hexToBytes(hex){
  const hx=String(hex??"").replace(/[^0-9a-fA-F]/g,"");
  if(!hx) return new Uint8Array(0);
  const pairs=hx.match(/.{2}/g)??[];
  return new Uint8Array(pairs.map(x=>parseInt(x,16)));
}

export async function analyzeKo(imageBytes, opts={}){
  const r=await analyzeKoOnce(imageBytes, opts);
  if(opts.autoHybridFallback===false) return r;
  if(opts.makeBackend || opts.cpu) return r;
  if(opts.backend && opts.backend!=="js") return r;
  const err=`${r.init?.error??""} ${r.bugcheck??""}`;
  if(!/unimplemented|unsupported|0f opcode/i.test(err)) return r;
  try{
    const { HybridCpuBackend } = await import("@kernelforge/ntsim-unicorn/src/hybrid.mjs");
    const retried=await analyzeKoOnce(imageBytes,{...opts, backendName:"hybrid", makeBackend: async()=> HybridCpuBackend.create(null)});
    if(retried.init?.status==="ok" || !/unimplemented/i.test(retried.init?.error??"")){ retried.meta.fallbackFrom="js"; return retried; }
  } catch{}
  return r;
}

async function analyzeKoOnce(imageBytes, opts={}){
  let cpu;
  if(typeof opts.makeBackend==="function") cpu=await opts.makeBackend(null);
  else if(opts.cpu) cpu=opts.cpu;

  const kernel=new LinuxKernel({ cpu, bases: opts.bases, heap: opts.heap });
  const mem=kernel.mem;
  if(cpu && typeof cpu.attachMemory==="function") cpu.attachMemory(mem);

  const report={
    meta:{ size: imageBytes.length, engine: opts.backendName ?? (kernel.cpu.constructor.name), at: new Date().toISOString(), kver: "6.6.18"},
    load:null, init:null, cleanup:null, fileOps: [], harvestedOps: null, autoOps: null, deferred:null,
    dbgLog:[], apiTraceSummary:null, exceptions:[], bugcheck:null,
  };

  // Parse & map
  let parsed;
  try{
    parsed=parseElfKo(imageBytes);
  } catch(e){
    report.load={ error: e.message };
    report.init={ status:"fault", error: e.message };
    return finalizeReport(report, kernel, null);
  }

  const base = opts.base ? BigInt(opts.base) : DEFAULT_MODULE_BASE;
  let mapped;
  try{
    mapped=mapModule(kernel, parsed, base, (name)=> kernel.resolveImportProvisioned(name));
  } catch(e){
    report.load={ error: e.message, base:`0x${base.toString(16)}` };
    report.init={ status:"fault", error: e.message };
    return finalizeReport(report, kernel, null);
  }

  const driverName=opts.name ?? "uploaded.ko";
  const modName=serviceKeyOf(driverName);
  report.load={
    base:`0x${mapped.base.toString(16)}`,
    imageSize: mapped.imageSize,
    init: mapped.init ? `0x${mapped.init.toString(16)}` : null,
    cleanup: mapped.cleanup ? `0x${mapped.cleanup.toString(16)}` : null,
    applied: mapped.applied,
    unresolved: mapped.unresolved,
    unmodeledExports: [...kernel.unmodeledExports],
    sections: mapped.sections,
    modinfo: mapped.modinfo,
    driverName,
    modName,
  };

  // Run init_module
  kernel.tracePhase="init_module";
  let initResult={status:"ok"};
  if(mapped.init){
    // Linux init_module takes no args? But our earlier map says 0. We'll pass 0.
    initResult=kernel.callFunctionSeh(mapped.init, [], {base: mapped.base, bytes: imageBytes});
  } else {
    initResult={status:"fault", error: new Error("no init_module symbol")};
  }
  report.init=summarizeCall(initResult);
  report.dbgLog.push(...kernel.dbgLog.splice(0));
  report.exceptions.push(...kernel.exceptionTrace.splice(0));
  if(kernel.bugcheck||kernel.crash) report.bugcheck=kernel.bugcheck??kernel.crash;

  // Deferred (workqueues)
  if(initResult.status==="ok" && !report.bugcheck){
    kernel.tracePhase="deferred";
    report.deferred=kernel.drainDeferred();
    report.dbgLog.push(...kernel.dbgLog.splice(0));
  }

  // Determine devices
  let device=null;
  if(kernel.deviceRegistry.length){
    device=kernel.deviceRegistry[0];
  } else {
    // synthetic fallback: create dummy file_operations region with no ops -> auto harvest will be empty
    // Still create a placeholder device entry
    const dummyFops=kernel.allocSlub(0x80,"fops_dummy");
    kernel.deviceRegistry.push({name:"dummy", fops: dummyFops, major:240, type:"synthetic"});
    device=kernel.deviceRegistry[0];
  }

  // Harvested ops
  try{
    const dynamic=getHarvestedOps(kernel);
    const stat=harvestFileOpsStatic(imageBytes, parsed);
    report.harvestedOps = dynamic.map(op=>({op: op.op, va:`0x${op.va.toString(16)}`, device: op.device, fops:`0x${op.fops.toString(16)}`}));
    report.harvestedOpsStatic = stat.map(s=>({sec:s.sec, off:`0x${s.offset.toString(16)}`, rva:`0x${s.rva.toString(16)}`, matches:s.matches}));
    // also store combined for UI
    report.fileOps = dynamic;
  } catch(e){ report.harvestedOps=[]; }

  // AutoOps if requested
  if(opts.autoOps && initResult.status==="ok" && !report.bugcheck && device){
    const { autoDriveFileOps } = await import("./autoops.mjs");
    const cfg=typeof opts.autoOps==="object"? opts.autoOps:{};
    kernel.tracePhase="auto-ops";
    report.autoOps=await autoDriveFileOps(kernel, device, {
      sendFileOp,
      harvested: report.fileOps,
      maxOps: cfg.maxOps??32,
      inputPatterns: cfg.inputPatterns,
      outputLen: cfg.outputLen??64,
      imageBase: mapped.base,
      imageSize: mapped.imageSize,
      fuzz: cfg.fuzz??null,
      concolic: cfg.concolic??null,
      onPhase:(label)=>{ kernel.tracePhase=label; },
    });
    report.dbgLog.push(...kernel.dbgLog.splice(0));
    report.exceptions.push(...kernel.exceptionTrace.splice(0));
    if(kernel.bugcheck||kernel.crash) report.bugcheck=kernel.bugcheck??kernel.crash;
  }

  // explicit fileops if opts.fileOps provided
  if(device && initResult.status==="ok" && !report.bugcheck && opts.fileOps?.length){
    report.ops=[];
    for(const spec of opts.fileOps){
      if(report.bugcheck) break;
      kernel.tracePhase=`fileop ${spec.op} ${spec.cmd??""}`;
      const input = spec.input instanceof Uint8Array ? spec.input : hexToBytes(spec.inputHex ?? spec.input);
      const r=await sendFileOp(kernel, device, {
        op: spec.op ?? "unlocked_ioctl",
        cmd: spec.cmd ?? spec.ioctl,
        input,
        outputLen: spec.outputLen??64,
        offset: spec.offset,
      });
      report.ops.push({...r, outputHex: r.outputHex??"", error: r.error? String(r.error.message??r.error):undefined});
      report.dbgLog.push(...kernel.dbgLog.splice(0));
      report.exceptions.push(...kernel.exceptionTrace.splice(0));
      if(r.status!=="ok" && r.status!=="no_handler") break;
    }
  }

  // cleanup_module
  if(opts.runCleanup && initResult.status==="ok" && !report.bugcheck && mapped.cleanup){
    kernel.tracePhase="cleanup";
    report.cleanup=summarizeCall(kernel.callFunctionSeh(mapped.cleanup, [], {base: mapped.base, bytes: imageBytes}));
    report.dbgLog.push(...kernel.dbgLog.splice(0));
  }

  // Finalize trace similar to ntsim-analyzer — include engine for BUG-1 verification
  {
    const modules=[{name: driverName, base: mapped.base, size: mapped.imageSize}];
    try{
      const { finalizeTrace } = await import("@kernelforge/ntsim/src/tracer.mjs");
      if(!opts.trace?.disable){
        const { events, text } = finalizeTrace(kernel, modules);
        report.trace=events;
        report.traceText=`engine: ${report.meta.engine}\n` + text;
      }
      report.etw=kernel.etwLog??[];
      kernel.tracePhase="idle";
    } catch{
      report.traceText = `engine: ${report.meta.engine}\n` + kernel.traceEvents.map(e=> `[${e.phase}] ${e.kind} ${e.name??e.text??""}`).join("\n");
    }
  }
  report.apiTraceSummary=summarizeApiTrace(kernel.apiTrace);
  report.__session={ kernel, device, image:{base: mapped.base, bytes: imageBytes}, mapped, parsed };
  return report;
}

function summarizeCall(r){
  if(!r) return null;
  const out={status: r.status};
  if("retval" in r){
    let v = BigInt(r.retval);
    // BUG-9: init_module returns int (-1 = 0xffffffff in eax, zero-extended to 0x00000000ffffffff in rax)
    // For display, sign-extend 32-bit negative returns to 64 for readability (0xffffffffffffffff)
    if((v & 0xffffffffn) === 0xffffffffn && (v >> 32n) === 0n) v = 0xffffffffffffffffn;
    else if((v & 0xffffffffn) === 0xfffffffen && (v >> 32n) === 0n) v = 0xfffffffffffffffen; // -2
    out.retval=`0x${BigInt.asUintN(64, v).toString(16).padStart(16,"0")}`;
  }
  if(r.error) out.error=String(r.error.message??r.error);
  if(r.rip!==undefined) out.rip=`0x${r.rip.toString(16)}`;
  return out;
}
function summarizeApiTrace(trace){
  if(!trace || !trace.length) return null;
  const byName=new Map();
  for(const e of trace){
    const rec=byName.get(e.name)??{count:0, args:[]};
    rec.count++;
    if(rec.args.length<3) rec.args.push({args:e.args.slice(0,4).map(a=>`0x${a.toString(16)}`), ret:e.ret===undefined?null:`0x${e.ret.toString(16)}`});
    byName.set(e.name, rec);
  }
  return { totalCalls: trace.length, distinct: byName.size, byName: Object.fromEntries([...byName.entries()].slice(0,256)) };
}

function finalizeReport(report, kernel, mapped){
  report.apiTraceSummary=summarizeApiTrace(kernel.apiTrace);
  report.traceText=kernel.traceEvents.map(e=> `[${e.phase}] ${e.kind} ${e.name??e.text??""}`).join("\n");
  return report;
}
