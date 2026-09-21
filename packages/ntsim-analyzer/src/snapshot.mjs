/**
 * snapshot.mjs — deterministic kernel/device/cpu snapshotting for fuzz iterations.
 *
 * Each fuzz iteration must reset to a clean device/driver state or coverage
 * deltas become non-reproducible from cross-run contamination (heap, IRQL,
 * trace buffers, CPU regs/flags).
 *
 * Uses SparseMemory.dump/restore + truncations for pool/heap and direct
 * register capture. Works with JsInterpreter, Unicorn, Hybrid via generic
 * regfile access.
 */

import { R64, M64 } from "@kernelforge/ntsim/src/cpu.mjs";
import { DEVICE_OBJECT } from "@kernelforge/ntsim/src/devices.mjs";

export function captureSnapshot(kernel) {
  const cpu = kernel.cpu;
  const isHybrid = !!(cpu && cpu.js && cpu.uc);
  const snap = {
    mem: kernel.mem.dump(),
    nextPool: kernel.nextPool,
    poolAllocsLen: kernel.poolAllocs.length,
    heapPrng: kernel._heapPrng,
    cpuSteps: cpu.steps,
    cpuHalted: cpu.halted,
    cpuFault: cpu.fault,
    cpuPendingBreak: cpu.pendingBreak ?? null,
    cpuRip: null,
    cpuRegs: {},
    cpuFlags: {},
    // hybrid-specific splits
    isHybrid,
    hybrid: isHybrid ? {
      jsSteps: cpu.js.steps,
      ucSteps: cpu.uc.steps,
      jsFault: cpu.js.fault,
      ucFault: cpu.uc.fault,
      jsHalted: cpu.js.halted,
      ucHalted: cpu.uc.halted,
      active: cpu.active,
    } : null,
    kernelState: {
      currentIrql: kernel.currentIrql,
      dbgLogLen: kernel.dbgLog.length,
      exceptionTraceLen: kernel.exceptionTrace.length,
      irqlViolationsLen: kernel.irqlViolations.length,
      traceEventsLen: kernel.traceEvents.length,
      apiTraceLen: kernel.apiTrace.length,
      traceSeq: kernel.traceSeq,
      tickCount: kernel.tickCount,
      bugcheck: kernel.bugcheck,
      crash: kernel.crash,
    },
    // architectural virtualization state (arch.mjs): MSR file + virtual TSC
    // PRNG must rewind or repeated fuzz iterations see different timings.
    arch: kernel.arch ? {
      msrFile: [...kernel.arch.msrFile.entries()].map(([k, v]) => [k.toString(), v.toString()]),
      tscBase: kernel.arch.tscBase,
      tscBias: kernel.arch.tscBias,
      lastSteps: kernel.arch.lastSteps,
      streak: kernel.arch.streak,
      lastTsc: kernel.arch.lastTsc,
      prng: kernel.arch.prng,
      eventsLen: kernel.arch.events.length,
      counts: { ...kernel.arch.counts },
      cpuidLeaves: [...kernel.arch.cpuidLeaves.entries()],
      msrReads: [...kernel.arch.msrReads.entries()].map(([k, v]) => [k.toString(), v]),
      msrWrites: [...kernel.arch.msrWrites.entries()].map(([k, v]) => [k.toString(), v]),
    } : null,
    diag: kernel.diag ? {
      counts: { ...kernel.diag.counts },
      eventsLen: kernel.diag.events.length,
      eventCursor: kernel.diag.eventCursor ?? 0,
      probeSeq: kernel.diag.probeSeq ?? 0,
    } : null,
    callbackState: {
      registryWriteLogLen: kernel.registryWriteLog?.length ?? 0,
      registryAutoCreatedLen: kernel.registryAutoCreated?.length ?? 0,
      apiResolutions: kernel.apiResolutions
        ? [...kernel.apiResolutions.entries()].map(([k, v]) => [k, { ...v, target: String(v.target) }])
        : null,
      irpCompletionsLen: kernel.irpCompletions?.length ?? 0,
      obEventsLen: kernel.obEvents?.length ?? 0,
      cmEventsLen: kernel.cmEvents?.length ?? 0,
      doubleFault: kernel.doubleFault ?? null,
      tripleFault: kernel.tripleFault ?? null,
      nestedCodes: kernel.bugcheck?.nestedCodes
        ? kernel.bugcheck.nestedCodes.map((c) => c.toString()) : null,
    },
  };

  // capture regs generically (works for Proxy-based Unicorn/Hybrid)
  try {
    snap.cpuRip = BigInt(cpu.rip ?? cpu.regs?.rip ?? 0n);
  } catch { snap.cpuRip = 0n; }
  for (const r of R64) {
    try {
      const v = cpu.regs?.[r];
      snap.cpuRegs[r] = v !== undefined ? BigInt(v) & M64 : 0n;
    } catch { snap.cpuRegs[r] = 0n; }
  }
  // flags (JsInterpreter only; harmless for others)
  for (const f of ["cf","zf","sf","of","df","tf","iflag","inhibitWindow"]) {
    if (f in cpu) snap.cpuFlags[f] = cpu[f];
  }
  // CRs (if present)
  for (const cr of ["cr0","cr3","cr4","efer"]) {
    if (cr in cpu) {
      try { snap.cpuFlags[cr] = BigInt(cpu[cr]); } catch { /* ignore */ }
    } else if (typeof cpu.getCR === "function") {
      try { snap.cpuFlags[cr] = BigInt(cpu.getCR(cr)); } catch { /* ignore */ }
    }
  }
  return snap;
}

export function restoreSnapshot(kernel, snap) {
  // memory
  kernel.mem.restore(snap.mem);
  // pool
  kernel.nextPool = snap.nextPool;
  kernel.poolAllocs.length = snap.poolAllocsLen;
  kernel._heapPrng = snap.heapPrng;
  // kernel arrays
  kernel.dbgLog.length = snap.kernelState.dbgLogLen;
  kernel.exceptionTrace.length = snap.kernelState.exceptionTraceLen;
  kernel.irqlViolations.length = snap.kernelState.irqlViolationsLen;
  kernel.traceEvents.length = snap.kernelState.traceEventsLen;
  kernel.apiTrace.length = snap.kernelState.apiTraceLen;
  kernel.traceSeq = snap.kernelState.traceSeq;
  kernel.tickCount = snap.kernelState.tickCount;
  kernel.bugcheck = snap.kernelState.bugcheck;
  kernel.crash = snap.kernelState.crash;
  kernel.currentIrql = snap.kernelState.currentIrql;

  // arch/diag/callback state (new surfaces must rewind with the snapshot)
  if (snap.arch && kernel.arch) {
    kernel.arch.msrFile.clear();
    for (const [k, v] of snap.arch.msrFile) kernel.arch.msrFile.set(BigInt(k), BigInt(v));
    kernel.arch.tscBase = snap.arch.tscBase;
    kernel.arch.tscBias = snap.arch.tscBias;
    kernel.arch.lastSteps = snap.arch.lastSteps;
    kernel.arch.streak = snap.arch.streak;
    kernel.arch.lastTsc = snap.arch.lastTsc;
    kernel.arch.prng = snap.arch.prng;
    kernel.arch.events.length = snap.arch.eventsLen;
    Object.assign(kernel.arch.counts, snap.arch.counts);
    kernel.arch.cpuidLeaves = new Map(snap.arch.cpuidLeaves);
    kernel.arch.msrReads = new Map(snap.arch.msrReads.map(([k, v]) => [BigInt(k), v]));
    kernel.arch.msrWrites = new Map(snap.arch.msrWrites.map(([k, v]) => [BigInt(k), v]));
  }
  if (snap.diag && kernel.diag) {
    Object.assign(kernel.diag.counts, snap.diag.counts);
    kernel.diag.events.length = snap.diag.eventsLen;
    kernel.diag.eventCursor = snap.diag.eventCursor ?? 0;
    kernel.diag.probeSeq = snap.diag.probeSeq ?? 0;
  }
  if (snap.callbackState) {
    if (kernel.registryWriteLog) kernel.registryWriteLog.length = snap.callbackState.registryWriteLogLen ?? 0;
    if (kernel.registryAutoCreated) kernel.registryAutoCreated.length = snap.callbackState.registryAutoCreatedLen ?? 0;
    if (snap.callbackState.apiResolutions) {
      kernel.apiResolutions = new Map(snap.callbackState.apiResolutions.map(
        ([k, v]) => [k, { ...v, target: BigInt(v.target) }]));
    }
    if (kernel.irpCompletions) kernel.irpCompletions.length = snap.callbackState.irpCompletionsLen;
    if (kernel.obEvents) kernel.obEvents.length = snap.callbackState.obEventsLen;
    if (kernel.cmEvents) kernel.cmEvents.length = snap.callbackState.cmEventsLen;
    kernel.doubleFault = snap.callbackState.doubleFault;
    kernel.tripleFault = snap.callbackState.tripleFault;
    if (kernel.bugcheck && snap.callbackState.nestedCodes) {
      kernel.bugcheck.nestedCodes = snap.callbackState.nestedCodes.map((c) => BigInt(c));
    }
  }

  const cpu = kernel.cpu;
  if (snap.isHybrid && cpu.js && cpu.uc && snap.hybrid) {
    try { cpu.js.steps = snap.hybrid.jsSteps; } catch {}
    try { cpu.uc.steps = snap.hybrid.ucSteps; } catch {}
    try { cpu.js.fault = snap.hybrid.jsFault; } catch {}
    try { cpu.uc.fault = snap.hybrid.ucFault; } catch {}
    try { cpu.js.halted = snap.hybrid.jsHalted; } catch {}
    try { cpu.uc.halted = snap.hybrid.ucHalted; } catch {}
    try { cpu.active = snap.hybrid.active; } catch {}
    // also set generic via activeEngine for halted/fault
    try { cpu.halted = snap.cpuHalted; } catch {}
    try { cpu.fault = snap.cpuFault; } catch {}
  } else {
    try { cpu.steps = snap.cpuSteps; } catch {}
    try { cpu.halted = snap.cpuHalted; } catch {}
    try { cpu.fault = snap.cpuFault; } catch {}
  }
  if ("pendingBreak" in cpu) try { cpu.pendingBreak = snap.cpuPendingBreak; } catch {}
  else if (snap.isHybrid) {
    try { cpu.js.pendingBreak = snap.cpuPendingBreak; } catch {}
  }
  try { cpu.rip = snap.cpuRip; } catch { /* hybrid proxy may throw if detached */ }
  for (const r of R64) {
    try { cpu.regs[r] = snap.cpuRegs[r]; } catch { /* ignore */ }
  }
  for (const [k,v] of Object.entries(snap.cpuFlags)) {
    if (k in cpu) {
      try { cpu[k] = v; } catch { /* ignore */ }
    } else if (snap.isHybrid) {
      // try both engines
      try { if (k in cpu.js) cpu.js[k] = v; } catch {}
      try { if (k in cpu.uc) cpu.uc[k] = v; } catch {}
      if (typeof cpu.js?.setCR === "function" && ["cr0","cr3","cr4","efer"].includes(k)) try { cpu.js.setCR(k, v); } catch {}
      if (typeof cpu.uc?.setCR === "function" && ["cr0","cr3","cr4","efer"].includes(k)) try { cpu.uc.setCR(k, v); } catch {}
    } else if (typeof cpu.setCR === "function" && ["cr0","cr3","cr4","efer"].includes(k)) {
      try { cpu.setCR(k, v); } catch { /* ignore */ }
    }
  }
  // ensure CURRENT_IRP cleared (mem restore already does, but be explicit for pool-reuse edge)
  // device CURRENT_IRP slot is inside mem restore; no extra action needed
}
