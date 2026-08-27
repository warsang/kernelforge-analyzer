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
