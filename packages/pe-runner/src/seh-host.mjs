/**
 * Userland SEH adapter — wires ntsim's table-based x64 exception dispatch
 * (packages/ntsim/src/seh.mjs) into the PE harness.
 *
 * The kernel harness calls `kernel.callFunctionSeh`; userland has no kernel, so
 * this module provides the small host facade `tryDispatchException` expects
 * ({mem, cpu, allocPool, dbgLog}) plus `callWithSeh`, a drop-in replacement for
 * `cpu.callFunction` that dispatches hardware faults into the image's
 * __try/__except scopes.
 */


import { tryDispatchException } from "@kernelforge/ntsim/src/seh.mjs";

const M64 = 0xffffffffffffffffn;

/**
 * @param {{mem:object, cpu:object, alloc:(n:number)=>bigint, dbgLog:string[]}} env
 */
export function createSehHost({ mem, cpu, alloc, dbgLog }) {
  return {
    mem,
    cpu,
    dbgLog,
    /** SEH record allocation: guest pool, 16-byte aligned, zero-filled. */
    allocPool: (size) => {
      const va = alloc(size);
      try { mem.write(va, new Uint8Array(Math.max(16, Number(size) + 15) & ~15)); } catch { /* optional */ }
      return va;
    },
  };
}

/**
 * cpu.callFunction + x64 table-SEH dispatch on fault.
 *
 * @param {object} host createSehHost() result
 * @param {{base:bigint, bytes:Uint8Array}} image mapped image (needs .bytes)
 * @param {bigint} addr callee VA
 * @param {bigint[]} [args]
 */
export function callWithSeh(host, image, addr, args = []) {
  const r = host.cpu.callFunction(addr, args);
  if (r.status !== "fault" || !image?.bytes) return r;

  // SEH filter/handler calls re-enter the CPU and clear the fault frame; keep
  // the original so CONTINUE_EXECUTION can resume the outer call afterwards.
  const savedFaultFrame = host.cpu.faultFrame ?? null;

  let dispatch;
  try {
    dispatch = tryDispatchException(host, image, r.error);
  } catch (e) {
    return { ...r, sehDetail: `malformed unwind data: ${String(e?.message ?? e)}` };
  }
  if (!dispatch.handled) return { ...r, sehDetail: dispatch.detail };

  if (dispatch.resume) {
    const cpu = host.cpu;
    if (typeof cpu.resumeFromFault !== "function") {
      host.dbgLog.push("[seh] CONTINUE_EXECUTION requested but backend cannot resume");
      return { status: "fault", error: r.error, sehHandled: true, sehDetail: dispatch.detail };
    }
    try {
      if (cpu.faultFrame == null && savedFaultFrame) cpu.faultFrame = savedFaultFrame;
      if (dispatch.resume.regs) Object.assign(cpu.regs, dispatch.resume.regs);
      cpu.rip = BigInt(dispatch.resume.rip) & M64;
      const resumed = cpu.resumeFromFault();
      if (!resumed) return r;
      return { ...resumed, sehHandled: true, sehDetail: dispatch.detail };
    } catch (e) {
      host.dbgLog.push(`[seh] resume failed: ${String(e?.message ?? e)}`);
      return { status: "fault", error: r.error, sehHandled: true, sehDetail: dispatch.detail };
    }
  }

  return {
    status: "ok",
    retval: dispatch.ntstatus ?? dispatch.result?.retval ?? 0n,
    sehHandled: true,
    sehDetail: dispatch.detail,
  };
}
