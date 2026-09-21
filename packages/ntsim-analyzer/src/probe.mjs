/**
 * probe.mjs — bounded DriverEntry trajectory probe.
 *
 * Maps a .sys, runs DriverEntry in small step chunks with a wall-clock
 * guard, and records per-chunk RIP/RVA progress + API-trace growth. For
 * huge protected drivers where a full-budget callFunctionSeh may exceed
 * interactive timeouts, and for localizing hangs/faults without babysitting
 * a runaway emulator.
 *
 * Also detects fixed-point spins: a repeating chunk-boundary RIP window
 * with zero API growth (e.g. a VM wait loop parked on state the harness
 * never provides).
 *
 * The same code runs in Node (CLI --probe) and in the browser (analyzer
 * "Probe trajectory" button) — no fs, no Buffer, no process.
 */

import {
  NtKernel,
  mapPe,
  createDriverObject,
  initDriverObjectName,
} from "@kernelforge/ntsim/src/index.mjs";

const GS_COOKIE_SENTINEL = 0x00002b992ddfa232n;
const U64 = (1n << 64n) - 1n;
const DEFAULT_BASE = 0xfffff80300000000n;

function hex(n) {
  return `0x${BigInt(n).toString(16)}`;
}

/**
 * @param {Uint8Array} imageBytes raw PE32+ (.sys) file content
 * @param {object} [opts]
 *   name         driver filename (default "uploaded.sys")
 *   tables       StructTables instance (required)
 *   base         map base override (default 0xfffff80300000000)
 *   chunkSteps   steps per chunk (default 20000)
 *   maxChunks    chunk budget (default 250)
 *   wallMs       wall-clock budget (default 100000)
 *   traceFrom    step index to start RIP tracing (-1 = off)
 *   traceTo      step index to end RIP tracing (-1 = end of run)
 *   traceCap     max traced RIP lines kept (default 20000)
 *   dispatchRva  extra hook RVA (hex string/number): record rdx each hit
 *   makeBackend  async (mem)=>CpuBackend factory override (default JsInterpreter)
 *   stackFill    byte (0-255) to pre-fill the stack window, or null/undefined
 *                for the default zero-backed sparse behavior. Non-zero fills
 *                expose computations that depend on uninitialized stack
 *                leftovers (real kernel stacks are never zeroed).
 *   onProgress   (line: string) => void progress sink (default no-op)
 * @returns {Promise<object>} JSON-serializable trajectory
 */
export async function probeDriver(imageBytes, opts = {}) {
  const {
    name = "uploaded.sys",
    tables,
    base = DEFAULT_BASE,
    chunkSteps = 20000,
    maxChunks = 250,
    wallMs = 100000,
    traceFrom = -1,
    traceTo = -1,
    traceCap = 20000,
    dispatchRva = null,
    makeBackend = null,
    stackFill = null,
    onProgress = null,
  } = opts;
  if (!tables) throw new Error("probeDriver needs opts.tables (StructTables)");

  const progress = typeof onProgress === "function" ? onProgress : () => {};
  let extCpu = null;
  if (typeof makeBackend === "function") extCpu = await makeBackend(null);
  const kernel = new NtKernel({ tables, ...(extCpu ? { cpu: extCpu } : {}) });
  const mem = kernel.mem;
  if (extCpu && typeof extCpu.attachMemory === "function") extCpu.attachMemory(mem);
  kernel.bootstrap();

  const drvRec = createDriverObject(kernel, name, {});
  const mapped = mapPe(bytesOf(imageBytes), mem, BigInt(base),
    (q) => kernel.resolveImportProvisioned(q));
  initDriverObjectName(kernel, drvRec, name, mapped.base, mapped.imageSize);
  try { kernel.materializeModuleRange(mapped.base, mapped.imageSize, { fill: 0x00 }); } catch { /* best effort */ }

  const svcStem = String(name).split(/[\\/]/).pop().split(".")[0];
  const svcKey = `\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Services\\${svcStem}`;
  try {
    kernel.registry.set(svcKey, new Map([
      ["Start", { type: 4, data: Uint8Array.from([0x03, 0x00, 0x00, 0x00]) }],
      ["Type", { type: 4, data: Uint8Array.from([0x01, 0x00, 0x00, 0x00]) }],
      ["ErrorControl", { type: 4, data: Uint8Array.from([0x01, 0x00, 0x00, 0x00]) }],
    ]));
    kernel.registry.set(svcKey + "\\Parameters",
      new Map([["Config", { type: 1, data: new TextEncoder().encode("default\0") }]]));
  } catch { /* registry seeding is best effort */ }

  let rekeyed = 0;
  for (let off = 0; off + 8 <= mapped.imageSize; off += 8) {
    if (mem.u64(mapped.base + BigInt(off)) !== GS_COOKIE_SENTINEL) continue;
    mem.w64(mapped.base + BigInt(off), (0x0000f1e2d3c4b5a6n ^ BigInt(off)) | 1n);
    rekeyed++;
  }

  const regPathBuf = kernel.allocPool(0x10);
  const regPathStrBuf = kernel.allocPool(0x200);
  mem.writeUtf16(regPathStrBuf, svcKey);
  mem.w16(regPathBuf, svcKey.length * 2);
  mem.w16(regPathBuf + 2n, 0x200);
  mem.w64(regPathBuf + 8n, regPathStrBuf);

  // Manual callFunction setup (mirrors cpu.callFunction, chunked run).
  const cpu = kernel.cpu;
  const retMark = 0xdead0000feed0000n;
  cpu.regs.rsp = (cpu.regs.rsp & ~0xfn) - 8n;
  cpu.regs.rcx = drvRec.va & U64;
  cpu.regs.rdx = regPathBuf & U64;
  cpu.regs.r8 = 0n;
  cpu.regs.r9 = 0n;
  if (stackFill !== null && stackFill !== undefined) {
    const fb = Number(stackFill) & 0xff;
    mem.write((cpu.regs.rsp - 0x3000n) & U64, new Uint8Array(0x3000).fill(fb));
  }
  for (let i = 0; i < 32; i += 8) {
    cpu.regs.rsp = (cpu.regs.rsp - 8n) & U64;
    mem.w64(cpu.regs.rsp, 0n);
  }
  cpu.regs.rsp = (cpu.regs.rsp - 8n) & U64;
  mem.w64(cpu.regs.rsp, retMark);
  cpu.rip = mapped.entry & U64;
  cpu.stopOnRip = retMark;

  const trace = [];
  if (traceFrom >= 0) {
    const from = traceFrom;
    const to = traceTo >= 0 ? traceTo : Number.MAX_SAFE_INTEGER;
    cpu.addCodeHook((addr) => {
      if (trace.length >= traceCap) return null;
      if (cpu.steps >= from && cpu.steps <= to) {
        const inImg = addr >= mapped.base && addr < mapped.base + BigInt(mapped.imageSize);
        trace.push(`${cpu.steps} ${hex(addr)} ${inImg ? "img" : "WILD"} ` +
          `rdx=${hex(cpu.regs.rdx)} rax=${hex(cpu.regs.rax)} rcx=${hex(cpu.regs.rcx)}`);
      }
      return null;
    });
  }
  const dispatch = [];
  if (dispatchRva !== null && dispatchRva !== undefined) {
    const dAddr = mapped.base + BigInt(dispatchRva);
    cpu.addCodeHook((addr) => {
      if (addr === dAddr) dispatch.push(`${cpu.steps} ${hex(cpu.regs.rdx)}`);
      return null;
    });
  }

  const inImage = () => cpu.rip >= mapped.base && cpu.rip < mapped.base + BigInt(mapped.imageSize);
  const rvaOf = (rip) => Number(BigInt(rip) - mapped.base);
  const chunks = [];
  const boundaryRvas = [];
  let lastApi = 0;
  let outcome = "timeout";
  let fault = null;
  let retval = null;
  const t0 = Date.now();
  progress(`[probe] entry=${hex(mapped.entry)} base=${hex(mapped.base)} imageSize=${mapped.imageSize} rekeyed=${rekeyed}`);

  for (let c = 0; c < maxChunks; c++) {
    const reason = cpu.run((c + 1) * chunkSteps); // run() budget is absolute
    const apis = kernel.apiTrace?.length ?? 0;
    const line = `[probe] chunk=${c} steps=${cpu.steps} rip=${hex(cpu.rip)} ` +
      `rva=${inImage() ? hex(rvaOf(cpu.rip)) : "OUT-OF-IMAGE"} reason=${reason} ` +
      `apis=${apis}(+${apis - lastApi}) elapsed=${Date.now() - t0}ms`;
    progress(line);
    chunks.push({
      chunk: c, steps: Number(cpu.steps), rip: hex(cpu.rip),
      rva: inImage() ? hex(rvaOf(cpu.rip)) : null, reason,
      apis, apiDelta: apis - lastApi, elapsedMs: Date.now() - t0,
    });
    boundaryRvas.push(inImage() ? rvaOf(cpu.rip) : -1);
    lastApi = apis;
    if (reason === "returned") {
      outcome = "returned";
      retval = hex(cpu.regs.rax);
      progress(`[probe] DriverEntry returned rax=${retval}`);
      break;
    }
    if (reason === "error") {
      outcome = "fault";
      const f = cpu.fault;
      fault = { message: String(f?.message ?? "unknown"), rip: hex(cpu.rip), rva: hex(rvaOf(cpu.rip)) };
      try {
        const b = mem.read(cpu.rip, 16);
        fault.bytes = [...b].map((x) => x.toString(16).padStart(2, "0")).join(" ");
      } catch (e) { fault.bytes = `unreadable: ${e.message}`; }
      fault.lastApis = (kernel.apiTrace ?? []).slice(-8).map((e) => e.name);
      progress(`[probe] FAULT: ${fault.message} @ ${fault.rip} rva=${fault.rva} bytes=${fault.bytes}`);
      break;
    }
    if (reason !== "timeout") {
      outcome = `stopped:${reason}`;
      progress(`[probe] stopped: ${reason}`);
      break;
    }
    if (Date.now() - t0 > wallMs) {
      outcome = "wall";
      progress(`[probe] wall-clock budget hit at rva=${hex(rvaOf(cpu.rip))}`);
      break;
    }
  }

  return {
    outcome,
    entry: hex(mapped.entry),
    base: hex(mapped.base),
    imageSize: mapped.imageSize,
    rekeyed,
    steps: Number(cpu.steps),
    elapsedMs: Date.now() - t0,
    retval,
    fault,
    chunks,
    spin: detectSpin(boundaryRvas, chunks),
    trace,
    traceTruncated: trace.length >= traceCap,
    dispatch,
  };
}

/** Repeating or stagnant chunk-boundary window with zero API growth, if any. */
function detectSpin(boundaryRvas, chunks) {
  if (boundaryRvas.length < 6) return null;
  const tail = boundaryRvas.slice(-8);
  if (tail.some((r) => r < 0)) return null; // left the image
  const apisGrew = chunks.slice(-8).some((c) => c.apiDelta !== 0);
  if (apisGrew) return null;
  for (let p = 1; p <= 4; p++) {
    let ok = true;
    for (let i = tail.length - p - 1; i >= 0; i--) {
      if (tail[i] !== tail[i + p]) { ok = false; break; }
    }
    if (ok) {
      const window = tail.slice(-p);
      return {
        kind: "periodic",
        periodChunks: p,
        rvaLo: hex(Math.min(...window)),
        rvaHi: hex(Math.max(...window)),
        chunksObserved: tail.length,
      };
    }
  }
  // No exact period (e.g. a period-37-step loop sampled every N steps
  // lands on a different phase each chunk): fall back to a no-progress
  // window — all recent boundaries inside a small RVA range.
  const lo = Math.min(...tail);
  const hi = Math.max(...tail);
  if (hi - lo <= 0x1000) {
    return {
      kind: "window",
      periodChunks: null,
      rvaLo: hex(lo),
      rvaHi: hex(hi),
      chunksObserved: tail.length,
    };
  }
  return null;
}

function bytesOf(imageBytes) {
  return imageBytes instanceof Uint8Array ? imageBytes : Uint8Array.from(imageBytes);
}
