/**
 * coverage.mjs — basic-block / opcode coverage tracker for all CPU backends.
 *
 * Uses the CpuBackend.addCodeHook(range) abstraction that exists on
 * JsInterpreter, UnicornCpuBackend and HybridCpuBackend. While enabled it
 * records every executed RIP inside the driver image range.
 *
 * Edge coverage (prev->cur) is also tracked as string "prev->cur" for
 * AFL-style novelty. Callers can query blocks or edges.
 */

export class CoverageTracker {
  /**
   * @param {object} kernel NtKernel (cpu, mem)
   * @param {bigint} base driver image base
   * @param {bigint|number} size image size
   */
  constructor(kernel, base, size) {
    this.kernel = kernel;
    this.base = BigInt(base);
    this.size = BigInt(size);
    this.end = this.base + this.size;
    this.blocks = new Set(); // string hex rips
    this.edges = new Set(); // "prev->cur"
    this.prevRip = null;
    this.enabled = false;
    this._hook = null;
  }

  install() {
    if (this._hook) return;
    const cpu = this.kernel.cpu;
    const handler = (rip) => {
      if (!this.enabled) return null;
      // rip is BigInt from backend
      const r = BigInt(rip);
      // range check already done by backend, but guard for hybrid replay
      if (r < this.base || r >= this.end) return null;
      const key = "0x" + r.toString(16);
      this.blocks.add(key);
      if (this.prevRip !== null) {
        const edge = "0x" + this.prevRip.toString(16) + "->" + key;
        this.edges.add(edge);
      }
      this.prevRip = r;
      return null; // do not consume instruction
    };
    this._hook = handler;
    // register on backend (Hybrid forwards to both engines)
    if (typeof cpu.addCodeHook === "function") {
      try {
        cpu.addCodeHook(handler, this.base, this.end - 1n);
      } catch (e) {
        // fallback: onCodeHook path missing — store handler for later removal attempt
        // still works on JsInterpreter older builds if needed
        if (!cpu.codeHooks) cpu.codeHooks = [];
        cpu.codeHooks.push({ fn: handler, begin: this.base, end: this.end - 1n });
      }
    } else {
      // legacy
      cpu.onCodeHook = handler;
    }
    this.enabled = true;
  }

  reset() {
    this.blocks.clear();
    this.edges.clear();
    this.prevRip = null;
  }

  pause() {
    this.enabled = false;
  }

  resume() {
    this.enabled = true;
    this.prevRip = null; // avoid cross-run edge contamination
  }

  /**
   * Snapshot current coverage and reset for next iteration.
   * @returns {{blocks:Set<string>, edges:Set<string>}}
   */
  snapshotAndReset() {
    const out = { blocks: new Set(this.blocks), edges: new Set(this.edges) };
    this.reset();
    return out;
  }

  dispose() {
    this.enabled = false;
    // We intentionally do NOT remove the hook to keep Hybrid simple (hook_del throws).
    // Disabling via flag is sufficient and avoids risky deregistration.
    this._hook = null;
  }

  summary() {
    return { blocks: this.blocks.size, edges: this.edges.size };
  }
}

/**
 * Convenience: run `fn` with coverage enabled, return coverage delta.
 * @param {CoverageTracker} tracker
 * @param {() => Promise<any>} fn async function that drives one IRP
 */
export async function withCoverage(tracker, fn) {
  tracker.reset();
  tracker.resume();
  let result;
  try {
    result = await fn();
  } finally {
    tracker.pause();
  }
  const cov = tracker.snapshotAndReset();
  return { result, coverage: cov };
}
