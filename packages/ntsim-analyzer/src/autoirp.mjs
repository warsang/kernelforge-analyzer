/**
 * autoirp.mjs — speakeasy-class automatic IRP driving for the analyzer.
 *
 * After DriverEntry succeeds, most of a driver's behavior hides behind
 * MajorFunction. This module:
 *   1. sends IRP_MJ_CREATE / IRP_MJ_CLOSE (the lifecycle every driver has),
 *   2. harvests candidate CTL_CODEs from .text by decoding immediate-bearing
 *      instructions (mov/push/cmp/arith imm32 forms) and keeping dwords whose
 *      DeviceType/Access/Function/Method bitfields look like real IOCTL codes,
 *   3. synthesizes METHOD_BUFFERED requests against each harvested code with
 *      a few canned input patterns, reading back IoStatus/SystemBuffer.
 *
 * Deterministic: no randomness, stable ordering, capped work.
 *
 * Extended with coverage-guided fuzzing + concolic execution when requested
 * via cfg.fuzz / cfg.concolic (both optional, off by default). When those
 * tickboxes are enabled the per-code loop delegates to the fuzz/concolic
 * engines which maintain their own corpus & coverage tracking via
 * CoverageTracker (uses addCodeHook on JsInterpreter/Unicorn/Hybrid).
 */

import { IRP_MJ } from "@kernelforge/ntsim/src/devices.mjs";

// ---------------------------------------------------------------- harvesting

/** Decode-friendly scan: sliding imm32 window over executable sections.
 *
 * Rather than fully decoding x64, sweep every dword-aligned-to-byte offset
 * and keep dwords passing the CTL_CODE bitfield filter — the same
 * constant-harvesting trick speakeasy-class fuzzers use. False positives are
 * cheap: they just become one extra probed request.
 */
export function harvestCtlCodes(imageBytes, pe, opts = {}) {
  const cap = opts.maxCodes ?? 32;
  const out = [];
  const seen = new Set();

  const exec = pe.sections.filter((s) => s.chars & 0x20000000); // IMAGE_SCN_MEM_EXECUTE
  const spans = (exec.length ? exec : pe.sections).map((s) => ({
    start: s.rva,
    bytes: imageBytes.subarray(
      s.rawPtr,
      s.rawPtr + Math.min(s.virtualSize || s.rawSize, opts.maxScanBytes ?? 0x40000),
    ),
  }));

  for (const { start, bytes } of spans) {
    for (let i = 0; i + 4 <= bytes.length; i++) {
      const v =
        (bytes[i] | (bytes[i + 1] << 8) | (bytes[i + 2] << 16) | (bytes[i + 3] << 24)) >>> 0;
      if (!looksLikeCtlCode(v)) continue;
      if (seen.has(v)) continue;
      seen.add(v);
      out.push({ value: v, rva: BigInt(start + i), major: IRP_MJ.DEVICE_CONTROL });
      if (out.length >= cap) return out.sort((a, b) => a.value - b.value);
    }
  }
  return out.sort((a, b) => a.value - b.value);
}

/** CTL_CODE(DeviceType, Function, Method, Access) bit layout filter. */
export function looksLikeCtlCode(v) {
  const method = v & 3;
  const func = (v >>> 2) & 0xfff;
  const access = (v >>> 14) & 3;
  const devType = (v >>> 16) & 0xffff;
  if (method !== 0 && method !== 3) return false; // BUFFERED or NEITHER only
  if (func < 0x800) return false; // custom range per winioctl.h
  if (devType === 0 || devType > 0x8000) return false;
  if (v === 0xffffffff) return false;
  return true;
}

// --------------------------------------------------------------- auto-drive

function inputPatterns(opts) {
  if (opts.inputPatterns?.length) return opts.inputPatterns;
  return [
    new Uint8Array(16),
    Uint8Array.from({ length: 16 }, (_, i) => 0xff),
    Uint8Array.from({ length: 16 }, (_, i) => i),
  ];
}

function toHex(buf) {
  return [...buf].map((b) => b.toString(16).padStart(2, "0")).join("");
}

/**
 * Drive lifecycle majors + harvested DEVICE_CONTROL codes through sendIrp.
 * Supports optional fuzz / concolic modes (tickboxes in analyzer UI).
 * @param {object} kernel NtKernel
 * @param {object} device device record (createDeviceObject / driver's own)
 * @param {{harvested?:Array<{value:number}>, maxCodes?:number, inputPatterns?:Uint8Array[], sendIrp:Function, fuzz?:object, concolic?:object, imageBase?:bigint, imageSize?:number|bigint, onPhase?:Function, outputLen?:number}} cfg
 * @returns {Promise<Array<object>>} per-IRP results in drive order
 */
export async function autoDriveIrps(kernel, device, cfg) {
  const sendIrp = cfg.sendIrp;
  if (!sendIrp) throw new Error("autoDriveIrps: cfg.sendIrp required");
  const onPhase = cfg.onPhase ?? (() => {});
  const results = [];
  const push = async (spec, phase) => {
    if (phase) onPhase(phase);
    const r = await sendIrp(kernel, device, spec);
    results.push({
      ...r,
      outputHex: r.outputHex ?? "",
      error: r.error ? String(r.error.message ?? r.error) : undefined,
    });
    return r;
  };

  // lifecycle
  await push({ major: IRP_MJ.CREATE }, "irp MJ_CREATE");
  if (results.at(-1).status !== "ok") return results;

  const fuzzEnabled = !!cfg.fuzz;
  const concEnabled = !!cfg.concolic;
  const useAdvanced = fuzzEnabled || concEnabled;
  // advanced path needs imageBase/imageSize for coverage hook
  const imageBase = cfg.imageBase != null ? BigInt(cfg.imageBase) : null;
  const imageSize = cfg.imageSize != null ? BigInt(cfg.imageSize) : null;
  const canAdvanced = useAdvanced && imageBase !== null && imageSize !== null;

  // fallback to legacy if advanced requested but image unavailable
  if (useAdvanced && !canAdvanced) {
    console.warn("[autoDrive] advanced mode requested but imageBase/imageSize missing — falling back to legacy canned inputs");
  }

  if (canAdvanced) {
    // lazy imports to avoid circular deps and to keep legacy path lightweight
    const baseOpts = {
      sendIrp,
      imageBase,
      imageSize,
      outputLen: cfg.outputLen ?? 64,
      onProgress: null,
    };
    for (const code of (cfg.harvested ?? []).slice(0, cfg.maxCodes ?? 32)) {
      if (kernel.bugcheck || kernel.crash) break;
      const codeVal = code.value >>> 0;
      onPhase(`ioctl 0x${codeVal.toString(16)} (advanced)`);

      if (fuzzEnabled && concEnabled) {
        // Driller hybrid: fuzz first, then concolic with fuzz corpus as seeds, merge
        const { fuzzIoctl } = await import("./fuzz.mjs");
        const fuzzRes = await fuzzIoctl(kernel, device, codeVal, {
          ...baseOpts,
          iterations: cfg.fuzz.iterations ?? 256,
          corpusCap: cfg.fuzz.corpusCap ?? 32,
          inputLen: cfg.fuzz.inputLen ?? 16,
          outputLen: cfg.outputLen ?? 64,
          seedPatterns: inputPatterns(cfg),
          onProgress: (evt) => onPhase(`fuzz 0x${codeVal.toString(16)} iter ${evt.iter ?? evt.phase}`),
        });
        // seed concolic with fuzz corpus
        const seedsFromFuzz = fuzzRes.corpus.map((c) => c.buf);
        const { concolicCampaign } = await import("./symbolic/concolic.mjs");
        const concRes = await concolicCampaign(kernel, device, codeVal, {
          ...baseOpts,
          maxSymBytes: cfg.concolic.maxSymBytes ?? 64,
          solverTimeoutMs: cfg.concolic.solverTimeoutMs ?? 500,
          maxQueries: cfg.concolic.maxQueries ?? 8,
          inputLen: cfg.fuzz.inputLen ?? 16,
          outputLen: cfg.outputLen ?? 64,
          corpus: fuzzRes.corpus,
          onProgress: (evt) => onPhase(`concolic 0x${codeVal.toString(16)} ${evt.phase}`),
        });
        // Merge corpora, dedup by buf hex
        const seenHex = new Set();
        const merged = [];
        for (const c of [...fuzzRes.corpus, ...concRes.corpus]) {
          const h = toHex(c.buf);
          if (seenHex.has(h)) continue;
          seenHex.add(h);
          merged.push(c);
        }
        // push merged as results
        let i = 0;
        for (const entry of merged.slice(0, 64)) {
          // deduplicate output: push as synthetic result
          // entry.res may be from fuzz (which already is sendIrp result) or from concolic confirmation
          const r = entry.res ?? entry.confirmRes;
          if (!r) continue;
          results.push({
            ...r,
            outputHex: r.outputHex ?? "",
            error: r.error ? String(r.error.message ?? r.error) : undefined,
            ioctl: BigInt(codeVal),
            majorName: "DEVICE_CONTROL",
            inputHex: toHex(entry.buf),
            coverage: entry.coverage ? { blocks: entry.coverage.blocks?.size ?? 0, edges: entry.coverage.edges?.size ?? 0 } : undefined,
            source: entry.witness ? "concolic" : "fuzz",
          });
          i++;
          onPhase(`ioctl 0x${codeVal.toString(16)} #${i} ${entry.witness ? "concolic" : "fuzz"} cov=${entry.coverage?.blocks?.size ?? 0}`);
          if (kernel.bugcheck || kernel.crash) break;
        }
        if (!merged.length) {
          // fallback canned
          for (const input of inputPatterns(cfg)) {
            const r = await push({ major: IRP_MJ.DEVICE_CONTROL, ioctl: BigInt(codeVal), input, outputLen: cfg.outputLen ?? 64 }, `ioctl 0x${codeVal.toString(16)} canned`);
            if (r.status !== "ok") break;
            if (kernel.bugcheck || kernel.crash) break;
          }
        }
      } else if (fuzzEnabled) {
        const { fuzzIoctl } = await import("./fuzz.mjs");
        const fuzzRes = await fuzzIoctl(kernel, device, codeVal, {
          ...baseOpts,
          iterations: cfg.fuzz.iterations ?? 256,
          corpusCap: cfg.fuzz.corpusCap ?? 32,
          inputLen: cfg.fuzz.inputLen ?? 16,
          outputLen: cfg.outputLen ?? 64,
          seedPatterns: inputPatterns(cfg),
          onProgress: (evt) => {
            if (evt.phase==="fuzz") onPhase(`fuzz 0x${codeVal.toString(16)} iter ${evt.iter}`);
          },
        });
        let i = 0;
        for (const entry of fuzzRes.corpus.slice(0, 64)) {
          const r = entry.res;
          results.push({
            ...r,
            outputHex: r.outputHex ?? "",
            error: r.error ? String(r.error.message ?? r.error) : undefined,
            ioctl: BigInt(codeVal),
            majorName: "DEVICE_CONTROL",
            inputHex: toHex(entry.buf),
            coverage: { blocks: entry.coverage.blocks.size, edges: entry.coverage.edges.size },
            source: "fuzz",
          });
          i++;
          if (kernel.bugcheck || kernel.crash) break;
        }
        if (!fuzzRes.corpus.length) {
          for (const input of inputPatterns(cfg)) {
            const r = await push({ major: IRP_MJ.DEVICE_CONTROL, ioctl: BigInt(codeVal), input, outputLen: cfg.outputLen ?? 64 }, `ioctl 0x${codeVal.toString(16)} fuzz-fallback`);
            if (r.status !== "ok") break;
            if (kernel.bugcheck || kernel.crash) break;
          }
        }
        // also push summary event for UI
        results.push({
          status: "ok",
          ntstatus: 0n,
          majorName: "__fuzz_summary",
          ioctl: BigInt(codeVal),
          outputHex: "",
          coverage: { corpus: fuzzRes.corpus.length, globalBlocks: fuzzRes.globalSeen.size, iterations: fuzzRes.iterations },
        });
      } else if (concEnabled) {
        const { concolicCampaign } = await import("./symbolic/concolic.mjs");
        const concRes = await concolicCampaign(kernel, device, codeVal, {
          ...baseOpts,
          maxSymBytes: cfg.concolic.maxSymBytes ?? 64,
          solverTimeoutMs: cfg.concolic.solverTimeoutMs ?? 500,
          maxQueries: cfg.concolic.maxQueries ?? 8,
          inputLen: cfg.concolic.inputLen ?? 16,
          outputLen: cfg.outputLen ?? 64,
          corpus: inputPatterns(cfg).map((buf)=>({ buf, coverage: { blocks: new Set(), edges: new Set() } })),
          onProgress: (evt) => onPhase(`concolic 0x${codeVal.toString(16)} ${evt.phase}`),
        });
        let i = 0;
        for (const entry of concRes.corpus.slice(0, 64)) {
          const r = entry.res ?? entry.confirmRes;
          if (!r) continue;
          results.push({
            ...r,
            outputHex: r.outputHex ?? "",
            error: r.error ? String(r.error.message ?? r.error) : undefined,
            ioctl: BigInt(codeVal),
            majorName: "DEVICE_CONTROL",
            inputHex: toHex(entry.buf),
            coverage: entry.coverage ? { blocks: entry.coverage.blocks?.size ?? 0 } : undefined,
            source: entry.witness ? "concolic" : "seed",
            smt2: entry.smt2,
          });
          i++;
          if (kernel.bugcheck || kernel.crash) break;
        }
        if (!concRes.corpus.length) {
          for (const input of inputPatterns(cfg)) {
            const r = await push({ major: IRP_MJ.DEVICE_CONTROL, ioctl: BigInt(codeVal), input, outputLen: cfg.outputLen ?? 64 }, `ioctl 0x${codeVal.toString(16)} concolic-fallback`);
            if (r.status !== "ok") break;
            if (kernel.bugcheck || kernel.crash) break;
          }
        }
      }
    }
  } else {
    // legacy canned path
    for (const code of (cfg.harvested ?? []).slice(0, cfg.maxCodes ?? 32)) {
      let hardFail = false;
      let i = 0;
      for (const input of inputPatterns(cfg)) {
        const r = await push({
          major: IRP_MJ.DEVICE_CONTROL,
          ioctl: BigInt(code.value),
          input,
          outputLen: cfg.outputLen ?? 64,
        }, `ioctl 0x${code.value.toString(16)} #${++i}`);
        if (r.status !== "ok") { hardFail = true; break; }
        if (kernel.bugcheck || kernel.crash) return results;
      }
      if (hardFail) break;
    }
  }

  await push({ major: IRP_MJ.CLOSE }, "irp MJ_CLOSE");
  return results;
}
