#!/usr/bin/env node
/**
 * analyze-downloads.mjs — headless Driver Analyzer runner for ~/Downloads/*.sys
 * Runs each file through ntsim-analyzer on JS + (optionally) Unicorn,
 * capturing load/entry/exceptions/bugcheck/coverage/trace.
 * Usage: node tools/analyze-downloads.mjs [--unicorn] [--out /tmp/report.json]
 */

import { readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { glob } from "node:fs";

const args = process.argv.slice(2);
const wantUnicorn = args.includes("--unicorn");
const outIdx = args.indexOf("--out");
const outPath = outIdx >= 0 ? args[outIdx + 1] : null;
const verbose = args.includes("--verbose");

const downloads = "/Users/warsang/Downloads";
const patterns = [
  path.join(downloads, "00748bd6b97e6ea3b46750c45691689401ab32505387d963c3efdcfa758b6227.sys"),
  path.join(downloads, "3cfdbc52e8f93fe584cb470e4057335b394e4539b2873d378fe9a806bc98093c.sys"),
  path.join(downloads, "98eaa3d2df64ac8703ede8e0087e41a2ce589593f56cba56b048d7d121f990d3.sys"),
  path.join(downloads, "driver_challenge.sys"),
  path.join(downloads, "f9dd0b57a5c133ca0c4cab3cca1ac8debdc4a798b452167a1e5af78653af00c1.sys"),
];

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const tablesDir = path.join(__dirname, "../packages/ntsim-assets/data/vergilius/windows-10/22h2");
const tablesDirAlt = path.join(__dirname, "../apps/web/public/tables/windows-10/22h2");

async function loadTables() {
  const { StructTables } = await import("@kernelforge/ntsim/src/structs.mjs");
  const names = ["_EPROCESS", "_ETHREAD", "_KPROCESS", "_KTHREAD", "_LIST_ENTRY", "_UNICODE_STRING", "_OBJECT_HEADER", "_HANDLE_TABLE", "_PS_PROTECTION", "_KLDR_DATA_TABLE_ENTRY", "_LDR_DATA_TABLE_ENTRY", "_MMVAD", "_MMVAD_SHORT", "_OBJECT_TYPE", "_POOL_HEADER", "_KPCR", "_KPRCB", "_DISPATCHER_HEADER", "_ETHREAD", "_EPROCESS"];
  try {
    return await StructTables.loadDir(tablesDir, names.filter((v,i,a)=>a.indexOf(v)===i));
  } catch {
    return await StructTables.loadDir(tablesDirAlt, names.filter((v,i,a)=>a.indexOf(v)===i));
  }
}

function summarize(report) {
  const s = {
    load: report.load,
    entry: report.entry,
    bugcheck: report.bugcheck,
    exceptions: report.exceptions?.slice(0, 5) ?? [],
    irqlViolations: report.irqlViolations?.slice(0, 5) ?? [],
    unmodeled: report.load?.unmodeledExports?.slice(0, 20) ?? [],
    unmodeledCount: report.load?.unmodeledExports?.length ?? 0,
    harvested: report.harvestedIoctls ?? null,
    autoIrps: report.autoIrps ? report.autoIrps.map(r => ({
      majorName: r.majorName,
      ioctl: typeof r.ioctl==="bigint" ? `0x${r.ioctl.toString(16)}` : r.ioctl,
      ntstatus: typeof r.ntstatus==="bigint" ? `0x${r.ntstatus.toString(16)}` : r.ntstatus,
      status: r.status,
      coverage: r.coverage,
      source: r.source,
      inputHex: r.inputHex?.slice(0, 32),
      error: r.error?.slice(0, 200),
    })) : null,
    dbgLogHead: report.dbgLog?.slice(0, 10) ?? [],
    dbgLogCount: report.dbgLog?.length ?? 0,
    apiTraceSummary: report.apiTraceSummary ? { totalCalls: report.apiTraceSummary.totalCalls, distinct: report.apiTraceSummary.distinct, byNameHead: Object.keys(report.apiTraceSummary.byName).slice(0, 12)} : null,
    traceLines: report.traceText ? report.traceText.split("\n").slice(0, 40).join("\n") : null,
    traceCount: report.trace?.length ?? 0,
    notifyRoutines: report.notifyRoutines,
    deferred: report.deferred,
  };
  return s;
}

async function analyzeOne(bytes, name, backendName) {
  const { analyzeDriver } = await import("@kernelforge/ntsim-analyzer/src/index.mjs");
  const tables = await loadTables();
  const opts = {
    name,
    backendName: backendName === "unicorn" ? "unicorn" : "js",
    tables,
    autoIrp: { maxCodes: 8, outputLen: 64 },
    runUnload: false,
    trace: { disable: false },
  };
  if (backendName === "unicorn") {
    opts.makeBackend = async () => {
      const mod = await import("@kernelforge/ntsim-unicorn");
      const factory = mod.createUnicornBackend ?? mod.default?.createUnicornBackend ?? mod.create;
      if (typeof factory !== "function") throw new Error(`createUnicornBackend not found exports ${Object.keys(mod).join(",")}`);
      return await factory(null);
    };
  } else if (backendName === "hybrid") {
    opts.makeBackend = async () => {
      const { HybridCpuBackend } = await import("@kernelforge/ntsim-unicorn/src/hybrid.mjs");
      return await HybridCpuBackend.create(null);
    };
  }
  try {
    const report = await analyzeDriver(bytes, opts);
    return { ok: true, report, summary: summarize(report) };
  } catch (e) {
    return { ok: false, error: e.message, stack: e.stack?.slice(0, 2000) };
  }
}

async function main() {
  const results = [];
  for (const f of patterns) {
    let bytes;
    try { bytes = await readFile(f); } catch (e) { console.error(`skip ${f}: ${e.message}`); continue; }
    const name = path.basename(f);
    console.log(`\n=== ${name} (${bytes.length} bytes) ===`);
    for (const backend of wantUnicorn ? ["js", "unicorn"] : ["js"]) {
      console.log(`\n-- backend=${backend} --`);
      const t0 = Date.now();
      const res = await analyzeOne(bytes, name, backend);
      const dt = Date.now() - t0;
      console.log(`elapsed ${dt}ms ok=${res.ok}`);
      if (!res.ok) {
        console.log(`ERROR: ${res.error}`);
        console.log(res.stack?.slice(0, 800));
        results.push({ file: name, backend, error: res.error, elapsedMs: dt });
        continue;
      }
      const s = res.summary;
      console.log(`load: base ${s.load?.base} imageSize 0x${s.load?.imageSize?.toString(16)} relocated ${s.load?.relocated} imports ${s.load?.imports?.length} unmodeled ${s.unmodeledCount}`);
      if (s.unmodeledCount) console.log(`  unmodeled: ${s.unmodeled.slice(0, 10).join(", ")}${s.unmodeledCount>10?" ...":""}`);
      console.log(`entry: ${JSON.stringify(s.entry)} bugcheck:${JSON.stringify(s.bugcheck)}`);
      if (s.exceptions.length) console.log(`exceptions: ${JSON.stringify(s.exceptions)}`);
      if (s.irqlViolations.length) console.log(`irqlViolations: ${JSON.stringify(s.irqlViolations)}`);
      if (s.harvested) console.log(`harvested ${s.harvested.length}: ${s.harvested.map(h=>h.hex).join(", ")}`);
      if (s.autoIrps) {
        console.log(`autoIrps ${s.autoIrps.length}:`);
        for (const r of s.autoIrps) console.log(`  ${r.majorName} ${r.ioctl ?? ""} nt=${r.ntstatus} ${r.status} cov=${JSON.stringify(r.coverage)} src=${r.source ?? ""} ${r.error?"ERR "+r.error:""}`);
      }
      console.log(`apiTrace: ${JSON.stringify(s.apiTraceSummary)}`);
      console.log(`traceCount ${s.traceCount} dbgLog ${s.dbgLogCount}`);
      if (verbose && s.traceLines) console.log(s.traceLines);
      if (verbose && s.dbgLogHead.length) console.log("dbgHead", s.dbgLogHead);
      results.push({ file: name, backend, elapsedMs: dt, summary: s });
    }
  }
  if (outPath) {
    await writeFile(outPath, JSON.stringify(results, (k,v)=> typeof v==="bigint"? `0x${v.toString(16)}`:v, 2));
    console.log(`\nwrote ${outPath}`);
  } else {
    const tmp = "/tmp/sys-report.json";
    await writeFile(tmp, JSON.stringify(results, (k,v)=> typeof v==="bigint"? `0x${v.toString(16)}`:v, 2));
    console.log(`\nwrote ${tmp}`);
  }
}

main().catch(e => { console.error(e); process.exit(1); });
