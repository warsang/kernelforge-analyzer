#!/usr/bin/env node
/**
 * tools/dump-extract.mjs — extract a compact "kernel world snapshot" from a
 * Windows x64 kernel dump (PAGEDU64) so ntsim can boot REAL data.
 *
 * Usage: node tools/dump-extract.mjs <mem.dmp> <tablesDir> <out.json> [maxProcs]
 *
 * Everything structural comes from the Vergilius tables (same ones the
 * runtime uses) — no hardcoded struct layouts beyond PAGEDU64's own header,
 * which is a documented on-disk format.
 */

import { open } from "node:fs/promises";
import { readFile, writeFile } from "node:fs/promises";
import path from "node:path";

const PAGE = 0x1000;

async function main() {
  const [dumpPath, tablesDir, outPath, maxProcArg] = process.argv.slice(2);
  if (!dumpPath || !tablesDir || !outPath) {
    console.error("usage: dump-extract.mjs <dump.dmp> <tablesDir> <out.json> [maxProcesses=48]");
    process.exit(1);
  }
  const maxProcesses = Number(maxProcArg ?? 48);

  const fh = await open(dumpPath, "r");
  const head = Buffer.alloc(0x1000);
  await fh.read({ buffer: head, position: 0 });

  if (head.toString("ascii", 0, 8) !== "PAGEDU64") {
    throw new Error("not a PAGEDU64 dump");
  }
  const major = head.readUInt32LE(0x08);
  const minor = head.readUInt32LE(0x0c);
  const dtb = head.readBigUInt64LE(0x10);
  const psLoadedModuleList = head.readBigUInt64LE(0x20);
  const psActiveProcessHead = head.readBigUInt64LE(0x28);

  // ---- physical memory runs (@0x88 PHYSICAL_MEMORY_DESCRIPTOR) ----
  const numRuns = head.readUInt32LE(0x88);
  const runs = [];
  let fileOff = 0x1000; // first run's data starts right after the header page
  const RUNS_OFF = 0x98;
  for (let i = 0; i < numRuns; i++) {
    const basePage = head.readBigUInt64LE(RUNS_OFF + i * 16);
    const pageCount = head.readBigUInt64LE(RUNS_OFF + i * 16 + 8);
    const bytes = Number(pageCount) * PAGE;
    runs.push({ paStart: basePage * BigInt(PAGE), paEnd: basePage * BigInt(PAGE) + BigInt(bytes), fileOff });
    fileOff += bytes;
  }
  console.error(`runs=${numRuns} span=${fileOff} filesize=${(await fh.stat()).size}`);

  // ---- virtual address translation via DTB ----
  const physReadInto = async (pa, buf) => {
    const lo = 0n, hi = BigInt(runs.length - 1);
    let l = lo, r = hi;
    while (l <= r) {
      const m = (l + r) >> 1n;
      const run = runs[Number(m)];
      if (pa < run.paStart) r = m - 1n;
      else if (pa >= run.paEnd) l = m + 1n;
      else {
        const off = run.fileOff + Number(pa - run.paStart);
        const got = await fh.read({ buffer: buf, position: off });
        return got.bytesRead;
      }
    }
    return -1;
  };

  const PTE_FLAGS_PRESENT = 1n, PS_FLAG = 1n << 7n;
  async function vaRead(va, buf) {
    let remaining = buf.length, off = 0;
    while (remaining > 0) {
      const cur = va + BigInt(off);
      let pa = -1n;
      let table = dtb & ~0xfffn;
      // levels: PML4E -> PDPTE -> PDE -> PTE
      for (let level = 3; level >= 0 && pa === -1n; level--) {
        const shift = 12n + BigInt(level) * 9n;
        const idx = (cur >> shift) & 0x1ffn;
        const entryBuf = Buffer.alloc(8);
        if ((await physReadInto(table + idx * 8n, entryBuf)) < 0) break;
        const entry = entryBuf.readBigUInt64LE(0);
        if (!(entry & PTE_FLAGS_PRESENT)) break;
        if (level > 0 && !(entry & PS_FLAG)) {
          table = entry & ~0xfffn; // descend
          continue;
        }
        // large page (PS) or leaf
        const pageSizeBits = level === 3 ? 30n : level === 2 ? 21n : level === 1 ? 12n : 12n;
        if (level > 0 && (entry & PS_FLAG)) {
          pa = (entry & ~((1n << pageSizeBits) - 1n)) | (cur & ((1n << pageSizeBits) - 1n));
        } else if (level === 0) {
          pa = (entry & ~0xfffn) | (cur & 0xfffn);
        } else {
          break; // PS at unexpected level
        }
      }
      if (pa === -1n) break;
      // clip chunk to page boundary
      const inPage = Number(cur & 0xfffn);
      const chunk = Math.min(remaining, PAGE - inPage);
      const tmp = Buffer.alloc(chunk);
      const got = await physReadInto(pa, tmp);
      if (got < 0) break;
      tmp.copy(buf, off);
      off += chunk; remaining -= chunk;
    }
    return off; // bytes actually read
  }

  // ---- tables ----
  const tablesDirAbs = path.resolve(tablesDir);
  async function loadType(name) {
    const j = JSON.parse(await readFile(path.join(tablesDirAbs, `${name}.json`), "utf8"));
    const f = {};
    for (const [k, v] of Object.entries(j.fieldsByName)) f[k] = v.offset;
    return { size: j.totalSize, off: f };
  }
  const EPROC = await loadType("_EPROCESS");
  const KLDR = await loadType("_KLDR_DATA_TABLE_ENTRY");
  console.error(`eprocess size=${EPROC.size} links=0x${EPROC.off.ActiveProcessLinks.toString(16)} token=0x${EPROC.off.Token.toString(16)}`);

  const u64 = async (va) => { const b = Buffer.alloc(8); const n = await vaRead(va, b); return n === 8 ? b.readBigUInt64LE(0) : null; };
  const readC = async (va, len) => { const b = Buffer.alloc(len); const n = await vaRead(va, b); return n > 0 ? b.subarray(0, n) : null; };

  // ---- walk PsActiveProcessHead ----
  const linksOff = BigInt(EPROC.off.ActiveProcessLinks);
  const processes = [];
  {
    let cur = await u64(psActiveProcessHead);
    const headEnt = psActiveProcessHead;
    let guard = 512;
    while (cur && cur !== headEnt && guard-- > 0) {
      const eproc = cur - linksOff;
      const pidB = await u64(eproc + BigInt(EPROC.off.UniqueProcessId));
      const nameB = await readC(eproc + BigInt(EPROC.off.ImageFileName), 15);
      const tokenRaw = await u64(eproc + BigInt(EPROC.off.Token));
      const protB = EPROC.off.Protection !== undefined ? await readC(eproc + BigInt(EPROC.off.Protection), 1) : null;
      const name = nameB ? nameB.toString("latin1").replace(/\0.*$/, "") : "?";
      let tokenTarget = 0n, tokenHex = null;
      if (tokenRaw) {
        const t = tokenRaw & ~0xfn;
        const blob = await readC(t, 0x28);
        if (blob) { tokenTarget = t; tokenHex = blob.toString("hex"); }
      }
      processes.push({
        pid: pidB !== null ? Number(pidB) : -1,
        name,
        eprocess: "0x" + eproc.toString(16),
        protectionByte: protB ? protB[0] : undefined,
        token: tokenRaw ? { raw: "0x" + tokenRaw.toString(16), target: "0x" + tokenTarget.toString(16), blob256: tokenHex ?? undefined } : undefined,
      });
      cur = await u64(cur);
    }
    console.error(`processes walked: ${processes.length}`);
  }

  // ---- walk PsLoadedModuleList (_KLDR_DATA_TABLE_ENTRY.InLoadOrderLinks) ----
  const modules = [];
  {
    const linksOffKldr = BigInt(KLDR.off.InLoadOrderLinks);
    let cur = await u64(psLoadedModuleList);
    const headEnt = psLoadedModuleList;
    let guard = 256;
    while (cur && cur !== headEnt && guard-- > 0) {
      const ent = cur - linksOffKldr;
      const dllBase = await u64(ent + BigInt(KLDR.off.DllBase));
      const sizeOfImg = await u64(ent + BigInt(KLDR.off.SizeOfImage));
      // FullDllName UNICODE_STRING: Length u16, Max u16, pad, Buffer ptr @+8
      const usLen = (await readC(ent + BigInt(KLDR.off.FullDllName), 2))?.readUInt16LE(0) ?? 0;
      const usBuf = await u64(ent + BigInt(KLDR.off.FullDllName) + 8n);
      let full = "";
      if (usLen > 0 && usBuf) {
        const wb = await readC(usBuf, Math.min(usLen, 1024));
        if (wb) full = wb.toString("utf16le");
      }
      modules.push({
        base: "0x" + dllBase.toString(16),
        sizeOfImage: sizeOfImg !== null ? Number(sizeOfImg) : undefined,
        fullDllName: full,
      });
      cur = await u64(cur);
    }
    console.error(`modules walked: ${modules.length}`);
  }

  const out = {
    meta: {
      source: "ShallowFeather/KDemu mem.dmp (kernel dump at DriverEntry)",
      format: "PAGEDU64",
      buildMajor: major,
      buildMinor: minor,
      directoryTableBase: "0x" + dtb.toString(16),
      extractedAt: new Date().toISOString(),
      processCount: processes.length,
      moduleCount: modules.length,
    },
    processes,
    modules,
  };
  await writeFile(outPath, JSON.stringify(out, null, 1));
  console.error(`wrote ${outPath}`);
}

main().catch((e) => { console.error(e); process.exit(1); });
