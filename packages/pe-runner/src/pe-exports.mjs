/**
 * PE export directory reader — feeds the DLL Analyzer's export picker and the
 * rundll32-style invocation path in index.mjs.
 *
 * Returns entries in ordinal order with forwarder strings resolved
 * (`KERNEL32.Sleep` style); ordinal-only exports carry name=null.
 */

import { parsePe, rvaToOffset } from "@kernelforge/ntsim/src/pe.mjs";

/** Hard cap so a hostile export table cannot stall the UI. */
export const MAX_EXPORTS = 4096;

const u16 = (b, o) => b[o] | (b[o + 1] << 8);
const u32 = (b, o) => (b[o] | (b[o + 1] << 8) | (b[o + 2] << 16) | (b[o + 3] << 24)) >>> 0;
const cstr = (b, o, max = 512) => {
  let e = o;
  while (e < b.length && b[e] !== 0 && e - o < max) e++;
  return String.fromCharCode(...b.subarray(o, e));
};

/**
 * @param {Uint8Array} bytes PE32+ image
 * @returns {{ total: number, moduleName: string|null, entries: Array<{name:string|null, ordinal:number, index:number, rva:number, forwarder?:string|null}> }}
 */
export function listPeExports(bytes) {
  const out = { total: 0, moduleName: null, entries: [] };
  const pe = parsePe(bytes);
  const dir = pe.dirs?.[0];
  if (!dir || !dir.rva || !dir.size) return out;

  const o = rvaToOffset(pe, dir.rva);
  if (o === null || o + 40 > bytes.length) return out;

  const nameRva = u32(bytes, o + 12);
  const base = u32(bytes, o + 16);
  const nfunc = u32(bytes, o + 20);
  const nnames = u32(bytes, o + 24);
  const funcsRva = u32(bytes, o + 28);
  const namesRva = u32(bytes, o + 32);
  const ordsRva = u32(bytes, o + 36);

  if (nameRva) {
    const no = rvaToOffset(pe, nameRva);
    if (no !== null) out.moduleName = cstr(bytes, no, 128);
  }

  const byIndex = new Map();
  const funcsOff = rvaToOffset(pe, funcsRva);
  if (funcsOff !== null) {
    for (let i = 0; i < Math.min(nfunc, MAX_EXPORTS); i++) {
      byIndex.set(i, u32(bytes, funcsOff + i * 4));
    }
  }

  const named = new Set();
  const namesOff = rvaToOffset(pe, namesRva);
  const ordsOff = rvaToOffset(pe, ordsRva);
  if (namesOff !== null && ordsOff !== null) {
    for (let i = 0; i < Math.min(nnames, MAX_EXPORTS); i++) {
      const nr = u32(bytes, namesOff + i * 4);
      const idx = u16(bytes, ordsOff + i * 2);
      const rva = byIndex.get(idx) ?? 0;
      if (rva === 0) continue; // invalid/absent entry — loaders skip it
      const no = rvaToOffset(pe, nr);
      const name = no === null ? null : cstr(bytes, no, 512);
      named.add(idx);
      out.entries.push({ name, ordinal: base + idx, index: idx, rva });
    }
  }
  for (const [idx, rva] of byIndex) {
    if (!named.has(idx) && rva !== 0) out.entries.push({ name: null, ordinal: base + idx, index: idx, rva });
  }

  for (const e of out.entries) {
    if (e.rva >= dir.rva && e.rva < dir.rva + dir.size) {
      const fo = rvaToOffset(pe, e.rva);
      e.forwarder = fo === null ? null : cstr(bytes, fo, 512);
    }
  }

  out.entries.sort((a, b) => a.ordinal - b.ordinal);
  out.total = out.entries.length;
  return out;
}

/** "Name", "#123" or "123" -> matching entry (or null). */
export function findPeExport(entries, spec) {
  const s = String(spec ?? "").trim();
  if (!s) return null;
  if (s.startsWith("#") || /^\d+$/.test(s)) {
    const ord = Number(s.replace(/^#/, ""));
    return entries.find((e) => e.ordinal === ord) ?? null;
  }
  return entries.find((e) => e.name === s)
    ?? entries.find((e) => (e.name ?? "").toLowerCase() === s.toLowerCase())
    ?? null;
}

/** Canonical spec string used in reports: name when present, else #ordinal. */
export function exportSpecOf(entry) {
  return entry?.name ?? `#${entry?.ordinal}`;
}
