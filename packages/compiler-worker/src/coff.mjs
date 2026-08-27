/**
 * COFF object parser + section linker for real clang-emitted .obj files
 * (x86_64-windows-msvc flavor). Supports the freestanding-C subset:
 * classic COFF layout, .text/.rdata/.data/.bss, extern definitions,
 * DIR32/REL32/ABS relocations.
 */

export class CoffError extends Error {}

const u16 = (b, o) => b[o] | (b[o + 1] << 8);
const u32 = (b, o) => (b[o] | (b[o + 1] << 8) | (b[o + 2] << 16) | (b[o + 3] << 24)) >>> 0;
const i32 = (b, o) => u32(b, o) | 0;

// x64 (AMD64) relocation type codes — per PE spec:
export const REL = {
  ABS: 0x0001,      // DIR64: 64-bit virtual address
  ADDR32: 0x0002,   // DIR32
  REL32: 0x0004,    // REL32: 32-bit signed disp from end of field
  SECTION: 0x000a,
  SECREL: 0x000b,
};

/** Parse a classic x64 COFF object. */
export function parseCoff(bytes) {
  const machine = u16(bytes, 0);
  if (machine !== 0x8664) {
    throw new CoffError(`machine 0x${machine.toString(16)} != x64`);
  }
  const numSections = u16(bytes, 2);
  const symTableOff = u32(bytes, 8);
  const numSymbols = u32(bytes, 12);
  const strTableOff = symTableOff + numSymbols * 18;

  const readCString = (off) => {
    let end = off;
    while (end < bytes.length && bytes[end] !== 0) end++;
    return String.fromCharCode(...bytes.subarray(off, end));
  };
  // symbol names: 8-byte inline string, or {0, strTableOffset} dword pair.
  // (section-header long names use '/NNN' ASCII instead — handled too)
  const nameAt = (o) => {
    if (bytes[o] === 0x2f /* '/' */) {
      let digits = "";
      for (let i = 1; i < 8 && bytes[o + i] >= 0x30 && bytes[o + i] <= 0x39; i++) {
        digits += String.fromCharCode(bytes[o + i]);
      }
      return readCString(strTableOff + parseInt(digits || "0", 10));
    }
    if (u32(bytes, o) === 0) {
      const strOff = u32(bytes, o + 4);
      if (strOff === 0) return "";
      return readCString(strTableOff + strOff);
    }
    return String.fromCharCode(...bytes.subarray(o, o + 8)).replace(/\0.*$/, "");
  };

  const sections = [];
  let off = 20;
  for (let i = 0; i < numSections; i++, off += 40) {
    const name = nameAt(off);
    const vsize = u32(bytes, off + 8);
    const rawSize = u32(bytes, off + 16);
    const rawPtr = u32(bytes, off + 20);
    const relocPtr = u32(bytes, off + 24);
    const numRelocs = u16(bytes, off + 32);
    const chars = u32(bytes, off + 36);

    const data = rawSize > 0
      ? bytes.slice(rawPtr, rawPtr + rawSize)
      : new Uint8Array(vsize);

    const relocs = [];
    for (let r = 0; r < numRelocs; r++) {
      const ro = relocPtr + r * 10;
      relocs.push({
        va: u32(bytes, ro),
        symIndex: u32(bytes, ro + 4),
        type: u16(bytes, ro + 8),
      });
    }
    sections.push({ index: i, name, data, vsize, relocs, chars });
  }

  const symbols = [];
  const symbolsByIndex = new Array(numSymbols).fill(null);
  let so = symTableOff;
  for (let i = 0; i < numSymbols; ) {
    const rec = {
      index: i,
      name: nameAt(so),
      value: u32(bytes, so + 8),
      sectionNumber: (bytes[so + 12] | (bytes[so + 13] << 8)) | 0,
      type: u16(bytes, so + 14),
      storageClass: bytes[so + 16],
      auxCount: bytes[so + 17],
    };
    symbols.push(rec);
    symbolsByIndex[i] = rec;
    const skip = rec.auxCount + 1;
    so += skip * 18;
    i += skip;
  }

  return { machine, sections, symbols, symbolsByIndex };
}

/**
 * Concatenate objects into output sections and compute final symbol offsets.
 * @returns {{sections: Map<string, Uint8Array>, symbols: Map<string, {section: string, offset: number}>}}
 */
export function linkSections(objects, order = [".text", ".rdata", ".data", ".bss"]) {
  const buckets = new Map();
  for (const name of order) buckets.set(name, []);
  /** symbol -> {section, offset} */
  const symbols = new Map();

  for (const obj of objects) {
    const secBase = new Map(); // section.index -> offset within bucket
    for (const s of obj.sections) {
      const arr = buckets.get(s.name);
      if (!arr) continue; // debug/other sections dropped
      const curLen = arr.reduce((a, c) => a + c.length, 0);
      const aligned = Math.ceil(curLen / 16) * 16;
      if (aligned > curLen) arr.push(new Uint8Array(aligned - curLen));
      secBase.set(s.index, aligned);
      arr.push(s.data);
    }
    for (const sym of obj.symbols) {
      if (sym.sectionNumber > 0 && sym.storageClass === 2 && sym.auxCount === 0) {
        const secIdx = sym.sectionNumber - 1;
        const sec = obj.sections.find((x) => x.index === secIdx);
        const base = secBase.get(secIdx);
        if (sec && base !== undefined) {
          symbols.set(sym.name, { section: sec.name, offset: base + sym.value });
        }
      }
    }
  }

  const sections = new Map();
  for (const [name, chunks] of buckets) {
    if (!chunks.length) continue;
    const total = chunks.reduce((a, c) => a + c.length, 0);
    const buf = new Uint8Array(total);
    let o = 0;
    for (const c of chunks) { buf.set(c, o); o += c.length; }
    sections.set(name, buf);
  }
  return { sections, symbols };
}
