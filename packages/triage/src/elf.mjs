/**
 * elf.mjs — compact ELF64 (x86-64) reader + static triage facts.
 *
 * `parseElf64` extracts what a loader needs (PT_LOAD segments, dynamic table,
 * imported symbol names + relocation/GOT slots). `parseElfStatic` adds the
 * triage layer: section entropy, RWX/exec-stack, RELRO, packer hints,
 * interesting strings and ssdeep.
 */

import { shannonEntropy } from "./entropy.mjs";
import { extractStrings } from "./strings.mjs";
import { ssdeep } from "./fuzzy/ssdeep.mjs";

const u16 = (b, o) => b[o] | (b[o + 1] << 8);
const u32 = (b, o) => (b[o] | (b[o + 1] << 8) | (b[o + 2] << 16) | (b[o + 3] << 24)) >>> 0;
const u64 = (b, o) => {
  let v = 0n;
  for (let i = 7; i >= 0; i--) v = (v << 8n) | BigInt(b[o + i] ?? 0);
  return v;
};
const i64 = (b, o) => BigInt.asIntN(64, u64(b, o));
const cstr = (b, o, max = 512) => {
  let s = "";
  for (let i = 0; i < max && o + i < b.length && b[o + i] !== 0; i++) s += String.fromCharCode(b[o + i]);
  return s;
};

const PT = { LOAD: 1, DYNAMIC: 2, INTERP: 3, NOTE: 4, PHDR: 6, TLS: 7, GNU_STACK: 0x6474e551, GNU_RELRO: 0x6474e552 };
const R_X86_64 = { GLOB_DAT: 6, JUMP_SLOT: 7, RELATIVE: 8, IRELATIVE: 37 };

const SHF = { WRITE: 0x1, ALLOC: 0x2, EXEC: 0x4 };
const SHT = { SYMTAB: 2, STRTAB: 3, DYNSYM: 11 };

export function parseElf64(bytes) {
  const b = bytes instanceof Uint8Array ? bytes : Uint8Array.from(bytes);
  if (b.length < 64 || b[0] !== 0x7f || b[1] !== 0x45 || b[2] !== 0x4c || b[3] !== 0x46) {
    throw new Error("not an ELF (bad magic)");
  }
  const cls = b[4];
  if (cls !== 2) throw new Error(`unsupported ELF class ${cls} (need 64-bit)`);
  const type = u16(b, 16);
  const machine = u16(b, 18);
  if (machine !== 0x3e) throw new Error(`unsupported ELF machine 0x${machine.toString(16)} (need x86-64)`);
  const entry = u64(b, 24);
  const phoff = u64(b, 32);
  const shoff = u64(b, 40);
  const phentsize = u16(b, 54);
  const phnum = u16(b, 56);
  const shnum = u16(b, 60);
  const shstrndx = u16(b, 62);

  const phdrs = [];
  for (let i = 0; i < phnum; i++) {
    const o = Number(phoff) + i * phentsize;
    if (o + 56 > b.length) break;
    phdrs.push({
      type: u32(b, o),
      flags: u32(b, o + 4),
      offset: u64(b, o + 8),
      vaddr: u64(b, o + 16),
      paddr: u64(b, o + 24),
      filesz: u64(b, o + 32),
      memsz: u64(b, o + 40),
      align: u64(b, o + 48),
    });
  }
  const loads = phdrs.filter((p) => p.type === PT.LOAD);
  // ET_REL (kernel modules / objects) legitimately has no program headers.
  if (!loads.length && type !== 1) throw new Error("ELF has no PT_LOAD segments");
  const interp = (() => {
    const p = phdrs.find((x) => x.type === PT.INTERP);
    return p ? cstr(b, Number(p.offset), 256) : null;
  })();
  const gnuStack = phdrs.find((x) => x.type === PT.GNU_STACK);
  const execStack = gnuStack ? (gnuStack.flags & 0x1) !== 0 : false;
  const relro = phdrs.some((x) => x.type === PT.GNU_RELRO);

  const sections = [];
  for (let i = 0; i < shnum; i++) {
    const o = Number(shoff) + i * 64;
    if (o + 64 > b.length) break;
    sections.push({
      nameOff: u32(b, o),
      type: u32(b, o + 4),
      flags: u64(b, o + 8),
      addr: u64(b, o + 16),
      offset: u64(b, o + 24),
      size: u64(b, o + 32),
      link: u32(b, o + 40),
      entsize: u64(b, o + 56),
    });
  }
  const shstrOff = shstrndx < sections.length ? Number(sections[shstrndx].offset) : 0;
  for (const s of sections) s.name = shstrOff ? cstr(b, shstrOff + s.nameOff, 64) : "";

  const dynPh = phdrs.find((p) => p.type === PT.DYNAMIC);
  const dynamic = new Map();
  if (dynPh) {
    for (let o = Number(dynPh.offset); o + 16 <= Number(dynPh.offset) + Number(dynPh.filesz); o += 16) {
      const tag = i64(b, o);
      const val = u64(b, o + 8);
      if (tag === 0n) break;
      if (!dynamic.has(tag)) dynamic.set(tag, []);
      dynamic.get(tag).push(val);
    }
  }
  const dt = (tag) => dynamic.get(tag)?.[0] ?? null;
  const strtabOff = dt(5n);
  const symtabOff = dt(6n);
  const symEnt = Number(dt(8n) ?? 24n);
  const needed = (dynamic.get(1n) ?? [])
    .map((off) => (strtabOff !== null ? cstr(b, Number(strtabOff) + Number(off)) : null))
    .filter(Boolean);
  const isPie = type === 3;
  const hasInterp = !!interp;
  const bindNow = dynamic.has(24n) || (dynamic.get(0x6ffffffbn)?.[0] ?? 0n) !== 0n;

  const imports = [];
  const relaChunks = [];
  if (dt(7n) !== null) relaChunks.push([dt(7n), dt(8n)]);
  if (dt(23n) !== null) relaChunks.push([dt(23n), dt(2n)]);
  for (const [off, size] of relaChunks) {
    if (off === null || size === null) continue;
    for (let o = Number(off); o + 24 <= Number(off) + Number(size); o += 24) {
      const rOffset = u64(b, o);
      const info = u64(b, o + 8);
      const addend = i64(b, o + 16);
      const rtype = Number(info & 0xffffffffn);
      const symIdx = Number(info >> 32n);
      let name = null;
      if (symtabOff !== null && strtabOff !== null && symIdx > 0) {
        const so = Number(symtabOff) + symIdx * symEnt;
        if (so + 24 <= b.length) name = cstr(b, Number(strtabOff) + u32(b, so));
      }
      imports.push({ type: rtype, offset: rOffset, addend, name, symIdx, got: rtype === R_X86_64.JUMP_SLOT || rtype === R_X86_64.GLOB_DAT });
    }
  }
  const importNames = [...new Set(imports.map((i) => i.name).filter(Boolean))];

  return {
    format: "elf",
    classBits: 64,
    type,
    typeName: type === 1 ? "REL" : type === 2 ? "EXEC" : type === 3 ? "DYN" : `0x${type.toString(16)}`,
    machine,
    machineName: "x86-64",
    entry,
    phdrs,
    loads,
    sections,
    interp,
    hasInterp,
    isPie,
    execStack,
    relro,
    bindNow,
    needed,
    imports,
    importNames,
    rwxSegments: loads.filter((p) => (p.flags & 0x7) === 0x7).length,
    totalMemSize: loads.reduce((a, p) => a + Number(p.memsz), 0),
    fileSize: b.length,
  };
}

const PACKER_SECTION = /^(?:\.upx|upx|\.packed|\.petite|\.aspack|\.themida|\.vmp)/i;

/**
 * Static triage facts for an ELF64 image.
 * @param {Uint8Array} bytes
 * @param {{strings?:boolean, maxStrings?:number}} [opts]
 */
export function parseElfStatic(bytes, { strings = true, maxStrings = 256 } = {}) {
  const b = bytes instanceof Uint8Array ? bytes : Uint8Array.from(bytes);
  const elf = parseElf64(b);
  const secs = [];
  for (const s of elf.sections) {
    const size = Number(s.size);
    const off = Number(s.offset);
    const raw = size > 0 && off + size <= b.length ? b.subarray(off, off + size) : new Uint8Array(0);
    const exec = (s.flags & BigInt(SHF.EXEC)) !== 0n;
    const write = (s.flags & BigInt(SHF.WRITE)) !== 0n;
    const alloc = (s.flags & BigInt(SHF.ALLOC)) !== 0n;
    secs.push({
      name: s.name,
      type: s.type,
      size,
      addr: `0x${s.addr.toString(16)}`,
      exec,
      write,
      alloc,
      entropy: raw.length ? Number(shannonEntropy(raw).toFixed(3)) : 0,
    });
  }

  const anomalies = [];
  const packerHints = [];
  const add = (kind, detail) => anomalies.push({ kind, detail });
  for (const p of elf.loads) {
    if ((p.flags & 0x7) === 0x7) add("rwx_segment", `segment @0x${p.vaddr.toString(16)} is RWX`);
  }
  if (elf.execStack) add("exec_stack", "PT_GNU_STACK requests an executable stack");
  if (!elf.relro) add("no_relro", "no PT_GNU_RELRO (GOT writable)");
  if (!elf.bindNow) add("lazy_binding", "lazy PLT binding (GOT writable at runtime)");
  for (const s of secs) {
    if (s.exec && s.entropy > 7.2 && s.size > 0x400) add("high_entropy_code", `${s.name} entropy ${s.entropy}`);
    if (PACKER_SECTION.test(s.name)) {
      packerHints.push(s.name);
      add("packer_section", `${s.name} matches known packer naming`);
    }
  }
  const hasSymtab = elf.sections.some((s) => s.type === SHT.SYMTAB);
  const stripped = !hasSymtab;
  if (stripped) add("stripped", "no .symtab");
  if (elf.typeName === "REL") add("relocatable_object", "ET_REL kernel module / object file");
  if (!elf.needed.length && !elf.hasInterp) add("static_linked", "no NEEDED libs and no interpreter");

  const str = strings ? extractStrings(b, { maxStrings }) : null;
  const interesting = str?.interesting ?? [];
  const upx = interesting.some((s) => /^UPX!?/i.test(s.value)) || /UPX!/i.test(cstr(b, 0, Math.min(b.length, 4096)));
  if (upx) {
    packerHints.push("UPX!");
    add("packer_string", "UPX! signature string present");
  }
  const go = interesting.some((s) => s.value.includes("Go build ID") || /^go1\.\d/.test(s.value));
  const rustMarkers = interesting.some((s) => s.value.includes("rustc") || s.value.includes("RUST_BACKTRACE"));

  return {
    format: "elf",
    type: elf.typeName,
    machine: elf.machineName,
    isPie: elf.isPie,
    hasInterp: elf.hasInterp,
    interp: elf.interp,
    needed: elf.needed,
    importCount: elf.importNames.length,
    imports: elf.importNames,
    entry: `0x${elf.entry.toString(16)}`,
    rwxSegments: elf.rwxSegments,
    execStack: elf.execStack,
    relro: elf.relro,
    bindNow: elf.bindNow,
    stripped,
    sections: secs,
    anomalies,
    packerHints: [...new Set(packerHints)],
    ssdeep: ssdeep(b),
    goBinary: go,
    rustBinary: rustMarkers,
    strings: str ? { total: str.total, interesting: interesting.slice(0, 64) } : null,
    fileSize: b.length,
    totalMemSize: elf.totalMemSize,
  };
}

/** Dynamic tags that are safe to export (no BigInt keys). */
const DT_SAFE = {
  NEEDED: 1n, STRTAB: 5n, SYMTAB: 6n, RELA: 7n, RELASZ: 8n, JMPREL: 23n, BIND_NOW: 24n,
};

export { R_X86_64, PT, DT_SAFE as DT };
