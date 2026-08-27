/**
 * ELF32 relocatable parsing + Linux module staging (i386 buildroot track).
 *
 * The browser compile bridge produces real `clang --target=i386-linux-gnu -c`
 * output. Before shipping a module into the v86 guest we validate the object
 * (magic, machine, section sanity), extract defined/undefined symbols and
 * package it as a guest-ready file. Final kernel-side linking stays inside the
 * guest (buildroot ships gcc + insmod) — we stage, we don't fake.
 */

export class ElfError extends Error {}

const ELF_MAGIC = 0x464c457f; // \x7fELF as LE u32
const EM_386 = 3;
const ET_REL = 1;

const SHN_UNDEF = 0;
const SHT_SYMTAB = 2;
const SHT_NOBITS = 8;

const u16 = (b, o) => b[o] | (b[o + 1] << 8);
const u32 = (b, o) => (b[o] | (b[o + 1] << 8) | (b[o + 2] << 16) | (b[o + 3] << 24)) >>> 0;

/**
 * @param {Uint8Array} bytes raw .o bytes
 * @returns {ElfObject}
 * @typedef {object} ElfObject
 * @property {string} magic
 * @property {number} eiClass 1=32-bit
 * @property {number} eType ET_REL for relocatables
 * @property {number} eMachine EM_386 for the i386 track
 * @property {{name: string, type: number, size: number, data: Uint8Array|null}[]} sections
 * @property {{name: string, defined: boolean, value: number, size: number, section: number}[]} symbols
 */
export function parseElf(bytes) {
  if (bytes.length < 52) throw new ElfError("truncated: shorter than ELF header");
  if (u32(bytes, 0) !== ELF_MAGIC) throw new ElfError("bad magic: not an ELF file");
  const eiClass = bytes[4];
  const eType = u16(bytes, 16);
  const eMachine = u16(bytes, 18);
  const eShoff = u32(bytes, 32);
  const eShentsize = u16(bytes, 46);
  const eShnum = u16(bytes, 48);
  const eShstrndx = u16(bytes, 50);

  if (eShnum === 0 || !eShoff || !eShentsize) throw new ElfError("no section headers");

  const readSection = (i) => {
    const h = eShoff + i * eShentsize;
    return {
      shName: u32(bytes, h),
      shType: u32(bytes, h + 4),
      shOffset: u32(bytes, h + 16),
      shSize: u32(bytes, h + 20),
      shLink: u32(bytes, h + 24),
    };
  };

  const headers = [];
  for (let i = 0; i < eShnum; i++) headers.push(readSection(i));
  const strTabHdr = headers[eShstrndx];
  if (!strTabHdr) throw new ElfError("missing shstrtab");

  const cstr = (tabBase, off) => {
    let end = off;
    while (bytes[tabBase + end] !== 0) end++;
    let s = "";
    for (let i = off; i < end; i++) s += String.fromCharCode(bytes[tabBase + i]);
    return s;
  };
  const secName = (h) => cstr(strTabHdr.shOffset, h.shName);

  const sections = headers.map((h) => ({
    name: secName(h),
    type: h.shType,
    size: h.shSize,
    data: h.shType === SHT_NOBITS ? null : bytes.slice(h.shOffset, h.shOffset + h.shSize),
  }));

  // symbols live in the symtab; names in its linked strtab
  const symbols = [];
  const symIdx = headers.findIndex((h) => h.shType === SHT_SYMTAB);
  if (symIdx >= 0) {
    const symHdr = headers[symIdx];
    const strHdr = headers[symHdr.shLink];
    if (!strHdr) throw new ElfError("symtab without linked strtab");
    const count = Math.floor(symHdr.shSize / 16); // Elf32_Sym == 16 bytes
    for (let i = 0; i < count; i++) {
      const o = symHdr.shOffset + i * 16;
      const stName = u32(bytes, o);
      const stValue = u32(bytes, o + 4);
      const stSize = u32(bytes, o + 8);
      const stShndx = u16(bytes, o + 14);
      const name = cstr(strHdr.shOffset, stName);
      if (!name && stShndx === SHN_UNDEF) continue; // section symbols etc.
      symbols.push({
        name,
        defined: stShndx !== SHN_UNDEF,
        value: stValue,
        size: stSize,
        section: stShndx,
      });
    }
  }

  return {
    magic: "ELF",
    eiClass,
    eType,
    eMachine,
    sections,
    symbols,
  };
}

/** Assert an object is stageable as an i386 LKM. Returns the parse result. */
export function validateLinuxModule(bytes) {
  const elf = parseElf(bytes);
  if (elf.eiClass !== 1) throw new ElfError("not a 32-bit ELF — build with --target=i386-linux-gnu");
  if (elf.eMachine !== EM_386) throw new ElfError(`wrong machine 0x${elf.eMachine.toString(16)} — expected EM_386`);
  if (elf.eType !== ET_REL) throw new ElfError("not relocatable — compile with -c");
  const hasText = elf.sections.some((s) => s.name === ".text" && s.size > 0);
  if (!hasText) throw new ElfError("no .text section — is this a kernel module object?");
  return elf;
}

/**
 * Stage a validated module for guest delivery: returns the original bytes
 * plus analysis the lab UI prints (symbols to expect in /proc/kallsyms after
 * insmod). Guest-side make+insmod performs final linking.
 */
export function stageLinuxModule(bytes) {
  const elf = validateLinuxModule(bytes);
  return {
    bytes,
    globalSymbols: elf.symbols.filter((s) => s.defined).map((s) => s.name),
    undefinedSymbols: elf.symbols.filter((s) => !s.defined).map((s) => s.name),
    sections: elf.sections.filter((s) => s.size > 0).map((s) => ({ name: s.name, size: s.size })),
  };
}
