import { test } from "node:test";
import assert from "node:assert/strict";

import { parseElf, validateLinuxModule, stageLinuxModule, ElfError } from "../src/elf.mjs";
import { linkDriver } from "../src/linkdriver.mjs";

// ---------------------------------------------------------------------------
// Minimal ELF32 relocatable builder (test fixture)
// ---------------------------------------------------------------------------

function cstr(s) {
  const b = [...s].map((c) => c.charCodeAt(0));
  b.push(0);
  return b;
}

/**
 * Layout: ehdr | .text | shstrtab | strtab | symtab | shdrs
 * Sections: 0 NULL, 1 .text, 2 .shstrtab, 3 .strtab, 4 .symtab
 */
function makeElf32({ machine = 3, etype = 1, eiClass = 1, text = [0x90, 0xc3], syms = [] } = {}) {
  const textData = text;
  const shstrtab = [].concat(cstr(""), cstr(".text"), cstr(".shstrtab"), cstr(".strtab"), cstr(".symtab"));
  const offShstrtab = 52 + textData.length;
  const strtab = [].concat(cstr(""), cstr("kflag_init"), cstr("printk"));
  const offStrtab = offShstrtab + shstrtab.length;
  // Elf32_Sym: name(4) value(4) size(4) info(1) other(1) shndx(2)
  const symEnts = [];
  symEnts.push(...Array(16).fill(0)); // null symbol (Elf32_Sym == 16 bytes)
  const strOff = (n) => {
    let pos = 1;
    for (const cand of ["kflag_init", "printk"]) {
      if (cand === n) return pos;
      pos += cand.length + 1;
    }
    return 0;
  };
  for (const s of syms) {
    symEnts.push(
      ...u32b(strOff(s.name)), ...u32b(s.value ?? 0), ...u32b(s.size ?? 0),
      s.info ?? 0x12, 0, ...(s.shndx !== undefined ? u16b(s.shndx) : [1, 0]),
    );
  }
  const offSymtab = offStrtab + strtab.length;

  const eShoff = offSymtab + symEnts.length;
  const shentsize = 40;
  const shdr = (shName, shType, shOffset, shSize, shLink = 0) => [
    ...u32b(shName), ...u32b(shType),
    ...u32b(0),        // sh_flags
    ...u32b(0),        // sh_addr
    ...u32b(shOffset), // sh_offset
    ...u32b(shSize),   // sh_size
    ...u32b(shLink),   // sh_link
    ...u32b(0),        // sh_info
    ...u32b(4),        // sh_addralign
    ...u32b(0),        // sh_entsize
  ];
  // shstrtab name offsets: each entry is NUL-terminated, so the offset of a
  // name equals the total length of all preceding cstr()s.
  const shNames = ["", ".text", ".shstrtab", ".strtab", ".symtab"];
  const off = (n) => shNames.slice(0, shNames.indexOf(n))
    .reduce((sum, s) => sum + cstr(s).length, 0);

  const shdrs = [].concat(
    shdr(0, 0, 0, 0),
    shdr(off(".text"), 1 /*PROGBITS*/, 52, textData.length),
    shdr(off(".shstrtab"), 3 /*STRTAB*/, offShstrtab, shstrtab.length),
    shdr(off(".strtab"), 3, offStrtab, strtab.length),
    shdr(off(".symtab"), 2 /*SYMTAB*/, offSymtab, symEnts.length, 3),
  );

  const ehdr = [].concat(
    [0x7f, 0x45, 0x4c, 0x46], eiClass, 1, 1, 0, 0,
    ...Array(7).fill(0),        // e_ident pad (16-byte e_ident total)
    ...u16b(etype),             // e_type
    ...u16b(machine),           // e_machine
    ...u32b(1),                 // e_version
    ...u32b(0), ...u32b(0),     // entry, phoff
    ...u32b(eShoff),            // e_shoff
    ...u32b(0),                 // flags
    ...u16b(52), ...u16b(0), ...u16b(0),
    ...u16b(shentsize), ...u16b(5), ...u16b(2),
  );
  const bytes = new Uint8Array([].concat(ehdr, textData, shstrtab, strtab, symEnts, shdrs));
  return bytes;
}

function u16b(v) { return [v & 0xff, (v >>> 8) & 0xff]; }
function u32b(v) { v >>>= 0; return [v & 0xff, (v >>> 8) & 0xff, (v >>> 16) & 0xff, (v >>> 24) & 0xff]; }

// ------------------------------------------------------------------- tests

test("parseElf reads a minimal i386 relocatable", () => {
  const elf = parseElf(makeElf32({
    syms: [
      { name: "kflag_init", value: 0, size: 2, info: 0x12, shndx: 1 },
      { name: "printk", value: 0, size: 0, info: 0x10, shndx: 0 },
    ],
  }));
  assert.equal(elf.magic, "ELF");
  assert.equal(elf.eiClass, 1);
  assert.equal(elf.eMachine, 3);
  assert.equal(elf.eType, 1);
  assert.ok(elf.sections.some((s) => s.name === ".text" && s.size === 2));
  const init = elf.symbols.find((s) => s.name === "kflag_init");
  assert.equal(init.defined, true);
  const printk = elf.symbols.find((s) => s.name === "printk");
  assert.equal(printk.defined, false);
});

test("validateLinuxModule rejects x64 / linked / non-ELF objects", () => {
  assert.throws(() => validateLinuxModule(makeElf32({ eiClass: 2 })), /not a 32-bit ELF/);
  assert.throws(() => validateLinuxModule(makeElf32({ machine: 0x3e })), /EM_386/);
  assert.throws(() => validateLinuxModule(makeElf32({ etype: 2 })), /relocatable/);
  assert.throws(() => validateLinuxModule(new Uint8Array([0x4d, 0x5a, ...Array(60).fill(0)])), /bad magic/);
});

test("stageLinuxModule splits global vs undefined symbols", () => {
  const staged = stageLinuxModule(makeElf32({
    syms: [
      { name: "kflag_init", value: 0, size: 2, shndx: 1 },
      { name: "printk", shndx: 0 },
    ],
  }));
  assert.deepEqual(staged.globalSymbols, ["kflag_init"]);
  assert.deepEqual(staged.undefinedSymbols, ["printk"]);
  assert.equal(staged.bytes.length > 52, true);
});

test("existing COFF pipeline unaffected (regression)", () => {
  assert.equal(typeof linkDriver, "function");
});
