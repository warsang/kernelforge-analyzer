#!/usr/bin/env node
/**
 * Generates deterministic ELF64 fixtures for the linux-internals track (m24+).
 *
 * Outputs:
 *   apps/web/public/fixtures/elf/<name>.elf      binaries students can download
 *   apps/web/src/elf/fixtures.gen.mjs            embedded copies (base64 -> Uint8Array)
 *
 * Usage: node tools/gen-elf-fixtures.mjs
 */

import { mkdir, writeFile } from "node:fs/promises";
import path from "node:path";

const ROOT = new URL("..", import.meta.url).pathname;
const PUB = path.join(ROOT, "apps/web/public/fixtures/elf");
const GEN = path.join(ROOT, "apps/web/src/elf/fixtures.gen.mjs");

// --- byte helpers -----------------------------------------------------------

class Buf {
  constructor(size) {
    this.b = new Uint8Array(size);
    this.dv = new DataView(this.b.buffer);
  }
  u8(o, v) { this.dv.setUint8(o, v); return this; }
  u16(o, v) { this.dv.setUint16(o, v, true); return this; }
  u32(o, v) { this.dv.setUint32(o, v, true); return this; }
  u64(o, v) {
    this.dv.setBigUint64(o, typeof v === "bigint" ? v : BigInt(v), true);
    return this;
  }
  str(o, s) {
    for (let i = 0; i < s.length; i++) this.b[o + i] = s.charCodeAt(i);
    return this;
  }
}

const PT_LOAD = 1, PT_NOTE = 4;
const PF_X = 1, PF_W = 2, PF_R = 4;
const SHT_PROGBITS = 1, SHT_SYMTAB = 2, SHT_STRTAB = 3, SHT_NOTE = 7;
const STT_FUNC = 2, STT_OBJECT = 1, STB_GLOBAL = 1;

/** Elf64_Ehdr (64 bytes) */
function ehdr(b, o, { entry, phoff, shoff, flags = 0, ehsize = 64,
  phentsize = 56, phnum, shentsize = 64, shnum, shstrndx, ident }) {
  b.str(o, ident ?? "\x7fELF");
  b.u8(o + 4, 2);       // EI_CLASS = ELFCLASS64
  b.u8(o + 5, 1);       // EI_DATA  = ELFDATA2LSB
  b.u8(o + 6, 1);       // EI_VERSION
  b.u16(o + 16, 2);     // e_type = ET_EXEC
  b.u16(o + 18, 0x3e);  // e_machine = EM_X86_64
  b.u32(o + 20, 1);     // e_version
  b.u64(o + 24, entry);
  b.u64(o + 32, phoff);
  b.u64(o + 40, shoff);
  b.u32(o + 48, flags);
  b.u16(o + 52, ehsize);
  b.u16(o + 54, phentsize);
  b.u16(o + 56, phnum);
  b.u16(o + 58, shentsize);
  b.u16(o + 60, shnum);
  b.u16(o + 62, shstrndx);
}

/** Elf64_Phdr (56 bytes) */
function phdr(b, o, p) {
  b.u32(o, p.type);
  b.u32(o + 4, p.flags ?? 0);
  b.u64(o + 8, p.offset ?? 0);
  b.u64(o + 16, p.vaddr ?? 0);
  b.u64(o + 24, p.paddr ?? p.vaddr ?? 0);
  b.u64(o + 32, p.filesz ?? 0);
  b.u64(o + 40, p.memsz ?? p.filesz ?? 0);
  b.u64(o + 48, p.align ?? 0);
}

/** Elf64_Shdr (64 bytes) */
function shdr(b, o, s) {
  b.u32(o, s.name ?? 0);
  b.u32(o + 4, s.type ?? 0);
  b.u64(o + 8, s.flags ?? 0n);
  b.u64(o + 16, s.addr ?? 0);
  b.u64(o + 24, s.offset ?? 0);
  b.u64(o + 32, s.size ?? 0);
  b.u32(o + 40, s.link ?? 0);
  b.u32(o + 44, s.info ?? 0);
  b.u64(o + 48, s.addralign ?? 0);
  b.u64(o + 56, s.entsize ?? 0);
}

/** Elf64_Sym (24 bytes) */
function sym(b, o, s) {
  b.u32(o, s.name ?? 0);
  b.u8(o + 4, ((s.bind ?? 0) << 4) | (s.type ?? 0));
  b.u8(o + 5, 0); // st_other
  b.u16(o + 6, s.shndx ?? 0);
  b.u64(o + 8, s.value ?? 0);
  b.u64(o + 16, s.size ?? 0);
}

/** Build a strtab; returns {bytes, offs} */
function strtab(names) {
  const out = [0]; // offset 0 = empty
  const offs = {};
  for (const n of names) {
    offs[n] = out.length;
    for (let i = 0; i < n.length; i++) out.push(n.charCodeAt(i));
    out.push(0);
  }
  return { bytes: Uint8Array.from(out), offs };
}

// --- hello.elf: clean baseline ----------------------------------------------

function buildHello() {
  // fixed geometry
  const TEXT_OFF = 0x100, TEXT_ADDR = 0x400100;
  // vaddr ≡ offset (mod align): 0x600200 % 0x1000 == 0x200 % 0x1000
  const DATA_OFF = 0x200, DATA_ADDR = 0x600200;
  const NOTE_OFF = 0x220;
  const MSG = "hello tmpout\n";
  const SECRET = "kf-greet-ok";
  const text =
    // _start @ TEXT_ADDR
    [0x48, 0xc7, 0xc0, 0x01, 0x00, 0x00, 0x00, // mov rax,1 (write)
      0x48, 0xc7, 0xc7, 0x01, 0x00, 0x00, 0x00, // mov rdi,1
      0x48, 0xbe, ...u64le(DATA_ADDR),          // movabs rsi,msg
      0xba, MSG.length, 0x00, 0x00, 0x00,       // mov edx,13
      0x0f, 0x05,                               // syscall
      0x48, 0xc7, 0xc7, 42, 0x00, 0x00, 0x00,   // mov rdi,42
      0x48, 0xc7, 0xc0, 0x3c, 0x00, 0x00, 0x00, // mov rax,60
      0x0f, 0x05,                               // syscall
    ]
    // pad to TEXT_ADDR+0x30
    .concat(Array(TEXT_OFF + 0x30 - (TEXT_OFF + 47)).fill(0x90))
    // kf_greet @ TEXT_ADDR+0x30
    .concat([0x31, 0xc0, 0xc3]);                // xor eax,eax; ret

  const dataSize = MSG.length + SECRET.length;
  const note = (() => {
    const name = "KF\x00\x00"; // namesz includes NUL
    const b = new Buf(0x20);
    b.u32(0, 4); b.u32(4, 4); b.u32(8, 1); // namesz, descsz, type NT_VERSION-ish
    b.str(12, name); b.str(16, "tmp");      // desc "tmp"
    return b.b;
  })();

  const symnames = strtab(["_start", "kf_greet", "secret_msg"]);
  const secnames = strtab([
    ".text", ".data", ".symtab", ".strtab", ".note.kf", ".shstrtab",
  ]);
  const SYMTAB_OFF = 0x240;
  const syms = new Buf(24 * 4);
  sym(syms, 0, {});
  sym(syms, 24, { name: symnames.offs["_start"], bind: STB_GLOBAL, type: STT_FUNC, shndx: 1, value: TEXT_ADDR, size: 47 });
  sym(syms, 48, { name: symnames.offs["kf_greet"], bind: STB_GLOBAL, type: STT_FUNC, shndx: 1, value: TEXT_ADDR + 0x30, size: 3 });
  sym(syms, 72, { name: symnames.offs["secret_msg"], bind: STB_GLOBAL, type: STT_OBJECT, shndx: 2, value: DATA_ADDR + MSG.length, size: SECRET.length });

  const STRTAB_OFF = SYMTAB_OFF + syms.b.length;           // 0x270
  const NOTE_SIZE = note.length;                            // 0x20 (NOTE_OFF 0x220)
  const SECNAMES_OFF = STRTAB_OFF + symnames.bytes.length;  // 0x290ish
  const SHOFF = SECNAMES_OFF + secnames.bytes.length;

  const total = SHOFF + 64 * 6;
  const b = new Buf(total);
  ehdr(b, 0, {
    entry: TEXT_ADDR,
    phoff: 0x40,
    shoff: SHOFF,
    phnum: 3,
    shnum: 6,
    shstrndx: 5,
  });
  phdr(b, 0x40, {
    type: PT_LOAD, flags: PF_R | PF_X, offset: 0,
    vaddr: 0x400000, filesz: TEXT_OFF + text.length, memsz: TEXT_OFF + text.length, align: 0x1000,
  });
  phdr(b, 0x78, {
    type: PT_LOAD, flags: PF_R | PF_W, offset: DATA_OFF,
    vaddr: DATA_ADDR, filesz: dataSize, memsz: dataSize + 0x20, align: 0x1000,
  });
  phdr(b, 0xb0, {
    type: PT_NOTE, flags: PF_R, offset: NOTE_OFF,
    vaddr: 0, filesz: NOTE_SIZE, memsz: NOTE_SIZE, align: 4,
  });
  b.str(TEXT_OFF, String.fromCharCode(...text));
  b.str(DATA_OFF, MSG + SECRET);
  b.b.set(note, NOTE_OFF);
  b.b.set(syms.b, SYMTAB_OFF);
  b.b.set(symnames.bytes, STRTAB_OFF);
  b.b.set(secnames.bytes, SECNAMES_OFF);

  const se = SHOFF;
  shdr(b, se + 0 * 64, { type: 0 }); // NULL
  shdr(b, se + 1 * 64, {
    name: secnames.offs[".text"], type: SHT_PROGBITS, flags: 6n,
    addr: TEXT_ADDR, offset: TEXT_OFF, size: text.length, addralign: 16,
  });
  shdr(b, se + 2 * 64, {
    name: secnames.offs[".data"], type: SHT_PROGBITS, flags: 3n,
    addr: DATA_ADDR, offset: DATA_OFF, size: dataSize, addralign: 16,
  });
  shdr(b, se + 3 * 64, {
    name: secnames.offs[".symtab"], type: SHT_SYMTAB, flags: 0n,
    offset: SYMTAB_OFF, size: syms.b.length, link: 4, info: 1,
    addralign: 8, entsize: 24,
  });
  shdr(b, se + 4 * 64, {
    name: secnames.offs[".strtab"], type: SHT_STRTAB, flags: 0n,
    offset: STRTAB_OFF, size: symnames.bytes.length, addralign: 1,
  });
  shdr(b, se + 5 * 64, {
    name: secnames.offs[".shstrtab"], type: SHT_STRTAB, flags: 0n,
    offset: SECNAMES_OFF, size: secnames.bytes.length, addralign: 1,
  });
  // NOTE section omitted from shdrs (program-header-only consumers still see it)

  return { bytes: b.b, meta: { entry: TEXT_ADDR, greet: TEXT_ADDR + 0x30, secretAddr: DATA_ADDR + MSG.length } };
}

function u64le(v) {
  const out = [];
  let x = BigInt(v);
  for (let i = 0; i < 8; i++) { out.push(Number(x & 0xffn)); x >>= 8n; }
  return out;
}

// --- infected.elf: hello + PT_NOTE->PT_LOAD parasite -------------------------

function buildInfected() {
  const host = buildHello();
  const H = host.bytes.length;
  const PARASITE_VA = 0xc000000 + H; // Midrashim-style far VA
  const OEP = host.meta.entry;

  const MARKER = "KFPARASITE\n";
  const parasite = [
    ...[...MARKER].map((c) => c.charCodeAt(0)),
    0x48, 0xb8, ...u64le(OEP), // movabs rax, OEP
    0xff, 0xe0,                // jmp rax
  ];

  const b = new Buf(H + parasite.length);
  b.b.set(host.bytes, 0);
  b.str(H, String.fromCharCode(...parasite));

  // repurpose PT_NOTE (phdr #3 at 0xb0) into PT_LOAD covering the parasite
  phdr(b, 0xb0, {
    type: PT_LOAD, flags: PF_R | PF_X, offset: H,
    vaddr: PARASITE_VA, filesz: parasite.length, memsz: parasite.length,
    align: 0x200000,
  });
  b.u64(24, PARASITE_VA); // e_entry -> parasite

  return {
    bytes: b.b,
    meta: {
      oep: OEP,
      parasiteOffset: H,
      parasiteVa: PARASITE_VA,
      repurposedOriginalType: "PT_NOTE",
      marker: MARKER.trim(),
    },
  };
}

// --- weird.elf: extended-numbering parser stress -----------------------------

function buildWeird() {
  // Sections exist but e_shnum=0; real count lives in shdr[0].sh_size and
  // e_shstrndx=SHN_XINDEX (0xffff) with the real index in shdr[0].sh_link.
  // One section claims an offset past EOF; a SYMTAB has sh_entsize 0.
  const TRUE_SECTIONS = 6;
  const PAYLOAD_OFF = 0x100;
  const payload = new Uint8Array(0x80);
  payload[0] = 0xcc;

  const secnames = strtab(["", ".gone", ".past-eof", ".zerosym"]);
  const SHOFF = 0x200;
  const b = new Buf(SHOFF + 64 * TRUE_SECTIONS);
  ehdr(b, 0, {
    entry: 0x400080,
    phoff: 0x40,
    shoff: SHOFF,
    phnum: 1,
    shnum: 0,          // lie: extended numbering
    shstrndx: 0xffff,  // SHN_XINDEX
  });
  phdr(b, 0x40, {
    type: PT_LOAD, flags: PF_R | PF_X, offset: 0,
    vaddr: 0x400000, filesz: PAYLOAD_OFF + payload.length, memsz: PAYLOAD_OFF + payload.length, align: 0x1000,
  });
  b.b.set(payload, PAYLOAD_OFF);

  const se = SHOFF;
  const SECNAMES_OFF = se - secnames.bytes.length;
  b.b.set(secnames.bytes, SECNAMES_OFF);
  // shdr[0]: carries extended truth (sh_size = real count, sh_link = shstrndx)
  shdr(b, se, {
    type: 0, size: TRUE_SECTIONS, link: secnames.offs[""] === 0 ? 5 : 5, entsize: 0,
  });
  shdr(b, se + 1 * 64, {
    name: secnames.offs[".gone"], type: SHT_PROGBITS, addr: 0x400000,
    offset: 0, size: 0x10, flags: 6n, addralign: 16,
  });
  shdr(b, se + 2 * 64, {
    name: secnames.offs[".past-eof"], type: SHT_PROGBITS,
    offset: 0x90000, size: 0x40, flags: 2n, // way past EOF
  });
  shdr(b, se + 3 * 64, {
    name: 0, type: SHT_SYMTAB, offset: 0x300, size: 48,
    link: 5, entsize: 0, // division-by-zero hazard for naive parsers
  });
  shdr(b, se + 4 * 64, { name: secnames.offs[".zerosym"], type: SHT_STRTAB, offset: 0x300, size: 8 });
  shdr(b, se + 5 * 64, {
    name: 1, type: SHT_STRTAB, offset: SHOFF - secnames.bytes.length,
    size: secnames.bytes.length,
  });

  return {
    bytes: b.b,
    meta: { trueSections: TRUE_SECTIONS },
  };
}

// --- tiny.elf: 57 bytes, degenerate header (kernel-accepts form) -------------

function buildTiny() {
  // Mirrors the h4x.cz 57-byte construction: magic-only e_ident, ET_EXEC,
  // EM_X86_64, e_phoff=0 so the "Phdr" aliases the Ehdr itself (its p_type
  // reads as the ELF magic 0x464c457f, an unrecognized type the kernel's
  // loop skips). Trailing high bytes elided => 57 bytes total.
  const b = new Buf(57);
  b.str(0, "\x7fELF");
  b.u16(0x10, 2);       // ET_EXEC
  b.u16(0x12, 0x3e);    // EM_X86_64
  b.u32(0x14, 1);       // e_version
  b.u64(0x18, 0x58);    // e_entry (nominal)
  b.u64(0x20, 0);       // e_phoff = 0 -> phdr aliases ehdr
  b.u64(0x28, 0);       // e_shoff = 0
  b.u16(0x34, 64);      // e_ehsize
  b.u16(0x36, 56);      // e_phentsize
  b.u8(0x38, 1);        // e_phnum = 1 (high byte elided: file ends here)
  // e_shentsize/shnum/shstrndx live at 0x3a..0x3f -> elided (zero) in 57 bytes
  return {
    bytes: b.b,
    meta: { size: 57, entry: 0x58, phoff: 0, nominalPtype: "0x464c457f" },
  };
}

// --- emit --------------------------------------------------------------------

async function main() {
  await mkdir(PUB, { recursive: true });
  await mkdir(path.dirname(GEN), { recursive: true });

  const built = {
    hello: buildHello(),
    infected: buildInfected(),
    weird: buildWeird(),
    tiny: buildTiny(),
  };

  const lines = [
    "/**",
    " * GENERATED by tools/gen-elf-fixtures.mjs - deterministic ELF fixtures.",
    " * Do not edit by hand; regenerate with `node tools/gen-elf-fixtures.mjs`.",
    " */",
    "",
    "const b64 = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));",
    "",
  ];
  for (const [name, { bytes }] of Object.entries(built)) {
    const b64 = Buffer.from(bytes).toString("base64");
    lines.push(`export const ${name.toUpperCase()} = b64("${b64}");`);
  }
  lines.push(
    "",
    "export const FIXTURES = { hello: HELLO, infected: INFECTED, weird: WEIRD, tiny: TINY };",
    "",
  );
  await writeFile(GEN, lines.join("\n"));

  for (const [name, { bytes }] of Object.entries(built)) {
    await writeFile(path.join(PUB, `${name}.elf`), bytes);
  }

  // print pinned constants for flag authoring
  console.log("hello:", JSON.stringify(built.hello.meta));
  console.log("infected:", JSON.stringify(built.infected.meta));
  console.log("weird:", JSON.stringify(built.weird.meta));
  console.log("tiny:", JSON.stringify(built.tiny.meta));
}

main().catch((e) => { console.error(e); process.exit(1); });
