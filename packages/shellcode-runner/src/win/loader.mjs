/**
 * loader.mjs — synthesized Windows x64 world for shellcode.
 *
 * TEB/PEB/PEB_LDR_DATA with walkable, circular module lists and
 * LDR_DATA_TABLE_ENTRY nodes (DllBase +0x30, BaseDllName +0x58,
 * InMemoryOrderLinks +0x10 so flink-0x10 = entry), plus synthetic
 * kernel32/ntdll PE images with real, alphabetically sorted export tables
 * (EAT / name-pointer / ordinal arrays). Entries are either
 * `mov rax, <thunk>; jmp rax` stubs into the Win32 thunk region, or real
 * `mov r10, rcx; mov eax, SSN; syscall; ret` stubs (so Hell's-Gate style
 * SSN scraping finds consistent numbers matching the SSN table).
 *
 * gs-segment overrides are not modeled by the JS interpreter, so
 * `gs:[0x60]` resolves to the literal address 0x60 — the PEB pointer lives
 * there (same trick as pe-runner's TEB seed).
 */

import { NT_SSNS, zwAlias } from "./syscalls.mjs";

export const TEB_BASE = 0x0n;
export const PEB_BASE = 0x1000n;
export const LDR_BASE = 0x2000n;
export const LDR_ENTRY_BASE = 0x3000n; // 3 entries x 0x100
export const PROCESS_PARAMS_BASE = 0x4000n;
export const PARAMS_BASE = 0x8000n; // paramBytes buffer (rcx/rx arg)
export const STRINGS_BASE = 0x9000n;

export const CODE_BASE = 0x0000000000400000n;
export const HEAP_BASE = 0x0000000002000000n;
export const HEAP_SIZE = 0x800000n;
export const STACK_BASE = 0x0000000010000000n;
export const STACK_SIZE = 0x40000n;
export const THUNK_BASE = 0x0000000060000000n;
export const THUNK_SLOT = 0x10n;
export const THUNK_REGION = 0x10000n;
export const NT_DLL_BASE = 0x0000000071000000n;
export const K32_DLL_BASE = 0x0000000072000000n;

/** Linux argv-convention scratch (see runShellcode): argc block + trampoline. */
export const ARGV_BASE = 0x00007ffff0000000n;
export const ARGV_STRINGS = ARGV_BASE + 0x1000n;
export const ARGC_VA = ARGV_BASE + 0x40n; // 16-aligned; argc lives here
export const TRAMP_VA = 0x0000000051000000n;

const u16le = (b, o, v) => { b[o] = v & 0xff; b[o + 1] = (v >>> 8) & 0xff; };
const u32le = (b, o, v) => {
  b[o] = v & 0xff; b[o + 1] = (v >>> 8) & 0xff;
  b[o + 2] = (v >>> 16) & 0xff; b[o + 3] = (v >>> 24) & 0xff;
};
const u64le = (b, o, v) => {
  let x = BigInt(v);
  for (let i = 0; i < 8; i++) { b[o + i] = Number(x & 0xffn); x >>= 8n; }
};
const align = (n, a) => (n + a - 1) & ~(a - 1);

/** `mov rax, <thunkVa>; jmp rax` — 12 bytes. */
export function buildThunkStub(thunkVa) {
  const s = new Uint8Array(12);
  s[0] = 0x48; s[1] = 0xb8;
  u64le(s, 2, thunkVa);
  s[10] = 0xff; s[11] = 0xe0;
  return s;
}

/** `mov r10, rcx; mov eax, <ssn>; syscall; ret` — 11 bytes (real ntdll shape). */
export function buildNtStub(ssn) {
  const s = new Uint8Array(11);
  s[0] = 0x4c; s[1] = 0x8b; s[2] = 0xd1;
  s[3] = 0xb8;
  u32le(s, 4, ssn >>> 0);
  s[8] = 0x0f; s[9] = 0x05;
  s[10] = 0xc3;
  return s;
}

/** All ntdll-shaped exports: Nt and Zw syscall stubs share SSNs via zwAlias. */
export function ntDllExports(thunkVaFor) {
  const out = [];
  for (const [name, ssn] of Object.entries(NT_SSNS)) {
    out.push({ name, stub: buildNtStub(ssn) });
    const zw = zwAlias(name);
    out.push({ name: zw, stub: buildNtStub(ssn) });
  }
  for (const rtl of ["RtlZeroMemory", "RtlMoveMemory", "RtlCopyMemory", "RtlFillMemory", "RtlCompareMemory", "RtlAllocateHeap", "RtlFreeHeap"]) {
    out.push({ name: rtl, stub: buildThunkStub(thunkVaFor(rtl)) });
  }
  return out;
}

/**
 * Build a flat synthetic PE32+ DLL image with a real, sorted export table.
 * Layout (RVA == file offset): headers 0x0-0x1FF, stubs at 0x1000 (".text"),
 * export dir + arrays + names in ".edata" right after.
 *
 * @param {object} mem SparseMemory
 * @param {{base: bigint, dllName: string, exports: Array<{name: string, stub: Uint8Array}>}} spec
 * @returns {{base: bigint, size: bigint, entryVa: bigint, exportsVa: Map<string, bigint>}}
 */
export function buildSyntheticDll(mem, { base, dllName, exports }) {
  const sorted = [...exports].sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));
  const n = sorted.length;

  const stubRva0 = 0x1000;
  const stubBytes = align(n * 16, 0x200);
  const edataRva = align(stubRva0 + stubBytes, 0x1000);

  // edata blob: export dir(0x28) | dll name | EAT | names | ords | name strings
  const dllNameBytes = dllName.length + 1;
  const eatOff = 0x28 + align(dllNameBytes, 4);
  const namesOff = eatOff + n * 4;
  const ordsOff = namesOff + n * 4;
  let strOff = ordsOff + align(n * 2, 4);
  const nameOffsets = [];
  for (const e of sorted) {
    nameOffsets.push(strOff);
    strOff += e.name.length + 1;
    strOff = align(strOff, 2);
  }
  const edataSize = align(strOff, 16);

  const img = new Uint8Array(edataRva + edataSize + 0x1000);
  // ---- DOS / NT / optional headers ----
  img[0] = 0x4d; img[1] = 0x5a;
  u32le(img, 0x3c, 0x80);
  img[0x80] = 0x50; img[0x81] = 0x45; // "PE\0\0"
  u16le(img, 0x84, 0x8664); // Machine = AMD64
  u16le(img, 0x86, 2); // NumberOfSections
  u16le(img, 0x94, 0xf0); // SizeOfOptionalHeader
  u16le(img, 0x96, 0x2022); // EXECUTABLE | LARGE_ADDRESS_AWARE | LINE_NUMS_STRIPPED
  const opt = 0x98;
  u16le(img, opt, 0x20b); // PE32+
  u32le(img, opt + 0x10, stubRva0); // AddressOfEntryPoint
  u32le(img, opt + 0x14, 0x1000); // BaseOfCode
  u64le(img, opt + 0x18, base); // ImageBase
  u32le(img, opt + 0x20, 0x1000); // SectionAlignment
  u32le(img, opt + 0x24, 0x200); // FileAlignment
  u16le(img, opt + 0x28, 6); // MajorOSVersion
  u16le(img, opt + 0x30, 6); // MajorSubsystemVersion
  const sizeOfImage = align(edataRva + edataSize, 0x1000);
  u32le(img, opt + 0x38, sizeOfImage);
  u32le(img, opt + 0x3c, 0x200); // SizeOfHeaders
  u16le(img, opt + 0x44, 3); // Subsystem = CUI
  u64le(img, opt + 0x48, 0x100000); // StackReserve
  u64le(img, opt + 0x50, 0x1000);
  u64le(img, opt + 0x58, 0x100000); // HeapReserve
  u64le(img, opt + 0x60, 0x1000);
  u32le(img, opt + 0x6c, 16); // NumberOfRvaAndSizes
  u32le(img, opt + 0x70, edataRva); // DataDirectory[0].Export RVA
  u32le(img, opt + 0x74, edataSize);

  // ---- section table (2 x 40 bytes at 0x188) ----
  const sec = 0x188;
  const putSection = (off, name, va, vsize, rawSize, rawPtr, chars) => {
    for (let i = 0; i < 8; i++) img[off + i] = name.charCodeAt(i) || 0;
    u32le(img, off + 8, vsize);
    u32le(img, off + 12, va);
    u32le(img, off + 16, rawSize);
    u32le(img, off + 20, rawPtr);
    u32le(img, off + 36, chars);
  };
  putSection(sec, ".text", 0x1000, n * 16, stubBytes, 0x1000, 0x60000020);
  putSection(sec + 40, ".edata", edataRva, edataSize, align(edataSize, 0x200), edataRva, 0x40000040);

  // ---- stubs (16-byte slots) ----
  const exportsVa = new Map();
  sorted.forEach((e, i) => {
    const rva = stubRva0 + i * 16;
    img.set(e.stub, rva);
    for (let j = e.stub.length; j < 16; j++) img[rva + j] = 0x90;
    exportsVa.set(e.name, base + BigInt(rva));
  });

  // ---- export directory ----
  const dir = edataRva;
  u32le(img, dir + 0x0c, edataRva + 0x28); // Name RVA
  u32le(img, dir + 0x10, 1); // Ordinal base
  u32le(img, dir + 0x14, n); // NumberOfFunctions
  u32le(img, dir + 0x18, n); // NumberOfNames
  u32le(img, dir + 0x1c, edataRva + eatOff); // AddressOfFunctions
  u32le(img, dir + 0x20, edataRva + namesOff); // AddressOfNames
  u32le(img, dir + 0x24, edataRva + ordsOff); // AddressOfNameOrdinals
  for (let i = 0; dllName[i]; i++) img[edataRva + 0x28 + i] = dllName.charCodeAt(i);
  img[edataRva + 0x28 + dllName.length] = 0;
  sorted.forEach((e, i) => {
    u32le(img, edataRva + eatOff + i * 4, stubRva0 + i * 16);
    u32le(img, edataRva + namesOff + i * 4, edataRva + nameOffsets[i]);
    u16le(img, edataRva + ordsOff + i * 2, i);
    for (let j = 0; j < e.name.length; j++) img[edataRva + nameOffsets[i] + j] = e.name.charCodeAt(j);
  });

  mem.write(base, img.subarray(0, Number(sizeOfImage)));
  return {
    base,
    size: BigInt(sizeOfImage),
    entryVa: base + BigInt(stubRva0),
    exportsVa,
  };
}

function wu16(mem, va, s) {
  const buf = new Uint8Array(s.length * 2 + 2);
  for (let i = 0; i < s.length; i++) {
    buf[i * 2] = s.charCodeAt(i) & 0xff;
    buf[i * 2 + 1] = s.charCodeAt(i) >> 8;
  }
  mem.write(va, buf);
}

/**
 * TEB (0x0) -> PEB (0x1000) -> PEB_LDR_DATA (0x2000) with three circular
 * lists over one LDR_DATA_TABLE_ENTRY per module (0x100 apart).
 *
 * @param {Array<{name: string, full: string, base: bigint, size: bigint}>} modules
 *   in walk order: [sample, ntdll.dll, kernel32.dll]
 */
export function seedTebPebLdr(mem, modules) {
  // ---- TEB (gs-override-free: fields at their literal offsets) ----
  mem.w64(TEB_BASE + 0x30n, TEB_BASE); // Self
  mem.w64(TEB_BASE + 0x60n, PEB_BASE); // PEB pointer (gs:[0x60] -> 0x60)

  // ---- PEB ----
  mem.write(PEB_BASE + 0x02n, new Uint8Array([0])); // BeingDebugged = 0
  mem.w64(PEB_BASE + 0x10n, modules[0]?.base ?? 0n); // ImageBaseAddress
  mem.w64(PEB_BASE + 0x18n, LDR_BASE); // Ldr
  mem.w64(PEB_BASE + 0x20n, PROCESS_PARAMS_BASE); // ProcessParameters
  mem.w32(PEB_BASE + 0xbcn, 0); // NtGlobalFlag = 0 (no debugger)

  // ---- RTL_USER_PROCESS_PARAMETERS (minimal) ----
  const pp = PROCESS_PARAMS_BASE;
  mem.w32(pp, 0x1000); // MaximumLength
  const full = modules[0]?.full ?? "C:\\kfsample\\sample.bin";
  const imgPathVa = STRINGS_BASE;
  wu16(mem, imgPathVa, full);
  wu16(mem, imgPathVa + 0x200n, full);
  mem.w16(pp + 0x60n, full.length * 2);
  mem.w16(pp + 0x62n, full.length * 2 + 2);
  mem.w64(pp + 0x68n, imgPathVa); // ImagePathName
  mem.w16(pp + 0x70n, full.length * 2);
  mem.w16(pp + 0x72n, full.length * 2 + 2);
  mem.w64(pp + 0x78n, imgPathVa + 0x200n); // CommandLine

  // ---- PEB_LDR_DATA ----
  mem.w32(LDR_BASE, 0x48); // Length
  mem.write(LDR_BASE + 0x08n, new Uint8Array([1])); // Initialized
  const heads = {
    load: LDR_BASE + 0x10n,
    mem: LDR_BASE + 0x20n,
    init: LDR_BASE + 0x30n,
  };

  // ---- entries ----
  let strVa = STRINGS_BASE + 0x400n;
  const entries = modules.map((m, i) => {
    const e = LDR_ENTRY_BASE + BigInt(i) * 0x100n;
    mem.w64(e + 0x30n, m.base); // DllBase
    mem.w64(e + 0x38n, m.base); // EntryPoint
    mem.w32(e + 0x40n, Number(m.size & 0xffffffffn)); // SizeOfImage
    // FullDllName @+0x48 (UNICODE_STRING), BaseDllName @+0x58
    wu16(mem, strVa, m.full);
    mem.w16(e + 0x48n, m.full.length * 2);
    mem.w16(e + 0x4an, m.full.length * 2 + 2);
    mem.w64(e + 0x50n, strVa);
    strVa += BigInt(m.full.length * 2 + 2);
    wu16(mem, strVa, m.name);
    mem.w16(e + 0x58n, m.name.length * 2);
    mem.w16(e + 0x5an, m.name.length * 2 + 2);
    mem.w64(e + 0x60n, strVa);
    strVa += BigInt(m.name.length * 2 + 2);
    return e;
  });

  // circular lists: link at +0x00 (load), +0x10 (mem), +0x20 (init)
  for (const [key, linkOff] of [["load", 0x00n], ["mem", 0x10n], ["init", 0x20n]]) {
    const head = heads[key];
    const link = (e) => e + linkOff;
    entries.forEach((e, i) => {
      const prev = i === 0 ? head : link(entries[i - 1]);
      const next = i === entries.length - 1 ? head : link(entries[i + 1]);
      mem.w64(link(e), next); // Flink
      mem.w64(link(e) + 8n, prev); // Blink
    });
    mem.w64(head, link(entries[0])); // head.Flink
    mem.w64(head + 8n, link(entries[entries.length - 1])); // head.Blink
  }
  return entries.map((e, i) => ({ entry: e, name: modules[i].name, base: modules[i].base }));
}
