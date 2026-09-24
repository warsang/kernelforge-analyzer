/**
 * triage primitives: hashes, entropy, strings, static PE facts.
 */
import { test } from "node:test";
import assert from "node:assert/strict";

import { md5, sha256, shannonEntropy, extractStrings, parsePeStatic } from "../src/index.mjs";
import { PeBuilder } from "@kernelforge/ntsim/src/pebuilder.mjs";

test("md5/sha256 match known vectors", () => {
  const enc = new TextEncoder();
  assert.equal(md5(enc.encode("")), "d41d8cd98f00b204e9800998ecf8427e");
  assert.equal(md5(enc.encode("abc")), "900150983cd24fb0d6963f7d28e17f72");
  assert.equal(md5(enc.encode("The quick brown fox jumps over the lazy dog")), "9e107d9d372bb6826bd81d3542a419d6");
  assert.equal(sha256(enc.encode("abc")), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
});

test("shannon entropy is 0 for constant and 8 for uniform bytes", () => {
  assert.equal(shannonEntropy(new Uint8Array(1024).fill(0x41)), 0);
  const uniform = Uint8Array.from({ length: 256 }, (_, i) => i);
  assert.equal(Number(shannonEntropy(uniform).toFixed(3)), 8);
});

test("extractStrings finds ascii/utf16 and tags interesting kinds", () => {
  const ascii = "hello world http://evil.test/payload SOFTWARE\\Microsoft\\Windows";
  const wide = "C:\\Windows\\Temp\\x.dll";
  const bytes = new Uint8Array(ascii.length + wide.length * 2 + 4);
  for (let i = 0; i < ascii.length; i++) bytes[i] = ascii.charCodeAt(i);
  for (let i = 0; i < wide.length; i++) {
    bytes[ascii.length + i * 2] = wide.charCodeAt(i);
    bytes[ascii.length + i * 2 + 1] = 0;
  }
  const out = extractStrings(bytes, { minLength: 4 });
  assert.ok(out.ascii.some((s) => s.value.includes("hello world")));
  assert.ok(out.utf16.some((s) => s.value === wide));
  const kinds = new Set(out.interesting.map((s) => s.kind));
  assert.ok(kinds.has("url"));
  assert.ok(kinds.has("registry"));
  assert.ok(kinds.has("path"));
});

test("parsePeStatic extracts sections, imports and imphash", () => {
  const b = new PeBuilder();
  b.addSection(".text", new Uint8Array(0x200).fill(0x90), 0x60000020);
  b.addSection(".rdata", new Uint8Array(0x100).fill(0x41), 0x40000040);
  b.addImports([{ dll: "KERNEL32.dll", funcs: ["VirtualAllocEx", "WriteProcessMemory"] }]);
  const img = b.build(0x1000).image;
  const pe = parsePeStatic(img, { strings: true });
  assert.equal(pe.format, "pe");
  assert.equal(pe.is64, true);
  assert.equal(pe.machineName, "x64");
  assert.ok(pe.sections.length >= 2);
  const text = pe.sections.find((s) => s.name === ".text");
  assert.ok(text, JSON.stringify(pe.sections.map((s) => s.name)));
  assert.equal(pe.imports.length, 1);
  assert.deepEqual(pe.imports[0].functions, ["VirtualAllocEx", "WriteProcessMemory"]);
  assert.match(pe.imphash, /^[0-9a-f]{32}$/);
  assert.ok(pe.entrySection);
  assert.ok(Array.isArray(pe.anomalies));
  assert.ok(pe.strings);
});

test("parsePeStatic flags RWX sections, packer names and tiny import tables", () => {
  const b = new PeBuilder();
  b.addSection(".UPX0", new Uint8Array(0x2000).fill(0x41), 0xe0000060); // exec+write+code
  const img = b.build(0x1000).image;
  const pe = parsePeStatic(img);
  const kinds = new Set(pe.anomalies.map((a) => a.kind));
  assert.ok(kinds.has("rwx_section"), JSON.stringify(pe.anomalies));
  assert.ok(kinds.has("packer_section"));
  assert.ok(pe.packerHints.includes(".UPX0"));
});

test("parsePeStatic rejects non-PE input", () => {
  assert.throws(() => parsePeStatic(new Uint8Array(0x100)), /not a PE/);
});

// --- ssdeep (spamsum) ---
import { ssdeep, ssdeepCompare } from "../src/fuzzy/ssdeep.mjs";

test("ssdeep matches reference fuzzy_hash_buf vectors", () => {
  const enc = new TextEncoder();
  // Vectors generated with the reference ssdeep implementation (fuzzy.c).
  assert.equal(ssdeep(enc.encode("")), "3::");
  assert.equal(ssdeep(enc.encode("hello world")), "3:iKFSMPn:rJPn");
  assert.equal(ssdeep(enc.encode("The quick brown fox jumps over the lazy dog")), "3:FJKKIUKact:FHIGi");
  assert.equal(ssdeep(enc.encode("a".repeat(80))), "3:tjl:X");
  assert.equal(
    ssdeep(enc.encode("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")),
    "3:oW36Hm6Hm6Hm6Hmj:oW36Hm6Hm6Hm6Hmj");
});

test("ssdeep matches reference vectors across block sizes (xorshift buffers)", () => {
  // Generated with the reference C harness: xs = 0x12345678 + index, then
  // xorshift32 per byte (see /tmp harness in the port commit notes).
  const vectors = [
    [1, "3:i:i"],
    [7, "3:QJn:QJn"],
    [64, "3:gHba+NuELZ4Yk1ptn/nAdHZ5/n:PyuQGY2AFZ5/"],
    [255, "6:xFqOdZC2lB0RX72WR0WtKX+ZiVp7/KpSxebgu6zMrNX:CZRX73EX+CKgebdfrp"],
    [4096, "96:r6SNpcyywpkO0eJHibaGuHBzQLl4pSpMKEBaZhGks8gu:rNctwpke1j+l4cWNeLs8gu"],
    [65536, "1536:/gRQFkzyURLWO7MAPoQJfj8LM2CmQrGJkh4bntzQAGm:4mFrURb3B3Ns+tm"],
    [300000, "6144:gKWwTAz7E2RjYNHU6/MEnFOxgeRVI6hMIXJ3/ZOFOF2hvKAwVaSXAZzDGtM:5pcUosNHnRAxFirIXV/QreDX4kM"],
  ];
  vectors.forEach(([size, expected], index) => {
    let xs = (0x12345678 + index) >>> 0;
    const buf = new Uint8Array(size);
    for (let i = 0; i < size; i++) {
      xs = (xs ^ (xs << 13)) >>> 0;
      xs = (xs ^ (xs >>> 17)) >>> 0;
      xs = (xs ^ (xs << 5)) >>> 0;
      buf[i] = (xs >>> 24) & 0xff;
    }
    assert.equal(ssdeep(buf), expected, `size ${size}`);
  });
});

test("ssdeepCompare scores near-identical buffers higher than unrelated ones", () => {
  const enc = new TextEncoder();
  const base = "MZ" + "kernel driver payload ".repeat(400);
  const variant = base.replace("payload", "payloaX");
  const other = "completely different content ".repeat(400);
  const a = ssdeep(enc.encode(base));
  const b = ssdeep(enc.encode(variant));
  const c = ssdeep(enc.encode(other));
  const near = ssdeepCompare(a, b);
  const far = ssdeepCompare(a, c);
  assert.ok(near > far, `${near} should exceed ${far}`);
  assert.ok(near >= 60, `near similarity ${near}`);
});

// --- pure-JS rules engine ---
import { compileRule, parseCondition, scanRules, matchRuleIds } from "../src/rules.mjs";
import { KERNEL_DRIVER_RULES } from "../src/rules/kernel-driver.mjs";

const enc2 = new TextEncoder();
const utf16 = (s) => {
  const b = new Uint8Array(s.length * 2);
  for (let i = 0; i < s.length; i++) { b[i * 2] = s.charCodeAt(i) & 0xff; b[i * 2 + 1] = 0; }
  return b;
};

test("parseCondition supports the documented subset", () => {
  assert.deepEqual(parseCondition("any of them"), { t: "count", n: 1 });
  assert.deepEqual(parseCondition("3 of them"), { t: "count", n: 3 });
  assert.deepEqual(parseCondition("all of them"), { t: "all" });
  const ast = parseCondition("($a and not $b) or filesize > 1024");
  assert.equal(ast.t, "or");
  assert.equal(ast.left.t, "and");
  assert.equal(ast.left.right.t, "not");
  assert.deepEqual(ast.right, { t: "filesize", op: ">", value: 1024 });
  assert.throws(() => parseCondition("$a and"), /unexpected end/);
});

test("scanRules matches text, wide, nocase, hex-wildcard and regex strings", () => {
  const payload = new Uint8Array([
    ...enc2.encode("KdDebuggerEnabled"),
    ...utf16("PsLoadedModuleList"),
    ...utf16("InLoadOrderLinks"),
    ...enc2.encode("VMware Tools"),
    0x0f, 0x31,
    0xde, 0xad, 0xbe, 0xef,
  ]);
  const rules = [
    { id: "r_text", meta: {}, strings: [{ id: "$a", type: "text", value: "KdDebuggerEnabled" }], condition: "$a" },
    { id: "r_wide", meta: {}, strings: [{ id: "$a", type: "text", value: "PsLoadedModuleList", wide: true }], condition: "$a" },
    { id: "r_nocase", meta: {}, strings: [{ id: "$a", type: "text", value: "vmware tools", nocase: true }], condition: "$a" },
    { id: "r_hex", meta: {}, strings: [{ id: "$a", type: "hex", value: "0F 31" }], condition: "$a" },
    { id: "r_hexwild", meta: {}, strings: [{ id: "$a", type: "hex", value: "DE ?? BE ??" }], condition: "$a" },
    { id: "r_regex", meta: {}, strings: [{ id: "$a", type: "regex", value: "V[Mm]ware", nocase: true }], condition: "$a" },
    { id: "r_and", meta: {}, strings: [
      { id: "$a", type: "text", value: "PsLoadedModuleList", wide: true },
      { id: "$b", type: "text", value: "InLoadOrderLinks", wide: true },
    ], condition: "$a and $b" },
    { id: "r_missing", meta: {}, strings: [{ id: "$a", type: "text", value: "NotThereAtAll" }], condition: "$a" },
  ];
  const ids = matchRuleIds(payload, rules);
  assert.deepEqual(new Set(ids), new Set(["r_text", "r_wide", "r_nocase", "r_hex", "r_hexwild", "r_regex", "r_and"]));
  const out = scanRules(payload, rules);
  assert.equal(out.scanned, payload.length);
  const andMatch = out.matches.find((m) => m.id === "r_and");
  assert.equal(andMatch.strings.length, 2);
  assert.ok(andMatch.strings[0].offsets[0] > 0);
});

test("scanRules honours filesize and N-of-them conditions", () => {
  const buf = enc2.encode("alpha beta gamma");
  const rules = [
    { id: "r_n2", meta: {}, strings: [
      { id: "$a", type: "text", value: "alpha" },
      { id: "$b", type: "text", value: "beta" },
      { id: "$c", type: "text", value: "delta" },
    ], condition: "2 of them" },
    { id: "r_big", meta: {}, strings: [{ id: "$a", type: "text", value: "alpha" }], condition: "filesize > 1000" },
    { id: "r_small", meta: {}, strings: [{ id: "$a", type: "text", value: "alpha" }], condition: "filesize < 1000" },
  ];
  const ids = matchRuleIds(buf, rules);
  assert.deepEqual(new Set(ids), new Set(["r_n2", "r_small"]));
});

test("kernel rule pack flags anti-analysis and rootkit indicators", () => {
  const antiAnalysis = enc2.encode("KdDebuggerEnabled \0 MmGetSystemRoutineAddress \0 ZwTerminateProcess \0 UPX!");
  const ids = matchRuleIds(antiAnalysis, KERNEL_DRIVER_RULES);
  assert.ok(ids.includes("kf_kernel_debug_flags"));
  assert.ok(ids.includes("kf_dynamic_api_resolution"));
  assert.ok(ids.includes("kf_packer_artifacts"));

  const rootkit = utf16("PsLoadedModuleList\0InLoadOrderLinks\0KeServiceDescriptorTable\0ActiveProcessLinks");
  const rootIds = matchRuleIds(rootkit, KERNEL_DRIVER_RULES);
  assert.ok(rootIds.includes("kf_loaded_module_walk"));
  assert.ok(rootIds.includes("kf_ssdt_symbols"));
  assert.ok(rootIds.includes("kf_dkom_links"));

  const clean = enc2.encode("WDF driver for a USB printer \0 IoCreateDevice \0 WdfVersionBind");
  const cleanIds = matchRuleIds(clean, KERNEL_DRIVER_RULES);
  assert.ok(!cleanIds.includes("kf_dkom_links"));
  assert.ok(!cleanIds.includes("kf_ci_bypass"));
});

test("compileRule rejects malformed patterns", () => {
  assert.throws(() => compileRule({ id: "bad", strings: [{ id: "$a", type: "hex", value: "ZZ" }], condition: "$a" }), /bad hex token/);
  assert.throws(() => compileRule({ id: "bad", strings: [{ id: "$a", type: "regex", value: "(" }], condition: "$a" }), /bad regex/);
  assert.throws(() => compileRule({ id: "bad", strings: [{ type: "text", value: "x" }], condition: "$a" }), /string without id/);
});

// --- stack strings / API hashes / yara-x ---
import { extractStackStrings } from "../src/stackstrings.mjs";
import { detectApiHashes, ror13, buildApiHashTable, HASH_ALGOS } from "../src/apihash.mjs";
import { scanWithYaraX, normalizeYaraMatches } from "../src/yara.mjs";
import { KERNEL_DRIVER_YARA } from "../src/yara-packs.mjs";

test("extractStackStrings reconstructs byte-by-byte stack strings", () => {
  // mov byte ptr [rsp+8], 'h' ... for "https" then a NUL
  const word = "https";
  const code = [];
  for (let i = 0; i < word.length; i++) {
    code.push(0xc6, 0x44, 0x24, 0x08 + i, word.charCodeAt(i));
  }
  code.push(0xc6, 0x44, 0x24, 0x08 + word.length, 0);
  const out = extractStackStrings(new Uint8Array(code), { minLength: 4 });
  assert.ok(out.strings.some((s) => s.value === "https"), JSON.stringify(out));
  assert.ok(out.stores >= word.length);
});

test("extractStackStrings reconstructs dword stores", () => {
  // mov dword ptr [rsp+0x10], 0x6c6c6568 ("hell" little-endian)
  const bytes = new Uint8Array([0xc7, 0x44, 0x24, 0x10, 0x68, 0x65, 0x6c, 0x6c]);
  const out = extractStackStrings(bytes, { minLength: 4 });
  assert.ok(out.strings.some((s) => s.value === "hell"), JSON.stringify(out));
});

test("detectApiHashes finds ROR13/djb2/crc32/murmur3 constants", () => {
  const names = ["VirtualAlloc", "LoadLibraryA", "WinExec", "CreateFileA"];
  const buf = new Uint8Array(names.length * 8);
  const dv = new DataView(buf.buffer);
  names.forEach((n, i) => {
    dv.setUint32(i * 8, ror13(n), true);
    dv.setUint32(i * 8 + 4, HASH_ALGOS.djb2(n), true);
  });
  const { hits } = detectApiHashes(buf);
  const found = new Set(hits.map((h) => h.name));
  for (const n of names) assert.ok(found.has(n), `missing ${n}: ${JSON.stringify(hits)}`);
  assert.ok(hits.some((h) => h.algo === "ror13"));
  assert.ok(hits.some((h) => h.algo === "djb2"));
  // table sanity: distinct algorithms must not collide wholesale
  const table = buildApiHashTable(["A", "B"]);
  assert.notEqual(table.ror13.get(ror13("A")), table.ror13.get(ror13("B")));
});

test("scanWithYaraX compiles and scans with the real YARA-X engine", async () => {
  const enc = new TextEncoder();
  const payload = new Uint8Array([...enc.encode("junk KeServiceDescriptorTable junk")]);
  const res = await scanWithYaraX(payload, KERNEL_DRIVER_YARA);
  assert.ok(res, "yara-x should be available in Node");
  assert.equal(res.errors.length, 0);
  const matches = normalizeYaraMatches(res);
  assert.ok(matches.some((m) => m.id === "kf_ssdt_symbols"), JSON.stringify(matches));
  const clean = await scanWithYaraX(enc.encode("just a printer driver"), KERNEL_DRIVER_YARA);
  assert.equal(normalizeYaraMatches(clean).length, 0);
});
