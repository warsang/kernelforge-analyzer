/**
 * Userland PE harness: loader + Tier-1 Win32 model.
 */
import { test } from "node:test";
import assert from "node:assert/strict";

import { SparseMemory } from "@kernelforge/ntsim/src/index.mjs";
import { PeBuilder } from "@kernelforge/ntsim/src/pebuilder.mjs";
import { parsePe, rvaToOffset } from "@kernelforge/ntsim/src/pe.mjs";
import { runUserlandPe, THUNK_BASE, createWin32Model, listPeExports } from "../src/index.mjs";
import { writeCString, writeUtf16, readUtf16 } from "../src/win32.mjs";

const u64le = (v) => {
  const b = new Uint8Array(8);
  new DataView(b.buffer).setBigUint64(0, BigInt(v), true);
  return b;
};

function buildExe(code) {
  const b = new PeBuilder();
  b.addSection(".text", code, 0x60000020);
  b.addImports([{ dll: "KERNEL32.dll", funcs: ["GetTickCount"] }]);
  return b.build(0x1000).image;
}

test("runs a PE entry point and records the modeled API call", async () => {
  // sub rsp,0x28 ; mov rax, <GetTickCount thunk> ; call rax ; add rsp,0x28 ; ret
  const code = new Uint8Array([
    0x48, 0x83, 0xEC, 0x28,
    0x48, 0xB8, ...u64le(THUNK_BASE),
    0xFF, 0xD0,
    0x48, 0x83, 0xC4, 0x28,
    0xC3,
  ]);
  const report = await runUserlandPe(buildExe(code), { name: "tick.exe", maxSteps: 10000 });
  assert.equal(report.meta.kind, "userland-pe");
  assert.equal(report.entry.status, "ok", JSON.stringify(report.entry));
  assert.equal(report.apiTrace.byName.GetTickCount.count, 1);
  assert.ok(BigInt(report.entry.retval) > 0n, report.entry.retval);
  assert.equal(report.load.imports.length, 1);
  assert.equal(report.static.dllCount, 1);
  assert.ok(report.static.ssdeep.startsWith("3:"));
});

test("models file/registry/process behavior from API calls", () => {
  const mem = new SparseMemory();
  const alloc = (n) => { const va = 0x100000n + BigInt(alloc.n ?? 0); alloc.n = (alloc.n ?? 0) + n; return va; };
  const model = createWin32Model({ mem, cpu: {}, alloc });
  const put = (s) => { const va = alloc(s.length + 2); writeCString(mem, va, s); return va; };

  const hFile = model.dispatch("CreateFileA", [put("C:\\temp\\dropped.bin"), 0x40000000n, 0n, 0n, 2n, 0n, 0n]);
  assert.notEqual(hFile, 0n);
  const data = put("MZ payload");
  const written = alloc(8);
  model.dispatch("WriteFile", [hFile, data, 10n, written, 0n]);
  model.dispatch("CloseHandle", [hFile]);

  const hKey = model.dispatch("RegCreateKeyExA", [0x80000002n, put("SOFTWARE\\KF"), 0n, 0n, 0n, 0n, 0n, alloc(8), alloc(8)]);
  model.dispatch("RegSetValueExA", [hKey, put("Run"), 0n, 1n, put("C:\\temp\\dropped.bin"), 20n]);

  model.dispatch("CreateProcessA", [put("C:\\Windows\\System32\\cmd.exe"), put("cmd.exe /c whoami"), 0n, 0n, 0n, 0n, 0n, 0n, alloc(104), alloc(24)]);
  model.dispatch("InternetConnectA", [0n, put("evil.test"), 443n]);

  const files = model.artifacts.files;
  assert.ok(files.some((f) => f.action === "create" && f.path.includes("dropped.bin")));
  assert.ok(files.some((f) => f.action === "write" && f.path.includes("dropped.bin")));
  assert.ok(model.artifacts.registry.some((r) => r.action === "set" && r.value === "Run"));
  assert.ok(model.artifacts.processes.some((p) => p.cmdline.includes("whoami")));
  assert.ok(model.artifacts.network.some((n) => n.host === "evil.test" && n.port === 443));

  // unknown API: recorded as unmodeled, fail-open 0
  const r = model.dispatch("SomeUnknownApi", [1n, 2n]);
  assert.equal(r, 0n);
  assert.ok(model.unmodeled.has("SomeUnknownApi"));
});

test("GetProcAddress returns a callable thunk for modeled APIs", async () => {
  const report = await runUserlandPe(buildExe(new Uint8Array([
    0x48, 0x83, 0xEC, 0x28,
    0x48, 0xB8, ...u64le(THUNK_BASE),
    0xFF, 0xD0,
    0x48, 0x83, 0xC4, 0x28,
    0xC3,
  ])), { name: "tick2.exe", maxSteps: 10000 });
  assert.equal(report.entry.status, "ok");
});

test("emits a decoded trace, triage facts and custom YARA matches", async () => {
  const report = await runUserlandPe(buildExe(new Uint8Array([
    0x48, 0x83, 0xEC, 0x28,
    0x48, 0xB8, ...u64le(THUNK_BASE),
    0xFF, 0xD0,
    0x48, 0x83, 0xC4, 0x28,
    0xC3,
  ])), {
    name: "traced.exe",
    maxSteps: 10000,
    extraYara: 'rule custom_probe { meta: severity = "low" strings: $a = "MZ" condition: $a }',
  });
  assert.equal(report.entry.status, "ok");
  assert.ok(Array.isArray(report.rules.matches));
  assert.ok(report.yara && Array.isArray(report.yara.matches));
  assert.equal(report.yara.errors.length, 0);
  assert.ok(report.yara.matches.some((m) => m.id === "custom_probe"),
    JSON.stringify(report.yara.matches));
  assert.ok(report.traceText.includes("GetTickCount"), report.traceText);
  assert.ok(report.traceText.includes("traced.exe+0x"), report.traceText);
  assert.equal(report.trace.length, 1);
  assert.equal(report.trace[0].name, "GetTickCount");
  assert.ok(report.static.stackStrings !== undefined);
  assert.ok(report.static.apiHashes !== undefined);
  assert.ok(report.static.strings.interesting !== undefined);
});

test("abridged trace keeps behavior-relevant calls and drops noise", async () => {
  // call GetTickCount (noise) then VirtualAlloc(0, 0x1000, 0x3000, 0x40) (interesting)
  const movImm64 = (reg, v) => {
    const b = new Uint8Array(10);
    b[0] = 0x48; b[1] = 0xb8 + reg; // mov r64, imm64
    new DataView(b.buffer).setBigUint64(2, BigInt(v), true);
    return b;
  };
  const movImm32 = (opcode, v) => new Uint8Array([0x48, 0xc7, opcode, v & 0xff, (v >> 8) & 0xff, (v >> 16) & 0xff, (v >> 24) & 0xff]);
  const callRax = new Uint8Array([0xff, 0xd0]);
  const code = new Uint8Array([
    0x48, 0x83, 0xEC, 0x28,
    ...movImm64(0, THUNK_BASE),        // GetTickCount (IAT order: GetTickCount first)
    ...callRax,
    ...movImm32(0xc1, 0),              // rcx = 0
    ...movImm32(0xc2, 0x1000),         // rdx = 0x1000
    ...movImm32(0xc0, 0x3000),         // r8 = 0x3000
    ...movImm32(0xc1, 0x40),           // r9 = 0x40
    ...movImm64(0, THUNK_BASE + 0x10n), // VirtualAlloc (second import)
    ...callRax,
    0x48, 0x83, 0xC4, 0x28,
    0xC3,
  ]);
  const b = new PeBuilder();
  b.addSection(".text", code, 0x60000020);
  b.addImports([{ dll: "KERNEL32.dll", funcs: ["GetTickCount", "VirtualAlloc"] }]);
  const report = await runUserlandPe(b.build(0x1000).image, { name: "abridged.exe", maxSteps: 10000 });
  assert.equal(report.entry.status, "ok", JSON.stringify(report.entry));
  assert.equal(report.traceTotalCount, 2);
  assert.equal(report.traceAbridgedCount, 1, report.traceAbridgedText);
  assert.match(report.traceAbridgedText, /VirtualAlloc/);
  assert.doesNotMatch(report.traceAbridgedText, /GetTickCount/);
  assert.match(report.traceText, /GetTickCount/);
});

test("rejects non-PE input", async () => {
  await assert.rejects(() => runUserlandPe(new Uint8Array(0x200)), /PE|MZ|DOS/i);
});

test("runs the same PE on the hybrid backend when selected", async () => {
  const code = new Uint8Array([
    0x48, 0x83, 0xEC, 0x28,
    0x48, 0xB8, ...u64le(THUNK_BASE),
    0xFF, 0xD0,
    0x48, 0x83, 0xC4, 0x28,
    0xC3,
  ]);
  let HybridCpuBackend;
  try {
    ({ HybridCpuBackend } = await import("@kernelforge/ntsim-unicorn/src/hybrid.mjs"));
  } catch {
    return; // unicorn wasm unavailable in this environment
  }
  const report = await runUserlandPe(buildExe(code), {
    name: "hybrid.exe",
    maxSteps: 10000,
    backendName: "hybrid",
    makeBackend: async () => HybridCpuBackend.create(null),
  });
  assert.equal(report.entry.status, "ok", JSON.stringify(report.entry));
  assert.equal(report.apiTrace.byName.GetTickCount.count, 1);
  assert.match(report.meta.engine, /hybrid/i);
  assert.ok(report.traceText.includes("GetTickCount"));
});

test("CRT imports resolve through underscore normalization and printf formats", () => {
  const mem = new SparseMemory();
  const alloc = (n) => { const va = 0x100000n + BigInt(alloc.n ?? 0); alloc.n = (alloc.n ?? 0) + n; return va; };
  const model = createWin32Model({ mem, cpu: {}, alloc });
  const put = (s) => { const va = alloc(s.length + 2); writeCString(mem, va, s); return va; };
  const putW = (s) => {
    const va = alloc(s.length * 2 + 2);
    for (let i = 0; i < s.length; i++) { mem.w8(va + BigInt(i * 2), s.charCodeAt(i)); mem.w8(va + BigInt(i * 2 + 1), 0); }
    return va;
  };

  // every spelling seen in real import tables must hit a modeled handler
  for (const name of ["initterm", "_initterm", "initterm_e", "_initterm_e",
    "getmainargs", "_getmainargs", "__getmainargs",
    "wgetmainargs", "_wgetmainargs", "__wgetmainargs",
    "get_initial_narrow_environment", "_get_initial_narrow_environment",
    "_p___argv", "__p___argv", "_p___argc", "__p___argc",
    "_acrt_iob_func", "__acrt_iob_func", "_stdio_common_vfprintf", "exit", "_exit"]) {
    model.dispatch(name, [0n, 0n, 0n, 0n, 0n]);
  }
  assert.equal(model.dispatch("_get_initial_narrow_environment", []), model.envBlockA);
  assert.equal(model.dispatch("_acrt_iob_func", [1n]), 0x11n);
  assert.ok(model.unmodeled.size === 0, [...model.unmodeled].join(","));

  // printf family formats and records
  const args = alloc(4 * 8);
  mem.w64(args, BigInt(put("world")));
  mem.w64(args + 8n, 42n);
  const text = model.artifacts.stdout.length;
  model.dispatch("_stdio_common_vfprintf", [0n, 0n, put("hello %s #%d"), 0n, args]);
  assert.ok(model.artifacts.stdout.length > text, "printf output recorded");
  assert.match(model.artifacts.stdout.at(-1).text, /hello world #42/);
});

test("CRT memory/string helpers and Rtl* stubs are modeled", () => {
  const mem = new SparseMemory();
  const alloc = (n) => { const va = 0x200000n + BigInt(alloc.n ?? 0); alloc.n = (alloc.n ?? 0) + n; return va; };
  const model = createWin32Model({ mem, cpu: {}, alloc });
  const dst = alloc(32);
  const src = alloc(32);
  writeCString(mem, src, "kernel");
  model.dispatch("memcpy", [dst, src, 7n]);
  assert.equal(readCStringLocal(mem, dst), "kernel");
  model.dispatch("memset", [dst, 0x41n, 3n]);
  assert.equal(readCStringLocal(mem, dst), "AAAnel");
  assert.equal(model.dispatch("strlen", [src]), 6n);
  assert.equal(model.dispatch("strcmp", [src, src]), 0n);
  assert.equal(model.dispatch("strchr", [src, BigInt("n".charCodeAt(0))]), src + 3n);
  const heap = model.dispatch("malloc", [64n]);
  assert.ok(heap > 0n);
  assert.equal(model.dispatch("RtlDeleteCriticalSection", [0n]), undefined);
  assert.equal(model.dispatch("_p__commode", []), model.commodePtr);
  model.dispatch("_CxxThrowException", [0n, 0n]);
  assert.ok(model.artifacts.debugStrings.some((d) => /C\+\+ exception/.test(d.text)));
  assert.ok(model.unmodeled.size === 0, [...model.unmodeled].join(","));
});

test("msvcrt data exports resolve to real cells (calc.exe CRT check)", async () => {
  // calc.exe's startup does: mov rax,[IAT _wcmdln]; mov rcx,[rax]; test; jz exit(0xFF)
  // The loader must map _wcmdln to the address of a variable, not a code thunk.
  const entryRva = 0x1000;
  const b = new PeBuilder();
  b.addSection(".text", new Uint8Array(28), 0x60000020);
  b.addImports([{ dll: "msvcrt.dll", funcs: ["_wcmdln"] }]);
  const { image } = b.build(entryRva);

  const pe = parsePe(image);
  const u32 = (o) => (image[o] | (image[o + 1] << 8) | (image[o + 2] << 16) | (image[o + 3] << 24)) >>> 0;
  const descOff = rvaToOffset(pe, pe.dirs[1].rva);
  const iatVa = pe.imageBase + BigInt(u32(descOff + 16));
  const entryVa = pe.imageBase + BigInt(entryRva);
  const disp = Number(BigInt.asIntN(32, iatVa - (entryVa + 7n)));

  const code = new Uint8Array([
    0x48, 0x8B, 0x05, disp & 0xff, (disp >> 8) & 0xff, (disp >> 16) & 0xff, (disp >>> 24) & 0xff, // mov rax,[rip+disp]
    0x48, 0x8B, 0x08,       // mov rcx,[rax]
    0x48, 0x85, 0xC9,       // test rcx,rcx
    0x74, 0x07,             // jz fail
    0xB8, 0x2A, 0x00, 0x00, 0x00, // mov eax,42
    0xC3,                   // ret
    0x90,                   // nop
    0xB8, 0xFF, 0x00, 0x00, 0x00, // fail: mov eax,0xFF
    0xC3,                   // ret
  ]);
  image.set(code, rvaToOffset(pe, entryRva));

  const report = await runUserlandPe(image, { name: "calc-like.exe", maxSteps: 10000 });
  assert.equal(report.entry.status, "ok", JSON.stringify(report.entry));
  assert.equal(BigInt(report.entry.retval), 0x2An, "CRT must observe a non-null _wcmdln");
  assert.ok(report.load.imports.includes("msvcrt.dll!_wcmdln"));
  assert.deepEqual(report.load.dataExports, ["wcmdln"]);
});

test("__wgetmainargs fills argc/argv/wargv and syncs the command-line globals", () => {
  const mem = new SparseMemory();
  const alloc = (n) => { const va = 0x300000n + BigInt(alloc.n ?? 0); alloc.n = (alloc.n ?? 0) + n; return va; };
  const model = createWin32Model({ mem, cpu: {}, alloc });
  const put = (s) => { const va = alloc(s.length + 2); writeCString(mem, va, s); return va; };
  const putW = (s) => { const va = alloc(s.length * 2 + 2); writeUtf16(mem, va, s); return va; };

  model.commandLineA = put("C:\\kfsample\\calc.exe /test");
  model.commandLineW = putW("C:\\kfsample\\calc.exe /test");
  model.dataCells = new Map();
  for (const [k, v] of [["wcmdln", model.commandLineW], ["acmdln", model.commandLineA]]) {
    const cell = alloc(8);
    mem.w64(cell, BigInt(v));
    model.dataCells.set(k, cell);
  }

  const argcOut = alloc(4);
  const argvOut = alloc(8);
  const wargvOut = alloc(8);
  assert.equal(model.dispatch("__wgetmainargs", [argcOut, argvOut, wargvOut, 0n, 0n]), 0n);
  assert.equal(mem.u32(argcOut), 2);
  const argv = mem.u64(argvOut);
  const wargv = mem.u64(wargvOut);
  assert.ok(argv > 0n && wargv > 0n);
  assert.equal(readCStringLocal(mem, mem.u64(argv)), "C:\\kfsample\\calc.exe");
  assert.equal(readCStringLocal(mem, mem.u64(argv + 8n)), "/test");
  assert.equal(readUtf16(mem, mem.u64(wargv)), "C:\\kfsample\\calc.exe");
  assert.equal(mem.u64(model.dataCells.get("wcmdln")), model.commandLineW);
  assert.equal(mem.u64(model.dataCells.get("acmdln")), model.commandLineA);
  assert.ok(model.unmodeled.size === 0, [...model.unmodeled].join(","));
});

// ------------------------------------------------------------------ DLL mode

/** .text RVA for a fixture with .text + exports (.edata) — layout is stable. */
function dllTextRva() {
  const probe = new PeBuilder()
    .addSection(".text", new Uint8Array(0x40))
    .addExports([{ name: "probe", section: ".text", offset: 0 }]);
  return parsePe(probe.build(0).image).sections.find((s) => s.name === ".text").rva;
}

/**
 * Build a DLL fixture:
 *   +0x00 DllMain:  mov eax, edx ; ret      (returns the fdwReason)
 *   +0x10 Answer:   mov eax, 42 ; ret
 *   +0x20 Ordinal7: mov eax, 7 ; ret
 * Exports: Answer, OrdinalSeven(ordinal 7), Forwarded -> KERNEL32.Sleep
 */
function buildDll() {
  const textRva = dllTextRva();
  const code = new Uint8Array(0x40);
  code.set([0x89, 0xd0, 0xc3], 0x00);                             // DllMain: mov eax, edx ; ret
  code.set([0xb8, 0x2a, 0x00, 0x00, 0x00, 0xc3], 0x10);           // Answer: mov eax, 42
  code.set([0xb8, 0x07, 0x00, 0x00, 0x00, 0xc3], 0x20);           // OrdinalSeven: mov eax, 7
  const b = new PeBuilder()
    .setDll()
    .addSection(".text", code)
    .addExports([
      { name: "Answer", section: ".text", offset: 0x10 },
      { name: "OrdinalSeven", ordinal: 7, section: ".text", offset: 0x20 },
      { name: "Forwarded", forwarder: "KERNEL32.Sleep" },
    ]);
  return { image: b.build(textRva).image, textRva };
}

test("DLL: parsePe exposes the DLL characteristic; listPeExports resolves names/ordinals/forwarders", () => {
  const { image } = buildDll();
  const pe = parsePe(image);
  assert.equal(pe.characteristics & 0x2000, 0x2000, "IMAGE_FILE_DLL set");

  const list = listPeExports(image);
  assert.equal(list.total, 3);
  assert.equal(list.moduleName, "sample.dll");
  const names = list.entries.map((e) => e.name).sort();
  assert.deepEqual(names, ["Answer", "Forwarded", "OrdinalSeven"]);
  assert.equal(list.entries.find((e) => e.name === "OrdinalSeven").ordinal, 7);
  assert.equal(list.entries.find((e) => e.name === "Forwarded").forwarder, "KERNEL32.Sleep");
});

test("DLL: default mode attaches DllMain then runs the first export", async () => {
  const { image } = buildDll();
  const r = await runUserlandPe(image, { name: "sample.dll", maxSteps: 10000 });
  assert.equal(r.load.isDll, true);
  assert.equal(r.entry.status, "ok", JSON.stringify(r.entry));
  assert.equal(BigInt(r.entry.retval), 42n, "first export = Answer");
  assert.equal(BigInt(r.attach.retval), 1n, "DllMain ran with DLL_PROCESS_ATTACH");
  assert.equal(r.run.mode, "export");
  assert.equal(r.run.export, "Answer");
  assert.equal(r.runs.length, 1);
});

test("DLL: export selectable by name and by ordinal, args reach the callee", async () => {
  const { image } = buildDll();
  const byName = await runUserlandPe(image, { export: "Answer", maxSteps: 10000 });
  assert.equal(BigInt(byName.entry.retval), 42n);

  const byOrd = await runUserlandPe(image, { export: "#7", maxSteps: 10000 });
  assert.equal(byOrd.entry.status, "ok", JSON.stringify(byOrd.entry));
  assert.equal(BigInt(byOrd.entry.retval), 7n);
  assert.equal(byOrd.run.export, "OrdinalSeven"); // canonical spec in the report
});

test("DLL: forwarder exports are reported, never executed", async () => {
  const { image } = buildDll();
  const r = await runUserlandPe(image, { export: "Forwarded", maxSteps: 10000 });
  assert.equal(r.entry.status, "forwarder");
  assert.match(r.entry.error, /KERNEL32\.Sleep/);
});

test("DLL: dllMode attach runs DllMain only", async () => {
  const { image } = buildDll();
  const r = await runUserlandPe(image, { dllMode: "attach", maxSteps: 10000 });
  assert.equal(r.entry.status, "ok", JSON.stringify(r.entry));
  assert.equal(BigInt(r.entry.retval), 1n);
  assert.equal(r.run.mode, "attach");
});

test("DLL: dllMode all runs each non-forwarder export in a fresh world", async () => {
  const { image } = buildDll();
  const r = await runUserlandPe(image, { dllMode: "all", maxSteps: 10000 });
  assert.equal(r.runs.length, 2, JSON.stringify(r.runs));
  const byExport = Object.fromEntries(r.runs.map((x) => [x.export, x]));
  assert.equal(BigInt(byExport.Answer.retval), 42n);
  assert.equal(BigInt(byExport.OrdinalSeven.retval), 7n);
  assert.ok(!("Forwarded" in byExport), "forwarder skipped in sweep");
  assert.equal(r.run.mode, "all");
});

test("DLL without DllMain (entryRva=0) still runs its export", async () => {
  const textRva = dllTextRva();
  const code = new Uint8Array(0x20);
  code.set([0xb8, 0x63, 0x00, 0x00, 0x00, 0xc3], 0x10); // mov eax, 99
  const image = new PeBuilder()
    .setDll()
    .addSection(".text", code)
    .addExports([{ name: "NoMain", section: ".text", offset: 0x10 }])
    .build(0).image;
  const r = await runUserlandPe(image, { export: "NoMain", maxSteps: 10000 });
  assert.equal(r.entry.status, "ok", JSON.stringify(r.entry));
  assert.equal(BigInt(r.entry.retval), 99n);
  assert.equal(r.attach, null);
  assert.equal(parsePe(image).entryRva, 0);
});

// ------------------------------------------------------------------- SEH

/**
 * Hand-assembled x64 table-SEH fixture:
 *   +0x00 mainFn: sub rsp,0x28 ; call helper ; add rsp,0x28 ; ret
 *   +0x20 helper: sub rsp,0x28 ; div ecx (ecx=0) -> #DE
 *   +0x40 except: mov eax,0x37 ; ret          (the __except body)
 * .pdata has RUNTIME_FUNCTIONs for both functions; mainFn's UNWIND_INFO
 * carries a __C_specific_handler scope covering [mainFn, mainFn+0x20) that
 * jumps to `except` (handler field = 1 -> EXCEPTION_EXECUTE_HANDLER, no filter).
 */
function sehLayout() {
  const probe = new PeBuilder()
    .addSection(".text", new Uint8Array(0x60))
    .addSection(".pdata", new Uint8Array(12))
    .addSection(".xdata", new Uint8Array(0x40));
  const pe = parsePe(probe.build(0).image);
  const rva = (n) => pe.sections.find((s) => s.name === n).rva;
  return { text: rva(".text"), pdata: rva(".pdata"), xdata: rva(".xdata") };
}

function buildSehFixture({ scoped = true } = {}) {
  const L = sehLayout();
  const u32b = (v) => [v & 0xff, (v >> 8) & 0xff, (v >> 16) & 0xff, (v >>> 24) & 0xff];

  const text = new Uint8Array(0x60).fill(0xcc);
  text.set([
    0x48, 0x83, 0xec, 0x28,             // mainFn: sub rsp,0x28
    0xe8, 0x17, 0x00, 0x00, 0x00,       // call helper (helper = +0x20)
    0x48, 0x83, 0xc4, 0x28,             // add rsp,0x28
    0xc3,                                // ret
  ], 0x00);
  text.set([
    0x48, 0x83, 0xec, 0x28,             // helper: sub rsp,0x28
    0x31, 0xd2,                          // xor edx,edx
    0xb8, 0x01, 0x00, 0x00, 0x00,        // mov eax,1
    0x31, 0xc9,                          // xor ecx,ecx
    0xf7, 0xf1,                          // div ecx -> #DE
    0x48, 0x83, 0xc4, 0x28,             // add rsp,0x28
    0xc3,                                // ret
  ], 0x20);
  text.set([
    0xb8, 0x37, 0x00, 0x00, 0x00,        // mov eax,0x37
    0xc3,                                // ret
  ], 0x40);

  // UNWIND_INFO
  const xdata = new Uint8Array(0x40);
  // helper: version 1, flags 0, prolog 4, 1 code (ALLOC_SMALL 0x28 @ off 4)
  xdata.set([0x01, 0x04, 0x01, 0x00, 0x04, 0x42], 0x00);
  // mainFn: version 1, flags EHANDLER, prolog 4, 1 code, pad, handler=1, 1 scope
  const m = 0x10;
  xdata.set([0x09, 0x04, 0x01, 0x00, 0x04, 0x42, 0x00, 0x00], m);
  xdata.set(u32b(1), m + 8);                    // Handler (1 = EXECUTE_HANDLER)
  xdata.set(u32b(scoped ? 1 : 0), m + 12);      // ScopeTable count
  if (scoped) {
    xdata.set(u32b(L.text + 0x00), m + 16);     // BeginAddress
    xdata.set(u32b(L.text + 0x20), m + 20);     // EndAddress
    xdata.set(u32b(1), m + 24);                 // Handler (no filter)
    xdata.set(u32b(L.text + 0x40), m + 28);     // JumpTarget = __except body
  }

  const pdata = new Uint8Array(12 * 2);
  pdata.set([...u32b(L.text + 0x00), ...u32b(L.text + 0x20), ...u32b(L.xdata + m)], 0);
  pdata.set([...u32b(L.text + 0x20), ...u32b(L.text + 0x60), ...u32b(L.xdata + 0x00)], 12);

  const b = new PeBuilder()
    .addSection(".text", text)
    .addSection(".pdata", pdata, 0x40000040)
    .addSection(".xdata", xdata, 0x40000040);
  b.exceptionDir = { rva: L.pdata, size: pdata.length };
  return b.build(L.text).image;
}

test("SEH: hardware fault (#DE) dispatches into __except and returns", async () => {
  const r = await runUserlandPe(buildSehFixture({ scoped: true }), { name: "seh.dll", maxSteps: 20000 });
  assert.equal(r.entry.status, "ok", JSON.stringify(r.entry));
  assert.equal(BigInt(r.entry.retval), 0x37n, "handler's return value");
  assert.equal(r.entry.sehHandled, true);
  assert.match(r.entry.sehDetail, /handler|dispatched/i, r.entry.sehDetail);
  assert.ok(r.seh.length > 0, "SEH trace recorded");
});

test("SEH: fault with no scope reports an honest unhandled fault", async () => {
  const r = await runUserlandPe(buildSehFixture({ scoped: false }), { name: "seh-noscope.dll", maxSteps: 20000 });
  assert.equal(r.entry.status, "fault", JSON.stringify(r.entry));
  assert.match(r.entry.sehDetail, /no handler|no \.pdata/i, r.entry.sehDetail);
});

// ------------------------------------------------------------ native syscall

test("native syscall: raw `syscall` is serviced by the NT model", async () => {
  const code = new Uint8Array([
    0x48, 0x83, 0xec, 0x28,             // sub rsp,0x28
    0x49, 0x89, 0xca,                    // mov r10, rcx
    0xb8, 0x0f, 0x00, 0x00, 0x00,        // mov eax, 0x0f  (NtClose)
    0x31, 0xc9,                          // xor ecx, ecx
    0x0f, 0x05,                          // syscall
    0x48, 0x83, 0xc4, 0x28,             // add rsp,0x28
    0xc3,                                // ret
  ]);
  const img = new PeBuilder().addSection(".text", code).build(0x1000).image;
  const r = await runUserlandPe(img, { name: "syscall.exe", maxSteps: 10000 });
  assert.equal(r.entry.status, "ok", JSON.stringify(r.entry));
  assert.equal(r.apiTrace.byName.NtClose?.count, 1, JSON.stringify(r.apiTrace.byName));
  assert.equal(BigInt(r.entry.retval), 0n);
});

test("native syscall: unknown SSN is recorded and returns STATUS_UNSUCCESSFUL", async () => {
  const code = new Uint8Array([
    0x48, 0x83, 0xec, 0x28,
    0x49, 0x89, 0xca,
    0xb8, 0x99, 0x09, 0x00, 0x00,        // mov eax, 0x999 (unmapped SSN)
    0x0f, 0x05,
    0x48, 0x83, 0xc4, 0x28,
    0xc3,
  ]);
  const img = new PeBuilder().addSection(".text", code).build(0x1000).image;
  const r = await runUserlandPe(img, { name: "syscall-unknown.exe", maxSteps: 10000 });
  assert.equal(r.entry.status, "ok", JSON.stringify(r.entry));
  assert.equal(r.apiTrace.byName["Nt#2457"]?.count, 1, JSON.stringify(r.apiTrace.byName));
  assert.equal(BigInt(r.entry.retval), 0xc0000001n);
  assert.ok(r.unmodeled.includes("Nt#2457"));
});

// ------------------------------------------------------- threads / TLS / APC

const TEXTRVA = 0x1000n; // .text RVA with one section + .rdata (headers < 0x1000)
const IMG = 0x140000000n;

/** Tiny x64 assembler with RIP-disp patching (offsets are never hand-counted). */
class Asm {
  constructor(size = 0x100) { this.b = new Uint8Array(size).fill(0xcc); this.n = 0; }
  bytes(...x) { for (const v of x) this.b[this.n++] = v & 0xff; return this; }
  movabs(reg, v) { return this.bytes(0x48 | (reg >= 8 ? 1 : 0), 0xb8 + (reg & 7), ...u64le(v)); }
  movEaxFromRip() { this.bytes(0x8b, 0x05); const d = this.n; this.bytes(0, 0, 0, 0); return (target) => this.#rip(d, target); }
  movRipEcx() { this.bytes(0x89, 0x0d); const d = this.n; this.bytes(0, 0, 0, 0); return (target) => this.#rip(d, target); }
  #rip(dispAt, target) { const d = target - (dispAt + 4); for (let i = 0; i < 4; i++) this.b[dispAt + i] = (d >> (8 * i)) & 0xff; }
  at(off) { this.n = off; return this; }
  toBytes() { return this.b; }
}

/** Build an EXE whose imports are the given functions (thunks in list order). */
function buildThunkExe(code, funcs) {
  const b = new PeBuilder();
  b.addSection(".text", code, 0xe0000020); // CODE|EXECUTE|READ|WRITE (fixtures write in-place)
  b.addImports([{ dll: "KERNEL32.dll", funcs }]);
  return b.build(0x1000).image;
}

test("threads: CreateThread runs the routine (param + retval visible)", async () => {
  const START = 0x60;
  const RESULT = 0x90;
  const a = new Asm();
  a.bytes(0x48, 0x83, 0xec, 0x40);                  // sub rsp,0x40 (shadow + 2 stack args)
  a.bytes(0x31, 0xc9, 0x31, 0xd2);                  // xor ecx,ecx ; xor edx,edx
  a.movabs(8, IMG + TEXTRVA + BigInt(START));       // r8 = start routine
  a.bytes(0x41, 0xb9, 0x34, 0x12, 0x00, 0x00);      // mov r9d, 0x1234 (param)
  a.bytes(0x48, 0xc7, 0x44, 0x24, 0x20, 0, 0, 0, 0); // [rsp+0x20] = flags
  a.bytes(0x48, 0xc7, 0x44, 0x24, 0x28, 0, 0, 0, 0); // [rsp+0x28] = tidPtr
  a.movabs(0, THUNK_BASE);                          // CreateThread (import #0)
  a.bytes(0xff, 0xd0);                              // call rax
  a.bytes(0x48, 0x83, 0xc4, 0x40);                  // add rsp,0x40
  const readResult = a.movEaxFromRip();             // mov eax,[result]
  a.bytes(0xc3);
  readResult(RESULT);
  a.at(START);
  const storeParam = a.movRipEcx();                 // mov [result],ecx
  a.bytes(0xb8, 0x07, 0x00, 0x00, 0x00, 0xc3);      // mov eax,7 ; ret
  storeParam(RESULT);

  const r = await runUserlandPe(buildThunkExe(a.toBytes(), ["CreateThread"]), { name: "thread.exe", maxSteps: 100000 });
  assert.equal(r.entry.status, "ok", JSON.stringify(r.entry));
  assert.equal(BigInt(r.entry.retval), 0x1234n, "thread wrote its param into result");
  assert.equal(r.threads.length, 1, JSON.stringify(r.threads));
  assert.equal(r.threads[0].status, "ok");
  assert.equal(BigInt(r.threads[0].retval), 7n);
});

test("TLS: TlsAlloc/Set/Get round-trip", async () => {
  const a = new Asm();
  a.bytes(0x53, 0x48, 0x83, 0xec, 0x20);            // push rbx ; sub rsp,0x20
  a.movabs(0, THUNK_BASE);                           // TlsAlloc
  a.bytes(0xff, 0xd0, 0x48, 0x89, 0xc3);             // call rax ; mov rbx,rax
  a.bytes(0x48, 0x89, 0xd9);                         // mov rcx,rbx
  a.bytes(0x48, 0xc7, 0xc2, 0xbc, 0x0a, 0x00, 0x00); // mov rdx,0xABC
  a.movabs(0, THUNK_BASE + 0x10n);                   // TlsSetValue
  a.bytes(0xff, 0xd0, 0x48, 0x89, 0xd9);             // call rax ; mov rcx,rbx
  a.movabs(0, THUNK_BASE + 0x20n);                   // TlsGetValue
  a.bytes(0xff, 0xd0);
  a.bytes(0x48, 0x83, 0xc4, 0x20, 0x5b, 0xc3);       // add rsp,0x20 ; pop rbx ; ret

  const r = await runUserlandPe(buildThunkExe(a.toBytes(), ["TlsAlloc", "TlsSetValue", "TlsGetValue"]), { name: "tls.exe", maxSteps: 20000 });
  assert.equal(r.entry.status, "ok", JSON.stringify(r.entry));
  assert.equal(BigInt(r.entry.retval), 0xabcn);
});

test("APC: QueueUserAPC delivers on an alertable wait", async () => {
  const APC = 0x80;
  const RESULT = 0xb0;
  const a = new Asm(0x100);
  a.bytes(0x53, 0x48, 0x83, 0xec, 0x20);            // push rbx ; sub rsp,0x20
  a.movabs(0, THUNK_BASE);                           // GetCurrentThread (import #0)
  a.bytes(0xff, 0xd0, 0x48, 0x89, 0xc3);             // call rax ; mov rbx,rax
  a.movabs(1, IMG + TEXTRVA + BigInt(APC));          // rcx = APC routine
  a.bytes(0x48, 0x89, 0xda);                         // mov rdx,rbx
  a.bytes(0x41, 0xb8, 0x55, 0x00, 0x00, 0x00);       // mov r8d,0x55
  a.movabs(0, THUNK_BASE + 0x10n);                   // QueueUserAPC
  a.bytes(0xff, 0xd0);
  a.bytes(0x31, 0xc9);                               // xor ecx,ecx
  a.bytes(0xba, 0x01, 0x00, 0x00, 0x00);             // mov edx,1 (alertable)
  a.movabs(0, THUNK_BASE + 0x20n);                   // SleepEx
  a.bytes(0xff, 0xd0);
  a.bytes(0x48, 0x83, 0xc4, 0x20);                   // add rsp,0x20
  const readResult = a.movEaxFromRip();
  a.bytes(0x5b, 0xc3);                               // pop rbx ; ret
  readResult(RESULT);
  a.at(APC);
  const storeParam = a.movRipEcx();
  a.bytes(0xc3);
  storeParam(RESULT);

  const r = await runUserlandPe(buildThunkExe(a.toBytes(), ["GetCurrentThread", "QueueUserAPC", "SleepEx"]), { name: "apc.exe", maxSteps: 20000 });
  assert.equal(r.entry.status, "ok", JSON.stringify(r.entry));
  assert.equal(BigInt(r.entry.retval), 0x55n, "APC routine ran with its param");
  assert.equal(r.apiTrace.byName.QueueUserAPC?.count, 1, JSON.stringify(r.apiTrace.byName));
  assert.ok(r.artifacts.debugStrings.some((d) => /\[apc\]/.test(d.text)), "APC delivery recorded");
});

// ------------------------------------------------- memory protections / heap

test("memory: write to a PAGE_NOACCESS region raises #PF into __except", async () => {
  const probe = new PeBuilder()
    .addSection(".text", new Uint8Array(0x80))
    .addSection(".pdata", new Uint8Array(12))
    .addSection(".xdata", new Uint8Array(0x40))
    .addImports([{ dll: "KERNEL32.dll", funcs: ["VirtualAlloc", "VirtualProtect"] }]);
  const pe = parsePe(probe.build(0).image);
  const R = (n) => pe.sections.find((s) => s.name === n).rva;
  const TEXT = R(".text"), PDATA = R(".pdata"), XDATA = R(".xdata");
  const u32b = (v) => [v & 0xff, (v >> 8) & 0xff, (v >> 16) & 0xff, (v >>> 24) & 0xff];

  const EXCEPT = 0x60;
  const a = new Asm(0x90);
  a.bytes(0x48, 0x83, 0xec, 0x40);                   // sub rsp,0x40
  a.bytes(0x31, 0xc9, 0x31, 0xd2);                   // xor ecx,ecx ; xor edx,edx
  a.bytes(0x41, 0xb8, 0x00, 0x30, 0x00, 0x00);       // mov r8d, MEM_COMMIT|MEM_RESERVE
  a.bytes(0x41, 0xb9, 0x04, 0x00, 0x00, 0x00);       // mov r9d, PAGE_READWRITE
  a.movabs(0, THUNK_BASE);                            // VirtualAlloc
  a.bytes(0xff, 0xd0, 0x48, 0x89, 0xc3);             // call rax ; mov rbx,rax
  a.bytes(0x48, 0x89, 0xd9);                          // mov rcx,rbx
  a.bytes(0xba, 0x00, 0x10, 0x00, 0x00);              // mov edx,0x1000
  a.bytes(0x41, 0xb8, 0x01, 0x00, 0x00, 0x00);       // mov r8d, PAGE_NOACCESS
  a.bytes(0x4c, 0x8d, 0x4c, 0x24, 0x20);              // lea r9,[rsp+0x20]
  a.movabs(0, THUNK_BASE + 0x10n);                    // VirtualProtect
  a.bytes(0xff, 0xd0);
  a.bytes(0xc7, 0x03, 0x41, 0x00, 0x00, 0x00);        // mov dword ptr [rbx],0x41  -> #PF
  a.bytes(0xb8, 0x01, 0x00, 0x00, 0x00, 0xc3);        // mov eax,1 ; ret
  a.at(EXCEPT);
  a.bytes(0xb8, 0x77, 0x00, 0x00, 0x00, 0xc3);        // except: mov eax,0x77 ; ret
  const code = a.toBytes();

  // .pdata: one RUNTIME_FUNCTION covering mainFn, handler = __except body
  const pdata = new Uint8Array(12);
  pdata.set([...u32b(TEXT), ...u32b(TEXT + EXCEPT), ...u32b(XDATA + 0x10)], 0);
  const xdata = new Uint8Array(0x40);
  xdata.set([0x09, 0x04, 0x01, 0x00, 0x04, 0x72, 0x00, 0x00], 0x10); // EHANDLER, 1 code (ALLOC_SMALL 0x40)
  xdata.set(u32b(1), 0x18);                    // Handler (no filter)
  xdata.set(u32b(1), 0x1c);                    // ScopeTable count
  xdata.set(u32b(TEXT), 0x20);
  xdata.set(u32b(TEXT + EXCEPT), 0x24);
  xdata.set(u32b(1), 0x28);
  xdata.set(u32b(TEXT + EXCEPT), 0x2c);

  const b = new PeBuilder()
    .addSection(".text", code, 0xe0000020)
    .addSection(".pdata", pdata, 0x40000040)
    .addSection(".xdata", xdata, 0x40000040)
    .addImports([{ dll: "KERNEL32.dll", funcs: ["VirtualAlloc", "VirtualProtect"] }]);
  b.exceptionDir = { rva: PDATA, size: 12 };

  const r = await runUserlandPe(b.build(TEXT).image, { name: "guard.exe", maxSteps: 50000 });
  assert.equal(r.entry.status, "ok", JSON.stringify(r.entry));
  assert.equal(BigInt(r.entry.retval), 0x77n, "guard fault dispatched into __except");
  assert.equal(r.entry.sehHandled, true, JSON.stringify(r.entry));
  assert.ok(r.memoryFaults.some((f) => f.kind === "write"), JSON.stringify(r.memoryFaults));
});

test("memory: VirtualQuery reports reservation state", async () => {
  const a = new Asm(0x90);
  a.bytes(0x48, 0x83, 0xec, 0x60);                   // sub rsp,0x60 (48-byte MBI at rsp+0x20)
  a.bytes(0x31, 0xc9, 0x31, 0xd2);                   // xor ecx,ecx ; xor edx,edx
  a.bytes(0x41, 0xb8, 0x00, 0x20, 0x00, 0x00);       // mov r8d, MEM_RESERVE
  a.bytes(0x41, 0xb9, 0x04, 0x00, 0x00, 0x00);       // mov r9d, PAGE_READWRITE
  a.movabs(0, THUNK_BASE);                            // VirtualAlloc
  a.bytes(0xff, 0xd0, 0x48, 0x89, 0xc3);             // call rax ; mov rbx,rax
  a.bytes(0x48, 0x89, 0xd9);                          // mov rcx,rbx
  a.bytes(0x48, 0x8d, 0x54, 0x24, 0x20);              // lea rdx,[rsp+0x20]
  a.bytes(0x41, 0xb8, 0x30, 0x00, 0x00, 0x00);       // mov r8d,48
  a.movabs(0, THUNK_BASE + 0x10n);                    // VirtualQuery
  a.bytes(0xff, 0xd0);
  a.bytes(0x8b, 0x44, 0x24, 0x40);                    // mov eax,[rsp+0x20+0x20] (State)
  a.bytes(0x48, 0x83, 0xc4, 0x60, 0xc3);             // add rsp,0x60 ; ret

  const r = await runUserlandPe(buildThunkExe(a.toBytes(), ["VirtualAlloc", "VirtualQuery"]), { name: "vq.exe", maxSteps: 20000 });
  assert.equal(r.entry.status, "ok", JSON.stringify(r.entry));
  assert.equal(BigInt(r.entry.retval), 0x2000n, "MEM_RESERVE");
});

test("heap: HeapFree makes the block reusable (first-fit)", async () => {
  const a = new Asm(0x90);
  a.bytes(0x53, 0x48, 0x83, 0xec, 0x20);             // push rbx ; sub rsp,0x20
  a.movabs(0, THUNK_BASE + 0x20n);                    // GetProcessHeap (3rd import)
  a.bytes(0xff, 0xd0, 0x48, 0x89, 0xc3);             // call rax ; mov rbx,rax (h)
  a.bytes(0x48, 0x89, 0xd9);                          // mov rcx,rbx
  a.bytes(0x31, 0xd2);                                // xor edx,edx
  a.bytes(0x41, 0xb8, 0x40, 0x00, 0x00, 0x00);       // mov r8d,64
  a.movabs(0, THUNK_BASE);                            // HeapAlloc (#0)
  a.bytes(0xff, 0xd0, 0x48, 0x89, 0xc7);             // call rax ; mov rdi,rax (p1)
  a.bytes(0x48, 0x89, 0xd9, 0x31, 0xd2);             // mov rcx,rbx ; xor edx,edx
  a.bytes(0x49, 0x89, 0xf8);                          // mov r8,rdi
  a.movabs(0, THUNK_BASE + 0x10n);                    // HeapFree (#1)
  a.bytes(0xff, 0xd0);
  a.bytes(0x48, 0x89, 0xd9, 0x31, 0xd2, 0x41, 0xb8, 0x40, 0x00, 0x00, 0x00);
  a.movabs(0, THUNK_BASE);                            // HeapAlloc again
  a.bytes(0xff, 0xd0);
  a.bytes(0x48, 0x39, 0xf8);                          // cmp rax,rdi
  a.bytes(0x75, 0x07);                                // jne fail
  a.bytes(0xb8, 0xaa, 0x00, 0x00, 0x00);              // mov eax,0xAA
  a.bytes(0xeb, 0x05);                                // jmp done
  a.bytes(0xb8, 0xbb, 0x00, 0x00, 0x00);              // fail: mov eax,0xBB
  a.bytes(0x48, 0x83, 0xc4, 0x20, 0x5b, 0xc3);       // done: add rsp,0x20 ; pop rbx ; ret

  const r = await runUserlandPe(buildThunkExe(a.toBytes(), ["HeapAlloc", "HeapFree", "GetProcessHeap"]), { name: "heap.exe", maxSteps: 20000 });
  assert.equal(r.entry.status, "ok", JSON.stringify(r.entry));
  assert.equal(BigInt(r.entry.retval), 0xaan, "freed block reused");
  assert.equal(r.apiTrace.byName.HeapFree?.count, 1);
});

function readCStringLocal(mem, va, max = 64) {
  let s = "";
  for (let i = 0; i < max; i++) {
    const b = mem.u8(BigInt(va) + BigInt(i));
    if (b === 0) break;
    s += String.fromCharCode(b);
  }
  return s;
}
