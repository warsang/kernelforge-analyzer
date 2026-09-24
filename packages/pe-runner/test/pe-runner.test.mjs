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

function readCStringLocal(mem, va, max = 64) {
  let s = "";
  for (let i = 0; i < max; i++) {
    const b = mem.u8(BigInt(va) + BigInt(i));
    if (b === 0) break;
    s += String.fromCharCode(b);
  }
  return s;
}
