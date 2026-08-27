/**
 * Analyzer end-to-end tests over hand-built PE32+ fixtures (no toolchain).
 *
 * CodeBuf-style byte assembly keeps fixtures honest: these are real x64
 * instruction streams that both CPU backends execute identically.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { fileURLToPath } from "node:url";
import path from "node:path";

import { PeBuilder } from "@kernelforge/ntsim/src/pebuilder.mjs";
import { parsePe } from "@kernelforge/ntsim/src/pe.mjs";
import { StructTables } from "@kernelforge/ntsim/src/structs.mjs";
import { analyzeDriver } from "../src/index.mjs";

const tablesDir = path.join(
  path.dirname(fileURLToPath(import.meta.url)),
  "../../ntsim-assets/data/vergilius/windows-10/22h2",
);

// The analyzer always maps at this base — fixtures hardcode absolute VAs.
const BASE = 0xfffff80300000000n;

/** .text section RVA for an image whose only section is `len` bytes. */
function probeTextRva(len) {
  const b = new PeBuilder().addSection(".text", new Uint8Array(len), 0x60000020);
  return parsePe(b.build(0).image).sections[0].rva;
}

/** Build the final image given absolute image RVAs. */
function buildImage({ entryRva, text, exception }) {
  const b = new PeBuilder();
  b.addSection(".text", new Uint8Array(text), 0x60000020);
  if (exception) b.exceptionDir = exception;
  return b.build(entryRva).image;
}

const u32 = (v) => [v & 0xff, (v >> 8) & 0xff, (v >> 16) & 0xff, (v >>> 24) & 0xff];
const vaBytes = (v) => {
  const out = [];
  let x = v;
  for (let i = 0; i < 8; i++) { out.push(Number(x & 0xffn)); x >>= 8n; }
  return out;
};

const loadTables = () => StructTables.loadDir(tablesDir, ["_EPROCESS", "_ETHREAD", "_KLDR_DATA_TABLE_ENTRY"]);

test("analyzeDriver: clean DriverEntry returns SUCCESS + load report", async () => {
  const t = probeTextRva(0x20);
  const text = new Uint8Array(0x20);
  text.set([0x31, 0xc0, 0xc3], 0x10); // xor eax,eax ; ret @ text+0x10
  const img = buildImage({ entryRva: t + 0x10, text });
  const r = await analyzeDriver(img, { tables: await loadTables() });
  assert.equal(r.entry.status, "ok");
  assert.equal(r.entry.retval, "0x00000000");
  assert.equal(r.load.base, `0x${BASE.toString(16)}`);
});

test("analyzeDriver: driver name seeds DriverName + Services registry path", async () => {
  const t = probeTextRva(0x20);
  const text = new Uint8Array(0x20);
  text.set([0x31, 0xc0, 0xc3], 0x10);
  const img = buildImage({ entryRva: t + 0x10, text });

  for (const name of ["mhyprot2.sys", `C:\\Windows\\System32\\drivers\\evil.SYS`]) {
    const r = await analyzeDriver(img, { tables: await loadTables(), name });
    assert.equal(r.load.driverName, name);
    const svc = name.split(/[\\/]/).pop().replace(/\.[^.]*$/, "");
    assert.equal(
      r.load.registryPath,
      `\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Services\\${svc}`,
    );

    // DriverName UNICODE_STRING (at +0x20) points at a buffer holding the name
    const kernel = r.__session.kernel;
    const drvVa = r.__session.drvRec.va;
    const len = kernel.mem.u16(drvVa + 0x20n);
    const buf = kernel.mem.u64(drvVa + 0x28n);
    assert.equal(kernel.mem.readUtf16(buf, 128), name);
    assert.ok(len > 0);
  }
});

test("analyzeDriver: unknown imports are provisioned as traced stubs", async () => {
  const t = probeTextRva(0x20);
  const b = new PeBuilder();
  b.addSection(".text", new Uint8Array(0x20).fill(0xc3), 0x60000020);
  b.addImports([{ dll: "ntoskrnl.exe", funcs: ["MmTotallyFakeExport"] }]);
  const img = b.build(t + 0x10).image;
  const r = await analyzeDriver(img, { tables: await loadTables() });
  assert.ok(r.load.unmodeledExports.includes("MmTotallyFakeExport"));
  assert.equal(r.entry.status, "ok");
});

test("analyzeDriver: scripted IOCTL reaches MajorFunction handler", async () => {
  // .text layout:
  //   +0x00 padding | +0x10 DriverEntry installs handler into MJ[14]
  //   +0x40 ioctl handler writes ioctl|0xAA000000 marker to SystemBuffer
  const textLen = 0x100;
  const t = probeTextRva(textLen);
  const handlerVa = BASE + BigInt(t + 0x40);

  const text = new Uint8Array(textLen);
  text.set([
    0x48, 0xb8, ...vaBytes(handlerVa),        // mov rax, imm64
    0x48, 0x89, 0x81, 0xe0, 0, 0, 0,          // mov [rcx+0xE0], rax  (MJ[14])
    0x31, 0xc0,                               // xor eax, eax
    0xc3,                                     // ret
  ], 0x10);

  text.set([
    0x49, 0x89, 0xd0,                         // mov r8, rdx            ; irp
    0x4d, 0x8d, 0x88, 0xd0, 0, 0, 0,          // lea r9, [r8+0xd0]      ; stack loc (disp32!)
    0x45, 0x8b, 0x49, 0x18,                   // mov r9d, [r9+0x18]     ; IoControlCode
    0x49, 0x8b, 0x48, 0x18,                   // mov rcx, [r8+0x18]     ; SystemBuffer
    0x41, 0x81, 0xc9, 0, 0, 0, 0xaa,          // or  r9d, 0xAA000000
    0x44, 0x89, 0x09,                         // mov [rcx], r9d         ; marker out
    0x31, 0xc0,                               // xor eax, eax
    0x41, 0x89, 0x40, 0x30,                   // mov [r8+0x30], eax     ; IoStatus.Status=0
    0x49, 0xc7, 0x40, 0x38, 4, 0, 0, 0,       // mov qword [r8+0x38],4  ; Information
    0xc3,
  ], 0x40);

  const img = buildImage({ entryRva: t + 0x10, text });

  const IOCTL = 0x222000;
  const r = await analyzeDriver(img, {
    tables: await loadTables(),
    ioctls: [{ code: IOCTL, inputHex: "deadbeef", outputLen: 16 }],
  });

  assert.equal(r.entry.status, "ok");
  assert.equal(r.ioctls.length, 1);
  const io = r.ioctls[0];
  assert.equal(io.status, "ok");
  assert.equal(io.ntstatus, 0n);
  assert.equal(io.information, 4n);
  const expected = ((IOCTL | 0xaa000000) >>> 0)
    .toString(16).padStart(8, "0").match(/../g).reverse().join("");
  assert.ok(io.outputHex.startsWith(expected), `output ${io.outputHex} vs ${expected}`);
});

test("analyzeDriver: SEH scope-table dispatch rescues faulting entry", async () => {
  // .text layout:
  //   +0x10 DriverEntry: FF 30 -> interpreter CpuError (#UD-class)
  //   +0x20 filter funclet: mov eax,1 ; ret
  //   +0x30 __except body: mov eax,0xDEADC0DE ; ret
  //   +0x80 UNWIND_INFO (+scope table @+0xA0)
  //   +0xC0 RUNTIME_FUNCTION
  const entrySub = 0x10;
  const len = 0x100;
  const t = probeTextRva(len);

  const text = new Uint8Array(len);
  text.set([0x0f, 0x0b, 0x31, 0xc0, 0xc3], entrySub);        // faulting body (UD2)
  text.set([0xb8, 1, 0, 0, 0, 0xc3], 0x20);                  // filter
  text.set([0xb8, ...u32(0xdeadc0de), 0xc3], 0x30);          // except body

  // UNWIND_INFO @t+0x80: version1 | EHANDLER<<3 = 0x09.
  // Real __C_specific_handler .xdata: handler RVA immediately followed by
  // the scope table (u32 count + 4xu32 entries) — no gaps.
  text.set([0x09, 0x00, 0x00, 0x00], 0x80);
  text.set(u32(t + 0x88), 0x84);                             // scope table RVA
  text.set(u32(1), 0x88);                                    // one scope entry
  text.set(u32(t + entrySub), 0x8c);                         // begin (image RVA)
  text.set(u32(t + entrySub + 3), 0x90);                     // end
  text.set(u32(t + 0x20), 0x94);                             // filter funclet
  text.set(u32(t + 0x30), 0x98);                             // jump target

  // .pdata RUNTIME_FUNCTION @t+0xC0 (absolute image RVAs)
  text.set(u32(t + entrySub), 0xc0);
  text.set(u32(t + entrySub + 3), 0xc4);
  text.set(u32(t + 0x80), 0xc8);

  const img = buildImage({
    entryRva: t + entrySub,
    text,
    exception: { rva: t + 0xc0, size: 12 }, // absolute image RVA
  });

  const r = await analyzeDriver(img, { tables: await loadTables() });
  assert.equal(r.entry.status, "ok", JSON.stringify(r.entry));
  assert.equal(r.entry.sehHandled, true);
  assert.equal(r.entry.retval, "0xdeadc0de");
  assert.ok(r.exceptions.some((e) => e.handled));
});

test("analyzeDriver: chronological call trace with decoded args + phases", async () => {
  // DriverEntry body: call DbgPrint(fmt) via IAT, then xor eax,eax ; ret.
  // fmt string lives in .rdata (stable across the run, unlike stack strings).
  const t = probeTextRva(0x60);
  const fmt = "[kf] traced %d\n";
  const rdata = new Uint8Array(0x20);
  for (let i = 0; i < fmt.length; i++) rdata[i] = fmt.charCodeAt(i);

  const b0 = new PeBuilder().addSection(".text", new Uint8Array(0x60), 0x60000020);
  const tRva = parsePe(b0.build(0).image).sections[0].rva;

  const text = new Uint8Array(0x60);
  let o = t + 0x10;
  const push = (...bytes) => { text.set(bytes, o - t); o += bytes.length; };
  void push;
  // mov rcx, fmtVa (48 B9 dq)
  const fmtVa = BASE + BigInt(tRva + 0x30);
  const fb = [];
  let x = fmtVa;
  for (let i = 0; i < 8; i++) { fb.push(Number(x & 0xffn)); x >>= 8n; }
  text.set([0x48, 0xb9, ...fb], 0x10);
  // mov edx, 7
  text.set([0xba, 0x07, 0x00, 0x00, 0x00], 0x1a);
  // call qword [rip+disp32] — disp patched after layout known
  const CALL_OFF = 0x1f;
  text.set([0xff, 0x15, 0, 0, 0, 0], CALL_OFF);
  // xor eax,eax ; ret
  text.set([0x31, 0xc0, 0xc3], 0x25);
  text.set(rdata, 0x30);

  const b = new PeBuilder();
  b.addSection(".text", text, 0x60000020);
  b.addSection(".rdata", new Uint8Array(0x40), 0xc0000040);
  b.addImports([{ dll: "ntoskrnl.exe", funcs: ["DbgPrint"] }]);
  const { image } = b.build(t + 0x10);
  const img = image;

  // patch the rip-relative disp against the built IAT
  const pe = parsePe(image);
  const rd = pe.sections.find((s) => s.name === ".rdata");
  void rd;
  // find IAT rva: walk import dir in built image
  const r2o = (rva) => {
    for (const s of pe.sections) {
      if (rva >= s.rva && rva < s.rva + Math.max(s.virtualSize, s.rawSize)) {
        const d = rva - s.rva;
        if (d < s.rawSize) return s.rawPtr + d;
        break;
      }
    }
    return null;
  };
  const descOff = r2o(pe.dirs[1].rva);
  const u32At = (p) =>
    image[p] | (image[p + 1] << 8) | (image[p + 2] << 16) | (image[p + 3] << 24);
  const iatRva = u32At(descOff + 16);
  const disp = iatRva - (t + CALL_OFF + 6);
  image.set(u32(disp), r2o(t + CALL_OFF) + 2);

  const r = await analyzeDriver(img, {
    tables: await loadTables(),
    autoIrp: false,
    name: "trace-fixture.sys",
  });
  assert.equal(r.entry.status, "ok", JSON.stringify(r.entry));
  assert.ok(Array.isArray(r.trace) && r.trace.length > 0, "trace events recorded");
  assert.ok(typeof r.traceText === "string" && r.traceText.length > 0);

  const dbgEvent = r.trace.find((e) => e.kind === "api" && e.name === "DbgPrint");
  assert.ok(dbgEvent, "DbgPrint call captured");
  assert.match(dbgEvent.text, /fmt="\[kf\] traced %d/);
  assert.equal(dbgEvent.caller, `trace-fixture.sys+0x${dbgCallRetRva(t).toString(16)}`);
  assert.match(r.traceText, /--- phase: DriverEntry ---/);
});

function dbgCallRetRva(t) {
  return t + 0x1f + 6;
}
