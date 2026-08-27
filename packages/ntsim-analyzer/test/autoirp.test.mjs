/**
 * Auto-IRP driving tests — harvesting + synthetic request synthesis over
 * hand-built PE32+ fixtures (no toolchain).
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { fileURLToPath } from "node:url";
import path from "node:path";

import { PeBuilder } from "@kernelforge/ntsim/src/pebuilder.mjs";
import { parsePe } from "@kernelforge/ntsim/src/pe.mjs";
import { StructTables } from "@kernelforge/ntsim/src/structs.mjs";
import { looksLikeCtlCode, harvestCtlCodes } from "../src/autoirp.mjs";
import { analyzeDriver } from "../src/index.mjs";

const tablesDir = path.join(
  path.dirname(fileURLToPath(import.meta.url)),
  "../../ntsim-assets/data/vergilius/windows-10/22h2",
);
const loadTables = () => StructTables.loadDir(tablesDir, ["_EPROCESS", "_ETHREAD", "_KLDR_DATA_TABLE_ENTRY"]);

const u32 = (v) => [v & 0xff, (v >> 8) & 0xff, (v >>> 16) & 0xff, (v >>> 24) & 0xff];
const vaBytes = (v) => {
  const out = [];
  let x = v;
  for (let i = 0; i < 8; i++) { out.push(Number(x & 0xffn)); x >>= 8n; }
  return out;
};

function buildImage({ entryRva, text, exception }) {
  const b = new PeBuilder();
  b.addSection(".text", new Uint8Array(text), 0x60000020);
  if (exception) b.exceptionDir = exception;
  return b.build(entryRva).image;
}

test("looksLikeCtlCode filters winioctl bitfield layout", () => {
  assert.equal(looksLikeCtlCode(0x222000), true); // classic FILE_DEVICE_UNKNOWN buffered
  assert.equal(looksLikeCtlCode(0x22e004), true); // access 3, func 0x801, buffered
  assert.equal(looksLikeCtlCode(0x222001), false); // method 1 (IN direct) — conservative filter
  assert.equal(looksLikeCtlCode(0x222002), false); // func field = 0
  assert.equal(looksLikeCtlCode(0x00000004), false); // func 1 (<0x800 custom range)
  assert.equal(looksLikeCtlCode(0xffff0000), false); // access 0
  assert.equal(looksLikeCtlCode(0xffffffff), false);
});

// ---- fixture: DriverEntry installs a selective IOCTL handler -----------------
//
//   +0x10 DriverEntry: mov rax, handlerVa ; mov [rcx+0xE0], rax ; xor eax,eax ; ret
//   +0x40 handler:     only answers code 0x22E004, else STATUS_INVALID_PARAMETER

const MAGIC_CODE = 0x22e004;
const MAGIC_OUT = 0xc0ffee42;

function buildSelectiveDriver(textLen = 0x100) {
  // probe text RVA with final length
  const probe = new PeBuilder().addSection(".text", new Uint8Array(textLen), 0x60000020);
  const t = parsePe(probe.build(0).image).sections[0].rva;
  const BASE = 0xfffff80300000000n;
  const handlerVa = BASE + BigInt(t + 0x40);

  const text = new Uint8Array(textLen);
  text.set([
    0x48, 0xb8, ...vaBytes(handlerVa),
    0x48, 0x89, 0x81, 0xe0, 0, 0, 0,
    0x31, 0xc0,
    0xc3,
  ], 0x10);

  // handler at +0x40: answers only MAGIC_CODE, else STATUS_INVALID_PARAMETER
  text.set([
    0x49, 0x89, 0xd0,                        // mov r8, rdx            ; irp
    0x49, 0x8b, 0x48, 0x18,                  // mov rcx, [r8+0x18]     ; SystemBuffer
    0x45, 0x8b, 0x88, 0xe8, 0x00, 0x00, 0x00,// mov r9d, [r8+0xe8]     ; IoControlCode (stack+0x18)
    0x41, 0xb8, ...u32(MAGIC_CODE),          // mov r8d, MAGIC_CODE    (imm32 in .text!)
    0x45, 0x39, 0xc1,                        // cmp r9d, r8d
    0x75, 0x12,                              // jne fail (+0x12)
    0xc7, 0x01, ...u32(MAGIC_OUT),           // mov dword [rcx], MAGIC_OUT
    0x31, 0xc0,                              // xor eax, eax
    0x41, 0x89, 0x40, 0x30,                  // mov [r8+0x30], eax     ; Status = SUCCESS
    0x49, 0xc7, 0x40, 0x38, 8, 0, 0, 0,      // mov qword [r8+0x38], 8 ; Information
    0xc3,
    // fail:
    0xb8, ...u32(0xc000000d),                // mov eax, STATUS_INVALID_PARAMETER
    0x41, 0x89, 0x40, 0x30,                  // mov [r8+0x30], eax
    0xc3,
  ], 0x40);

  const img = buildImage({ entryRva: t + 0x10, text });
  return img;
}

test("harvestCtlCodes finds the embedded CTL_CODE immediate", () => {
  const img = buildSelectiveDriver();
  const pe = parsePe(img);
  const codes = harvestCtlCodes(img, pe, {});
  assert.ok(codes.some((c) => c.value === MAGIC_CODE),
    `expected 0x${MAGIC_CODE.toString(16)} in ${codes.map((c) => c.value.toString(16))}`);
});

test("analyzeDriver({autoIrp}) drives lifecycle majors + harvested codes", async () => {
  const img = buildSelectiveDriver();
  const r = await analyzeDriver(img, { tables: await loadTables(), autoIrp: true });

  assert.equal(r.entry.status, "ok");
  assert.ok(r.harvestedIoctls.some((h) => BigInt(h.value) === BigInt(MAGIC_CODE)));

  const majors = r.autoIrps.map((x) => x.majorName);
  assert.equal(majors[0], "CREATE");
  assert.equal(majors.at(-1), "CLOSE");
  assert.ok(majors.includes("DEVICE_CONTROL"));

  // the magic code got answered with the marker
  const hit = r.autoIrps.find(
    (x) => x.ntstatus === 0n && x.outputHex.startsWith("42eeffc0"), // LE bytes of 0xc0ffee42
  );
  assert.ok(hit, `marker not found: ${JSON.stringify(r.autoIrps.map((x) => x.outputHex.slice(0, 8)))}`);
});
