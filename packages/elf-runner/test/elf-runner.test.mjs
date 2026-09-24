/**
 * Userland ELF harness: loader + syscall model.
 */
import { test } from "node:test";
import assert from "node:assert/strict";

import { runElf, parseElf64 } from "../src/index.mjs";

/** Build a minimal ET_EXEC ELF64 with one R+X PT_LOAD segment. */
function buildElf(code, { entryOff = 0x1000, data = new Uint8Array(0), dataOff = 0x1080 } = {}) {
  const segOff = 0;
  const segVaddr = 0x400000;
  const fileSize = Math.max(0x2000, dataOff + data.length);
  const buf = new Uint8Array(fileSize);
  const dv = new DataView(buf.buffer);
  // ELF header
  buf.set([0x7f, 0x45, 0x4c, 0x46, 2, 1, 1, 0], 0);
  dv.setUint16(16, 2, true); // ET_EXEC
  dv.setUint16(18, 0x3e, true); // x86-64
  dv.setUint32(20, 1, true);
  dv.setBigUint64(24, BigInt(segVaddr + entryOff), true); // e_entry
  dv.setBigUint64(32, 0x40n, true); // e_phoff
  dv.setUint16(52, 64, true); // e_ehsize
  dv.setUint16(54, 56, true); // e_phentsize
  dv.setUint16(56, 1, true); // e_phnum
  // program header
  dv.setUint32(0x40, 1, true); // PT_LOAD
  dv.setUint32(0x44, 5, true); // R+X
  dv.setBigUint64(0x48, BigInt(segOff), true);
  dv.setBigUint64(0x50, BigInt(segVaddr), true);
  dv.setBigUint64(0x58, BigInt(segVaddr), true);
  dv.setBigUint64(0x60, BigInt(fileSize), true);
  dv.setBigUint64(0x68, BigInt(fileSize), true);
  dv.setBigUint64(0x70, 0x1000n, true);
  buf.set(code, entryOff);
  if (data.length) buf.set(data, dataOff);
  return buf;
}

test("parseElf64 reads headers, segments and imports", () => {
  const elf = parseElf64(buildElf(new Uint8Array([0xc3])));
  assert.equal(elf.format, "elf");
  assert.equal(elf.typeName, "EXEC");
  assert.equal(elf.machineName, "x86-64");
  assert.equal(elf.loads.length, 1);
  assert.equal(elf.entry, 0x401000n);
  assert.equal(elf.rwxSegments, 0);
});

test("runs an ELF entry point and models write/exit_group syscalls", async () => {
  const msg = new TextEncoder().encode("hello");
  const code = new Uint8Array([
    0xb8, 0x01, 0x00, 0x00, 0x00, // mov eax, 1 (write)
    0xbf, 0x01, 0x00, 0x00, 0x00, // mov edi, 1 (stdout)
    0x48, 0xc7, 0xc6, 0x80, 0x10, 0x40, 0x00, // mov rsi, 0x401080
    0xba, 0x05, 0x00, 0x00, 0x00, // mov edx, 5
    0x0f, 0x05, // syscall
    0xb8, 0xe7, 0x00, 0x00, 0x00, // mov eax, 231 (exit_group)
    0x31, 0xff, // xor edi, edi
    0x0f, 0x05, // syscall
  ]);
  const report = await runElf(buildElf(code, { data: msg, dataOff: 0x1080 }), { name: "hello.elf", maxSteps: 10000 });
  assert.equal(report.meta.kind, "userland-elf");
  assert.equal(report.entry.status, "ok", JSON.stringify(report.entry));
  assert.equal(report.exited, true);
  assert.equal(report.exitCode, 0);
  assert.equal(report.output, "hello");
  assert.equal(report.syscalls.byName.write.count, 1);
  assert.equal(report.syscalls.byName.exit_group.count, 1);
  assert.equal(report.load.type, "EXEC");
});

test("records file/network/execve intent", async () => {
  // openat(AT_FDCWD=-100, "/etc/passwd", O_RDONLY) ; execve("/bin/sh", ...) ; exit_group(0)
  const path = new TextEncoder().encode("/etc/passwd\0");
  const sh = new TextEncoder().encode("/bin/sh\0");
  const code = new Uint8Array([
    0xb8, 0x01, 0x01, 0x00, 0x00, // mov eax, 257 (openat)
    0x48, 0xc7, 0xc7, 0x9c, 0xff, 0xff, 0xff, // mov rdi, -100
    0x48, 0xc7, 0xc6, 0x80, 0x10, 0x40, 0x00, // mov rsi, 0x401080
    0x31, 0xd2, // xor edx, edx
    0x0f, 0x05,
    0xb8, 0x3b, 0x00, 0x00, 0x00, // mov eax, 59 (execve)
    0x48, 0xc7, 0xc7, 0x90, 0x10, 0x40, 0x00, // mov rdi, 0x401090
    0x31, 0xf6, // xor esi, esi
    0x31, 0xd2, // xor edx, edx
    0x0f, 0x05,
    0xb8, 0xe7, 0x00, 0x00, 0x00, // mov eax, 231
    0x31, 0xff,
    0x0f, 0x05,
  ]);
  const blob = new Uint8Array(0x80);
  blob.set(path, 0);
  blob.set(sh, 0x10);
  const report = await runElf(buildElf(code, { data: blob, dataOff: 0x1080 }), { name: "behave.elf", maxSteps: 10000 });
  assert.equal(report.entry.status, "ok", JSON.stringify(report.entry));
  assert.ok(report.artifacts.files.some((f) => f.action === "open" && f.path === "/etc/passwd"));
  assert.ok(report.artifacts.processes.some((p) => p.path === "/bin/sh"));
  assert.equal(report.syscalls.byName.openat.count, 1);
  assert.equal(report.syscalls.byName.execve.count, 1);
  // openat/execve are behavior-relevant; the other calls are not
  assert.match(report.traceAbridgedText, /openat/);
  assert.match(report.traceAbridgedText, /execve/);
});

test("emits a decoded syscall trace, triage facts and custom YARA matches", async () => {
  const msg = new TextEncoder().encode("hello");
  const code = new Uint8Array([
    0xb8, 0x01, 0x00, 0x00, 0x00,
    0xbf, 0x01, 0x00, 0x00, 0x00,
    0x48, 0xc7, 0xc6, 0x80, 0x10, 0x40, 0x00,
    0xba, 0x05, 0x00, 0x00, 0x00,
    0x0f, 0x05,
    0xb8, 0xe7, 0x00, 0x00, 0x00,
    0x31, 0xff,
    0x0f, 0x05,
  ]);
  const report = await runElf(buildElf(code, { data: msg, dataOff: 0x1080 }), {
    name: "traced.elf",
    maxSteps: 10000,
    extraYara: 'rule custom_elf { meta: severity = "low" strings: $a = "hello" condition: $a }',
  });
  assert.equal(report.entry.status, "ok");
  assert.ok(report.static && report.static.format === "elf");
  assert.match(report.static.ssdeep, /^\d+:[A-Za-z0-9+/]*:[A-Za-z0-9+/]*$/);
  assert.ok(Array.isArray(report.rules.matches));
  assert.ok(report.yara.matches.some((m) => m.id === "custom_elf"), JSON.stringify(report.yara));
  assert.ok(report.traceText.includes('write(0x1, "hello", 0x5) -> 0x5'), report.traceText);
  // abridged view drops stdout chatter and exit_group
  assert.equal(report.traceAbridgedCount, 0, report.traceAbridgedText);
  assert.equal(report.traceTotalCount, 2);
  assert.ok(report.traceText.includes("traced.elf+0x"), report.traceText);
  assert.ok(report.trace.length >= 2);
});

test("rejects ET_REL objects with a .ko hint", async () => {
  const rel = buildElf(new Uint8Array([0xc3]));
  new DataView(rel.buffer).setUint16(16, 1, true); // ET_REL
  await assert.rejects(() => runElf(rel), /Linux Driver Analyzer/);
});

test("rejects non-ELF and non-x86-64 input", async () => {
  await assert.rejects(() => runElf(new Uint8Array(0x100)), /not an ELF/);
  const arm = buildElf(new Uint8Array([0xc3]));
  new DataView(arm.buffer).setUint16(18, 0xb7, true); // aarch64
  await assert.rejects(() => runElf(arm), /unsupported ELF machine/);
});
