/**
 * shellcode-runner.test.mjs — hand-assembled x64 blobs over the Windows and
 * Linux shellcode worlds: conventions, PEB/EAT/ROR13 resolution (flagship),
 * NT syscall surface, clean trap stops, self-modifying unpacker diffs,
 * Linux syscalls/argv and stall reporting.
 */
import { test } from "node:test";
import assert from "node:assert/strict";

import { runShellcode, CODE_BASE, PARAMS_BASE, HEAP_BASE, NT_SSNS } from "../src/index.mjs";

/** tiny label/fixup emitter (rel8 + rel32-from-rip) */
function asm() {
  const out = [];
  const labels = {};
  const fixups = [];
  const api = {
    db(...b) { out.push(...b); return api; },
    label(n) { labels[n] = out.length; return api; },
    jmp8(n) { fixups.push({ at: out.length + 1, label: n, size: 1 }); out.push(0xeb, 0x00); return api; },
    jz8(n) { fixups.push({ at: out.length + 1, label: n, size: 1 }); out.push(0x74, 0x00); return api; },
    jnz8(n) { fixups.push({ at: out.length + 1, label: n, size: 1 }); out.push(0x75, 0x00); return api; },
    // lea reg, [rip+label] — 48 8D /r disp32; reg "rsi" | "rdi"
    leaRip(reg, n) {
      const modrm = reg === "rsi" ? 0x35 : 0x3d;
      fixups.push({ at: out.length + 3, label: n, size: 4 });
      out.push(0x48, 0x8d, modrm, 0x00, 0x00, 0x00, 0x00);
      return api;
    },
    bytes() {
      for (const f of fixups) {
        const rel = labels[f.label] - (f.at + f.size);
        out[f.at] = rel & 0xff;
        if (f.size === 4) {
          out[f.at + 1] = (rel >> 8) & 0xff;
          out[f.at + 2] = (rel >> 16) & 0xff;
          out[f.at + 3] = (rel >> 24) & 0xff;
        }
      }
      return Uint8Array.from(out);
    },
  };
  return api;
}

const le32 = (v) => [v & 0xff, (v >>> 8) & 0xff, (v >>> 16) & 0xff, (v >>> 24) & 0xff];

// ---------------------------------------------------------------------------
// Windows conventions
// ---------------------------------------------------------------------------

test("win raw: mov eax, 0x41; ret returns 0x41", async () => {
  const r = await runShellcode(Uint8Array.from([0xb8, 0x41, 0x00, 0x00, 0x00, 0xc3]), { os: "win", yara: false });
  assert.equal(r.meta.kind, "shellcode");
  assert.equal(r.meta.os, "win");
  assert.equal(r.entry.status, "ok", JSON.stringify(r.entry));
  assert.equal(r.entry.retval, "0x41");
});

test("win threadproc: rcx receives the param buffer", async () => {
  const r = await runShellcode(
    Uint8Array.from([0x48, 0x89, 0xc8, 0xc3]), // mov rax, rcx ; ret
    { os: "win", convention: "threadproc", paramBytes: Uint8Array.from([1, 2, 3, 4]), yara: false },
  );
  assert.equal(r.entry.status, "ok");
  assert.equal(BigInt(r.entry.retval), PARAMS_BASE);
});

test("win function: rcx=buffer, rdx=length", async () => {
  const r = await runShellcode(
    Uint8Array.from([0x48, 0x89, 0xd0, 0xc3]), // mov rax, rdx ; ret
    { os: "win", convention: "function", paramBytes: Uint8Array.from([1, 2, 3]), yara: false },
  );
  assert.equal(r.entry.retval, "0x3");
});

// ---------------------------------------------------------------------------
// Windows syscall surface
// ---------------------------------------------------------------------------

test("win: native syscall stub dispatches an SSN through the Win32 model", async () => {
  const ssn = NT_SSNS.NtDelayExecution;
  const blob = Uint8Array.from([
    0x4c, 0x8b, 0xd1, // mov r10, rcx
    0xb8, ...le32(ssn), // mov eax, ssn
    0x0f, 0x05, // syscall
    0x31, 0xc0, 0xc3, // xor eax, eax ; ret
  ]);
  const r = await runShellcode(blob, { os: "win", yara: false });
  assert.equal(r.entry.status, "ok", JSON.stringify(r.entry));
  assert.ok(r.apiTrace.byName.NtDelayExecution, Object.keys(r.apiTrace.byName).join(","));
  assert.equal(r.apiTrace.byName.NtDelayExecution.count, 1);
});

test("win: int 2e dispatches an SSN (EDX=0 -> register args)", async () => {
  const ssn = NT_SSNS.NtQuerySystemTime;
  const blob = Uint8Array.from([
    0xb8, ...le32(ssn), // mov eax, ssn
    0x31, 0xd2, // xor edx, edx (no arg block)
    0xcd, 0x2e, // int 2e
    0xc3,
  ]);
  const r = await runShellcode(blob, { os: "win", yara: false });
  assert.equal(r.entry.status, "ok", JSON.stringify(r.entry));
  assert.ok(r.apiTrace.byName.NtQuerySystemTime, Object.keys(r.apiTrace.byName).join(","));
});

test("win: sysenter also lands on the SSN dispatcher", async () => {
  const ssn = NT_SSNS.NtClose;
  const blob = Uint8Array.from([
    0x4c, 0x8b, 0xd1,
    0xb8, ...le32(ssn),
    0x0f, 0x34, // sysenter
    0xc3,
  ]);
  const r = await runShellcode(blob, { os: "win", yara: false });
  assert.equal(r.entry.status, "ok", JSON.stringify(r.entry));
  assert.ok(r.apiTrace.byName.NtClose);
});

// ---------------------------------------------------------------------------
// Clean trap stops
// ---------------------------------------------------------------------------

test("win: int3 stops cleanly with a reason", async () => {
  const r = await runShellcode(Uint8Array.from([0xb8, 0x07, 0x00, 0x00, 0x00, 0xcc]), { os: "win", yara: false });
  assert.equal(r.entry.status, "stopped");
  assert.match(r.entry.stopReason, /int3/);
  assert.equal(r.entry.retval, undefined, "stopped before the ret");
});

test("win: ud2 and int 2d stop cleanly", async () => {
  const ud2 = await runShellcode(Uint8Array.from([0x0f, 0x0b]), { os: "win", yara: false });
  assert.equal(ud2.entry.status, "stopped");
  assert.match(ud2.entry.stopReason, /ud2/);
  const int2d = await runShellcode(Uint8Array.from([0xcd, 0x2d]), { os: "win", yara: false });
  assert.equal(int2d.entry.status, "stopped");
  assert.match(int2d.entry.stopReason, /anti-debug/);
});

test("win: infinite loop reports a timeout stall", async () => {
  const r = await runShellcode(Uint8Array.from([0xeb, 0xfe]), { os: "win", maxSteps: 2000, yara: false });
  assert.equal(r.entry.status, "timeout");
  assert.ok(r.stall, "stall block present");
  assert.ok(r.entry.steps >= 2000);
});

// ---------------------------------------------------------------------------
// Flagship: PEB walk + EAT walk + ROR13 hash resolve -> VirtualAlloc
// ---------------------------------------------------------------------------

test("win: PEB walk + ROR13 EAT hash resolves and calls VirtualAlloc", async () => {
  const TARGET = "VirtualAlloc";
  let h = 0;
  for (let i = 0; i < TARGET.length; i++) {
    h = (((h >>> 13) | (h << 19)) + TARGET.charCodeAt(i)) >>> 0;
  }
  const a = asm();
  a.db(
    0x65, 0x48, 0x8b, 0x04, 0x25, 0x60, 0x00, 0x00, 0x00, // mov rax, gs:[0x60] ; PEB
    0x48, 0x8b, 0x40, 0x18, // mov rax, [rax+0x18] ; Ldr
    0x48, 0x8b, 0x40, 0x20, // mov rax, [rax+0x20] ; InMemoryOrder head -> e0 links (sample.bin)
    0x48, 0x8b, 0x00, // mov rax, [rax] ; e1 = ntdll.dll links
    0x48, 0x8b, 0x00, // mov rax, [rax] ; e2 = kernel32.dll links
    0x48, 0x8b, 0x58, 0x20, // mov rbx, [rax+0x20] ; DllBase
    0x48, 0x8b, 0x43, 0x3c, // mov rax, [rbx+0x3c] ; e_lfanew
    0x8b, 0x84, 0x03, 0x88, 0x00, 0x00, 0x00, // mov eax, [rbx+rax+0x88] ; export dir RVA
    0x48, 0x8d, 0x3c, 0x03, // lea rdi, [rbx+rax] ; export dir
    0x8b, 0x47, 0x20, // mov eax, [rdi+0x20] ; AddressOfNames RVA
    0x48, 0x8d, 0x34, 0x03, // lea rsi, [rbx+rax] ; names array
    0x49, 0x89, 0xf3, // mov r11, rsi ; names base
    0x8b, 0x4f, 0x18, // mov ecx, [rdi+0x18] ; NumberOfNames
    0x41, 0xb8, ...le32(h), // mov r8d, ror13("VirtualAlloc")
  );
  a.label("name_loop");
  a.db(
    0x8b, 0x06, // mov eax, [rsi] ; name RVA
    0x48, 0x8d, 0x14, 0x03, // lea rdx, [rbx+rax] ; name VA
    0x31, 0xc0, // xor eax, eax ; hash accumulator
  );
  a.label("hash_loop");
  a.db(
    0x44, 0x0f, 0xb6, 0x0a, // movzx r9d, byte [rdx]
    0x45, 0x84, 0xc9, // test r9b, r9b
  );
  a.jz8("hash_done");
  a.db(
    0xc1, 0xc8, 0x0d, // ror eax, 13
    0x44, 0x01, 0xc8, // add eax, r9d
    0x48, 0xff, 0xc2, // inc rdx
  );
  a.jmp8("hash_loop");
  a.label("hash_done");
  a.db(0x41, 0x3b, 0xc0); // cmp eax, r8d
  a.jz8("match");
  a.db(
    0x48, 0x83, 0xc6, 0x04, // add rsi, 4 ; next name RVA
    0xff, 0xc9, // dec ecx
  );
  a.jnz8("name_loop");
  a.db(0x31, 0xc0, 0xc3); // xor eax, eax ; ret (not found -> fail loud)
  a.label("match");
  a.db(
    0x4c, 0x29, 0xde, // sub rsi, r11 ; byte offset in names array
    0x48, 0xc1, 0xee, 0x02, // shr rsi, 2 ; name index
    0x8b, 0x47, 0x24, // mov eax, [rdi+0x24] ; AddressOfNameOrdinals RVA
    0x48, 0x8d, 0x04, 0x03, // lea rax, [rbx+rax]
    0x0f, 0xb7, 0x04, 0x70, // movzx eax, word [rax+rsi*2] ; ordinal
    0x8b, 0x4f, 0x1c, // mov ecx, [rdi+0x1c] ; AddressOfFunctions RVA
    0x48, 0x8d, 0x0c, 0x0b, // lea rcx, [rbx+rcx] ; EAT
    0x8b, 0x04, 0x81, // mov eax, [rcx+rax*4] ; function RVA
    0x48, 0x8d, 0x04, 0x03, // lea rax, [rbx+rax] ; VA
    0x31, 0xc9, // xor ecx, ecx ; lpAddress = NULL
    0x48, 0xc7, 0xc2, 0x00, 0x10, 0x00, 0x00, // mov rdx, 0x1000
    0x49, 0xc7, 0xc0, 0x00, 0x30, 0x00, 0x00, // mov r8, 0x3000 (MEM_COMMIT|RESERVE)
    0x41, 0xb9, 0x40, 0x00, 0x00, 0x00, // mov r9d, 0x40 (PAGE_EXECUTE_READWRITE)
    0xff, 0xd0, // call rax
    0xc3,
  );
  const r = await runShellcode(a.bytes(), { os: "win", yara: false, name: "resolve.bin" });
  assert.equal(r.entry.status, "ok", JSON.stringify(r.entry));
  assert.ok(r.apiTrace.byName.VirtualAlloc, `VirtualAlloc not dispatched: ${Object.keys(r.apiTrace.byName).join(",")}`);
  assert.equal(r.apiTrace.byName.VirtualAlloc.count, 1);
  const va = BigInt(r.entry.retval);
  assert.ok(va >= HEAP_BASE && va < HEAP_BASE + 0x800000n, `allocated ${r.entry.retval}`);
  assert.equal(r.unmodeled.length, 0, r.unmodeled.join(","));
  // the constant is visible to static triage too
  assert.ok(r.static.apiHashes.some((x) => x.name === "VirtualAlloc"));
  // ntdll/k32 are on the module list
  assert.deepEqual(r.load.modules.map((m) => m.name), ["sample.bin", "ntdll.dll", "kernel32.dll"]);
});

// ---------------------------------------------------------------------------
// Unpacked buffer diff
// ---------------------------------------------------------------------------

test("win: self-modifying XOR decoder shows up in the unpacked diff", async () => {
  const plain = new TextEncoder().encode("HELLO-UNPACKED!!"); // 16 bytes
  const payload = Uint8Array.from(plain, (b) => b ^ 0x5a);
  const a = asm();
  a.leaRip("rdi", "payload");
  a.db(
    0xb9, 0x10, 0x00, 0x00, 0x00, // mov ecx, 16
  );
  a.label("loop");
  a.db(
    0x80, 0x37, 0x5a, // xor byte [rdi], 0x5a
    0x48, 0xff, 0xc7, // inc rdi
    0xff, 0xc9, // dec ecx
  );
  a.jnz8("loop");
  a.db(0xc3);
  a.label("payload");
  a.db(...payload);
  const r = await runShellcode(a.bytes(), { os: "win", yara: false, name: "unpack.bin" });
  assert.equal(r.entry.status, "ok", JSON.stringify(r.entry));
  assert.equal(r.unpacked.changedBytes, 16, JSON.stringify(r.unpacked.ranges));
  assert.equal(r.shellcode.unpackedBytes, 16);
  assert.equal(r.unpacked.ranges.length, 1);
  const off = r.unpacked.ranges[0].start;
  const decoded = r.unpacked.buffer.subarray(off, off + 16);
  assert.deepEqual(decoded, plain);
  assert.ok(r.unpackedHeap === null, "no heap traffic expected");
});

// ---------------------------------------------------------------------------
// Linux
// ---------------------------------------------------------------------------

test("linux raw: exit(0) via exit_group is a clean ok", async () => {
  const blob = Uint8Array.from([
    0xb8, 0xe7, 0x00, 0x00, 0x00, // mov eax, 231 (exit_group)
    0x31, 0xff, // xor edi, edi
    0x0f, 0x05, // syscall
  ]);
  const r = await runShellcode(blob, { os: "linux", yara: false });
  assert.equal(r.entry.status, "ok", JSON.stringify(r.entry));
  assert.equal(r.exited, true);
});

test("linux raw: openat/write/exit_group record file intent", async () => {
  const a = asm();
  a.leaRip("rsi", "path"); // lea rsi, [rip+path] ; pathname
  a.db(
    0x48, 0xc7, 0xc7, 0x9c, 0xff, 0xff, 0xff, // mov rdi, -100 (AT_FDCWD)
    0x48, 0xc7, 0xc2, 0x41, 0x00, 0x00, 0x00, // mov rdx, 0x41 (O_CREAT|O_WRONLY)
    0x49, 0xc7, 0xc2, 0xa4, 0x01, 0x00, 0x00, // mov r10, 0x1a4 (0644)
    0xb8, 0x01, 0x01, 0x00, 0x00, // mov eax, 257 (openat)
    0x0f, 0x05, // syscall
    0x89, 0xc7, // mov edi, eax ; fd
  );
  a.leaRip("rsi", "msg");
  a.db(
    0x48, 0xc7, 0xc2, 0x05, 0x00, 0x00, 0x00, // mov rdx, 5
    0xb8, 0x01, 0x00, 0x00, 0x00, // mov eax, 1 (write)
    0x0f, 0x05,
    0x31, 0xff, // xor edi, edi
    0xb8, 0xe7, 0x00, 0x00, 0x00, // mov eax, 231 (exit_group)
    0x0f, 0x05,
  );
  a.label("path");
  a.db(...new TextEncoder().encode("/tmp/kf-sc\0"), 0x00);
  a.label("msg");
  a.db(...new TextEncoder().encode("hello"));
  const r = await runShellcode(a.bytes(), { os: "linux", yara: false, name: "behave.bin" });
  assert.equal(r.entry.status, "ok", JSON.stringify(r.entry));
  const paths = r.artifacts.files.map((f) => f.path);
  assert.ok(paths.includes("/tmp/kf-sc"), JSON.stringify(r.artifacts.files));
  assert.ok(r.artifacts.files.some((f) => f.action === "write"), JSON.stringify(r.artifacts.files));
  assert.ok(r.syscalls.byName.openat && r.syscalls.byName.write && r.syscalls.byName.exit_group,
    Object.keys(r.syscalls.byName).join(","));
});

test("linux argv: argc is on top of the stack (_start layout)", async () => {
  const r = await runShellcode(
    Uint8Array.from([
      0x48, 0x8b, 0x04, 0x24, // mov rax, [rsp] ; argc
      0x48, 0x83, 0xec, 0x30, // sub rsp, 48 ; back to the sentinel slot
      0xc3, // ret (to the sentinel)
    ]),
    { os: "linux", convention: "argv", yara: false },
  );
  assert.equal(r.entry.status, "ok", JSON.stringify(r.entry));
  assert.equal(r.entry.retval, "0x1", "argc default = 1");
});

test("linux function: rdi receives the param buffer", async () => {
  const r = await runShellcode(
    Uint8Array.from([0x48, 0x89, 0xf8, 0xc3]), // mov rax, rdi ; ret
    { os: "linux", convention: "function", paramBytes: Uint8Array.from([9, 9]), yara: false },
  );
  assert.equal(BigInt(r.entry.retval), PARAMS_BASE);
});

// ---------------------------------------------------------------------------
// Static triage + YARA ride along
// ---------------------------------------------------------------------------

test("report carries triage facts, rules and YARA matches", async () => {
  const blob = Uint8Array.from([
    0x65, 0x48, 0x8b, 0x04, 0x25, 0x60, 0x00, 0x00, 0x00, // PEB walk
    0xb8, 0x41, 0x00, 0x00, 0x00, 0xc3,
  ]);
  const r = await runShellcode(blob, {
    os: "win",
    name: "facts.bin",
    extraYara: 'rule custom_probe { strings: $a = { 65 48 8B 04 25 } condition: $a }',
  });
  assert.equal(r.meta.kind, "shellcode");
  assert.equal(r.shellcode.os, "win");
  assert.equal(r.shellcode.pebAccess, 1);
  assert.ok(r.rules.matches.length >= 1, JSON.stringify(r.rules.matches));
  assert.ok(r.yara.matches.some((m) => m.id === "sc_peb_walk"), r.yara.matches.map((m) => m.id).join(","));
  assert.ok(r.yara.matches.some((m) => m.id === "custom_probe"), r.yara.matches.map((m) => m.id).join(","));
  assert.ok(Array.isArray(r.trace) && Array.isArray(r.events));
  assert.equal(r.unpacked.changedBytes, 0, "PEB-walk blob does not self-modify");
});

// ---------------------------------------------------------------------------
// Real-world payload regressions (user-submitted)
// ---------------------------------------------------------------------------

const hexBytes = (s) =>
  Uint8Array.from(s.trim().split(/\s+/).map((p) => parseInt(p.replace(/^0x/i, ""), 16)));

// classic WinExec("calc.exe") — PEB walk (gs:[0x60]) + InMemoryOrder x2 +
// kernel32 EAT name walk with REPE CMPSB + NOT-obfuscated strings.
const WIN_CALC = hexBytes(`
48 31 ff 48 f7 e7 65 48 8b 58 60 48 8b 5b 18 48 8b 5b 20 48 8b 1b 48 8b 1b 48 8b 5b 20
49 89 d8 8b 5b 3c 4c 01 c3 48 31 c9 66 81 c1 ff 88 48 c1 e9 08 8b 14 0b 4c 01 c2 4d 31 d2
44 8b 52 1c 4d 01 c2 4d 31 db 44 8b 5a 20 4d 01 c3 4d 31 e4 44 8b 62 24 4d 01 c4 eb 32 5b
59 48 31 c0 48 89 e2 51 48 8b 0c 24 48 31 ff 41 8b 3c 83 4c 01 c7 48 89 d6 f3 a6 74 05 48
ff c0 eb e6 59 66 41 8b 04 44 41 8b 04 82 4c 01 c0 53 c3 48 31 c9 80 c1 07 48 b8 0f a8 96
91 ba 87 9a 9c 48 f7 d0 48 c1 e8 08 50 51 e8 b0 ff ff ff 49 89 c6 48 31 c9 48 f7 e1 50 48
b8 9c 9e 93 9c d1 9a 87 9a 48 f7 d0 50 48 89 e1 48 ff c2 48 83 ec 20 41 ff d6`);

// classic execve("/bin//sh", NULL, NULL) — cdq + syscall
const LIN_EXECVE = hexBytes(`48 31 f6 56 48 bf 2f 62 69 6e 2f 2f 73 68 57 54 5f b0 3b 99 0f 05`);

test('win: real calc shellcode (PEB walk + name lookup) calls WinExec("calc.exe")', async () => {
  const r = await runShellcode(WIN_CALC, {
    os: "win", convention: "raw", name: "calc.bin", yara: false, autoHybridFallback: false,
  });
  assert.ok(r.apiTrace.byName.WinExec, `WinExec missing: ${JSON.stringify(r.entry)}`);
  assert.match(r.traceText, /WinExec\("calc\.exe"/, r.traceText);
  assert.equal(r.entry.status, "stopped", JSON.stringify(r.entry));
  assert.match(r.entry.stopReason ?? "", /int3/, "tail call falls into int3 padding");
});

test("win: same payload on unicorn/hybrid (thunk region must be mapped)", async () => {
  const { HybridCpuBackend } = await import("@kernelforge/ntsim-unicorn/src/hybrid.mjs");
  const r = await runShellcode(WIN_CALC, {
    os: "win", convention: "raw", name: "calc.bin", yara: false, autoHybridFallback: false,
    makeBackend: async () => HybridCpuBackend.create(null),
  });
  assert.match(r.traceText ?? "", /WinExec\("calc\.exe"/, `hybrid failed: ${JSON.stringify(r.entry)}`);
  assert.equal(r.entry.status, "stopped", JSON.stringify(r.entry));
  assert.match(r.entry.stopReason ?? "", /int3/);
});

test('linux: execve("/bin//sh") payload stops cleanly and records the process', async () => {
  const r = await runShellcode(LIN_EXECVE, {
    os: "linux", convention: "raw", yara: false, autoHybridFallback: false,
  });
  assert.equal(r.entry.status, "stopped", JSON.stringify(r.entry));
  assert.match(r.entry.stopReason ?? "", /execve/);
  assert.ok(r.syscalls.byName.execve, JSON.stringify(r.syscalls));
  assert.match(r.traceText, /execve/);
  const procs = r.artifacts.processes ?? [];
  assert.ok(procs.some((p) => p.action === "execve" && /\/bin\/+.*sh/.test(p.path ?? "")), JSON.stringify(procs));
});

test("linux: execve payload on hybrid (syscall must not reach the core)", async () => {
  const { HybridCpuBackend } = await import("@kernelforge/ntsim-unicorn/src/hybrid.mjs");
  const r = await runShellcode(LIN_EXECVE, {
    os: "linux", convention: "raw", yara: false, autoHybridFallback: false,
    makeBackend: async () => HybridCpuBackend.create(null),
  });
  assert.equal(r.entry.status, "stopped", JSON.stringify(r.entry));
  assert.match(r.traceText ?? "", /execve/);
});
