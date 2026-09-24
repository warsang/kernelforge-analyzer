/**
 * shellcode.test.mjs — triage layer for raw x64 shellcode: SHELLCODE_RULES,
 * SHELLCODE_YARA, shellcodeFacts and the SHELLCODE FACTS state-text line.
 */
import { test } from "node:test";
import assert from "node:assert/strict";

import {
  SHELLCODE_RULES, SHELLCODE_YARA, shellcodeFacts, stateTextFromUserland,
  scanRules, matchRuleIds, scanWithYaraX, normalizeYaraMatches,
} from "../src/index.mjs";

/** synthetic windows shellcode-ish buffer with every signal we care about */
function winBlob() {
  return new Uint8Array([
    0x65, 0x48, 0x8B, 0x04, 0x25, 0x60, 0x00, 0x00, 0x00, // mov rax, gs:[0x60]
    0xE8, 0x00, 0x00, 0x00, 0x00,                          // call $+5 (get-PC)
    0x58,                                                  // pop rax
    0xC1, 0xC8, 0x0D,                                      // ror eax, 13
    0xC1, 0xC0, 0x07,                                      // rol eax, 7
    0x54, 0xCA, 0xAF, 0x91,                                // ror13("VirtualAlloc")
    0x98, 0xFE, 0x8A, 0x0E,                                // ror13("WinExec")
    0x0F, 0x05,                                            // syscall
    0xCD, 0x2E,                                            // int 2e
    // embedded PE: MZ ... e_lfanew=0x40 ... PE\0\0
    0x4D, 0x5A, ...Array(58).fill(0), 0x40, 0x00, 0x00, 0x00,
    0x50, 0x45, 0x00, 0x00,
    ...new TextEncoder().encode("https://evil.test/a.exe cmd.exe"),
  ]);
}

test("shellcode rule pack flags the PIC/PEB/hash/syscall signals", () => {
  const buf = winBlob();
  const ids = matchRuleIds(buf, SHELLCODE_RULES);
  for (const want of [
    "sc_pic_getpc", "sc_peb_walk", "sc_eat_hash_loop", "sc_api_hash_constants",
    "sc_syscall_stubs", "sc_embedded_pe", "sc_stage_strings",
  ]) {
    assert.ok(ids.includes(want), `missing ${want} in ${ids.join(",")}`);
  }
  const res = scanRules(buf, SHELLCODE_RULES);
  assert.ok(res.matches.length >= 7);
  // a clean buffer matches nothing
  const clean = new Uint8Array(32).fill(0x90);
  assert.deepEqual(matchRuleIds(clean, SHELLCODE_RULES), []);
});

test("SHELLCODE_YARA compiles and matches the same signals", async () => {
  const buf = winBlob();
  const res = await scanWithYaraX(buf, SHELLCODE_YARA, { throwOnError: true });
  const ids = normalizeYaraMatches(res).map((m) => m.id);
  for (const want of [
    "sc_pic_getpc", "sc_peb_walk", "sc_api_hash_constants",
    "sc_syscall_stubs", "sc_embedded_pe", "sc_stage_strings",
  ]) {
    assert.ok(ids.includes(want), `missing ${want} in ${ids.join(",")}`);
  }
  const clean = await scanWithYaraX(new Uint8Array(32).fill(0x90), SHELLCODE_YARA);
  assert.deepEqual(normalizeYaraMatches(clean).map((m) => m.id), []);
});

test("shellcodeFacts reports pattern counts, embedded PE and api hashes", () => {
  const f = shellcodeFacts(winBlob());
  assert.equal(f.getpc, 1);
  assert.equal(f.pebAccess, 1);
  assert.equal(f.eatHash, 1);
  assert.equal(f.syscalls.syscall, 1);
  assert.equal(f.syscalls.int2e, 1);
  assert.equal(f.embeddedPe, 33, "MZ offset in the synthetic blob");
  assert.deepEqual(f.apiHashes.map((h) => h.name).sort(), ["VirtualAlloc", "WinExec"]);
  assert.ok(f.strings.some((s) => s.value.includes("evil.test")));
  assert.ok(f.entropyChunks.length >= 1);
  assert.ok(f.entropy > 3, `entropy ${f.entropy}`);
});

test("shellcodeFacts on a NOP sled is quiet", () => {
  const f = shellcodeFacts(new Uint8Array(64).fill(0x90));
  assert.equal(f.getpc, 0);
  assert.equal(f.pebAccess, 0);
  assert.equal(f.embeddedPe, null);
  assert.equal(f.apiHashes.length, 0);
  assert.equal(f.entropy, 0);
});

test("stateTextFromUserland renders the SHELLCODE FACTS line", () => {
  const buf = winBlob();
  const facts = shellcodeFacts(buf);
  facts.os = "win";
  facts.unpackedBytes = 1234;
  const report = {
    meta: { kind: "shellcode", name: "sc.bin", size: buf.length },
    shellcode: facts,
    rules: { matches: [{ id: "sc_peb_walk" }] },
  };
  const { state, included } = stateTextFromUserland(report, { maxTokens: 700 });
  assert.match(state, /SHELLCODE FACTS: os=win/);
  assert.match(state, /api_hashes=\[VirtualAlloc:ror13/);
  assert.match(state, /embedded_pe=0x21/);
  assert.match(state, /unpacked=1234B/);
  assert.ok(included.includes("shellcodeFacts"));
});
