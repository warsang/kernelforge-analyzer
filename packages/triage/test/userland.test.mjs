/**
 * Userland triage: ELF static facts, PE/ELF/LKM rule packs, YARA packs,
 * userland state text.
 */
import { test } from "node:test";
import assert from "node:assert/strict";

import {
  parseElfStatic, PE_USERLAND_RULES, ELF_USERLAND_RULES, LKM_RULES,
  scanRules, matchRuleIds, PE_USERLAND_YARA, ELF_USERLAND_YARA, LKM_YARA,
  scanWithYaraX, normalizeYaraMatches, stateTextFromUserland,
} from "../src/index.mjs";

/** Minimal ET_EXEC ELF64 with one R+X PT_LOAD (code at 0x1000, data at 0x1080). */
function buildElf(code, { entryOff = 0x1000, data = new Uint8Array(0), dataOff = 0x1080 } = {}) {
  const segVaddr = 0x400000;
  const fileSize = Math.max(0x2000, dataOff + data.length);
  const buf = new Uint8Array(fileSize);
  const dv = new DataView(buf.buffer);
  buf.set([0x7f, 0x45, 0x4c, 0x46, 2, 1, 1, 0], 0);
  dv.setUint16(16, 2, true);
  dv.setUint16(18, 0x3e, true);
  dv.setUint32(20, 1, true);
  dv.setBigUint64(24, BigInt(segVaddr + entryOff), true);
  dv.setBigUint64(32, 0x40n, true);
  dv.setUint16(52, 64, true);
  dv.setUint16(54, 56, true);
  dv.setUint16(56, 1, true);
  dv.setUint32(0x40, 1, true);
  dv.setUint32(0x44, 5, true);
  dv.setBigUint64(0x48, 0n, true);
  dv.setBigUint64(0x50, BigInt(segVaddr), true);
  dv.setBigUint64(0x58, BigInt(segVaddr), true);
  dv.setBigUint64(0x60, BigInt(fileSize), true);
  dv.setBigUint64(0x68, BigInt(fileSize), true);
  dv.setBigUint64(0x70, 0x1000n, true);
  buf.set(code, entryOff);
  if (data.length) buf.set(data, dataOff);
  return buf;
}

test("parseElfStatic reports format facts and anomalies", () => {
  const st = parseElfStatic(buildElf(new Uint8Array([0xc3]), { data: new TextEncoder().encode("https://evil.test/x\0") }));
  assert.equal(st.format, "elf");
  assert.equal(st.type, "EXEC");
  assert.equal(st.machine, "x86-64");
  assert.equal(st.isPie, false);
  assert.ok(st.ssdeep.startsWith("3:"));
  assert.ok(Array.isArray(st.sections));
  assert.equal(st.stripped, true);
  assert.ok(st.anomalies.some((a) => a.kind === "stripped"));
  assert.ok(st.anomalies.some((a) => a.kind === "no_relro"));
  assert.ok(st.strings.interesting.some((s) => s.kind === "url"));
  assert.equal(st.entry, "0x401000");
});

test("PE userland rule pack flags injection, credentials and ransomware", () => {
  const bytes = new TextEncoder().encode(
    "OpenProcess\0VirtualAllocEx\0WriteProcessMemory\0CreateRemoteThread\0lsass.exe\0MiniDumpWriteDump\0vssadmin\0delete shadows\0");
  const ids = matchRuleIds(bytes, PE_USERLAND_RULES);
  assert.ok(ids.includes("pe_process_injection"), ids.join(","));
  assert.ok(ids.includes("pe_credential_access"));
  assert.ok(ids.includes("pe_ransomware_behavior"));
  const clean = new TextEncoder().encode("GetWindowText\0MessageBoxA\0LoadStringA\0");
  assert.ok(!matchRuleIds(clean, PE_USERLAND_RULES).includes("pe_process_injection"));
});

test("ELF userland rule pack flags shells, miners and preload rootkits", () => {
  const bytes = new TextEncoder().encode(
    "/dev/tcp/10.0.0.1/4444\0stratum+tcp://pool.example:3333\0/etc/ld.so.preload\0LD_PRELOAD\0memfd_create\0");
  const ids = matchRuleIds(bytes, ELF_USERLAND_RULES);
  assert.ok(ids.includes("elf_reverse_shell"), ids.join(","));
  assert.ok(ids.includes("elf_miner"));
  assert.ok(ids.includes("elf_ld_preload_persistence"));
  assert.ok(ids.includes("elf_memfd_execution"));
  const clean = new TextEncoder().encode("glibc 2.31\0libstdc++\0Usage: tool [options]\0");
  assert.equal(matchRuleIds(clean, ELF_USERLAND_RULES).length, 0);
});

test("LKM rule pack flags kallsyms/syscall hooks and credential escalation", () => {
  const bytes = new TextEncoder().encode(
    "kallsyms_lookup_name\0sys_call_table\0native_write_cr0\0commit_creds\0prepare_kernel_cred\0register_kprobe\0");
  const ids = matchRuleIds(bytes, LKM_RULES);
  assert.ok(ids.includes("lkm_kallsyms_resolution"), ids.join(","));
  assert.ok(ids.includes("lkm_syscall_hooking"));
  assert.ok(ids.includes("lkm_cred_escalation"));
  assert.ok(ids.includes("lkm_ftrace_kprobe"));
  const clean = new TextEncoder().encode("GPL\0author=me\0description=usb printer driver\0");
  assert.equal(matchRuleIds(clean, LKM_RULES).length, 0);
});

test("YARA-X packs compile and match for PE/ELF/LKM", async () => {
  const enc = new TextEncoder();
  const pe = await scanWithYaraX(enc.encode("OpenProcess WriteProcessMemory CreateRemoteThread"), PE_USERLAND_YARA);
  assert.ok(normalizeYaraMatches(pe).some((m) => m.id === "pe_injection_chain"));
  const elf = await scanWithYaraX(enc.encode("stratum+tcp://pool:3333 /etc/ld.so.preload"), ELF_USERLAND_YARA);
  const elfIds = normalizeYaraMatches(elf).map((m) => m.id);
  assert.ok(elfIds.includes("elf_crypto_miner"), elfIds.join(","));
  assert.ok(elfIds.includes("elf_ld_preload_rootkit"));
  const lkm = await scanWithYaraX(enc.encode("kallsyms_lookup_name native_write_cr0 sys_call_table"), LKM_YARA);
  assert.ok(normalizeYaraMatches(lkm).some((m) => m.id === "lkm_kallsyms_lookup"));
});

test("stateTextFromUserland renders behavior, detections and negatives", () => {
  const report = {
    meta: { kind: "userland-pe", name: "dropper.exe", size: 200_000 },
    static: {
      dllCount: 4, importCount: 60, subsystemName: "windows-gui", machineName: "x64",
      imphash: "0123456789abcdef0123456789abcdef",
      sections: [{ name: ".text" }, { name: ".rdata" }],
      anomalies: [{ kind: "high_entropy_code" }],
      packerHints: [],
      stackStrings: [{ value: "cmd.exe /c whoami" }],
      apiHashes: [{ algo: "ror13", name: "VirtualAlloc" }],
      strings: { interesting: [{ kind: "url", value: "http://evil.test/a.exe" }] },
    },
    rules: { matches: [{ id: "pe_downloader", severity: "high" }] },
    yara: {
      matches: [{ id: "pe_injection_chain", meta: { severity: "high" } }],
      community: [{ id: "MAL_STEALER_X", tags: ["MALWARE"], meta: { severity: "high" }, strings: [] }],
    },
    entry: { status: "ok", steps: 12345, retval: "0x0" },
    artifacts: {
      files: [{ action: "write", path: "C:\\Users\\kf\\AppData\\Local\\Temp\\a.exe" }],
      registry: [{ action: "set", path: "HKCU\\...\\Run", value: "Run" }],
      network: [{ action: "download", url: "http://evil.test/a.exe" }],
      processes: [{ action: "create", path: "C:\\Windows\\System32\\cmd.exe", cmdline: "cmd.exe /c whoami" }],
      commands: [],
      modules: [],
      mutexes: [],
      ptrace: [],
      debugStrings: [],
    },
    trace: [{ name: "VirtualAlloc" }, { name: "VirtualAlloc" }, { name: "CreateFileA" }],
  };
  const { state, included } = stateTextFromUserland(report, { maxTokens: 700 });
  assert.match(state, /Windows PE executable dropper\.exe/);
  assert.match(state, /DETECTIONS: pe_downloader\(high\) yara:pe_injection_chain\(high\) yara:community:MAL_STEALER_X\(high\)/);
  assert.match(state, /files_written=\[C:\\Users\\kf\\AppData\\Local\\Temp\\a\.exe\]/);
  assert.match(state, /network=\[download:http:\/\/evil\.test\/a\.exe\]/);
  assert.match(state, /registry_writes=observed/);
  assert.match(state, /TRACE: VirtualAllocx2>CreateFileA/);
  assert.ok(included.includes("behavior"));
  assert.ok(included.includes("notObserved"));
  const tight = stateTextFromUserland(report, { maxTokens: 80 });
  assert.ok(tight.chars <= tight.budget);
  assert.ok(tight.dropped.length > 0);
});
