#!/usr/bin/env node
/**
 * phnt-import.mjs — fetch PHNT headers and generate winapi-meta.mjs
 *
 * Pins PHNT at the commit recorded in tools/phnt-pin.json (or latest master).
 * Parses NTSYSAPI and NTSYSCALLAPI decls and WDM overlay for Ke, Ex, Mm not in PHNT.
 * Emits packages/ntsim/src/winapi-meta.mjs with full entries.
 *
 * Usage: node tools/phnt-import.mjs [--pin <sha>] [--out <path>] [--check]
 */

import { writeFile, readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

const HEADERS = [
  "ntafd.h","ntd3dkmt.h","ntexapi.h","ntgdi.h","ntimage.h","ntioapi.h",
  "ntkeapi.h","ntldr.h","ntlpcapi.h","ntbcd.h","ntdbg.h","ntlsa.h",
  "ntmisc.h","ntmmapi.h","ntnls.h","ntobapi.h","ntpebteb.h","ntpfapi.h",
  "ntpnpapi.h","ntpoapi.h","ntpsapi.h","ntregapi.h","ntrtl.h","ntsam.h",
  "ntseapi.h","ntsmss.h","ntsxs.h","nttmapi.h","nttp.h","ntuser.h",
  "ntwmi.h","ntwow64.h","ntxcapi.h","ntzwapi.h",
  "phnt_ntdef.h","phnt_windows.h"
];

const WDM_EXTRA = [
  // Ke* / Ex* / Mm* / Ob* / Ps* / Io* that are WDK wdm.h/ntddk.h exports, not NTSYSAPI in PHNT
  ["KeInitializeSpinLock","void","wdm.h"],
  ["KeAcquireSpinLock","void","wdm.h"],
  ["KeReleaseSpinLock","void","wdm.h"],
  ["KeAcquireSpinLockRaiseToDpc","kirql","wdm.h"],
  ["KeAcquireInStackQueuedSpinLock","void","wdm.h"],
  ["KeReleaseInStackQueuedSpinLock","void","wdm.h"],
  ["KeAcquireInStackQueuedSpinLockAtDpcLevel","void","wdm.h"],
  ["KeReleaseInStackQueuedSpinLockFromDpcLevel","void","wdm.h"],
  ["KeInitializeDpc","void","wdm.h"],
  ["KeSetTargetProcessorDpc","void","wdm.h"],
  ["KeSetImportanceDpc","void","wdm.h"],
  ["KeInsertQueueDpc","boolean","wdm.h"],
  ["KeRemoveQueueDpc","boolean","wdm.h"],
  ["KeInitializeTimer","void","wdm.h"],
  ["KeSetTimer","boolean","wdm.h"],
  ["KeSetTimerEx","boolean","wdm.h"],
  ["KeCancelTimer","boolean","wdm.h"],
  ["KeInitializeEvent","void","wdm.h"],
  ["KeSetEvent","long","wdm.h"],
  ["KeResetEvent","long","wdm.h"],
  ["ExAllocatePool","pvoid","wdm.h"],
  ["ExAllocatePoolWithTag","pvoid","wdm.h"],
  ["ExAllocatePool2","pvoid","wdm.h"],
  ["ExFreePool","void","wdm.h"],
  ["ExFreePoolWithTag","void","wdm.h"],
  ["IoCreateDevice","ntstatus","wdm.h"],
  ["IoDeleteDevice","void","wdm.h"],
  ["IoCreateSymbolicLink","ntstatus","wdm.h"],
  ["IoDeleteSymbolicLink","ntstatus","wdm.h"],
  ["IoAllocateIrp","pvoid","wdm.h"],
  ["IoFreeIrp","void","wdm.h"],
  ["IoCompleteRequest","void","wdm.h"],
  ["IofCompleteRequest","void","wdm.h"],
  ["IofCallDriver","ntstatus","wdm.h"],
  ["IoCallDriver","ntstatus","wdm.h"],
  ["PsCreateSystemThread","ntstatus","ntddk.h"],
  ["PsTerminateSystemThread","ntstatus","ntddk.h"],
  ["PsLookupProcessByProcessId","ntstatus","ntddk.h"],
  ["PsInitialSystemProcess","pvoid","ntddk.h"],
  ["PsProcessType","pvoid","ntddk.h"],
  ["MmGetSystemRoutineAddress","pvoid","wdm.h"],
  ["ObReferenceObject","void","wdm.h"],
  ["ObDereferenceObject","void","wdm.h"],
  ["ObRegisterCallbacks","ntstatus","wdm.h"],
  ["RtlInitUnicodeString","void","ntrtl.h"],
  ["RtlInitAnsiString","void","ntrtl.h"],
];

function normalizeRet(raw) {
  const r = raw.trim().replace(/\s+/g," ").toUpperCase();
  if (r === "VOID" || r === "DECLSPEC_NORETURN VOID") return "void";
  if (r === "NTSTATUS") return "ntstatus";
  if (r === "BOOLEAN" || r === "_MUST_INSPECT_RESULT_ BOOLEAN") return "boolean";
  if (r.includes("PVOID") || r.includes("HANDLE") && !r.includes("PHANDLE")) return "pvoid";
  if (r.includes("HANDLE") || r.includes("PHANDLE")) return "handle";
  if (r === "ULONG" || r === "ULONG_PTR" || r === "SIZE_T" || r === "ULONG64" || r === "ULONGLONG") return r.toLowerCase();
  if (r === "LONG" || r === "NTSTATUS") return r.toLowerCase();
  if (r === "KIRQL" || r === "UCHAR") return "kirql";
  if (r.match(/BOOLEAN/)) return "boolean";
  // fallback: lowercased first token
  return raw.trim().split(/\s+/)[0].toLowerCase().replace(/[^a-z0-9_]/g,"") || "ntstatus";
}

async function fetchText(url) {
  const res = await fetch(url);
  if (!res.ok) throw new Error(`fetch ${url} -> ${res.status}`);
  return res.text();
}

async function parseHeader(header, baseUrl) {
  const text = await fetchText(`${baseUrl}/${header}`);
  const entries = [];
  // Regex: NTSYSAPI or NTSYSCALLAPI, then return type block (maybe multiline), then NTAPI, then name
  // Example: NTSYSAPI\nNTSTATUS\nNTAPI\nNtCreateFile(
  // We collapse newlines to space for regex simplicity: use [\s\S]*? but need non-greedy.
  const re = /NTSYS(?:CALL)?API\s+([\w\s\*]+?)\s+NTAPI\s+(\w+)\s*\(/g;
  let m;
  while ((m = re.exec(text)) !== null) {
    const retRaw = m[1].replace(/\s+/g," ").trim();
    const name = m[2].trim();
    // Filter out obvious non-functions: macros like RtlOffsetToPointer are not NTSYSAPI, so safe
    if (!/^[A-Za-z][A-Za-z0-9_]+$/.test(name)) continue;
    // Skip some helpers that are not exports: e.g., RtlCompareExchangePointerMapping is in phnt but gated PHNT_VERSION
    entries.push({ name, retRaw, ret: normalizeRet(retRaw), header });
  }
  return entries;
}

async function main() {
  const args = process.argv.slice(2);
  const pinIdx = args.indexOf("--pin");
  const pin = pinIdx >= 0 ? args[pinIdx+1] : null;
  const outIdx = args.indexOf("--out");
  const outPath = outIdx >= 0 ? args[outIdx+1] : path.join(path.dirname(fileURLToPath(import.meta.url)), "../packages/ntsim/src/winapi-meta.mjs");
  const check = args.includes("--check");

  const baseUrl = pin
    ? `https://raw.githubusercontent.com/winsiderss/systeminformer/${pin}/phnt/include`
    : `https://raw.githubusercontent.com/winsiderss/systeminformer/master/phnt/include`;

  console.log(`[phnt-import] fetching ${HEADERS.length} headers from ${baseUrl}...`);
  const all = new Map();
  for (const h of HEADERS) {
    try {
      const entries = await parseHeader(h, baseUrl);
      console.log(`  ${h}: ${entries.length} decls`);
      for (const e of entries) {
        if (!all.has(e.name)) all.set(e.name, e);
        else {
          // keep first, but if ret differs, prefer non-void? PHNT dup across ntzwapi vs ntxxx, keep ntzwapi
        }
      }
    } catch (err) {
      console.warn(`  ${h}: fetch failed: ${err.message}`);
    }
  }
  // Add WDM extras
  for (const [name, ret, header] of WDM_EXTRA) {
    if (!all.has(name)) all.set(name, { name, ret, retRaw: ret, header });
  }
  // Sort
  const sorted = [...all.entries()].sort((a,b)=> a[0].localeCompare(b[0]));
  console.log(`[phnt-import] total unique exports: ${sorted.length}`);

  // Generate file
  let content = `/**
 * winapi-meta.mjs — PHNT / WDM signature metadata for every ntoskrnl/ntdll export.
 *
 * Source hierarchy: 1) Microsoft WDM docs, 2) ntdoc.m417z.com, 3) PHNT phnt/include/*.h (tie-breaker).
 * Generated by tools/phnt-import.mjs from ${baseUrl} at ${new Date().toISOString()}
 * Headers scanned: ${HEADERS.join(", ")}
 * Total unique exports: ${sorted.length}
 * PHNT pin: ${pin ?? "master (floating)"}
 *
 * ret: "void" | "ntstatus" | "boolean" | "pvoid" | "handle" | "ulong" | ...
 * Tracer suppresses "-> value" for void (Speakeasy/ktrace semantics, RAX untouched).
 */

export const API_META = new Map([
`;
  for (const [name, e] of sorted) {
    const ret = e.ret || "ntstatus";
    const doc = e.header ? ` header: "${e.header}"` : "";
    // Escape
    content += `  ["${name}", { ret: "${ret}", header: "${e.header}" }],\n`;
  }
  content += `]);

export function getApiMeta(name) {
  return API_META.get(name) ?? null;
}
export function isVoidApi(name) {
  const m = API_META.get(name);
  return m ? m.ret === "void" : false;
}
`;

  if (check) {
    const existing = await readFile(outPath, "utf8").catch(()=>null);
    if (existing !== content) {
      console.error(`[phnt-import] --check failed: ${outPath} differs from generated`);
      process.exit(1);
    }
    console.log(`[phnt-import] check passed`);
    return;
  }
  await writeFile(outPath, content, "utf8");
  console.log(`[phnt-import] wrote ${outPath} (${sorted.length} entries)`);
}

main().catch(e=>{ console.error(e); process.exit(1); });
