/**
 * Host-clang smoke tests for the teaching WDK headers: replays the exact
 * driver sources that failed in issues #13 and #21 through the SAME clang
 * invocation compile-bridge.mjs uses. Skips when clang is unavailable.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { mkdtemp, writeFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { promisify } from "node:util";
import { includeDir } from "../src/wdk-headers.mjs";

const execFileP = promisify(execFile);

const haveClang = await execFileP("which", ["clang"])
  .then(() => true).catch(() => false);

async function tryCompile(name, source) {
  const dir = await mkdtemp(path.join(tmpdir(), "kf-hdrtest-"));
  try {
    const cFile = path.join(dir, "driver.c");
    const oFile = path.join(dir, "driver.obj");
    await writeFile(cFile, source);
    await execFileP("clang", [
      "--target=x86_64-pc-windows-msvc",
      "-O1", "-ffreestanding", "-fno-stack-protector",
      "-isystem", includeDir(),
      "-c", cFile, "-o", oFile,
    ], { timeout: 20000 });
    return { ok: true, stderr: "" };
  } catch (e) {
    return { ok: false, stderr: e.stderr ?? e.message };
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
}

/** issue #13: WDK-flavored forward declarations outside the headers. */
const ISSUE13_SOURCE = `#include <ntddk.h>

NTKERNELAPI HANDLE NTAPI PsGetProcessId(_In_ PEPROCESS Process);
NTKERNELAPI PCHAR NTAPI PsGetProcessImageFileName(_In_ PEPROCESS Process);

static KDPC g_lockDpc[4];

VOID CoreLockDpcRoutine(
    _In_ PKDPC Dpc,
    _In_opt_ PVOID DeferredContext,
    _In_opt_ PVOID SystemArgument1,
    _In_opt_ PVOID SystemArgument2)
{
    UNREFERENCED_PARAMETER(Dpc);
    UNREFERENCED_PARAMETER(DeferredContext);
    UNREFERENCED_PARAMETER(SystemArgument1);
    UNREFERENCED_PARAMETER(SystemArgument2);
}

NTSTATUS DriverEntry(
    _In_ PDRIVER_OBJECT  DriverObject,
    _In_ PUNICODE_STRING RegistryPath)
{
    UNREFERENCED_PARAMETER(DriverObject);
    UNREFERENCED_PARAMETER(RegistryPath);

    KIRQL oldIrql = KeRaiseIrqlToDpcLevel();
    for (ULONG cpu = 1; cpu < 4; cpu++) {
        KeInitializeDpc(&g_lockDpc[cpu], CoreLockDpcRoutine, NULL);
        KeSetTargetProcessorDpc(&g_lockDpc[cpu], (CCHAR)cpu);
        KeInsertQueueDpc(&g_lockDpc[cpu], NULL, NULL);
    }
    PEPROCESS currentProcess = PsGetCurrentProcess();
    HANDLE pid = PsGetProcessId(currentProcess);
    PCHAR processName = PsGetProcessImageFileName(currentProcess);
    DbgPrint("ATTACK-READ: [EPROCESS: %p] PID: %p | Name: %s\\n",
             (PVOID)currentProcess, pid, processName ? processName : "Unknown");
    KeLowerIrql(oldIrql);
    return STATUS_SUCCESS;
}
`;

/** issue #21 snippet 1: __readgsqword with NO explicit <intrin.h> include. */
const ISSUE21_NO_INTRIN = `#include <ntddk.h>

typedef struct _KDPC_DATA {
    LIST_ENTRY DpcListHead;
    ULONG_PTR DpcLock;
    ULONG DpcQueueDepth;
    ULONG DpcCount;
} KDPC_DATA, *PKDPC_DATA;

ULONG GetCurrentProcessorDpcDepth(VOID)
{
#if defined(_M_AMD64) || defined(__x86_64__)
    PUCHAR prcb = (PUCHAR)__readgsqword(0x20);
    PKDPC_DATA dpcData = (PKDPC_DATA)(prcb + 0x3000);
    return dpcData[0].DpcQueueDepth;
#else
    return 0;
#endif
}

NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT DriverObject,
                     _In_ PUNICODE_STRING RegistryPath)
{
    UNREFERENCED_PARAMETER(DriverObject);
    UNREFERENCED_PARAMETER(RegistryPath);
    ULONG depth = GetCurrentProcessorDpcDepth();
    DbgPrint("SENTINEL-TELEMETRY: sampled IRQL = %u queue-depth = %u\\n",
             (ULONG)KeGetCurrentIrql(), depth);
    return STATUS_SUCCESS;
}
`;

/** issue #21 snippet 2: #include <intrin.h> AFTER ntddk.h — the shim must
 *  shadow the resource-dir intrinsics header so no macro/decl clash fires. */
const ISSUE21_WITH_INTRIN = `#include <ntddk.h>
#include <intrin.h>

NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT DriverObject,
                     _In_ PUNICODE_STRING RegistryPath)
{
    UNREFERENCED_PARAMETER(DriverObject);
    UNREFERENCED_PARAMETER(RegistryPath);
    unsigned long long cr0 = __readcr0();
    unsigned long long gs = __readgsqword(0x20);
    DbgPrint("cr0=%llx gs=%llu\\n", cr0, gs);
    return STATUS_SUCCESS;
}
`;

const it = haveClang ? test : test.skip;

it("issue #13 source compiles against the teaching headers", async () => {
  const r = await tryCompile("issue13", ISSUE13_SOURCE);
  assert.ok(r.ok, `compile failed:\n${r.stderr}`);
});

it("issue #21 __readgsqword compiles without <intrin.h>", async () => {
  const r = await tryCompile("issue21a", ISSUE21_NO_INTRIN);
  assert.ok(r.ok, `compile failed:\n${r.stderr}`);
});

it("issue #21 <intrin.h> inclusion no longer clashes with wdm macros", async () => {
  const r = await tryCompile("issue21b", ISSUE21_WITH_INTRIN);
  assert.ok(r.ok, `compile failed:\n${r.stderr}`);
});
