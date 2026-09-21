/**
 * snapshot.mjs — the fuzz/concolic determinism backbone must rewind the new
 * arch (MSR/TSC), diag and callback state alongside memory/CPU.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { fileURLToPath } from "node:url";
import path from "node:path";

import { NtKernel } from "@kernelforge/ntsim/src/kernel.mjs";
import { StructTables } from "@kernelforge/ntsim/src/structs.mjs";
import { captureSnapshot, restoreSnapshot } from "../src/snapshot.mjs";

const tablesDir = path.join(
  path.dirname(fileURLToPath(import.meta.url)),
  "../../ntsim-assets/data/vergilius/windows-10/22h2",
);

test("snapshot restore rewinds the virtual TSC stream", () => {
  const kernel = new NtKernel({ arch: {} });
  const snap = captureSnapshot(kernel);

  const first = [kernel.arch.rdtsc(), kernel.arch.rdtsc(), kernel.arch.rdtsc()];
  const msrBeforeSnapshot = kernel.arch.rdmsr(0x3an);

  restoreSnapshot(kernel, snap);
  const replay = [kernel.arch.rdtsc(), kernel.arch.rdtsc(), kernel.arch.rdtsc()];
  assert.deepEqual(replay, first, "RDTSC sequence is reproducible after restore");
  assert.equal(kernel.arch.rdmsr(0x3an), msrBeforeSnapshot);

  // an MSR write made after the snapshot must be rolled back too
  const snap2 = captureSnapshot(kernel);
  kernel.arch.wrmsr(0x3an, 0n);
  kernel.arch.wrmsr(0x1a0n, 0x1234n);
  restoreSnapshot(kernel, snap2);
  assert.equal(kernel.arch.rdmsr(0x3an), 1n, "FEATURE_CONTROL write rolled back");
  assert.equal(kernel.arch.rdmsr(0x1a0n), 0x4000000001n, "MISC_ENABLE write rolled back");
});

test("snapshot restore rewinds diag counters and callback logs", async () => {
  const tables = await StructTables.loadDir(tablesDir, ["_EPROCESS"]);
  const kernel = new NtKernel({ arch: {}, diag: {}, tables });
  const snap = captureSnapshot(kernel);

  kernel.diag.classify(0xfffff78000000000n, 4, "read");
  kernel.obEvents.push({ synthetic: true });
  kernel.cmEvents.push({ synthetic: true });
  kernel.irpCompletions = kernel.irpCompletions ?? [];
  kernel.irpCompletions.push({ synthetic: true });

  restoreSnapshot(kernel, snap);
  assert.equal(kernel.diag.counts.unmappedReads, 0);
  assert.equal(kernel.diag.events.length, snap.diag.eventsLen);
  assert.equal(kernel.obEvents.length, 0);
  assert.equal(kernel.cmEvents.length, 0);
  assert.equal(kernel.irpCompletions.length, 0);
});
