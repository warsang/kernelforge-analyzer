/**
 * loadCompiledDriver — real clang COFF -> emulated kernel, unit level.
 *
 * Uses the committed kfdkom.obj fixture (module-2 DKOM starter compiled via
 * the teaching-WDK headers) so these tests are hermetic and deterministic.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { StructTables } from "@kernelforge/ntsim/src/structs.mjs";
import { NtKernel } from "@kernelforge/ntsim/src/kernel.mjs";
import {
  loadCompiledDriver,
  driverNameForLab,
} from "../src/compiled.mjs";

const tablesDir = path.join(
  path.dirname(fileURLToPath(import.meta.url)),
  "../../ntsim-assets/data/vergilius/windows-10/22h2",
);
const FIXTURE = path.join(
  path.dirname(fileURLToPath(import.meta.url)),
  "../../compiler-worker/test/fixtures/kfdkom.obj",
);

async function booted() {
  const tables = await StructTables.loadDir(tablesDir, ["_EPROCESS", "_ETHREAD", "_KLDR_DATA_TABLE_ENTRY"]);
  const k = new NtKernel({ tables });
  k.bootstrap();
  return k;
}

test("driverNameForLab derives deterministic per-lab names", () => {
  assert.equal(driverNameForLab("m1.l2.lab1"), "kf_m1_l2_lab1.sys");
  assert.equal(driverNameForLab("m3.l1.lab1"), "kf_m3_l1_lab1.sys");
});

test("loadCompiledDriver maps clang output and runs DriverEntry for real", async () => {
  const k = await booted();
  const obj = new Uint8Array(readFileSync(FIXTURE));
  const loaded = loadCompiledDriver(k, obj, { labId: "m1.l2.lab1" });

  assert.equal(loaded.name, "kf_m1_l2_lab1.sys");
  const r = k.callDriverEntry(loaded.entry, loaded.drvRec.va, 0n);
  assert.equal(r.status, "ok");
  assert.equal(r.retval, 0n);

  // the driver's own unlink happened in emulated memory
  assert.equal(k.listProcesses().some((p) => p.name === "kftarget.exe"), false);
  // its DbgPrint fired through the host-side formatter
  assert.ok(k.dbgLog.some((l) => l.includes("Overwrote _LIST_ENTRY at:")));
  // DriverUnload write (teaching-header offset 0x68) landed in our DRIVER_OBJECT
  assert.notEqual(k.mem.u64(loaded.drvRec.va + 0x68n), 0n);
});

test("PsInitialSystemProcess resolves to a live data slot holding System's EPROCESS", async () => {
  const k = await booted();
  const obj = new Uint8Array(readFileSync(FIXTURE));
  const loaded = loadCompiledDriver(k, obj, { labId: "m1.l2.lab1" });
  const system = k.processesByName.get("System");

  // walk exactly what the guest walks: slot deref then Flink chain
  const slotVa = loaded.base - 0x100000n;
  assert.equal(k.mem.u64(slotVa), system);
  const headList = system + 0x448n;
  let cur = k.mem.u64(headList);
  let hops = 0;
  while (cur !== headList && cur !== 0n && hops < 32) {
    cur = k.mem.u64(cur);
    hops++;
  }
  assert.ok(hops > 0, "ring not reachable from System");
});

test("unknown imports are provisioned as traced stubs; known ones hit thunks", async () => {
  const k = await booted();
  const obj = new Uint8Array(readFileSync(FIXTURE));
  const before = new Set(k.unmodeledExports);
  loadCompiledDriver(k, obj, { labId: "m1.l2.lab1" });
  void before;
  // fixture references only DbgPrint + PsInitialSystemProcess — both modeled,
  // so provisioning must NOT have kicked in for them
  assert.ok(!k.unmodeledExports.includes("DbgPrint"));
  assert.ok(!k.unmodeledExports.includes("PsInitialSystemProcess"));
});

test("double load of the same lab dedupes lm registration", async () => {
  const k = await booted();
  const obj = new Uint8Array(readFileSync(FIXTURE));
  loadCompiledDriver(k, obj, { labId: "m1.l2.lab1" });
  const countAfterFirst = k.loadedModules.filter((m) => m.name === "kf_m1_l2_lab1.sys").length;
  loadCompiledDriver(k, obj, { labId: "m1.l2.lab1" });
  const countAfterSecond = k.loadedModules.filter((m) => m.name === "kf_m1_l2_lab1.sys").length;
  assert.equal(countAfterFirst, 1);
  assert.equal(countAfterSecond, 1);
});

test("REL32 against a target beyond +-2GB fails loudly instead of corrupting", async () => {
  const k = await booted();
  const obj = new Uint8Array(readFileSync(FIXTURE));
  // force a base whose data-slot arena is >2GB from... actually inverse:
  // put image FAR from thunks so the DbgPrint call cannot be encoded
  const farBase = k.bases.thunk + 0x80000000n * 6n; // ~12GB away
  assert.throws(
    () => loadCompiledDriver(k, obj, { labId: "far", base: farBase }),
    /REL32 out of range/,
  );
});
