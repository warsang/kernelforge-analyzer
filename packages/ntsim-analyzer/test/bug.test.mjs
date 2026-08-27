/**
 * bug.test.mjs — tests for Find Bugs stack (taint, sinks, worker bootstrap)
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { fileURLToPath } from "node:url";
import path from "node:path";

import { PeBuilder } from "@kernelforge/ntsim/src/pebuilder.mjs";
import { parsePe } from "@kernelforge/ntsim/src/pe.mjs";
import { StructTables } from "@kernelforge/ntsim/src/structs.mjs";
import { NtKernel, createDriverObject, initDriverObjectName, createDeviceObject, sendIrp, mapPe } from "@kernelforge/ntsim/src/index.mjs";
import { findBugsCampaign } from "../src/bug/engine.mjs";
import { TaintState } from "../src/bug/taint.mjs";
import { BugDB, makeBug } from "../src/bug/bugdb.mjs";

const tablesDir = path.join(path.dirname(fileURLToPath(import.meta.url)), "../../ntsim-assets/data/vergilius/windows-10/22h2");
const loadTables = () => StructTables.loadDir(tablesDir, ["_EPROCESS","_ETHREAD","_KLDR_DATA_TABLE_ENTRY","_KPROCESS","_LIST_ENTRY"]);

const BASE = 0xfffff80300000000n;
const u32 = (v)=>[v&0xff,(v>>8)&0xff,(v>>>16)&0xff,(v>>>24)&0xff];
const vaBytes = (v)=>{ const out=[]; let x=v; for(let i=0;i<8;i++){out.push(Number(x&0xffn)); x>>=8n;} return out; };

function buildArbitraryWriteDriver() {
  const textLen=0x400;
  const probe=new PeBuilder().addSection('.text', new Uint8Array(textLen), 0x60000020);
  const t=parsePe(probe.build(0).image).sections[0].rva;
  const handlerVa=BASE+BigInt(t+0x40);
  const text=new Uint8Array(textLen);
  text.set([0x48,0xb8,...vaBytes(handlerVa),0x48,0x89,0x81,0xe0,0,0,0,0x31,0xc0,0xc3],0x10);
  text.set([
    0x49,0x89,0xd0,
    0x49,0x8b,0x48,0x18,
    0x48,0x8b,0x01,
    0x48,0x8b,0x51,0x08,
    0x48,0x89,0x10,
    0x31,0xc0, 0x41,0x89,0x40,0x30, 0x49,0xc7,0x40,0x38,0x08,0,0,0, 0xc3,
    0xb8,0x0d,0x00,0x00,0xc0, 0x41,0x89,0x40,0x30, 0xc3
  ],0x40);
  const b=new PeBuilder(); b.addSection('.text', text, 0x60000020);
  b.addImports([{dll:'ntoskrnl.exe', funcs:['RtlCopyMemory']}]); 
  return b.build(t+0x10).image;
}

test("TaintState per-byte IDs", ()=>{
  const t = new TaintState();
  t.taintRange(0x1000n, 4);
  assert.equal(t.getByteTaint(0x1000n), 1);
  assert.equal(t.getByteTaint(0x1001n), 2);
  assert.equal(t.getByteTaint(0x1003n), 4);
  assert.equal(t.getByteTaint(0x1004n), 0);
  const r = t.getRangeTaint(0x1000n, 4);
  assert.equal(r.any, true);
  assert.deepEqual(r.ids, [1,2,3,4]);
  t.clearRange(0x1000n, 2);
  assert.equal(t.getByteTaint(0x1000n), 0);
  assert.equal(t.getByteTaint(0x1002n), 3);
});

test("StructTables serialize/deserialize for worker bootstrap (EPROCESS check)", async ()=>{
  const tables = await loadTables();
  const serialized = [...tables.types.entries()].map(([k,v])=> [k, {totalSize: v.totalSize, fieldsByName: v.fieldsByName, fields: v.fields}]);
  const { StructTables: ST2 } = await import("@kernelforge/ntsim/src/structs.mjs");
  const reconstructed = new ST2();
  for(const [name, info] of serialized){
    const fields = info.fields ? info.fields : Object.values(info.fieldsByName||{});
    reconstructed.register(name, info.totalSize, fields);
  }
  assert.equal(reconstructed.has("_EPROCESS"), true, "reconstructed must have _EPROCESS");
  assert.equal(reconstructed.has("_ETHREAD"), true);
  const kernel = new NtKernel({ tables: reconstructed });
  assert.doesNotThrow(()=> kernel.bootstrap(), "bootstrap with reconstructed tables should not throw EPROCESS table not loaded");
});

test("findBugsCampaign finds arbitrary write via tainted pointer", async ()=>{
  const tables = await loadTables();
  const img = buildArbitraryWriteDriver();
  const kernel = new NtKernel({ tables });
  kernel.bootstrap();
  const drvRec = createDriverObject(kernel,'vuln.sys');
  const mapped = mapPe(img, kernel.mem, BASE, (q)=> kernel.resolveImportProvisioned(q));
  initDriverObjectName(kernel, drvRec, 'vuln.sys', mapped.base, mapped.imageSize);
  drvRec.image={base:mapped.base, bytes:img};
  kernel.materializeModuleRange(mapped.base, mapped.imageSize,{fill:0});
  const pe=parsePe(img);
  kernel.callFunctionSeh(mapped.base+BigInt(pe.entryRva),[drvRec.va,0n],drvRec.image);
  const device=drvRec.deviceList[0] ?? createDeviceObject(kernel, drvRec,{});
  const { bugDB } = await findBugsCampaign(kernel, device, 0x222000, {
    sendIrp, imageBase: mapped.base, imageSize: mapped.imageSize,
    iterations: 16, corpusCap: 8, driverHash:'testhash',
  });
  const bugs = bugDB.all();
  const arb = bugs.find(b=> b.sinkType==="ARBITRARY_WRITE_DEREF");
  assert.ok(arb, `should find ARBITRARY_WRITE_DEREF, got ${bugs.map(b=>b.sinkType).join(",")}`);
  assert.equal(arb.controlDegree, "full");
  assert.ok(arb.witnessInput, "witnessInput should be present");
  assert.equal(arb.severity, 10);
});

test("findBugsCampaign no false EPROCESS error when tables correctly passed (worker path simulation)", async ()=>{
  const tables = await loadTables();
  const serialized = [...tables.types.entries()].map(([k,v])=> [k, {totalSize: v.totalSize, fieldsByName: v.fieldsByName, fields: v.fields}]);
  const { StructTables: ST2 } = await import("@kernelforge/ntsim/src/structs.mjs");
  const wTables = new ST2();
  for(const [name, info] of serialized){
    wTables.register(name, info.totalSize, Object.values(info.fieldsByName||{}));
  }
  const img = buildArbitraryWriteDriver();
  const kernel = new NtKernel({ tables: wTables });
  kernel.bootstrap();
  const drvRec = createDriverObject(kernel,'worker.sys');
  const mapped = mapPe(img, kernel.mem, BASE, (q)=> kernel.resolveImportProvisioned(q));
  initDriverObjectName(kernel, drvRec, 'worker.sys', mapped.base, mapped.imageSize);
  drvRec.image={base:mapped.base, bytes:img};
  kernel.materializeModuleRange(mapped.base, mapped.imageSize,{fill:0});
  const pe=parsePe(img);
  const entryRes = kernel.callFunctionSeh(mapped.base+BigInt(pe.entryRva),[drvRec.va,0n],drvRec.image);
  assert.equal(entryRes.status, "ok");
});

test("BugDB severity ordering and dedup", ()=>{
  const db=new BugDB();
  const b1=makeBug({sinkType:"NULL_DEREF", severity:1, ioctlCode:0x222000, sinkLocation:"0x1000", controlDegree:"influenced"});
  const b2=makeBug({sinkType:"ARBITRARY_WRITE_DEREF", severity:10, ioctlCode:0x222000, sinkLocation:"0x1000", controlDegree:"full"});
  const b3=makeBug({sinkType:"ARBITRARY_WRITE_DEREF", severity:10, ioctlCode:0x222000, sinkLocation:"0x1000", controlDegree:"full"});
  assert.equal(db.add(b1), true);
  assert.equal(db.add(b2), true);
  assert.equal(db.add(b3), false, "duplicate should be rejected");
  const all=db.all();
  assert.equal(all[0].sinkType, "ARBITRARY_WRITE_DEREF", "highest severity first");
  assert.equal(all[1].sinkType, "NULL_DEREF");
});
