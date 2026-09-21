import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { stateTextFromReport } from "../src/state-text.mjs";

function fakeReport(overrides = {}) {
  return {
    meta: { size: 38408, engine: "js" },
    load: {
      driverName: "sample.sys",
      imageSize: 53248,
      packed: null,
      sections: [{ name: ".text" }, { name: ".rdata" }, { name: ".data" }],
      imports: ["ntoskrnl.exe!IoCreateDevice", "ntoskrnl.exe!MmGetSystemRoutineAddress"],
      unmodeledExports: [],
    },
    entry: { status: "ok", retval: "0x00000000" },
    deferred: { dpcs: 1, workItems: 0, threads: 1 },
    harvestedIoctls: [{ value: 0x222000, hex: "0x222000", rva: 0x1000 }],
    ioctls: [],
    trace: [
      { seq: 1, phase: "DriverEntry", kind: "kdemu" },
      { seq: 2, phase: "DriverEntry", kind: "api", name: "IoCreateDevice" },
      { seq: 3, phase: "DriverEntry", kind: "api", name: "IoCreateDevice" },
      { seq: 4, phase: "DriverEntry", kind: "api", name: "IoCreateSymbolicLink" },
      { seq: 5, phase: "DriverEntry", kind: "api", name: "MmGetSystemRoutineAddress" },
    ],
    dbgLog: [
      "[loader] noise",
      "[analyzer] modeled data export PsProcessType",
      "[kdemu] seeded service key",
      "KLMNOPQRSTUVWXYZ[\\]^_`abc",
      "driver says hello",
      "another driver line",
    ],
    apiTraceSummary: {
      totalCalls: 12,
      distinct: 3,
      byName: {
        IoCreateDevice: { count: 2, args: [] },
        MmGetSystemRoutineAddress: { count: 1, args: [] },
        DbgPrint: { count: 9, args: [] },
      },
    },
    exceptions: [],
    irqlViolations: [],
    bugcheck: null,
    notifyRoutines: { process: 1, thread: 0, image: 1 },
    registryWrites: [{ path: "\\Registry\\Machine\\X" }],
    filesWritten: [],
    symbolicLinks: [],
    ...overrides,
  };
}

describe("stateTextFromReport", () => {
  it("renders the high-signal sections in priority order", () => {
    const { state, included } = stateTextFromReport(fakeReport());
    assert.match(state, /Windows kernel driver sample\.sys \(52 KB image\)\. Not packed\./);
    assert.match(state, /2 imports, 0 unmodeled exports\. Sections: \.text \.rdata \.data\./);
    assert.match(state, /DriverEntry ok \(0x00000000\)\./);
    assert.match(state, /registers 1 process, 1 image notification callbacks/);
    assert.match(state, /deferred work: 1 DPCs, 0 work items, 1 threads/);
    assert.ok(included.includes("header"));
    assert.ok(included.includes("callSequence"));
  });

  it("compresses the trace into a run-length call sequence", () => {
    const { state } = stateTextFromReport(fakeReport());
    assert.match(state, /Call sequence: IoCreateDevice×2→IoCreateSymbolicLink→MmGetSystemRoutineAddress\./);
  });

  it("abridges driver output and drops analyzer/string-buffer noise", () => {
    const { state } = stateTextFromReport(fakeReport());
    assert.match(state, /Driver output: driver says hello \(\+1 more\)/);
    assert.doesNotMatch(state, /\[loader\]|\[analyzer\]|\[kdemu\]|KLMNOPQRSTUVWXYZ/);
  });

  it("falls back to API counts when no trace exists", () => {
    const { state, included } = stateTextFromReport(fakeReport({ trace: [] }));
    assert.doesNotMatch(state, /Call sequence/);
    assert.match(state, /API calls: DbgPrint\(9\), IoCreateDevice\(2\), MmGetSystemRoutineAddress\(1\)\./);
    assert.ok(included.includes("apis"));
  });

  it("keeps the state within the token budget and reports what was dropped", () => {
    const longStrings = Array.from({ length: 60 }, (_, i) => `VeryLongApiNameNumber${i}(3)`);
    const report = fakeReport({
      dbgLog: [`${"x".repeat(2000)}`],
      apiTraceSummary: {
        totalCalls: 180,
        distinct: 60,
        byName: Object.fromEntries(longStrings.map((name) => [name.split("(")[0], { count: 3 }])),
      },
    });
    const out = stateTextFromReport(report, { maxTokens: 120 });
    assert.ok(out.chars <= out.budget, `${out.chars} <= ${out.budget}`);
    assert.equal(out.truncated, true);
    assert.ok(out.dropped.length > 0);
  });

  it("caps very long traces instead of stringifying them", () => {
    const trace = Array.from({ length: 5000 }, (_, i) => ({ kind: "api", name: `Api${i}` }));
    const out = stateTextFromReport(fakeReport({ trace }), { maxChars: 5000 });
    const seq = out.state.match(/Call sequence: ([^.]*)\./)?.[1] ?? "";
    assert.ok(seq.split("→").length <= 13, seq); // 12 runs + possible ellipsis
  });

  it("accepts an explicit maxChars and never splits below the floor", () => {
    const out = stateTextFromReport(fakeReport(), { maxChars: 300 });
    assert.ok(out.chars <= 300);
    assert.equal(out.budget, 300);
  });

  it("handles an empty/minimal report without throwing", () => {
    const out = stateTextFromReport({ meta: { size: 10 } });
    assert.equal(typeof out.state, "string");
    assert.ok(out.state.length > 0);
    assert.throws(() => stateTextFromReport(null), /report must be an object/);
  });
});
