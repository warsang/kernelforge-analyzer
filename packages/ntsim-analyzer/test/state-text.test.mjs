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
    capabilities: {
      devices: 1,
      symbolicLinks: 1,
      objectCallbacks: 1,
      cmCallbacks: 0,
      wdfBindings: 0,
      notify: { process: 1, thread: 0, image: 1 },
      deferred: { dpcs: 1, workItems: 0, apcs: 0, threads: 1 },
      timers: 0,
      callbackInvocations: { process: 1, thread: 0, image: 2, object: 0, cm: 0 },
    },
    registryActivity: {
      writes: 3, creates: 1, deletes: 0, total: 4,
      categories: { self: 2, security: 0, boot: 0, services: 1, user: 0, bcd: 0, other: 1 },
      modifiedKeys: [{ key: "\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Services\\sample", category: "self", ops: 2, values: ["Start"] }],
      autoCreatedKeys: 1,
      flags: { selfServiceKey: true, securityPolicy: false, bootConfig: false, otherServices: true, userHive: false, bcd: false },
    },
    apiResolutions: {
      resolved: [{ name: "ZwQueryInformationProcess", kind: "provisioned", target: "0xfffff80100001000", count: 1 }],
      provisioned: [{ name: "ZwQueryVirtualMemory", count: 1 }],
      unresolved: [{ name: "PsGetProcessSectionBaseAddress", count: 1 }],
      counts: { resolved: 1, provisioned: 1, unresolved: 1 },
    },
    registryWrites: [{ path: "\\Registry\\Machine\\X" }],
    filesWritten: [],
    symbolicLinks: [],
    ...overrides,
  };
}

describe("stateTextFromReport", () => {
  it("renders the structured sections in priority order", () => {
    const { state, included } = stateTextFromReport(fakeReport(), { maxTokens: 700 });
    assert.match(state, /Windows kernel driver sample\.sys \(52 KB image\)\./);
    assert.match(state, /STATIC: image=0xd000 imports=2 unmodeled=0 sections=\[\.text \.rdata \.data\]/);
    assert.match(state, /OBSERVED CAPABILITIES \(registered\): object_callbacks=1/);
    assert.match(state, /process_notify=1 thread_notify=0 image_notify=1/);
    assert.match(state, /system_threads=1/);
    assert.match(state, /DriverEntry ok \(0x00000000\)\./);
    assert.match(state, /NOT OBSERVED \(this run\): code_encryption=not observed/);
    assert.match(state, /OBSERVED EFFECTS: registry: writes=3 creates=1 deletes=0/);
    assert.match(state, /MmGetSystemRoutineAddress: resolved\[ZwQueryInformationProcess\(provisioned\)\]/);
    assert.match(state, /unresolved\[PsGetProcessSectionBaseAddress\]/);
    assert.match(state, /SEMANTIC EVENTS: INSPECTION: MmGetSystemRoutineAddress/);
    assert.match(state, /emulator_limitations:/);
    assert.ok(included.includes("header"));
    assert.ok(included.includes("rawTrace"));
  });

  it("compresses the trace into a run-length call sequence", () => {
    const { state } = stateTextFromReport(fakeReport(), { maxTokens: 700 });
    assert.match(state, /RAW TRACE: IoCreateDevicex2>IoCreateSymbolicLink>MmGetSystemRoutineAddress\./);
  });

  it("abridges driver output and drops analyzer/string-buffer noise", () => {
    const { state } = stateTextFromReport(fakeReport(), { maxTokens: 700 });
    assert.match(state, /Driver output: driver says hello \(\+1 more\)/);
    assert.doesNotMatch(state, /\[loader\]|\[analyzer\]|\[kdemu\]|KLMNOPQRSTUVWXYZ/);
  });

  it("falls back to API counts when no trace exists", () => {
    const { state, included } = stateTextFromReport(fakeReport({ trace: [] }), { maxTokens: 700 });
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
    const seq = out.state.match(/RAW TRACE: ([^.]*)\./)?.[1] ?? "";
    assert.ok(seq.split(">").length <= 13, seq); // 12 runs + possible ellipsis
  });

  it("accepts an explicit maxChars and never splits below the floor", () => {
    const out = stateTextFromReport(fakeReport(), { maxChars: 300 });
    assert.ok(out.chars <= 300);
    assert.equal(out.budget, 300);
  });

  it("renders static PE facts, detection probes and execution outcome", () => {
    const report = fakeReport({
      static: {
        dllCount: 1, importCount: 7, imphash: "0123456789abcdef0123456789abcdef",
        sections: [
          { name: ".text", entropy: 6.1, flags: ["execute", "read", "code"] },
          { name: ".data", entropy: 7.9, flags: ["execute", "write", "read"] },
        ],
        anomalies: [{ kind: "rwx_section" }, { kind: "entry_outside_sections" }],
        hasCert: false, tls: { present: true, callbacks: 1 }, overlaySize: 4096,
        packerHints: [".vmp0"],
      },
      detections: {
        unmapped: { reads: 3, writes: 0 },
        probes: { kusd: 1, hvsp: 0, hyperspace: 2, systemModule: 1, kernelStruct: 0, pool: 0, peHeaderScan: 1, pageScan: 0, other: 0 },
        selfReads: { header: 2, iat: 1 },
        seh: { dispatched: 1, accepted: 1, rejected: 0 },
        cpu: { cpuid: 4, rdtsc: 12, rdmsr: 2, wrmsr: 0, busyWaitJumps: 3 },
        flags: { moduleEnumeration: true, hypervisorProbe: false, stuckAccessDenied: false },
      },
      selfModifying: { checked: 2, totalChanged: 128, sections: [{ name: ".text", rva: 0x1000, changedBytes: 128, ranges: [] }] },
      yara: { matches: [], community: [{ id: "MAL_RAT_Generic", tags: ["MALWARE"], meta: { severity: "high" }, strings: [] }] },
      stall: { phase: "DriverEntry", status: "timeout", rip: "0xfffff80300001234", steps: 20000000, lastEvents: ["MmGetSystemRoutineAddress", "rdtsc"] },
      entry: { status: "timeout" },
    });
    const { state, included } = stateTextFromReport(report, { maxTokens: 700 });
    assert.match(state, /STATIC PE: dlls=1 imports=7 imphash=0123456789abcdef/);
    assert.match(state, /RWX=\[\.data\]/);
    assert.match(state, /hi_entropy_code=\[\.data\]/);
    assert.match(state, /unsigned=yes/);
    assert.match(state, /packer_names=\[\.vmp0\]/);
    assert.match(state, /DETECTION PROBES: kusd=1/);
    assert.match(state, /self_header_reads=2 self_iat_reads=1/);
    assert.match(state, /rdtsc=12/);
    assert.match(state, /module_enumeration=yes/);
    assert.match(state, /EXECUTION: entry=timeout STALL=timeout@DriverEntry rip=0xfffff80300001234/);
    assert.match(state, /self_modifying_code=OBSERVED\(\.text:128B\)/);
    assert.match(state, /yara:community:MAL_RAT_Generic\(high\)/);
    assert.ok(included.includes("staticFacts"));
    assert.ok(included.includes("execution"));
    assert.ok(included.includes("detectionProbes"));
  });

  it("handles an empty/minimal report without throwing", () => {
    const out = stateTextFromReport({ meta: { size: 10 } });
    assert.equal(typeof out.state, "string");
    assert.ok(out.state.length > 0);
    assert.throws(() => stateTextFromReport(null), /report must be an object/);
  });
});
