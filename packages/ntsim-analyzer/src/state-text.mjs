/**
 * state-text.mjs — turn an analyzer report into a compact, structured "state"
 * for typed-decision / classification models.
 *
 * There is no chat prompt: the model sees this text plus the typed questions.
 * Sections are added in priority order until the character budget is spent;
 * whatever does not fit is reported in `dropped` (never silently lost).
 *
 * The structure deliberately separates:
 *   STATIC FACTS        PE/layout facts
 *   OBSERVED CAPABILITIES   what the driver *registered* (callbacks, devices, …)
 *   OBSERVED EFFECTS        what actually happened (registry mutations, invocations)
 *   NOT OBSERVED (this run) explicit negatives, incl. integrity-checked ones
 *   API ACTIVITY        MmGetSystemRoutineAddress resolution evidence
 *   SEMANTIC EVENTS     categorized call activity
 *   RAW TRACE           bounded run-length call sequence (secondary evidence)
 *   EMULATOR LIMITATIONS analysis caveats (provisioned APIs, synthetic events)
 *
 * Pure and deterministic — no I/O, no dependencies.
 */

// Ordered call-sequence caps: enough to show entry behaviour + loops without
// spending the whole state budget on symbol names.
const MAX_SEQUENCE_EVENTS = 40;
const MAX_SEQUENCE_RUNS = 12;

const NOTABLE_APIS = [
  "MmGetSystemRoutineAddress",
  "ZwTerminateProcess",
  "ZwOpenProcess",
  "ObRegisterCallbacks",
  "PsSetCreateProcessNotifyRoutineEx",
  "PsSetCreateProcessNotifyRoutine",
  "PsSetCreateThreadNotifyRoutine",
  "PsSetLoadImageNotifyRoutine",
  "KeStackAttachProcess",
  "KeWriteProtectPAT",
  "ZwProtectVirtualMemory",
  "ZwWriteVirtualMemory",
  "ZwReadVirtualMemory",
  "MmCopyVirtualMemory",
  "KeBugCheckEx",
  "IoCreateDevice",
  "IoCreateSymbolicLink",
  "ExAllocatePool",
  "ExAllocatePool2",
  "KeInitializeDpc",
  "KeSetTimer",
  "PsCreateSystemThread",
  "CmRegisterCallback",
  "SeAccessCheck",
  "NtQuerySystemInformation",
];

/** API -> semantic group (first match wins, checked in this order). */
const SEMANTIC_GROUPS = [
  ["MONITORING", [
    "ObRegisterCallbacks", "PsSetCreateProcessNotifyRoutineEx2", "PsSetCreateProcessNotifyRoutineEx",
    "PsSetCreateProcessNotifyRoutine", "PsSetCreateThreadNotifyRoutine", "PsSetLoadImageNotifyRoutine",
    "CmRegisterCallbackEx", "CmRegisterCallback", "FltRegisterFilter", "IoRegisterBootDriverCallback",
    "IoRegisterShutdownNotification", "IoRegisterLastChanceShutdownNotification",
  ]],
  ["INSPECTION", [
    "MmGetSystemRoutineAddress", "ZwQueryInformationProcess", "NtQueryInformationProcess",
    "ZwQueryVirtualMemory", "ZwQuerySystemInformation", "NtQuerySystemInformation",
    "PsLookupProcessByProcessId", "PsLookupThreadByThreadId", "SeQueryInformationToken",
    "PsGetProcessImageFileName", "PsGetProcessSectionBaseAddress",
  ]],
  ["EXECUTION", [
    "PsCreateSystemThread", "PsTerminateSystemThread", "KeWaitForSingleObject", "KeSetTimerEx",
    "KeSetTimer", "IoQueueWorkItem", "ExQueueWorkItem", "KeInsertQueueDpc", "KeIpiGenericCall",
  ]],
  ["SIDE_EFFECTS", [
    "ZwSetValueKey", "NtSetValueKey", "ZwCreateKey", "NtCreateKey", "ZwDeleteValueKey", "ZwDeleteKey",
    "ZwWriteFile", "NtWriteFile", "ZwDeleteFile", "ZwSetInformationFile",
  ]],
  ["INIT", [
    "WdfVersionBindClass", "WdfVersionBind", "KeInitializeSpinLock", "KeInitializeEvent",
    "KeInitializeDpc", "KeInitializeTimer", "KeInitializeMutex", "KeInitializeSemaphore",
    "ExAllocatePoolWithTag", "ExAllocatePool2", "ExAllocatePool", "IoCreateDevice",
    "IoCreateSymbolicLink", "RtlInitUnicodeString", "RtlCopyUnicodeString",
    "KeAcquireSpinLockRaiseToDpc", "KeReleaseSpinLock",
  ]],
];

const INJECTION_APIS = [
  "ZwAllocateVirtualMemory", "NtAllocateVirtualMemory", "ZwWriteVirtualMemory",
  "NtWriteVirtualMemory", "ZwMapViewOfSection", "MmCopyVirtualMemory", "ZwProtectVirtualMemory",
];

function squeeze(value) {
  return String(value ?? "").replace(/\s+/g, " ").trim();
}

function clip(value, max) {
  const s = squeeze(value);
  return s.length > max ? `${s.slice(0, max - 1).trimEnd()}…` : s;
}

export function stateTextFromReport(report, { maxTokens = 256, charsPerToken = 3.4, maxChars = null } = {}) {
  if (!report || typeof report !== "object") throw new TypeError("report must be an object");
  const budget = Number.isFinite(maxChars) ? maxChars : Math.max(64, Math.floor(maxTokens * charsPerToken));
  const r = report;
  const load = r.load ?? {};
  const imports = Array.isArray(load.imports) ? load.imports : [];
  const unmodeled = Array.isArray(load.unmodeledExports) ? load.unmodeledExports : [];
  const shallowStubs = Array.isArray(load.shallowStubs) ? load.shallowStubs : [];
  const sections = Array.isArray(load.sections) ? load.sections.map((s) => squeeze(s?.name)).filter(Boolean) : [];
  const byName = r.apiTraceSummary?.byName ?? {};
  const apiNames = new Set(Object.keys(byName));
  const notified = r.notifyRoutines ?? {};
  const caps = r.capabilities ?? null;
  const reg = r.registryActivity ?? null;
  const res = r.apiResolutions ?? null;
  const integ = r.integrity ?? null;
  const ioctls = Array.isArray(r.ioctls) ? r.ioctls : [];
  const harvested = Array.isArray(r.harvestedIoctls) ? r.harvestedIoctls : [];
  const st = r.static ?? null;
  const ruleMatches = r.rules?.matches ?? [];
  const yaraMatches = [
    ...(r.yara?.matches ?? []),
    ...((r.yara?.custom ?? []).map((m) => ({ ...m, id: `custom:${m.id}` }))),
    ...((r.yara?.community ?? []).map((m) => ({ ...m, id: `community:${m.id}` }))),
  ];
  const stall = r.stall ?? null;
  const selfmod = r.selfModifying ?? null;
  const probes = r.detections ?? null;
  const archSum = r.arch ?? null;
  const cpuCounts = archSum?.cpu ?? probes?.cpu ?? null;

  const hasApi = (names) => names.some((n) => apiNames.has(n));
  const hex = (v) => "0x" + Number(v ?? 0).toString(16);

  // Ordered call sequence from the trace: run-length compressed so loops and
  // repeated probes stay visible while the text stays inside the budget.
  const traceApiNames = [];
  for (const e of Array.isArray(r.trace) ? r.trace : []) {
    if (e?.kind !== "api" || !e.name) continue;
    traceApiNames.push(squeeze(e.name));
    if (traceApiNames.length >= MAX_SEQUENCE_EVENTS) break;
  }
  const runs = [];
  for (const name of traceApiNames) {
    const last = runs[runs.length - 1];
    if (last && last.name === name) last.count++;
    else runs.push({ name, count: 1 });
  }
  const sequence = runs.length
    ? runs.slice(0, MAX_SEQUENCE_RUNS).map((x) => (x.count > 1 ? `${x.name}x${x.count}` : x.name)).join(">") +
      (runs.length > MAX_SEQUENCE_RUNS ? ">…" : "")
    : null;

  // Driver debug output, abridged: drop analyzer plumbing and string-buffer
  // junk, keep the first informative line plus a count.
  const dbgDriverLines = (Array.isArray(r.dbgLog) ? r.dbgLog : [])
    .map((l) => squeeze(l))
    .filter((l) => l && !/^(\[analyzer\]|\[loader\]|\[kdemu\]|KLMNOPQRSTUVWXYZ)/.test(l));

  const semantic = SEMANTIC_GROUPS
    .map(([group, names]) => {
      const present = names.filter((n) => apiNames.has(n)).slice(0, 8);
      return present.length ? `${group}: ${present.join(",")}` : null;
    })
    .filter(Boolean)
    .join(" | ");

  const selfmodSections = (selfmod?.sections ?? []).filter((s) => s.changedBytes > 0);
  const selfmodObserved = selfmodSections.length > 0;
  const notObserved = [
    `code_encryption=${selfmodObserved ? `possible(exec_section_writes=${selfmod.totalChanged}B)` : "not observed"}`,
    `self_modifying_code=${selfmodObserved ? `OBSERVED(${selfmodSections.map((s) => `${s.name}:${s.changedBytes}B`).join(",")})` : "not observed"}`,
    `module_unlinking=${integ?.processList ? (integ.processList.ok === false ? "OBSERVED" : "not observed") : "not observed"}`,
    `ssdt_hooking=${integ?.ssdt ? (integ.ssdt.hooked?.length ? "OBSERVED" : "not observed") : "not checked"}`,
    "idt_hooking=not checked",
    `process_termination=${hasApi(["ZwTerminateProcess", "NtTerminateProcess"]) ? "api-called" : "not observed"}`,
    `remote_memory_write=${hasApi(["ZwWriteVirtualMemory", "NtWriteVirtualMemory", "MmCopyVirtualMemory"]) ? "api-called" : "not observed"}`,
    `code_injection=${hasApi(INJECTION_APIS) ? "partial-api-evidence" : "not observed"}`,
    `credential_access=${hasApi(["SeQueryInformationToken", "PsReferencePrimaryToken"]) ? "api-called" : "not observed"}`,
    `destructive_activity=${hasApi(["ZwDeleteFile", "ZwDeleteKey", "ZwDeleteValueKey", "ZwSetInformationFile"]) ? "api-called" : "not observed"}`,
  ].join(" ");

  // Static PE evidence: section flags/entropy, imphash, import scale, packer
  // names. Only emitted when the triage parser saw the image.
  const staticFactsLine = st
    ? (() => {
      const rwx = (st.sections ?? [])
        .filter((s) => s.flags?.includes("execute") && s.flags?.includes("write"))
        .map((s) => s.name);
      const hiEnt = (st.sections ?? [])
        .filter((s) => s.flags?.includes("execute") && (s.entropy ?? 0) > 7.2)
        .map((s) => s.name);
      const rawLtVirt = (st.anomalies ?? []).some((a) => a.kind === "raw_lt_virtual");
      const entryOutside = (st.anomalies ?? []).some((a) => a.kind === "entry_outside_sections");
      const bits = [
        `dlls=${st.dllCount ?? 0}`,
        `imports=${st.importCount ?? 0}`,
        st.imphash ? `imphash=${st.imphash.slice(0, 16)}` : null,
        `sections=[${(st.sections ?? []).map((s) => s.name).join(" ")}]`,
        rwx.length ? `RWX=[${rwx.join(",")}]` : null,
        hiEnt.length ? `hi_entropy_code=[${hiEnt.join(",")}]` : null,
        rawLtVirt ? "raw_lt_virtual=yes" : null,
        entryOutside ? "entry_outside_sections=yes" : null,
        `unsigned=${st.hasCert ? "no" : "yes"}`,
        st.tls?.callbacks ? `tls_callbacks=${st.tls.callbacks}` : null,
        st.overlaySize ? `overlay=${st.overlaySize}B` : null,
        (st.packerHints ?? []).length ? `packer_names=[${st.packerHints.join(",")}]` : null,
        st.stackStrings?.length ? `stack_strings=${st.stackStrings.length}` : null,
        st.apiHashes?.length ? `api_hashes=${st.apiHashes.length}` : null,
      ].filter(Boolean);
      return `STATIC PE: ${bits.join(" ")}`;
    })()
    : "";

  // Static rule-pack hits: deterministic indicators (rootkit/anti-analysis/
  // packer/BYOVD) that the emulator run alone may not expose.
  const rulesLine = (ruleMatches.length || yaraMatches.length)
    ? `STATIC RULES: ${[
      ...ruleMatches.map((m) => `${m.id}(${m.severity}${m.tags?.length ? ":" + m.tags.slice(0, 2).join("/") : ""})`),
      ...yaraMatches.map((m) => `yara:${m.id}(${m.meta?.severity ?? "?"})`),
    ].slice(0, 8).join(" ")}`
    : "";
  const hiddenStringsLine = (() => {
    const bits = [];
    if (st?.stackStrings?.length) {
      bits.push(`stack_strings=[${st.stackStrings.slice(0, 4).map((s) => clip(s.value, 40)).join(" | ")}]`);
    }
    if (st?.apiHashes?.length) {
      const names = [...new Set(st.apiHashes.map((h) => `${h.algo}:${h.name}`))];
      bits.push(`api_hashes=[${names.slice(0, 6).join(",")}]`);
    }
    return bits.length ? `HIDDEN STRINGS: ${bits.join(" ")}` : "";
  })();

  // Detection probes: what the driver *did to detect analysis*, from the diag
  // and arch telemetry. Without this the model cannot see anti-analysis at all.
  const probesLine = probes
    ? (() => {
      const p = probes.probes ?? {};
      const nz = (label, v) => (v ? `${label}=${v}` : null);
      const bits = [
        nz("kusd", p.kusd),
        nz("hyperspace", p.hyperspace),
        nz("system_module", p.systemModule),
        nz("kernel_struct", p.kernelStruct),
        nz("pool", p.pool),
        nz("pe_header_scan", p.peHeaderScan),
        nz("page_scan", p.pageScan),
        nz("other_probes", p.other),
        nz("self_header_reads", probes.selfReads?.header),
        nz("self_iat_reads", probes.selfReads?.iat),
        nz("cpuid", cpuCounts?.cpuid),
        nz("rdtsc", cpuCounts?.rdtsc),
        nz("rdmsr", cpuCounts?.rdmsr),
        nz("wrmsr", cpuCounts?.wrmsr),
        nz("busy_wait_jumps", cpuCounts?.busyWaitJumps),
        probes.seh?.dispatched ? `seh_dispatched=${probes.seh.dispatched}(ok=${probes.seh.accepted})` : null,
        probes.flags?.moduleEnumeration ? "module_enumeration=yes" : null,
        probes.flags?.hypervisorProbe ? "hypervisor_probe=yes" : null,
        probes.flags?.stuckAccessDenied ? "stuck_access_denied=yes" : null,
        (probes.unmapped?.reads ?? 0) + (probes.unmapped?.writes ?? 0) > 0
          ? `unmapped_access=${probes.unmapped.reads}r/${probes.unmapped.writes}w`
          : null,
      ].filter(Boolean);
      return bits.length ? `DETECTION PROBES: ${bits.join(" ")}` : "";
    })()
    : "";

  // Execution outcome: timeout/debug-stop runs must still carry rip, steps and
  // the tail of what executed; a bare "timeout" is not triage evidence.
  const executionLine = (() => {
    const bits = [];
    if (r.entry) {
      bits.push(`entry=${r.entry.status}${r.entry.retval ? `(${r.entry.retval})` : ""}`);
      if (r.entry.sehHandled) bits.push("seh_handled=yes");
    }
    if (stall) {
      bits.push(`STALL=${stall.status}@${stall.phase}${stall.rip ? ` rip=${stall.rip}` : ""}${stall.steps ? ` steps=${stall.steps}` : ""}`);
      if (stall.lastEvents?.length) bits.push(`last=[${stall.lastEvents.slice(-6).join(">")}]`);
    }
    bits.push(`bugcheck=${r.bugcheck ? "yes" : "no"}`);
    if (selfmod) bits.push(`exec_section_writes=${selfmod.totalChanged}B`);
    if (r.unload) bits.push(`unloaded=${r.unload.status === "ok" ? "yes" : r.unload.status}`);
    return bits.length ? `EXECUTION: ${bits.join(" ")}` : "";
  })();

  const registryLine = reg
    ? `registry: writes=${reg.writes} creates=${reg.creates} deletes=${reg.deletes} ` +
      `self_service_key=${reg.flags?.selfServiceKey ? "yes" : "no"} security_policy=${reg.flags?.securityPolicy ? "yes" : "no"} ` +
      `boot=${reg.flags?.bootConfig ? "yes" : "no"} other_services=${reg.flags?.otherServices ? "yes" : "no"}`
    : null;
  const registryKeys = reg?.modifiedKeys?.length
    ? `registry_keys: ${reg.modifiedKeys.slice(0, 4).map((k) => `${k.category}:${clip(k.key, 64)}`).join(" ")}`
    : null;

  const invocations = caps?.callbackInvocations ?? {};
  const invocationLine = caps
    ? `callback_invocations: process=${invocations.process ?? 0} thread=${invocations.thread ?? 0} ` +
      `image=${invocations.image ?? 0} object=${invocations.object ?? 0} cm=${invocations.cm ?? 0}`
    : null;
  const sideLine = (() => {
    const bits = [];
    if (r.filesWritten?.length) bits.push(`files_written=${r.filesWritten.length}`);
    if (r.etw?.length) bits.push(`etw=${r.etw.length}`);
    bits.push(`bugcheck=${r.bugcheck ? "yes" : "no"}`);
    if (r.unload) bits.push(`unloaded=${r.unload.status === "ok" ? "yes" : r.unload.status}`);
    return `effects: ${bits.join(" ")}`;
  })();

  const resolutionLine = res
    ? `MmGetSystemRoutineAddress: ` +
      (res.resolved?.length
        ? `resolved[${res.resolved.map((x) => `${x.name}(${x.kind})`).slice(0, 6).join(",")}] `
        : "") +
      (res.provisioned?.length ? `provisioned[${res.provisioned.map((x) => x.name).slice(0, 4).join(",")}] ` : "") +
      (res.unresolved?.length ? `unresolved[${res.unresolved.map((x) => x.name).slice(0, 4).join(",")}]` : "none")
    : null;

  const limitations = (() => {
    const bits = [];
    if (unmodeled.length) bits.push(`unmodeled_imports=${unmodeled.length}`);
    if (shallowStubs.length) bits.push(`shallow_stubbed_apis=${shallowStubs.length}`);
    if (res?.counts?.provisioned) bits.push(`provisioned_apis=${res.counts.provisioned}`);
    if (reg?.autoCreatedKeys) bits.push(`auto_created_registry_keys=${reg.autoCreatedKeys}`);
    if (r.exceptions?.length) bits.push(`emulator_faults=${r.exceptions.length}`);
    bits.push("callback_events=synthetic", "no_user_mode=yes");
    return `emulator_limitations: ${bits.join(" ")}`;
  })();

  const candidates = [
    ["header", () => {
      const name = load.driverName ?? "unknown.sys";
      const kb = Math.round((load.imageSize ?? r.meta?.size ?? 0) / 1024);
      const packers = [...new Set([
        ...(load.packed ? [String(load.packed)] : []),
        ...(st?.packerHints ?? []),
      ])];
      const packed = packers.length
        ? ` Packed/compressed (${clip(packers.join(","), 40)}).`
        : "";
      const kind = r.meta?.kind === "userland-pe"
        ? "Windows userland executable"
        : r.meta?.kind === "userland-elf"
          ? "Linux ELF executable"
          : "Windows kernel driver";
      const entryState = r.entry?.status === "timeout"
        ? " DriverEntry did not complete (timeout)."
        : r.entry?.status && r.entry.status !== "ok"
          ? ` DriverEntry ${r.entry.status}.`
          : "";
      return `${kind} ${clip(name, 60)} (${kb} KB image).${packed}${entryState}`;
    }],
    ["staticFacts", () => {
      const secs = sections.length ? ` sections=[${sections.join(" ")}]` : "";
      const base = `STATIC: image=${hex(load.imageSize ?? 0)} ` +
        `imports=${imports.length} unmodeled=${unmodeled.length}` +
        (shallowStubs.length ? ` shallow=${shallowStubs.length}` : "") + secs;
      return staticFactsLine ? staticFactsLine : base;
    }],
    ["execution", () => executionLine],
    ["detectionProbes", () => probesLine],
    ["staticRules", () => rulesLine],
    ["hiddenStrings", () => hiddenStringsLine],
    ["notObserved", () => `NOT OBSERVED (this run): ${notObserved}`],
    ["capabilities", () => {
      if (!caps) return "";
      const parts = [
        `object_callbacks=${caps.objectCallbacks ?? 0}`,
        `cm_callbacks=${caps.cmCallbacks ?? 0}`,
        `process_notify=${caps.notify?.process ?? 0}`,
        `thread_notify=${caps.notify?.thread ?? 0}`,
        `image_notify=${caps.notify?.image ?? 0}`,
        `devices=${caps.devices ?? 0}`,
        `symlinks=${caps.symbolicLinks ?? 0}`,
        `system_threads=${caps.deferred?.threads ?? 0}`,
        `wdf=${caps.wdfBindings ?? 0}`,
        `dpcs=${caps.deferred?.dpcs ?? 0}`,
        `timers=${caps.timers ?? 0}`,
      ];
      return `OBSERVED CAPABILITIES (registered): ${parts.join(" ")}`;
    }],
    ["effects", () => (registryLine || invocationLine || sideLine)
      ? `OBSERVED EFFECTS: ${[registryLine, invocationLine, sideLine].filter(Boolean).join(" | ")}`
      : ""],
    ["entry", () => {
      if (!r.entry) return "";
      const seh = r.entry.sehHandled ? " SEH exceptions handled." : "";
      const err = r.entry.error ? ` Entry error: ${clip(r.entry.error, 80)}.` : "";
      return `DriverEntry ${clip(r.entry.status, 20)}${r.entry.retval ? ` (${clip(r.entry.retval, 20)})` : ""}.${seh}${err}`;
    }],
    ["apiActivity", () => (resolutionLine ? resolutionLine : "")],
    ["registryKeys", () => (registryKeys ? registryKeys : "")],
    ["semanticEvents", () => (semantic ? `SEMANTIC EVENTS: ${semantic}` : "")],
    ["rawTrace", () => (sequence ? `RAW TRACE: ${sequence}.` : "")],
    ["limitations", () => limitations],
    ["notable", () => {
      const notable = NOTABLE_APIS.filter((name) => byName[name]);
      return runs.length < 3 && notable.length ? `Notable APIs: ${notable.slice(0, 6).join(", ")}.` : "";
    }],
    ["apis", () => {
      const apis = Object.entries(byName)
        .map(([name, info]) => ({ name, count: Number(info?.count) || 0 }))
        .sort((a, b) => b.count - a.count);
      return !sequence && apis.length ? `API calls: ${apis.slice(0, 6).map((a) => `${a.name}(${a.count})`).join(", ")}.` : "";
    }],
    ["dbg", () => {
      if (!dbgDriverLines.length) return "";
      const shown = clip(dbgDriverLines[0], 100);
      const more = dbgDriverLines.length > 1 ? ` (+${dbgDriverLines.length - 1} more)` : "";
      return `Driver output: ${shown}${more}`;
    }],
    ["ioctls", () => {
      const codes = [...ioctls.map((i) => i.ioctl).filter(Boolean), ...harvested.map((h) => h.hex).filter(Boolean)];
      const unique = [...new Set(codes.map((c) => squeeze(c)))];
      return unique.length ? `IOCTL codes: ${unique.slice(0, 10).join(", ")}.` : "";
    }],
  ];

  const included = [];
  const dropped = [];
  const chunks = [];
  let used = 0;
  let clippedOnce = false;
  for (const [name, build] of candidates) {
    let text;
    try {
      text = squeeze(build());
    } catch {
      text = "";
    }
    if (!text) continue;
    const separator = chunks.length ? " " : "";
    if (used + separator.length + text.length <= budget) {
      chunks.push(text);
      used += separator.length + text.length;
      included.push(name);
      continue;
    }
    // First overflow may be clipped to what remains; later (smaller) sections
    // still get a chance to fit in whatever budget is left.
    const remaining = budget - used - separator.length;
    if (!clippedOnce && remaining >= 40) {
      chunks.push(clip(text, remaining));
      used += separator.length + Math.min(text.length, remaining);
      included.push(`${name}(cut)`);
      clippedOnce = true;
    }
    dropped.push(name);
  }

  const state = chunks.join(" ");
  return { state, chars: state.length, budget, truncated: dropped.length > 0, included, dropped };
}
