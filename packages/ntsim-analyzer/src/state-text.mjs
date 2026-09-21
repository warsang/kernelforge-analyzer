/**
 * state-text.mjs — turn an analyzer report into a compact natural-language
 * "state" for typed-decision / classification models.
 *
 * The reference open-jev models cap the state at ~256 tokens, so sections are
 * added in priority order until the character budget is spent; whatever does
 * not fit is reported in `dropped` (never silently lost). Pure and
 * deterministic — no I/O, no dependencies.
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
  const sections = Array.isArray(load.sections) ? load.sections.map((s) => squeeze(s?.name)).filter(Boolean) : [];
  const byName = r.apiTraceSummary?.byName ?? {};
  const apis = Object.entries(byName)
    .map(([name, info]) => ({ name, count: Number(info?.count) || 0 }))
    .sort((a, b) => b.count - a.count);
  const notable = NOTABLE_APIS.filter((name) => byName[name] || imports.some((imp) => String(imp).includes(`!${name}`)));
  const notified = r.notifyRoutines ?? {};
  const notifyParts = ["process", "thread", "image"].filter((k) => notified[k]).map((k) => `${notified[k]} ${k}`);
  const ioctls = Array.isArray(r.ioctls) ? r.ioctls : [];
  const harvested = Array.isArray(r.harvestedIoctls) ? r.harvestedIoctls : [];

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
    ? runs.slice(0, MAX_SEQUENCE_RUNS).map((x) => (x.count > 1 ? `${x.name}×${x.count}` : x.name)).join("→") +
      (runs.length > MAX_SEQUENCE_RUNS ? "→…" : "")
    : null;

  // Driver debug output, abridged: drop analyzer plumbing and string-buffer
  // junk, keep the first informative line plus a count.
  const dbgDriverLines = (Array.isArray(r.dbgLog) ? r.dbgLog : [])
    .map((l) => squeeze(l))
    .filter((l) => l && !/^(\[analyzer\]|\[loader\]|\[kdemu\]|KLMNOPQRSTUVWXYZ)/.test(l));

  const candidates = [
    ["header", () => {
      const name = load.driverName ?? "unknown.sys";
      const kb = Math.round((load.imageSize ?? r.meta?.size ?? 0) / 1024);
      const packed = load.packed ? ` Packed/compressed (${clip(typeof load.packed === "string" ? load.packed : "yes", 40)}).` : " Not packed.";
      return `Windows kernel driver ${clip(name, 60)} (${kb} KB image).${packed}`;
    }],
    ["layout", () => {
      const secs = sections.length ? ` Sections: ${sections.join(" ")}.` : "";
      return `${imports.length} imports, ${unmodeled.length} unmodeled exports.${secs}`;
    }],
    ["entry", () => {
      if (!r.entry) return "";
      const seh = r.entry.sehHandled ? " SEH exceptions handled." : "";
      const err = r.entry.error ? ` Entry error: ${clip(r.entry.error, 80)}.` : "";
      return `DriverEntry ${clip(r.entry.status, 20)}${r.entry.retval ? ` (${clip(r.entry.retval, 20)})` : ""}.${seh}${err}`;
    }],
    ["behavior", () => {
      const parts = [];
      if (notifyParts.length) parts.push(`registers ${notifyParts.join(", ")} notification callbacks`);
      const d = r.deferred ?? {};
      if (d.dpcs || d.workItems || d.threads) {
        parts.push(`deferred work: ${d.dpcs ?? 0} DPCs, ${d.workItems ?? 0} work items, ${d.threads ?? 0} threads`);
      }
      if (ioctls.length) parts.push(`exercised ${ioctls.length} IOCTLs`);
      else if (harvested.length) parts.push(`exposes ${harvested.length} IOCTL codes`);
      if (r.unload) parts.push("implements DriverUnload");
      return parts.length ? `Behavior: ${parts.join("; ")}.` : "";
    }],
    ["callSequence", () => (sequence ? `Call sequence: ${sequence}.` : "")],
    ["faults", () => {
      const bits = [];
      if (r.irqlViolations?.length) bits.push(`${r.irqlViolations.length} IRQL violations`);
      if (r.exceptions?.length) bits.push(`${r.exceptions.length} exceptions`);
      bits.push(r.bugcheck ? "bugchecked" : "no bugcheck");
      return `Faults: ${bits.join(", ")}.`;
    }],
    ["notable", () => (runs.length < 3 && notable.length ? `Notable APIs: ${notable.slice(0, 6).join(", ")}.` : "")],
    ["apis", () => (!sequence && apis.length ? `API calls: ${apis.slice(0, 6).map((a) => `${a.name}(${a.count})`).join(", ")}.` : "")],
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
    ["sideEffects", () => {
      const bits = [];
      if (r.registryWrites?.length) bits.push(`${r.registryWrites.length} registry writes`);
      if (r.filesWritten?.length) bits.push(`${r.filesWritten.length} files written`);
      if (r.symbolicLinks?.length) bits.push(`${r.symbolicLinks.length} symbolic links`);
      if (r.etw?.length) bits.push(`${r.etw.length} ETW events`);
      return bits.length ? `Side effects: ${bits.join(", ")}.` : "";
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
