/**
 * state-text-userland.mjs — compact structured state for userland PE/ELF/LKM
 * reports (same shape as ntsim-analyzer's stateTextFromReport).
 *
 * Sections in priority order until the budget is spent; what does not fit is
 * reported in `dropped`. No I/O, no dependencies.
 */

const MAX_SEQUENCE_EVENTS = 48;
const MAX_SEQUENCE_RUNS = 14;

const squeeze = (v) => String(v ?? "").replace(/\s+/g, " ").trim();
const clip = (v, max) => {
  const s = squeeze(v);
  return s.length > max ? `${s.slice(0, max - 1).trimEnd()}…` : s;
};
const kindName = (kind) =>
  kind === "userland-pe" ? "Windows PE executable"
    : kind === "userland-elf" ? "Linux ELF executable"
      : kind === "userland-lkm" ? "Linux kernel module"
        : "userland binary";

export function stateTextFromUserland(report, { maxTokens = 256, charsPerToken = 3.4, maxChars = null } = {}) {
  if (!report || typeof report !== "object") throw new TypeError("report must be an object");
  const budget = Number.isFinite(maxChars) ? maxChars : Math.max(64, Math.floor(maxTokens * charsPerToken));
  const r = report;
  const st = r.static ?? {};
  const artifacts = r.artifacts ?? {};
  const ruleMatches = r.rules?.matches ?? [];
  const yaraMatches = [
    ...(r.yara?.matches ?? []),
    ...((r.yara?.custom ?? []).map((m) => ({ ...m, id: `custom:${m.id}` }))),
    ...((r.yara?.community ?? []).map((m) => ({ ...m, id: `community:${m.id}` }))),
  ];
  const isElf = r.meta?.kind === "userland-elf" || r.meta?.kind === "userland-lkm";

  const name = r.meta?.name ?? "sample";
  const kb = Math.round((r.meta?.size ?? 0) / 1024);

  const header = (() => {
    const bits = [`${kindName(r.meta?.kind)} ${clip(name, 60)} (${kb} KB)`];
    if (st.packerHints?.length) bits.push(`packed/obfuscated hints [${st.packerHints.slice(0, 3).join(",")}]`);
    if (r.stall) bits.push(`${r.stall.status} during execution`);
    else if (r.entry?.status) bits.push(`entry ${r.entry.status}`);
    return `${bits.join(". ")}.`;
  })();

  const staticLine = (() => {
    const bits = [];
    if (isElf) {
      bits.push(`format=${st.type ?? "?"}`, st.isPie ? "PIE" : "non-PIE");
      if (st.interp) bits.push(`interp=${clip(st.interp, 40)}`);
      if (st.needed?.length) bits.push(`needed=[${st.needed.slice(0, 5).join(" ")}]`);
      bits.push(`imports=${st.importCount ?? 0}`);
      bits.push(`rwx_segments=${st.rwxSegments ?? 0}`);
      bits.push(`exec_stack=${st.execStack ? "yes" : "no"}`);
      bits.push(`stripped=${st.stripped ? "yes" : "no"}`);
      if (st.goBinary) bits.push("go=yes");
      if (st.rustBinary) bits.push("rust=yes");
    } else {
      bits.push(`dlls=${st.dllCount ?? 0}`, `imports=${st.importCount ?? 0}`);
      if (st.subsystemName) bits.push(`subsystem=${st.subsystemName}`);
      if (st.machineName) bits.push(`machine=${st.machineName}`);
      if (st.imphash) bits.push(`imphash=${String(st.imphash).slice(0, 16)}`);
    }
    if (st.sections?.length) bits.push(`sections=[${st.sections.map((s) => s.name).filter(Boolean).slice(0, 10).join(" ")}]`);
    const anoms = (st.anomalies ?? []).map((a) => a.kind);
    if (anoms.length) bits.push(`anomalies=[${[...new Set(anoms)].slice(0, 6).join(" ")}]`);
    return bits.length ? `STATIC: ${bits.join(" ")}` : "";
  })();

  const detectionsLine = (() => {
    const ids = [
      ...ruleMatches.map((m) => `${m.id}(${m.severity ?? "?"})`),
      ...yaraMatches.map((m) => `yara:${m.id}(${m.meta?.severity ?? "?"})`),
    ];
    return ids.length ? `DETECTIONS: ${ids.slice(0, 10).join(" ")}` : "";
  })();

  const hiddenLine = (() => {
    const bits = [];
    const stack = st.stackStrings ?? [];
    if (stack.length) bits.push(`stack_strings=[${stack.slice(0, 5).map((s) => clip(s.value, 48)).join(" | ")}]`);
    const hashes = st.apiHashes ?? [];
    if (hashes.length) {
      bits.push(`api_hashes=[${[...new Set(hashes.map((h) => `${h.algo}:${h.name}`))].slice(0, 6).join(",")}]`);
    }
    const interesting = st.strings?.interesting ?? [];
    if (interesting.length) {
      bits.push(`interesting_strings=[${interesting.slice(0, 6).map((s) => `${s.kind}:${clip(s.value, 40)}`).join(" | ")}]`);
    }
    return bits.length ? `HIDDEN STRINGS: ${bits.join(" ")}` : "";
  })();

  const executionLine = (() => {
    const bits = [];
    if (r.load?.isDll) bits.push(`dll exports=${r.load.exportCount ?? 0}`);
    if (r.run?.mode) bits.push(`mode=${r.run.mode}`);
    if (r.run?.export) bits.push(`export=${r.run.export}`);
    if (r.attach?.retval) bits.push(`attach=${r.attach.retval}`);
    if (r.runs?.length > 1) bits.push(`runs=${r.runs.length}`);
    if (r.entry?.status) bits.push(`entry=${r.entry.status}`);
    if (r.entry?.steps !== undefined) bits.push(`steps=${r.entry.steps}`);
    if (r.entry?.retval) bits.push(`retval=${r.entry.retval}`);
    if (r.exited) bits.push(`exited=yes(${r.exitCode ?? "?"})`);
    if (r.stall) {
      bits.push(`STALL=${r.stall.status}${r.stall.rip ? ` rip=${r.stall.rip}` : ""}`);
      if (r.stall.lastEvents?.length) bits.push(`last=[${r.stall.lastEvents.slice(-6).join(">")}]`);
    }
    if (r.entry?.error) bits.push(`error=${clip(r.entry.error, 60)}`);
    return bits.length ? `EXECUTION: ${bits.join(" ")}` : "";
  })();

  const artifactBits = (() => {
    const bits = [];
    const files = artifacts.files ?? [];
    const writes = files.filter((f) => f.action === "create" || f.action === "write" || f.action === "mkdir");
    if (writes.length) bits.push(`files_written=[${writes.slice(0, 5).map((f) => clip(f.path, 56)).join(" | ")}]`);
    const deletes = files.filter((f) => f.action === "delete");
    if (deletes.length) bits.push(`files_deleted=${deletes.length}`);
    const reg = artifacts.registry ?? [];
    const regSets = reg.filter((x) => x.action === "set" || x.action === "create");
    if (regSets.length) {
      bits.push(`registry=[${regSets.slice(0, 5).map((x) => `${clip(x.path, 44)}${x.value ? `#${clip(x.value, 20)}` : ""}`).join(" | ")}]`);
    }
    const net = artifacts.network ?? [];
    if (net.length) {
      bits.push(`network=[${net.slice(0, 5).map((n) => `${n.action}:${clip(n.host ?? n.url ?? "?", 48)}${n.port ? `:${n.port}` : ""}`).join(" | ")}]`);
    }
    const procs = artifacts.processes ?? [];
    if (procs.length) {
      bits.push(`processes=[${procs.slice(0, 5).map((p) => `${p.action}:${clip(p.path ?? p.cmdline ?? "?", 48)}`).join(" | ")}]`);
    }
    const cmds = artifacts.commands ?? [];
    if (cmds.length) bits.push(`commands=[${cmds.slice(0, 4).map((c) => clip(c.command, 48)).join(" | ")}]`);
    const mods = artifacts.modules ?? [];
    if (mods.length) bits.push(`modules_loaded=[${mods.slice(0, 4).map((m) => clip(m.name, 32)).join(" ")}]`);
    const mutexes = artifacts.mutexes ?? [];
    if (mutexes.length) bits.push(`mutexes=[${mutexes.slice(0, 3).map((m) => clip(m.name, 32)).join(" ")}]`);
    const ptrace = artifacts.ptrace ?? [];
    if (ptrace.length) bits.push(`ptrace_requests=${ptrace.length}`);
    const debug = artifacts.debugStrings ?? [];
    if (debug.length) bits.push(`debug_output=[${debug.slice(0, 2).map((d) => clip(d.text, 60)).join(" | ")}]`);
    return bits.length ? `OBSERVED BEHAVIOR: ${bits.join(" ")}` : "";
  })();

  const negativeLine = (() => {
    const files = artifacts.files ?? [];
    const net = artifacts.network ?? [];
    const reg = artifacts.registry ?? [];
    const procs = artifacts.processes ?? [];
    const cmds = artifacts.commands ?? [];
    const bits = [
      `file_writes=${files.some((f) => f.action === "write" || f.action === "create") ? "observed" : "not observed"}`,
      `registry_writes=${reg.some((x) => x.action === "set") ? "observed" : "not observed"}`,
      `network=${net.length ? "observed" : "not observed"}`,
      `process_creation=${procs.length ? "observed" : "not observed"}`,
      `command_execution=${cmds.length ? "observed" : "not observed"}`,
      `stall=${r.stall ? "yes" : "no"}`,
    ];
    return `NOT OBSERVED (this run): ${bits.join(" ")}`;
  })();

  const shellcodeLine = (() => {
    const sc = r.shellcode;
    if (!sc) return "";
    const bits = [];
    if (sc.os) bits.push(`os=${sc.os}`);
    if (sc.getpc) bits.push(`get_pc=${sc.getpc}`);
    if (sc.pebAccess) bits.push(`peb_walk=${sc.pebAccess}`);
    if (sc.eatHash) bits.push(`eat_hash_loops=${sc.eatHash}`);
    const scAll = (sc.syscalls?.syscall ?? 0) + (sc.syscalls?.sysenter ?? 0) + (sc.syscalls?.int2e ?? 0);
    if (scAll) bits.push(`syscall_stubs=${scAll}`);
    if (sc.syscalls?.int2d) bits.push(`int2d=${sc.syscalls.int2d}`);
    if (sc.embeddedPe !== null && sc.embeddedPe !== undefined) bits.push(`embedded_pe=0x${sc.embeddedPe.toString(16)}`);
    if (sc.unpackedBytes) bits.push(`unpacked=${sc.unpackedBytes}B`);
    if (sc.apiHashes?.length) {
      bits.push(`api_hashes=[${[...new Set(sc.apiHashes.map((h) => `${h.name}:${h.algo}`))].slice(0, 8).join(",")}]`);
    }
    if (sc.entropy !== undefined) bits.push(`entropy=${sc.entropy}`);
    if (sc.maxChunkEntropy) bits.push(`max_chunk_entropy=${sc.maxChunkEntropy}@0x${(sc.maxChunkOffset ?? 0).toString(16)}`);
    return bits.length ? `SHELLCODE FACTS: ${bits.join(" ")}` : "";
  })();

  const trace = (() => {
    const names = [];
    for (const e of Array.isArray(r.trace) ? r.trace : []) {
      if (!e?.name) continue;
      names.push(squeeze(e.name));
      if (names.length >= MAX_SEQUENCE_EVENTS) break;
    }
    if (!names.length) {
      const byName = r.apiTrace?.byName ?? r.syscalls?.byName ?? {};
      const top = Object.entries(byName).sort((a, b) => (b[1].count ?? 0) - (a[1].count ?? 0));
      return top.length ? `API CALLS: ${top.slice(0, 8).map(([n, i]) => `${n}(${i.count})`).join(" ")}` : "";
    }
    const runs = [];
    for (const n of names) {
      const last = runs[runs.length - 1];
      if (last && last.name === n) last.count++;
      else runs.push({ name: n, count: 1 });
    }
    return `TRACE: ${runs.slice(0, MAX_SEQUENCE_RUNS).map((x) => (x.count > 1 ? `${x.name}x${x.count}` : x.name)).join(">")}` +
      (runs.length > MAX_SEQUENCE_RUNS ? ">…" : "");
  })();

  const candidates = [
    ["header", () => header],
    ["static", () => staticLine],
    ["detections", () => detectionsLine],
    ["execution", () => executionLine],
    ["behavior", () => artifactBits],
    ["hiddenStrings", () => hiddenLine],
    ["shellcodeFacts", () => shellcodeLine],
    ["notObserved", () => negativeLine],
    ["trace", () => trace],
  ];

  const included = [];
  const dropped = [];
  const chunks = [];
  let used = 0;
  let clippedOnce = false;
  for (const [label, build] of candidates) {
    let text;
    try { text = squeeze(build()); } catch { text = ""; }
    if (!text) continue;
    const sep = chunks.length ? " " : "";
    if (used + sep.length + text.length <= budget) {
      chunks.push(text);
      used += sep.length + text.length;
      included.push(label);
      continue;
    }
    const remaining = budget - used - sep.length;
    if (!clippedOnce && remaining >= 40) {
      chunks.push(clip(text, remaining));
      used += sep.length + Math.min(text.length, remaining);
      included.push(`${label}(cut)`);
      clippedOnce = true;
    }
    dropped.push(label);
  }
  const state = chunks.join(" ");
  return { state, chars: state.length, budget, truncated: dropped.length > 0, included, dropped };
}
