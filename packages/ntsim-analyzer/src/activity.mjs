/**
 * activity.mjs — turn raw kernel-side evidence into report-ready summaries.
 *
 * Two deterministic transforms the state text (and any downstream consumer)
 * relies on:
 *
 *  1. Registry activity: real driver mutations (`kernel.registryWriteLog`)
 *     classified by key, instead of "how many values exist in the registry"
 *     (which counts the analyzer's own seeding and the emulator's
 *     auto-created keys).
 *  2. API resolution evidence: what `MmGetSystemRoutineAddress` actually
 *     resolved, provisioned or failed to resolve.
 *
 * Both are pure functions over the kernel model — no policy about what is
 * "malicious", just structure. The verdict layer does the interpreting.
 */

/** Registry key categories, in match order. */
export const REGISTRY_CATEGORIES = [
  "user", "bcd", "security", "self", "boot", "services", "other",
];

const SECURITY_RE =
  /windows defender|\\policies\\system|firewallpolicy|\\wdac|ci\\policy|\\deviceguard|\\applocker/;
const SERVICES_RE = /currentcontrolset\\services\\([^\\]+)/;

/**
 * Classify one registry path.
 * @param {string} key full path (e.g. \Registry\Machine\SYSTEM\...)
 * @param {{driverStem?:string|null}} [opts]
 * @returns {"user"|"bcd"|"security"|"self"|"boot"|"services"|"other"}
 */
export function classifyRegistryKey(key, { driverStem = null } = {}) {
  const p = String(key ?? "").toLowerCase();
  if (!p) return "other";
  if (p.startsWith("\\registry\\user")) return "user";
  if (p.startsWith("\\registry\\machine\\bcd") || p.includes("\\bcd\\")) return "bcd";
  if (SECURITY_RE.test(p)) return "security";
  const svc = SERVICES_RE.exec(p);
  if (svc) {
    const stem = driverStem ? String(driverStem).toLowerCase() : null;
    return stem && svc[1] === stem ? "self" : "services";
  }
  if (p.includes("\\currentcontrolset\\control\\")) return "boot";
  return "other";
}

const hex = (v) => "0x" + BigInt(v ?? 0n).toString(16);

/**
 * Summarize real driver registry mutations.
 * @param {object} kernel
 * @param {{driverName?:string, regPath?:string|null}} [opts]
 */
export function summarizeRegistryActivity(kernel, { driverName = "", regPath = null } = {}) {
  const log = kernel?.registryWriteLog ?? [];
  const driverStem = driverName
    ? String(driverName).split(/[\\/]/).pop().replace(/\.[^.]*$/, "")
    : null;
  const categories = Object.fromEntries(REGISTRY_CATEGORIES.map((c) => [c, 0]));
  const keyCounts = new Map();
  let writes = 0, creates = 0, deletes = 0;

  for (const e of log) {
    if (e.op === "set") writes++;
    else if (e.op === "create") creates++;
    else if (e.op === "delete-value") deletes++;
    const cat = classifyRegistryKey(e.key, { driverStem });
    categories[cat] = (categories[cat] ?? 0) + 1;
    const rec = keyCounts.get(e.key) ?? { key: e.key, category: cat, ops: 0, values: new Set() };
    rec.ops++;
    if (e.value) rec.values.add(e.value);
    keyCounts.set(e.key, rec);
  }

  const modifiedKeys = [...keyCounts.values()]
    .sort((a, b) => b.ops - a.ops)
    .slice(0, 16)
    .map((r) => ({
      key: r.key,
      category: r.category,
      ops: r.ops,
      values: [...r.values].slice(0, 6),
    }));

  const autoCreated = (kernel?.registryAutoCreated ?? []).length;
  const servicePath = regPath ? String(regPath).toLowerCase() : null;
  const touchedSelfServiceKey = servicePath
    ? [...keyCounts.keys()].some((k) => String(k).toLowerCase().startsWith(servicePath))
    : categories.self > 0;

  return {
    writes,
    creates,
    deletes,
    total: log.length,
    categories,
    modifiedKeys,
    autoCreatedKeys: autoCreated,
    flags: {
      selfServiceKey: touchedSelfServiceKey,
      securityPolicy: categories.security > 0,
      bootConfig: categories.boot > 0,
      otherServices: categories.services > 0,
      userHive: categories.user > 0,
      bcd: categories.bcd > 0,
    },
  };
}

/**
 * Summarize `MmGetSystemRoutineAddress` evidence.
 * @param {object} kernel
 */
export function summarizeApiResolutions(kernel) {
  const map = kernel?.apiResolutions instanceof Map ? kernel.apiResolutions : new Map();
  const out = { resolved: [], provisioned: [], unresolved: [], counts: { resolved: 0, provisioned: 0, unresolved: 0 } };
  for (const rec of map.values()) {
    if (rec.result === "unresolved") {
      out.unresolved.push({ name: rec.name, count: rec.count });
      out.counts.unresolved++;
    } else if (rec.result === "provisioned") {
      out.provisioned.push({ name: rec.name, count: rec.count });
      out.counts.provisioned++;
    } else {
      out.resolved.push({
        name: rec.name,
        kind: rec.result, // "modeled" | "data"
        target: hex(rec.target),
        count: rec.count,
      });
      out.counts.resolved++;
    }
  }
  const byName = (a, b) => a.name.localeCompare(b.name);
  out.resolved.sort(byName);
  out.provisioned.sort(byName);
  out.unresolved.sort(byName);
  return out;
}
