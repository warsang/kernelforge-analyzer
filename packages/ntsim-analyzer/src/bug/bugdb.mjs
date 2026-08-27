/**
 * bugdb.mjs — bug record schema and in-memory DB for Find Bugs
 */

export function makeBug({
  driverHash, ioctlCode, sinkType, sinkApi, sinkLocation,
  taintedOperands, controlDegree, witnessInput, witnessLen,
  pathConstraints, callStack, coverageDelta, severity, taintFlows,
  rip, engine,
}) {
  return {
    driverHash: driverHash || "unknown",
    ioctlCode: typeof ioctlCode==="bigint" ? `0x${ioctlCode.toString(16)}` : ioctlCode,
    sinkType,
    sinkApi: sinkApi || null,
    sinkLocation: sinkLocation || (rip ? `0x${BigInt(rip).toString(16)}` : null),
    taintedOperands: taintedOperands || [],
    controlDegree, // "full" | "bounded" | "influenced"
    witnessInput: typeof witnessInput==="string" ? witnessInput : (witnessInput ? [...witnessInput].map(b=>b.toString(16).padStart(2,"0")).join("") : null),
    witnessLen,
    pathConstraints: pathConstraints || null,
    callStack: callStack || [],
    coverageDelta,
    severity,
    taintFlows: taintFlows || [],
    engine: engine || "js",
    foundAt: new Date().toISOString(),
  };
}

export class BugDB {
  constructor() { this.bugs = []; this.seen = new Set(); }
  add(bug) {
    const key = `${bug.ioctlCode}:${bug.sinkType}:${bug.sinkLocation}:${bug.controlDegree}`;
    if (this.seen.has(key)) return false;
    this.seen.add(key);
    this.bugs.push(bug);
    return true;
  }
  all() { return [...this.bugs].sort((a,b)=> (b.severity||0)-(a.severity||0)); }
  bySeverity(min=5) { return this.bugs.filter(b=> (b.severity||0) >= min); }
  toJSON() { return JSON.stringify(this.bugs, null, 2); }
}
