/**
 * selfmod.mjs — executable-section write detection ("self-modifying code").
 *
 * Packers, decryptors and anti-tamper stubs write new code into the mapped
 * image and jump to it. The emulator sees those writes; the report just never
 * looked. Snapshot every executable section right before DriverEntry and diff
 * afterwards.
 *
 * Only executable sections are compared: drivers legitimately write globals
 * in .data, and flagging that would drown the signal. Writes *into* code are
 * the triage-relevant event.
 */

const MEM_EXECUTE = 0x20000000;

/**
 * @param {{read:(addr:bigint,len:number)=>Uint8Array|number[]}} mem
 * @param {{base:bigint,imageSize:number}} mapped
 * @param {{sections:Array<{name:string,rva:number,virtualSize:number,rawSize:number,chars:number}>}} pe
 * @returns {Array<{name:string,rva:number,size:number,bytes:Uint8Array}>}
 */
export function snapshotExecSections(mem, mapped, pe, { maxTotalBytes = 8 << 20 } = {}) {
  const snaps = [];
  let total = 0;
  for (const s of pe.sections ?? []) {
    if ((s.chars & MEM_EXECUTE) === 0) continue;
    const size = Math.max(s.virtualSize, s.rawSize);
    if (size <= 0 || total + size > maxTotalBytes) continue;
    try {
      const bytes = Uint8Array.from(mem.read(mapped.base + BigInt(s.rva), size));
      snaps.push({ name: s.name, rva: s.rva, size, bytes });
      total += size;
    } catch {
      /* section not backed — skip */
    }
  }
  return snaps;
}

/**
 * Diff snapshots against live memory.
 * @returns {{checked:number, totalChanged:number, sections:Array<{name:string,rva:number,changedBytes:number,ranges:Array<{rva:number,length:number}>}>}}
 */
export function diffExecSections(mem, mapped, snapshots, { maxRanges = 8, mergeGap = 16 } = {}) {
  const sections = [];
  let totalChanged = 0;
  for (const snap of snapshots ?? []) {
    let now;
    try {
      now = Uint8Array.from(mem.read(mapped.base + BigInt(snap.rva), snap.size));
    } catch {
      continue;
    }
    let changed = 0;
    const ranges = [];
    let runStart = -1;
    let runEnd = -1;
    const flush = () => {
      if (runStart < 0) return;
      if (ranges.length < maxRanges) ranges.push({ rva: snap.rva + runStart, length: runEnd - runStart + 1 });
      runStart = -1;
      runEnd = -1;
    };
    for (let i = 0; i < snap.size; i++) {
      if (now[i] !== snap.bytes[i]) {
        changed++;
        if (runStart < 0) runStart = i;
        else if (i - runEnd > mergeGap) {
          flush();
          runStart = i;
        }
        runEnd = i;
      }
    }
    flush();
    if (changed > 0) {
      sections.push({ name: snap.name, rva: snap.rva, changedBytes: changed, ranges });
      totalChanged += changed;
    }
  }
  return { checked: (snapshots ?? []).length, totalChanged, sections };
}
