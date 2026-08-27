/**
 * fuzz.mjs — coverage-guided mutation fuzzing for IOCTL buffers.
 *
 * Architecture per prompt:
 *  - basic-block tracking via CoverageTracker addCodeHook (interpreter tracing)
 *  - corpus of Uint8Array inputs tagged with coverage
 *  - mutation: bit flips, interesting values, havoc (splice+resize)
 *  - scheduling: weighted queue favoring rare coverage
 *  - deterministic reset via snapshot.mjs per iteration
 */

import { CoverageTracker } from "./coverage.mjs";
import { captureSnapshot, restoreSnapshot } from "./snapshot.mjs";

// ------------------------------------------------------------------ constants

const INTERESTING8 = [0x00, 0xff, 0x7f, 0x80, 0x01, 0xfe, 0x55, 0xaa];
const INTERESTING16 = [0x0000, 0xffff, 0x7fff, 0x8000, 0x00ff, 0xff00, 0x0100];
const INTERESTING32 = [
  0x00000000, 0xffffffff, 0x7fffffff, 0x80000000,
  0x00000001, 0xfffffffe, 0x0000ffff, 0xffff0000,
  0x7fffff00, 0x80000001,
];

// ------------------------------------------------------------------ helpers

function xorshift32(state) {
  // returns next state and value
  let x = state >>> 0;
  x ^= (x << 13) >>> 0;
  x ^= x >>> 17;
  x ^= (x << 5) >>> 0;
  return x >>> 0;
}

function makeRng(seed = 0x9e3779b1) {
  let s = seed >>> 0;
  return () => { s = xorshift32(s); return s; };
}

function randInt(rng, max) {
  if (max <= 0) return 0;
  return rng() % max;
}

function cloneBuf(b) { return new Uint8Array(b); }

function tlKey(cov) {
  // coverage fingerprint for dedup — sorted blocks join
  return [...cov.blocks].sort().join(",");
}

// Enrich corpus with harvested CTL_CODE little-endian prefix (per user request)
export function enrichWithCtlCode(codeVal, basePatterns) {
  const codeLE = new Uint8Array(4);
  codeLE[0] = codeVal & 0xff;
  codeLE[1] = (codeVal >>> 8) & 0xff;
  codeLE[2] = (codeVal >>> 16) & 0xff;
  codeLE[3] = (codeVal >>> 24) & 0xff;
  const extra = [];
  for (const pat of basePatterns) {
    const e1 = new Uint8Array(Math.max(16, pat.length));
    e1.set(codeLE, 0);
    if (pat.length > 4) e1.set(pat.subarray(4), 4);
    else if (pat.length <= 4) e1.set(pat, 4);
    extra.push(e1.slice(0, 16));
    // splice at offsets 4 and 8 as well
    for (const off of [4, 8]) {
      if (off + 4 <= e1.length) {
        const v = cloneBuf(e1);
        extra.push(v);
      }
    }
  }
  // also raw codeLE repeated
  const repeat = new Uint8Array(16);
  for (let i = 0; i < 16; i++) repeat[i] = codeLE[i % 4];
  extra.push(repeat);
  return extra;
}

// ------------------------------------------------------------------ mutation strategies

function mutBitFlip(buf, rng) {
  const out = cloneBuf(buf);
  if (!out.length) return out;
  const idx = randInt(rng, out.length);
  const bit = 1 << randInt(rng, 8);
  out[idx] ^= bit;
  return out;
}

function mutByteFlip(buf, rng) {
  const out = cloneBuf(buf);
  if (!out.length) return out;
  const idx = randInt(rng, out.length);
  out[idx] ^= 0xff;
  return out;
}

function mutInteresting8(buf, rng) {
  const out = cloneBuf(buf);
  if (!out.length) return out;
  const idx = randInt(rng, out.length);
  out[idx] = INTERESTING8[randInt(rng, INTERESTING8.length)];
  return out;
}

function mutInteresting16LE(buf, rng) {
  const out = cloneBuf(buf);
  if (out.length < 2) return mutInteresting8(buf, rng);
  const idx = randInt(rng, out.length - 1);
  const v = INTERESTING16[randInt(rng, INTERESTING16.length)];
  out[idx] = v & 0xff;
  out[idx + 1] = (v >>> 8) & 0xff;
  return out;
}

function mutInteresting32LE(buf, rng) {
  const out = cloneBuf(buf);
  if (out.length < 4) return mutInteresting8(buf, rng);
  const idx = randInt(rng, out.length - 3);
  const v = INTERESTING32[randInt(rng, INTERESTING32.length)] >>> 0;
  out[idx] = v & 0xff;
  out[idx + 1] = (v >>> 8) & 0xff;
  out[idx + 2] = (v >>> 16) & 0xff;
  out[idx + 3] = (v >>> 24) & 0xff;
  return out;
}

function mutRandomByte(buf, rng) {
  const out = cloneBuf(buf);
  if (!out.length) return out;
  const idx = randInt(rng, out.length);
  out[idx] = randInt(rng, 256);
  return out;
}

function mutSplice(buf, corpus, rng) {
  if (!corpus.length) return mutBitFlip(buf, rng);
  const other = corpus[randInt(rng, corpus.length)].buf;
  if (!other.length || !buf.length) return cloneBuf(buf);
  const cutA = randInt(rng, buf.length);
  const cutB = randInt(rng, other.length);
  const out = new Uint8Array(Math.max(buf.length, other.length));
  // random: take prefix from buf up to cutA, suffix from other from cutB
  out.set(buf.subarray(0, cutA), 0);
  const suffixLen = Math.min(other.length - cutB, out.length - cutA);
  if (suffixLen > 0) out.set(other.subarray(cutB, cutB + suffixLen), cutA);
  // fill rest with existing
  return out.slice(0, buf.length);
}

function mutResize(buf, rng) {
  const delta = randInt(rng, 16) - 8; // -8..+7
  let newLen = Math.max(1, Math.min(256, buf.length + delta));
  // occasionally snap to interesting lengths
  if (randInt(rng, 8) === 0) {
    const sizes = [1, 4, 8, 16, 32, 64, 128];
    newLen = sizes[randInt(rng, sizes.length)];
  }
  const out = new Uint8Array(newLen);
  const copyLen = Math.min(buf.length, newLen);
  out.set(buf.subarray(0, copyLen), 0);
  if (newLen > copyLen) {
    for (let i = copyLen; i < newLen; i++) out[i] = randInt(rng, 256);
  }
  return out;
}

function mutHavoc(buf, corpus, rng) {
  let out = cloneBuf(buf);
  const stacks = 1 + randInt(rng, 4); // 1..4
  for (let i = 0; i < stacks; i++) {
    const pick = randInt(rng, 8);
    switch (pick) {
      case 0: out = mutBitFlip(out, rng); break;
      case 1: out = mutByteFlip(out, rng); break;
      case 2: out = mutInteresting8(out, rng); break;
      case 3: out = mutInteresting16LE(out, rng); break;
      case 4: out = mutInteresting32LE(out, rng); break;
      case 5: out = mutSplice(out, corpus, rng); break;
      case 6: out = mutResize(out, rng); break;
      case 7: out = mutRandomByte(out, rng); break;
    }
  }
  return out;
}

function mutateSingle(buf, corpus, rng) {
  const r = randInt(rng, 100);
  if (r < 10) return mutBitFlip(buf, rng);
  if (r < 18) return mutByteFlip(buf, rng);
  if (r < 28) return mutInteresting8(buf, rng);
  if (r < 36) return mutInteresting16LE(buf, rng);
  if (r < 44) return mutInteresting32LE(buf, rng);
  if (r < 56) return mutRandomByte(buf, rng);
  if (r < 70) return mutSplice(buf, corpus, rng);
  if (r < 80) return mutResize(buf, rng);
  return mutHavoc(buf, corpus, rng);
}

// ------------------------------------------------------------------ scheduling

function buildGlobalHitCounts(corpusEntries) {
  const m = new Map();
  for (const e of corpusEntries) {
    for (const b of e.coverage?.blocks ?? []) {
      m.set(b, (m.get(b) ?? 0) + 1);
    }
  }
  return m;
}

function pickParent(corpus, globalHits, rng) {
  if (!corpus.length) return null;
  if (corpus.length === 1) return corpus[0];
  // score = sum hit counts of its blocks; lower = rarer
  const scored = corpus.map((e, idx) => {
    let sum = 0;
    let n = 0;
    for (const b of e.coverage.blocks) {
      sum += globalHits.get(b) ?? 1;
      n++;
    }
    const avg = n ? sum / n : 1;
    return { idx, entry: e, score: avg };
  });
  scored.sort((a, b) => a.score - b.score);
  // weighted toward rare: pick among top 1/3 with bias
  const pool = Math.max(1, Math.min(3, Math.ceil(scored.length / 3)));
  const top = scored.slice(0, pool);
  // inverse score weights
  const inv = top.map((s) => 1 / (s.score + 1));
  const tot = inv.reduce((a, b) => a + b, 0);
  let r = (rng() / 0xffffffff) * tot;
  for (let i = 0; i < top.length; i++) {
    r -= inv[i];
    if (r <= 0) return top[i].entry;
  }
  return top[0].entry;
}

// ------------------------------------------------------------------ main fuzz

/**
 * Fuzz a single IOCTL code with coverage guidance.
 * @param {object} kernel NtKernel
 * @param {object} device device record
 * @param {number} ctlCode harvested CTL_CODE value
 * @param {object} opts {iterations, corpusCap, inputLen, outputLen, seedPatterns, onProgress, sendIrp, imageBase, imageSize}
 * @returns {{corpus:Array, globalSeen:Set, hits:Map, iterations:number, best:object|null}}
 */
export async function fuzzIoctl(kernel, device, ctlCode, opts = {}) {
  const iterations = opts.iterations ?? 256;
  const corpusCap = opts.corpusCap ?? 32;
  const inputLen = opts.inputLen ?? 16;
  const outputLen = opts.outputLen ?? 64;
  const sendIrp = opts.sendIrp;
  if (!sendIrp) throw new Error("fuzzIoctl: sendIrp required");
  const base = opts.imageBase;
  const size = opts.imageSize;
  if (base === undefined || size === undefined) throw new Error("fuzzIoctl: imageBase/imageSize required");

  const rng = makeRng((ctlCode >>> 0) ^ 0x9e3779b1 ^ iterations);

  // seed corpus
  let seeds = opts.seedPatterns ?? [
    new Uint8Array(inputLen),
    Uint8Array.from({ length: inputLen }, () => 0xff),
    Uint8Array.from({ length: inputLen }, (_, i) => i & 0xff),
  ];
  // enrich with CTL_CODE prefix as per user ask #5
  const enriched = enrichWithCtlCode(ctlCode >>> 0, seeds);
  seeds = [...seeds, ...enriched].map((b) => b.length === inputLen ? b : (() => { const u = new Uint8Array(inputLen); u.set(b.subarray(0, Math.min(b.length, inputLen))); return u; })());

  const tracker = new CoverageTracker(kernel, base, size);
  tracker.install();

  const snap0 = captureSnapshot(kernel);

  let corpus = [];
  const globalSeen = new Set();
  let globalHits = new Map();

  // helper to run one input with coverage, handling snapshot
  async function runInput(buf) {
    const snap = captureSnapshot(kernel);
    tracker.reset();
    tracker.resume();
    let res;
    try {
      res = await sendIrp(kernel, device, {
        major: 0x0e,
        ioctl: BigInt(ctlCode >>> 0),
        input: buf,
        outputLen,
      });
    } catch (e) {
      res = { status: "fault", error: e, ntstatus: 0xc0000005n };
    }
    tracker.pause();
    const cov = new Set(tracker.blocks); // copy
    // capture edges too but primary novelty is blocks
    const covObj = { blocks: new Set(tracker.blocks), edges: new Set(tracker.edges) };
    restoreSnapshot(kernel, snap);
    tracker.reset();
    return { res, coverage: covObj };
  }

  // seed phase: evaluate each seed, populate corpus with any that adds coverage
  for (const s of seeds.slice(0, Math.min(seeds.length, corpusCap * 2))) {
    const { res, coverage } = await runInput(s);
    if (opts.onProgress) opts.onProgress({ phase: "seed", buf: s, coverage, res });
    const newBlocks = [...coverage.blocks].filter((b) => !globalSeen.has(b));
    if (newBlocks.length > 0 || corpus.length === 0) {
      for (const b of coverage.blocks) globalSeen.add(b);
      corpus.push({ buf: cloneBuf(s), coverage, res });
      if (globalSeen.size > 0) {
        // early exit if we already hit success with minimal coverage?
      }
    }
    if (corpus.length >= corpusCap) break;
    if (kernel.bugcheck || kernel.crash) break;
    // keep globalHits up to date
    globalHits = buildGlobalHitCounts(corpus);
  }
  // if seeds produced nothing (e.g., every run trapped outside image), seed with one entry
  if (!corpus.length && seeds.length) {
    const s = seeds[0];
    const { res, coverage } = await runInput(s);
    corpus.push({ buf: cloneBuf(s), coverage, res });
    for (const b of coverage.blocks) globalSeen.add(b);
    globalHits = buildGlobalHitCounts(corpus);
  }

  let best = corpus.find((c) => c.res?.ntstatus === 0n) ?? null;
  let itersDone = 0;

  // main loop
  for (let iter = 0; iter < iterations; iter++) {
    if (kernel.bugcheck || kernel.crash) break;
    itersDone = iter + 1;
    const parent = pickParent(corpus, globalHits, rng);
    if (!parent) break;
    const child = mutateSingle(parent.buf, corpus, rng);
    // enforce expected length 1..64 but allow resize; clamp for this ioctl run
    // keep as is; sendIrp handles any length via SystemBuffer
    const { res, coverage } = await runInput(child);
    if (opts.onProgress) opts.onProgress({ phase: "fuzz", iter, buf: child, coverage, res });

    const newBlocks = [...coverage.blocks].filter((b) => !globalSeen.has(b));
    const hasNew = newBlocks.length > 0;
    const isSuccess = res?.status === "ok" && res?.ntstatus === 0n;
    // keep if new coverage OR (success and not already in corpus)
    const alreadyHave = corpus.some((e) => tlKey(e.coverage) === tlKey(coverage) && e.buf.length === child.length && e.buf.every((v,i)=>v===child[i]));
    if ((hasNew && !alreadyHave) || (isSuccess && !alreadyHave && corpus.length < corpusCap)) {
      for (const b of coverage.blocks) globalSeen.add(b);
      // update globalHits later
      corpus.push({ buf: cloneBuf(child), coverage, res });
      // evict if over cap: drop entry with highest avg hit (most common)
      if (corpus.length > corpusCap) {
        const scored = corpus.map((e) => {
          let sum = 0, n=0;
          for (const b of e.coverage.blocks) { sum += globalHits.get(b) ?? 1; n++; }
          return { e, score: n ? sum/n : 0 };
        });
        scored.sort((a,b)=> b.score - a.score);
        const worst = scored[0].e;
        const idx = corpus.indexOf(worst);
        if (idx>=0) corpus.splice(idx,1);
      }
      globalHits = buildGlobalHitCounts(corpus);
      if (isSuccess && (!best || (coverage.blocks.size > (best.coverage?.blocks.size ?? 0)))) {
        best = { buf: cloneBuf(child), coverage, res };
      }
    } else if (isSuccess && !best) {
      best = { buf: cloneBuf(child), coverage, res };
    }

    // early stop if we found a big coverage jump? continue until budget
  }

  restoreSnapshot(kernel, snap0);
  tracker.dispose();

  return {
    ctlCode,
    corpus,
    globalSeen,
    globalHits,
    iterations: itersDone,
    best,
  };
}
