/**
 * yara-rulesets.mjs — load community YARA rulesets for the YARA-X scanner.
 *
 * Built-in packs (./yara-packs.mjs) are small and always available; these
 * community sets are large (MBs of source), so they are loaded on demand,
 * extracted (ZIP for YARA Forge), concatenated and cached in the Cache API.
 *
 * Sources:
 *   - YARA Forge (core / extended / full) release ZIPs (YARAHQ/yara-forge)
 *   - Bartblaze Yara-rules (rules/**\/*.yar)
 *
 * Nothing here compiles rules; pass the returned source to scanWithYaraX().
 */

const CACHE_NAME = "kf-yara-rules-v1";

export const RULESETS = {
  "yara-forge-core": {
    label: "YARA Forge Core",
    description: "YARA Forge core package — deduplicated, FP-filtered, edge-friendly (~1.7 MB zip).",
    kind: "zip",
    url: "https://github.com/YARAHQ/yara-forge/releases/latest/download/yara-forge-rules-core.zip",
    approxBytes: 1_700_000,
  },
  "yara-forge-extended": {
    label: "YARA Forge Extended",
    description: "YARA Forge extended package — core plus hunting rules (~3.5 MB zip).",
    kind: "zip",
    url: "https://github.com/YARAHQ/yara-forge/releases/latest/download/yara-forge-rules-extended.zip",
    approxBytes: 3_500_000,
  },
  "yara-forge-full": {
    label: "YARA Forge Full",
    description: "YARA Forge full package (~4 MB zip).",
    kind: "zip",
    url: "https://github.com/YARAHQ/yara-forge/releases/latest/download/yara-forge-rules-full.zip",
    approxBytes: 4_000_000,
  },
  bartblaze: {
    label: "Bartblaze",
    description: "bartblaze/Yara-rules — lean, YARA-X-tested malware family rules (~110 .yar files).",
    kind: "tarball",
    tarballUrl: "https://codeload.github.com/bartblaze/Yara-rules/tar.gz/refs/heads/master",
    pathFilter: /(?:^|\/)rules\//,
    approxBytes: 500_000,
  },
  "signature-base": {
    label: "Signature-Base (Florian Roth)",
    description: "Neo23x0/signature-base — the full reference ruleset (~750 .yar files: APT, crimeware, webshells, memory, macOS/Linux).",
    kind: "tarball",
    tarballUrl: "https://codeload.github.com/Neo23x0/signature-base/tar.gz/refs/heads/master",
    pathFilter: /(?:^|\/)yara\//,
    approxBytes: 1_900_000,
  },
  "signature-base-lite": {
    label: "Signature-Base (Windows/PE lite)",
    description: "Signature-Base filtered to Windows/PE-relevant rules — drops macOS/Linux/webshell/script-only rules (~40% fewer rules, lower memory).",
    kind: "tarball",
    tarballUrl: "https://codeload.github.com/Neo23x0/signature-base/tar.gz/refs/heads/master",
    pathFilter: /(?:^|\/)yara\//,
    // file-based filter: keep Windows/PE/script rule files, drop macOS/Linux/
    // webshell/other-platform files (855 of 5,991 rules)
    fileFilter: /^(?:(?!.*(?:osx|macos|macho|linux|lnx_|_elf|webshell|android|iot|perl|python|_php)).*)$/i,
    approxBytes: 1_200_000,
  },
  elastic: {
    label: "Elastic Security",
    description: "elastic/protections-artifacts — Elastic's detection rules (~1000 .yar files, cross-platform malware).",
    kind: "tarball",
    tarballUrl: "https://codeload.github.com/elastic/protections-artifacts/tar.gz/refs/heads/main",
    pathFilter: /(?:^|\/)yara\/rules\//,
    approxBytes: 1_600_000,
  },
  reversinglabs: {
    label: "ReversingLabs",
    description: "reversinglabs/reversinglabs-yara-rules — RL malware family rules (~300 .yara files).",
    kind: "tarball",
    tarballUrl: "https://codeload.github.com/reversinglabs/reversinglabs-yara-rules/tar.gz/refs/heads/develop",
    pathFilter: /(?:^|\/)yara\//,
    approxBytes: 500_000,
  },
};

export const RULESET_IDS = Object.keys(RULESETS);

/**
 * The "one button" community bundle: YARA Forge Extended (superset of Core;
 * compiling both together fails on duplicate rule identifiers) plus Bartblaze.
 * Each set is compiled/scanned separately and matches are merged.
 */
export const DEFAULT_COMMUNITY_RULESETS = [
  // Core is the deduplicated, FP-filtered Forge package (~7.6 MB source);
  // Full/Extended stay available as opt-in checkboxes (they are 2-3x the
  // source and the usual cause of wasm memory pressure). Signature-Base is
  // the Windows/PE-filtered lite variant by default; the full set is opt-in.
  "yara-forge-core",
  "signature-base-lite",
  "elastic",
  "reversinglabs",
  "bartblaze",
];

/** Opt-in rulesets (off by default: large source, memory-hungry). */
export const OPTIONAL_RULESETS = ["yara-forge-extended", "yara-forge-full", "signature-base"];

/** Everything the staging script should fetch so any checkbox works offline. */
export const ALL_RULESETS = [...DEFAULT_COMMUNITY_RULESETS, ...OPTIONAL_RULESETS];

/** Rulesets whose source is large enough to warrant a memory warning. */
export const HEAVY_RULESETS = new Set(OPTIONAL_RULESETS);

/** Same-origin staged files (see apps/analyzer-web/scripts/fetch-yara-rulesets.mjs). */
export const STAGED_RULESET_BASE = "/yara/";

async function cacheStore() {
  try {
    return typeof caches !== "undefined" ? caches : null;
  } catch {
    return null;
  }
}

async function cacheGet(key) {
  const store = await cacheStore();
  if (!store) return null;
  try {
    const hit = await store.match(key);
    return hit ? await hit.text() : null;
  } catch {
    return null;
  }
}

async function cachePut(key, text) {
  const store = await cacheStore();
  if (!store) return;
  try {
    await store.put(key, new Response(text, { headers: { "content-type": "text/plain; charset=utf-8" } }));
  } catch {
    /* quota / private mode */
  }
}

async function fetchBytes(url, { fetchImpl = fetch, onProgress = null, file = null } = {}) {
  const res = await fetchImpl(url);
  if (!res?.ok) throw new Error(`ruleset fetch failed (HTTP ${res?.status ?? "?"}): ${url}`);
  const total = Number(res.headers?.get?.("content-length")) || 0;
  const name = file ?? String(url).split("/").pop();
  if (res.body?.getReader) {
    const reader = res.body.getReader();
    let received = 0;
    let data = total ? new Uint8Array(total) : null;
    const chunks = total ? null : [];
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      if (data) {
        if (received + value.length > data.length) {
          // content-length can describe the *encoded* size (gzip/br), so the
          // decoded stream may be larger — grow instead of overflowing.
          const grown = new Uint8Array(Math.max(data.length * 2, received + value.length));
          grown.set(data.subarray(0, received));
          data = grown;
        }
        data.set(value, received);
      } else {
        chunks.push(value);
      }
      received += value.length;
      onProgress?.({ phase: "download", file: name, loaded: received, total: total || null });
    }
    if (!data) {
      data = new Uint8Array(received);
      let off = 0;
      for (const c of chunks) { data.set(c, off); off += c.length; }
    } else {
      // the buffer may have grown past the decoded length (content-length is
      // the *encoded* size) — always trim to what was actually received
      data = data.subarray(0, received);
    }
    return data;
  }
  if (typeof res.arrayBuffer === "function") return new Uint8Array(await res.arrayBuffer());
  if (typeof res.text === "function") return new TextEncoder().encode(await res.text());
  throw new Error(`ruleset fetch: response has no body (${url})`);
}

/* ------------------------------------------------------------------- zip */

const u16 = (b, o) => b[o] | (b[o + 1] << 8);
const u32 = (b, o) => (b[o] | (b[o + 1] << 8) | (b[o + 2] << 16) | (b[o + 3] << 24)) >>> 0;

/** Locate the End Of Central Directory record (ignoring ZIP64 for now). */
function findEocd(bytes) {
  for (let i = bytes.length - 22; i >= Math.max(0, bytes.length - 66_000); i--) {
    if (bytes[i] === 0x50 && bytes[i + 1] === 0x4b && bytes[i + 2] === 0x05 && bytes[i + 3] === 0x06) return i;
  }
  return -1;
}

/**
 * List + extract ZIP entries (stored or deflate). Uses DecompressionStream
 * ("deflate-raw"), available in modern browsers and Node >= 18.
 * @returns {Promise<Array<{name:string, text:string}>>}
 */
export async function extractZipText(bytes) {
  const b = bytes instanceof Uint8Array ? bytes : Uint8Array.from(bytes);
  const eocd = findEocd(b);
  if (eocd < 0) throw new Error("zip: end-of-central-directory not found");
  const count = u16(b, eocd + 10);
  let cd = u32(b, eocd + 16);
  const out = [];
  for (let i = 0; i < count; i++) {
    if (cd + 46 > b.length || u32(b, cd) !== 0x02014b50) break;
    const method = u16(b, cd + 10);
    const compSize = u32(b, cd + 20);
    const nameLen = u16(b, cd + 28);
    const extraLen = u16(b, cd + 30);
    const commentLen = u16(b, cd + 32);
    const localOff = u32(b, cd + 42);
    const name = new TextDecoder().decode(b.subarray(cd + 46, cd + 46 + nameLen));
    cd += 46 + nameLen + extraLen + commentLen;
    if (!/\.(?:yar|yara)$/i.test(name)) continue;
    if (localOff + 30 > b.length || u32(b, localOff) !== 0x04034b50) continue;
    const lNameLen = u16(b, localOff + 26);
    const lExtraLen = u16(b, localOff + 28);
    const dataStart = localOff + 30 + lNameLen + lExtraLen;
    const raw = b.subarray(dataStart, dataStart + compSize);
    let text;
    if (method === 0) {
      text = new TextDecoder().decode(raw);
    } else if (method === 8) {
      if (typeof DecompressionStream !== "function") throw new Error("zip: deflate unsupported (no DecompressionStream)");
      const stream = new Blob([raw]).stream().pipeThrough(new DecompressionStream("deflate-raw"));
      text = await new Response(stream).text();
    } else {
      continue; // unsupported compression
    }
    out.push({ name, text });
  }
  return out;
}

/* ---------------------------------------------------------------- tar.gz */

const TAR_BLOCK = 512;

function octal(bytes, off, len) {
  let s = "";
  for (let i = 0; i < len; i++) {
    const c = bytes[off + i];
    if (c === 0 || c === 0x20) break;
    s += String.fromCharCode(c);
  }
  return parseInt(s, 8) || 0;
}

/**
 * List + extract .yar/.yara files from a .tar.gz archive (one HTTP request
 * per ruleset repository; no per-file fetches, no API rate limits).
 * @param {Uint8Array} bytes gzip-compressed tar
 * @returns {Promise<Array<{name:string, text:string}>>}
 */
export async function extractTarGzText(bytes, { filter = null } = {}) {
  const b = bytes instanceof Uint8Array ? bytes : Uint8Array.from(bytes);
  if (typeof DecompressionStream !== "function") throw new Error("tar.gz: DecompressionStream unavailable");
  const stream = new Blob([b]).stream().pipeThrough(new DecompressionStream("gzip"));
  const raw = new Uint8Array(await new Response(stream).arrayBuffer());
  const out = [];
  let off = 0;
  while (off + TAR_BLOCK <= raw.length) {
    const nameEnd = raw.indexOf(0, off);
    const name = new TextDecoder().decode(raw.subarray(off, nameEnd > off ? Math.min(nameEnd, off + 100) : off + 100)).replace(/\0.*$/, "");
    if (!name) break; // two zero blocks end the archive
    const size = octal(raw, off + 124, 12);
    const type = raw[off + 156];
    const prefix = new TextDecoder().decode(raw.subarray(off + 345, off + 345 + 155)).replace(/\0.*$/, "");
    const full = prefix ? `${prefix}/${name}` : name;
    const dataStart = off + TAR_BLOCK;
    const dataEnd = dataStart + size;
    if (dataEnd > raw.length) break;
    if ((type === 0 || type === 0x30 || type === 0) && /\.(?:yar|yara)$/i.test(full) && (!filter || filter.test(full))) {
      out.push({ name: full, text: new TextDecoder().decode(raw.subarray(dataStart, dataEnd)) });
    }
    off = dataStart + Math.ceil(size / TAR_BLOCK) * TAR_BLOCK;
  }
  return out;
}

/* --------------------------------------------------------------- loading */

async function loadYaraForge(id, meta, { fetchImpl, onProgress }) {
  onProgress?.({ phase: `fetching ${meta.label}`, file: null, loaded: 0, total: meta.approxBytes });
  const zip = await fetchBytes(meta.url, { fetchImpl, onProgress, file: `${id}.zip` });
  onProgress?.({ phase: `extracting ${meta.label}`, file: null, loaded: 0, total: 0 });
  const entries = await extractZipText(zip);
  if (!entries.length) throw new Error(`${id}: no .yar entries in archive`);
  return entries.map((e) => `/* ${e.name} */\n${e.text}`).join("\n");
}

async function loadTarball(id, meta, { fetchImpl, onProgress }) {
  onProgress?.({ phase: `fetching ${meta.label}`, file: null, loaded: 0, total: meta.approxBytes });
  const gz = await fetchBytes(meta.tarballUrl, { fetchImpl, onProgress, file: `${id}.tar.gz` });
  onProgress?.({ phase: `extracting ${meta.label}`, file: null, loaded: 0, total: 0 });
  let entries = await extractTarGzText(gz, { filter: meta.pathFilter ?? null });
  if (!entries.length) throw new Error(`${id}: no .yar entries in archive`);
  if (meta.fileFilter) {
    // keep only rule files whose path passes the filter (platform subsets)
    entries = entries.filter((e) => meta.fileFilter.test(e.name));
    if (!entries.length) throw new Error(`${id}: file filter removed every rule`);
  }
  return entries.map((e) => `/* ${e.name} */\n${e.text}`).join("\n");
}

/**
 * Split a YARA source into top-level rule blocks plus the `import` prelude.
 * Brace/regex/string/comment aware so `{n,m}` quantifiers and braces inside
 * strings don't confuse the splitter.
 * @returns {{imports:string[], blocks:Array<{name:string,text:string}>}}
 */
export function splitYaraSource(source) {
  const src = String(source ?? "");
  const imports = [];
  const blocks = [];
  const n = src.length;
  let i = 0;

  const skipString = (start) => {
    let j = start + 1;
    while (j < n) {
      if (src[j] === "\\") { j += 2; continue; }
      if (src[j] === '"') return j + 1;
      j++;
    }
    return n;
  };
  const skipRegex = (start) => {
    let j = start + 1;
    let inClass = false;
    while (j < n) {
      const c = src[j];
      if (c === "\\") { j += 2; continue; }
      if (c === "[") inClass = true;
      else if (c === "]") inClass = false;
      else if (c === "/" && !inClass) return j + 1;
      else if (c === "\n") return j; // not a regex after all
      j++;
    }
    return n;
  };
  const prevMeaningful = (idx) => {
    for (let j = idx - 1; j >= 0; j--) {
      const c = src[j];
      if (c === " " || c === "\t" || c === "\n" || c === "\r") continue;
      return c;
    }
    return "";
  };

  while (i < n) {
    const c = src[i];
    if (c === "/" && src[i + 1] === "/") { const nl = src.indexOf("\n", i); i = nl < 0 ? n : nl + 1; continue; }
    if (c === "/" && src[i + 1] === "*") { const end = src.indexOf("*/", i + 2); i = end < 0 ? n : end + 2; continue; }
    if (c === '"') { i = skipString(i); continue; }
    if (c === "/" && !/[\w)\]"'%]/.test(prevMeaningful(i))) { i = skipRegex(i); continue; }
    if (/^import\s/.test(src.slice(i, i + 7))) {
      const nl = src.indexOf("\n", i);
      imports.push(src.slice(i, nl < 0 ? n : nl).trim());
      i = nl < 0 ? n : nl + 1;
      continue;
    }
    if (/^rule\s/.test(src.slice(i, i + 5))) {
      // Include preceding `private` / `global` modifiers (and whitespace) so
      // recompiled blocks keep their semantics.
      let start = i;
      let back = i;
      for (;;) {
        let m = back - 1;
        while (m >= 0 && /\s/.test(src[m])) m--;
        let wordStart = m;
        while (wordStart >= 0 && /[A-Za-z_]/.test(src[wordStart])) wordStart--;
        const word = src.slice(wordStart + 1, m + 1);
        if (word === "private" || word === "global") {
          start = wordStart + 1;
          back = start;
          continue;
        }
        break;
      }
      // name
      let j = i + 5;
      while (j < n && /\s/.test(src[j])) j++;
      let name = "";
      while (j < n && /[A-Za-z0-9_]/.test(src[j])) name += src[j++];
      // find the opening brace
      while (j < n && src[j] !== "{") {
        if (src[j] === '"') { j = skipString(j); continue; }
        if (src[j] === "/" && src[j + 1] === "/") { const nl = src.indexOf("\n", j); j = nl < 0 ? n : nl; continue; }
        if (src[j] === "/" && src[j + 1] === "*") { const end = src.indexOf("*/", j + 2); j = end < 0 ? n : end + 2; continue; }
        j++;
      }
      let depth = 0;
      while (j < n) {
        const d = src[j];
        if (d === '"') { j = skipString(j); continue; }
        if (d === "/" && src[j + 1] === "/") { const nl = src.indexOf("\n", j); j = nl < 0 ? n : nl + 1; continue; }
        if (d === "/" && src[j + 1] === "*") { const end = src.indexOf("*/", j + 2); j = end < 0 ? n : end + 2; continue; }
        if (d === "/" && !/[\w)\]"'%]/.test(prevMeaningful(j))) { j = skipRegex(j); continue; }
        if (d === "{") depth++;
        else if (d === "}") { depth--; if (depth === 0) { j++; break; } }
        j++;
      }
      blocks.push({ name, text: src.slice(start, j) });
      i = j;
      continue;
    }
    i++;
  }
  return { imports, blocks };
}

/**
 * Compile+scan a large community source in chunks. A ruleset with a few
 * rules YARA-X rejects (e.g. signature-base uses `filename`) must not lose
 * the whole set: failed chunks are bisected and only the offending rules are
 * reported as errors.
 * @returns {Promise<{matches:Array, errors:Array<{rule:string,error:string}>, rules:number}>}
 */
export async function scanYaraSourceInChunks(bytes, source, {
  chunkSize = 800, onProgress = null, globals = null, sampleName = "sample.bin",
} = {}) {
  const { scanWithYaraX, normalizeYaraMatches, defaultYaraGlobals, isYaraWasmBroken } = await import("./yara.mjs");
  const wasmBrokenFast = isYaraWasmBroken;
  const ext = globals ?? defaultYaraGlobals(sampleName);
  const scanOpts = { throwOnError: true, globals: ext };
  const { imports, blocks } = splitYaraSource(source);
  const prelude = [...new Set(imports)].join("\n");
  const matches = [];
  const errors = [];
  const skipped = [];
  const usable = blocks;

  // Small sets compile in one go (fast, and helper rules stay visible).
  // Large sets (YARA Forge Full etc.) are chunked: each chunk is freed after
  // scanning, which keeps peak wasm memory well below the heap limit.
  const wholeFirst = source.length < 3_000_000;
  if (wholeFirst) {
    try {
      onProgress?.({ phase: "compiling ruleset", loaded: 0, total: usable.length });
      const res = await scanWithYaraX(bytes, source, scanOpts);
      matches.push(...normalizeYaraMatches(res, { includePrivate: true }));
      return { matches, errors, skipped, rules: blocks.length, chunked: false };
    } catch (e) {
      if (wasmBrokenFast()) throw e;
      /* fall through to chunked compilation */
    }
  }

  // Chunked fallback: helper rules (private) are compiled into every chunk so
  // dependent rules still resolve; failed chunks are bisected and only the
  // genuinely rejected rules are reported.
  const isPrivateBlock = (b) => /(?:^|\n)\s*(?:private|global)\s+.*?rule\s/.test(b.text.slice(0, 120));
  const privateBlocks = usable.filter(isPrivateBlock);
  const publicBlocks = usable.filter((b) => !isPrivateBlock(b));
  // Validate the helper prelude in ONE compile (bisect only on failure):
  // one bad private rule must not poison every chunk, and compiling each
  // helper individually costs one WebAssembly.Memory per helper (V8 caps live
  // wasm memories per process, so scan count must stay low).
  let privatePrelude = "";
  if (privateBlocks.length && privateBlocks.length < 800) {
    const validate = async (subset) => {
      try {
        await scanWithYaraX(bytes, `${prelude}\n${subset.map((b) => b.text).join("\n")}`, scanOpts);
        return true;
      } catch (e) {
        if (subset.length <= 1) {
          errors.push({ rule: subset[0]?.name ?? "?", error: String(e?.message ?? e).split("\n")[0].slice(0, 200) });
          return false;
        }
        const mid = Math.ceil(subset.length / 2);
        await validate(subset.slice(0, mid));
        await validate(subset.slice(mid));
        return false;
      }
    };
    const before = errors.length;
    await validate(privateBlocks);
    if (errors.length === before) {
      privatePrelude = privateBlocks.map((b) => b.text).join("\n");
    } else {
      // keep only the helpers that validated (drop the rejected ones)
      const rejected = new Set(errors.slice(before).map((e) => e.rule));
      privatePrelude = privateBlocks.filter((b) => !rejected.has(b.name)).map((b) => b.text).join("\n");
    }
  }
  const runChunk = async (chunk) => {
    if (isYaraWasmBroken()) {
      errors.push({ rule: chunk[0]?.name ?? "?", error: String(isYaraWasmBroken().message).slice(0, 200) });
      return false;
    }
    const text = `${prelude}\n${privatePrelude}\n${chunk.map((b) => b.text).join("\n")}`;
    try {
      const res = await scanWithYaraX(bytes, text, scanOpts);
      // Helper rules are in every chunk's prelude; report them once from the
      // dedicated private pass instead of duplicating per chunk.
      const found = normalizeYaraMatches(res, { includePrivate: true });
      matches.push(...(privatePrelude ? found.filter((m) => !m.isPrivate) : found));
      return true;
    } catch (e) {
      if (chunk.length <= 1) {
        errors.push({ rule: chunk[0]?.name ?? "?", error: String(e?.message ?? e).split("\n")[0].slice(0, 200) });
        return false;
      }
      const mid = Math.ceil(chunk.length / 2);
      await runChunk(chunk.slice(0, mid));
      await runChunk(chunk.slice(mid));
      return false;
    }
  };
  const work = privateBlocks.length && !privatePrelude.length
    ? usable // private prelude too large: keep everything together
    : publicBlocks;
  for (let i = 0; i < work.length; i += chunkSize) {
    if (isYaraWasmBroken()) throw isYaraWasmBroken();
    await runChunk(work.slice(i, i + chunkSize));
    onProgress?.({ phase: "scanning rules", loaded: Math.min(i + chunkSize, work.length), total: work.length });
  }
  if (privatePrelude) {
    // private helper matches are reported once, from the prelude
    try {
      const res = await scanWithYaraX(bytes, `${prelude}\n${privatePrelude}`, scanOpts);
      matches.push(...normalizeYaraMatches(res, { includePrivate: true }));
    } catch { /* helpers alone may not compile — ignore */ }
  }
  return { matches, errors, skipped, rules: blocks.length, chunked: true };
}

/**
 * Merge matches from several rulesets, removing overlaps: YARA Forge
 * aggregates rules from Signature-Base/Elastic/ReversingLabs, so the same
 * rule id can match in more than one set. First set in priority order wins.
 * @returns {{matches:Array, duplicates:number}}
 */
export function mergeRulesetMatches(matches) {
  const seen = new Set();
  const out = [];
  let duplicates = 0;
  for (const m of matches ?? []) {
    const key = m.id ?? m.identifier;
    if (key && seen.has(key)) { duplicates++; continue; }
    if (key) seen.add(key);
    out.push(m);
  }
  return { matches: out, duplicates };
}

/** Try the same-origin staged copy (brotli is decoded by the server). */
async function loadStaged(id, { fetchImpl, onProgress, base }) {
  if (!base) return null;
  for (const ext of [".yar.br", ".yar"]) {
    for (let attempt = 0; attempt < 2; attempt++) {
      try {
        const res = await fetchImpl(`${base}${id}${ext}`);
        if (!res?.ok) break;
      const bytes = typeof res.arrayBuffer === "function"
        ? new Uint8Array(await res.arrayBuffer())
        : new TextEncoder().encode(await res.text());
        const source = new TextDecoder().decode(bytes);
        if (!source.trim()) break;
        onProgress?.({ phase: `staged ${id}`, file: `${id}${ext}`, loaded: bytes.length, total: bytes.length });
        return source;
      } catch {
        /* transient failure or not staged — retry, then fall through */
      }
    }
  }
  return null;
}

/**
 * Load a community ruleset as YARA source text (cached in the Cache API).
 *
 * Order: Cache API -> same-origin staged file (`/yara/<id>.yar.br`, works
 * offline and avoids the GitHub release-asset CORS problem) -> remote source.
 *
 * @param {string} id one of RULESET_IDS
 * @returns {Promise<{id:string, label:string, source:string, cached:boolean, staged:boolean, bytes:number}>}
 */
export async function loadRulesetSource(id, {
  fetchImpl = fetch,
  onProgress = null,
  force = false,
  stagedBase = STAGED_RULESET_BASE,
} = {}) {
  const meta = RULESETS[id];
  if (!meta) throw new Error(`unknown ruleset "${id}" (have: ${RULESET_IDS.join(", ")})`);
  const cacheKey = `https://kf.local/yara-ruleset/${id}`;
  if (!force) {
    const cached = await cacheGet(cacheKey);
    if (cached) {
      onProgress?.({ phase: `cached ${meta.label}`, file: null, loaded: cached.length, total: cached.length });
      return { id, label: meta.label, source: cached, cached: true, staged: false, bytes: cached.length };
    }
  }
  const staged = await loadStaged(id, { fetchImpl, onProgress, base: stagedBase });
  if (staged) {
    await cachePut(cacheKey, staged);
    return { id, label: meta.label, source: staged, cached: false, staged: true, bytes: staged.length };
  }
  let source;
  try {
    source = meta.kind === "zip"
      ? await loadYaraForge(id, meta, { fetchImpl, onProgress })
      : await loadTarball(id, meta, { fetchImpl, onProgress });
  } catch (e) {
    // Staged files are the only reliable browser path (GitHub release assets
    // and codeload send no CORS headers for other origins).
    const hint = " — stage the rulesets with `npm run yara:fetch --workspace @kernelforge/analyzer-web`";
    throw new Error(`${meta.label}: ${String(e?.message ?? e).slice(0, 160)}${hint}`);
  }
  await cachePut(cacheKey, source);
  return { id, label: meta.label, source, cached: false, staged: false, bytes: source.length };
}
