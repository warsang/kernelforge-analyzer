/**
 * Community ruleset loading: zip extraction, plain fetch, caching.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { deflateRawSync } from "node:zlib";

import {
  extractZipText, extractTarGzText, loadRulesetSource, RULESETS, DEFAULT_COMMUNITY_RULESETS,
  HEAVY_RULESETS, OPTIONAL_RULESETS, mergeRulesetMatches, splitYaraSource, scanYaraSourceInChunks,
} from "../src/yara-rulesets.mjs";
import { describeYaraRule, normalizeYaraMatches } from "../src/yara.mjs";
import { gzipSync } from "node:zlib";

/** Build a minimal ZIP (stored + deflated entries) for the extractor test. */
function buildZip(entries) {
  const chunks = [];
  const central = [];
  let offset = 0;
  for (const [name, text, method] of entries) {
    const nameBytes = new TextEncoder().encode(name);
    const raw = new TextEncoder().encode(text);
    const data = method === 8 ? new Uint8Array(deflateRawSync(raw)) : raw;
    const local = new Uint8Array(30 + nameBytes.length);
    const dv = new DataView(local.buffer);
    dv.setUint32(0, 0x04034b50, true);
    dv.setUint16(8, method, true);
    dv.setUint32(18, data.length, true);
    dv.setUint32(22, raw.length, true);
    dv.setUint16(26, nameBytes.length, true);
    local.set(nameBytes, 30);
    chunks.push(local, data);
    const cd = new Uint8Array(46 + nameBytes.length);
    const cdv = new DataView(cd.buffer);
    cdv.setUint32(0, 0x02014b50, true);
    cdv.setUint16(10, method, true);
    cdv.setUint32(20, data.length, true);
    cdv.setUint32(24, raw.length, true);
    cdv.setUint16(28, nameBytes.length, true);
    cdv.setUint32(42, offset, true);
    cd.set(nameBytes, 46);
    central.push(cd);
    offset += local.length + data.length;
  }
  const cdSize = central.reduce((a, c) => a + c.length, 0);
  const eocd = new Uint8Array(22);
  const edv = new DataView(eocd.buffer);
  edv.setUint32(0, 0x06054b50, true);
  edv.setUint16(8, entries.length, true);
  edv.setUint16(10, entries.length, true);
  edv.setUint32(12, cdSize, true);
  edv.setUint32(16, offset, true);
  const total = offset + cdSize + 22;
  const out = new Uint8Array(total);
  let p = 0;
  for (const c of [...chunks, ...central, eocd]) { out.set(c, p); p += c.length; }
  return out;
}

/** Build a minimal .tar.gz containing the given files. */
function buildTarGz(files) {
  const blocks = [];
  for (const [name, text] of files) {
    const data = new TextEncoder().encode(text);
    const header = new Uint8Array(512);
    header.set(new TextEncoder().encode(name), 0);
    const sizeOctal = data.length.toString(8).padStart(11, "0") + "\0";
    header.set(new TextEncoder().encode(sizeOctal), 124);
    header[156] = 0x30; // regular file
    header.set(new TextEncoder().encode("ustar\0"), 257);
    const padded = new Uint8Array(Math.ceil(data.length / 512) * 512);
    padded.set(data);
    blocks.push(header, padded);
  }
  const end = new Uint8Array(1024);
  const tar = new Uint8Array(blocks.reduce((a, b) => a + b.length, 0) + end.length);
  let off = 0;
  for (const b of [...blocks, end]) { tar.set(b, off); off += b.length; }
  return new Uint8Array(gzipSync(tar));
}

test("extractTarGzText extracts .yar files from a tarball", async () => {
  const gz = buildTarGz([
    ["repo-main/yara/alpha.yar", "rule alpha { condition: true }"],
    ["repo-main/README.md", "not a rule"],
    ["repo-main/yara/sub/beta.yara", "rule beta { condition: true }"],
  ]);
  const all = await extractTarGzText(gz);
  assert.deepEqual(all.map((e) => e.name), ["repo-main/yara/alpha.yar", "repo-main/yara/sub/beta.yara"]);
  const filtered = await extractTarGzText(gz, { filter: /(?:^|\/)yara\/sub\// });
  assert.deepEqual(filtered.map((e) => e.name), ["repo-main/yara/sub/beta.yara"]);
});

test("splitYaraSource keeps private/global modifiers and helper rules", () => {
  const src = [
    'import "pe"',
    'import "pe"',
    "private rule helper_is_pe { condition: uint16(0) == 0x5A4D }",
    "global private rule helper_global { condition: true }",
    'rule public_detection : FILE { strings: $a = "evil" condition: $a }',
    'rule regex_rule { strings: $r = /a{2,3}b/ condition: $r }',
  ].join("\n");
  const { imports, blocks } = splitYaraSource(src);
  assert.deepEqual(imports, ['import "pe"', 'import "pe"']);
  assert.equal(blocks.length, 4);
  assert.match(blocks[0].text, /^private rule helper_is_pe/);
  assert.match(blocks[1].text, /^global private rule helper_global/);
  assert.match(blocks[2].text, /^rule public_detection/);
  assert.match(blocks[3].text, /a\{2,3\}b/, "regex quantifier braces must not split the block");
});

test("scanYaraSourceInChunks compiles the whole set and reports helpers", async () => {
  const src = [
    "private rule helper_is_pe { condition: uint16(0) == 0x5A4D }",
    'rule public_uses_helper { condition: helper_is_pe and filesize > 1 }',
  ].join("\n");
  const res = await scanYaraSourceInChunks(new TextEncoder().encode("MZ x"), src);
  assert.equal(res.chunked, false);
  assert.equal(res.errors.length, 0);
  assert.ok(res.matches.some((m) => m.id === "public_uses_helper"));
  assert.ok(res.matches.some((m) => m.id === "helper_is_pe" && m.isPrivate === true),
    JSON.stringify(res.matches));
});

test("scanYaraSourceInChunks defines externals so filename/extension rules compile", async () => {
  const src = [
    'rule uses_filename { condition: filename == "sudoers" }',
    'rule uses_extension { condition: extension == "aspx" }',
    'rule fine { condition: filesize > 0 }',
  ].join("\n");
  const res = await scanYaraSourceInChunks(new TextEncoder().encode("x"), src, {
    sampleName: "sudoers",
  });
  assert.equal(res.errors.length, 0, JSON.stringify(res.errors));
  assert.equal(res.skipped.length, 0);
  assert.ok(res.matches.some((m) => m.id === "uses_filename"), JSON.stringify(res.matches));
  const byExtension = await scanYaraSourceInChunks(new TextEncoder().encode("x"), src, {
    sampleName: "shell.aspx",
  });
  assert.ok(byExtension.matches.some((m) => m.id === "uses_extension"));
});

test("defaultYaraGlobals derives filename/extension/filepath", async () => {
  const { defaultYaraGlobals } = await import("../src/yara.mjs");
  const g = defaultYaraGlobals("dropper.exe");
  assert.equal(g.filename, "dropper.exe");
  assert.equal(g.extension, "exe");
  assert.match(g.filepath, /dropper\.exe$/);
  assert.equal(g.md5, "");
});

test("mergeRulesetMatches removes overlapping rule ids (first set wins)", () => {
  const { matches, duplicates } = mergeRulesetMatches([
    { id: "R1", ruleset: "forge" }, { id: "R2", ruleset: "forge" },
    { id: "R1", ruleset: "signature-base" }, { id: "R3", ruleset: "elastic" },
  ]);
  assert.deepEqual(matches.map((m) => `${m.id}:${m.ruleset}`), ["R1:forge", "R2:forge", "R3:elastic"]);
  assert.equal(duplicates, 1);
});

test("describeYaraRule explains private helper rules", () => {
  const helper = normalizeYaraMatches({
    matches: [{
      identifier: "ESET_Not_Ms_PRIVATE", namespace: "default", isPrivate: true, tags: [],
      metadata: [{ identifier: "author", value: "ESET TI" }, { identifier: "description", value: "No description has been set in the source file - ESET" }],
      patterns: [],
    }],
  })[0];
  assert.match(describeYaraRule(helper), /Microsoft Authenticode/);
  const generic = { id: "X_PRIVATE", isPrivate: true, meta: { author: "Someone" } };
  assert.match(describeYaraRule(generic), /helper rule by Someone/);
  const described = { id: "Y", meta: { description: "Real description" } };
  assert.equal(describeYaraRule(described), "Real description");
});

test("globals cost zero extra WebAssembly.Memory constructions (setGlobal regression)", async () => {
  // The yara-x wasm constructs one tiny WebAssembly.Memory per scan() call, and
  // its Scanner.setGlobal path constructs ANOTHER one per call. V8 caps the
  // number of live wasm memories per process (each reserves a sandbox slot),
  // so the old path (8 globals x every chunk + 1 scan = 9/chunk, ~198 for a
  // large ruleset) exhausted the renderer. Globals are baked in at compile
  // time with defineGlobal, so a scan must not grow with the globals count.
  const RealMemory = globalThis.WebAssembly.Memory;
  const count = { n: 0 };
  globalThis.WebAssembly = new Proxy(WebAssembly, {
    get(target, prop, receiver) {
      if (prop === "Memory") {
        return function CountingMemory(...args) {
          count.n++;
          return new RealMemory(...args);
        };
      }
      return Reflect.get(target, prop, receiver);
    },
  });
  try {
    const src = 'rule g { condition: filename == "sudoers" }';
    const noGlobals = await scanYaraSourceInChunks(new TextEncoder().encode("MZ x"), src, {});
    count.n = 0;
    const res = await scanYaraSourceInChunks(
      new TextEncoder().encode("MZ sudoers payload"),
      src,
      { sampleName: "sudoers" },
    );
    assert.equal(res.matches.length, 1, "compile-time globals must still match");
    assert.equal(noGlobals.matches.length, 0, "without the global the rule must not match");
    assert.ok(count.n <= 1, `expected at most 1 scan-time WebAssembly.Memory, got ${count.n} (globals must be free)`);
  } finally {
    globalThis.WebAssembly = WebAssembly;
  }
});

test("extractZipText reads stored and deflated .yar entries", async () => {
  const zip = buildZip([
    ["yara-rules-core.yar", 'rule a { condition: true }', 8],
    ["README.txt", "not a rule", 0],
    ["extra/b.yara", 'rule b { condition: true }', 0],
  ]);
  const entries = await extractZipText(zip);
  assert.deepEqual(entries.map((e) => e.name), ["yara-rules-core.yar", "extra/b.yara"]);
  assert.match(entries[0].text, /rule a/);
  assert.match(entries[1].text, /rule b/);
});

test("loadRulesetSource prefers the same-origin staged file", async () => {
  const prevCaches = globalThis.caches;
  delete globalThis.caches; // no Cache API in this test: staged path only
  try {
    const staged = "rule staged_forge { condition: true }";
    const calls = [];
    const fakeFetch = async (url) => {
      calls.push(String(url));
      if (String(url).endsWith("/yara/yara-forge-extended.yar.br")) {
        return { ok: true, headers: { get: () => null }, text: async () => staged };
      }
      return { ok: false, status: 404 };
    };
    const { source, staged: wasStaged } = await loadRulesetSource("yara-forge-extended", { fetchImpl: fakeFetch });
    assert.equal(source, staged);
    assert.equal(wasStaged, true);
    assert.deepEqual(calls, ["/yara/yara-forge-extended.yar.br"], "must not touch the network source");
  } finally {
    if (prevCaches !== undefined) globalThis.caches = prevCaches;
  }
});

test("loadRulesetSource falls back to the remote source when not staged", async () => {
  const prevCaches = globalThis.caches;
  delete globalThis.caches;
  try {
    const zip = buildZip([["rules.yar", 'rule remote_forge { condition: true }', 8]]);
    const calls = [];
    const fakeFetch = async (url) => {
      calls.push(String(url));
      if (String(url).includes("/yara/")) return { ok: false, status: 404 };
      return {
        ok: true,
        headers: { get: (h) => (h === "content-length" ? String(zip.length) : null) },
        body: {
          getReader() {
            let sent = false;
            return { async read() { if (sent) return { done: true }; sent = true; return { done: false, value: zip }; } };
          },
        },
      };
    };
    const { source, staged } = await loadRulesetSource("yara-forge-core", { fetchImpl: fakeFetch });
    assert.equal(staged, false);
    assert.match(source, /rule remote_forge/);
    assert.ok(calls.some((u) => u.includes("yara-forge-rules-core.zip")));
  } finally {
    if (prevCaches !== undefined) globalThis.caches = prevCaches;
  }
});

test("loadRulesetSource fetches, caches and returns source text", async () => {
  const store = new Map();
  const fakeCaches = {
    async match(key) { const hit = store.get(key); return hit ? new Response(hit) : undefined; },
    async put(key, res) { store.set(key, await res.text()); },
  };
  const prevCaches = globalThis.caches;
  globalThis.caches = fakeCaches;
  try {
    const zip = buildZip([["rules.yar", 'rule forge { condition: true }', 8]]);
    let fetches = 0;
    const fakeFetch = async (url) => {
      fetches++;
      assert.match(url, /yara-forge-rules-core\.zip$/);
      return {
        ok: true,
        headers: { get: (h) => (h === "content-length" ? String(zip.length) : null) },
        body: {
          getReader() {
            let sent = false;
            return { async read() { if (sent) return { done: true }; sent = true; return { done: false, value: zip }; } };
          },
        },
      };
    };
    const first = await loadRulesetSource("yara-forge-core", { fetchImpl: fakeFetch, stagedBase: null });
    assert.equal(first.cached, false);
    assert.match(first.source, /rule forge/);
    const second = await loadRulesetSource("yara-forge-core", { fetchImpl: fakeFetch, stagedBase: null });
    assert.equal(second.cached, true);
    assert.equal(second.source, first.source);
    assert.equal(fetches, 1, "second load must come from cache");
    await assert.rejects(() => loadRulesetSource("nope"), /unknown ruleset/);
    assert.ok(RULESETS["yara-forge-extended"].url.endsWith("yara-forge-rules-extended.zip"));
    assert.deepEqual(DEFAULT_COMMUNITY_RULESETS,
      ["yara-forge-core", "signature-base-lite", "elastic", "reversinglabs", "bartblaze"]);
    assert.ok(HEAVY_RULESETS.has("yara-forge-full"), "Full is flagged heavy");
    assert.ok(OPTIONAL_RULESETS.includes("signature-base"), "full Signature-Base is opt-in");
    assert.ok(RULESETS["signature-base-lite"].fileFilter instanceof RegExp, "lite variant has a file filter");
    for (const id of DEFAULT_COMMUNITY_RULESETS) {
      assert.ok(RULESETS[id], `ruleset ${id} must be declared`);
    }
  } finally {
    if (prevCaches === undefined) delete globalThis.caches;
    else globalThis.caches = prevCaches;
  }
});
