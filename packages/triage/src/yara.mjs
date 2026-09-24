/**
 * yara.mjs — optional YARA-X (wasm) integration.
 *
 * YARA-X is a real YARA engine (full condition language, modules, external
 * variables) compiled to wasm by VirusTotal. It is optional: the pure-JS
 * rules engine in ./rules.mjs is always available, and callers fall back to
 * it when the wasm package is not installed.
 *
 * Node: resolves the wasm next to the package entry automatically.
 * Browser: `initYaraX()` with no arguments uses the wasm-bindgen web default
 * (bundlers such as Vite emit the .wasm asset).
 */

let cachedModule = null;
let initPromise = null;

/**
 * YARA-X wasm can abort (emscripten "memory access out of bounds") when the
 * compiled rulesets exceed the wasm heap. After an abort the module instance
 * is unusable, so remember it and fail fast with a clear message instead of
 * letting every later call throw another uncaught RuntimeError.
 */
let wasmBroken = null;

export function isYaraWasmBroken() {
  return wasmBroken;
}

/** Test/UI hook: forget a broken wasm state (a reload is the real fix). */
export function resetYaraWasm() {
  wasmBroken = null;
}

const WASM_FATAL = /memory access out of bounds|Aborted\(|abort\(|unreachable/i;

function noteWasmFailure(e) {
  const message = String(e?.message ?? e);
  if (WASM_FATAL.test(message)) {
    wasmBroken = new Error(
      "YARA-X wasm ran out of memory while compiling the rulesets — reload the page and scan again " +
      "(fewer rulesets or a smaller ruleset selection keeps peak memory lower)",
    );
    wasmBroken.cause = e;
  }
  return wasmBroken;
}

async function readWasmFromNode() {
  if (typeof process === "undefined" || !process.versions?.node) return null;
  try {
    const fsSpec = "node:" + "fs";
    const pathSpec = "node:" + "path";
    const modSpec = "node:" + "module";
    const { readFileSync } = await import(/* @vite-ignore */ fsSpec);
    const path = await import(/* @vite-ignore */ pathSpec);
    const { createRequire } = await import(/* @vite-ignore */ modSpec);
    const req = createRequire(import.meta.url);
    const main = req.resolve("@virustotal/yara-x");
    return readFileSync(path.join(path.dirname(main), "yara_x_js_bg.wasm"));
  } catch {
    return null;
  }
}

/**
 * Load and initialize the YARA-X wasm module.
 * @param {{wasmBytes?:Uint8Array|ArrayBuffer, wasmPath?:string}} [opts]
 * @returns {Promise<object>} the yara-x module namespace
 */
export async function initYaraX(opts = {}) {
  if (cachedModule) return cachedModule;
  if (initPromise) return initPromise;
  initPromise = (async () => {
  const mod = await import("@virustotal/yara-x");
  if (opts.wasmBytes) {
    await mod.default({ module_or_path: opts.wasmBytes });
  } else if (opts.wasmPath) {
    const fsSpec = "node:" + "fs";
    const { readFileSync } = await import(/* @vite-ignore */ fsSpec);
    await mod.default({ module_or_path: readFileSync(opts.wasmPath) });
  } else {
    const bytes = await readWasmFromNode();
    if (bytes) await mod.default({ module_or_path: bytes });
    else await mod.default();
  }
  cachedModule = mod;
  return mod;
  })();
  try {
    return await initPromise;
  } catch (e) {
    initPromise = null;
    throw e;
  }
}

/** Compile YARA source; throws on compile errors. */
export async function compileYara(source, opts = {}) {
  if (wasmBroken) throw wasmBroken;
  const { Compiler } = await initYaraX(opts);
  const compiler = new Compiler();
  try {
    // External variables (filename/extension/...): community rulesets such as
    // signature-base reference these; defining them makes the rules compile
    // instead of failing with `unknown identifier`.
    for (const [name, value] of Object.entries(opts.globals ?? {})) {
      try { compiler.defineGlobal(name, value); } catch { /* unsupported value type */ }
    }
    compiler.addSource(String(source));
    return compiler.build();
  } catch (e) {
    throw noteWasmFailure(e) ?? e;
  } finally {
    try { compiler.free(); } catch { /* already freed */ }
  }
}

/**
 * Scan bytes with YARA-X.
 * @returns {Promise<{matches:Array, errors:Array, warnings:Array}|null>} null
 *   when YARA-X is unavailable (caller should use the pure-JS engine).
 */
export async function scanWithYaraX(bytes, source, opts = {}) {
  if (wasmBroken) {
    if (opts.throwOnError) throw wasmBroken;
    return null;
  }
  let rules = null;
  let scanner = null;
  try {
    const { Scanner } = await initYaraX(opts);
    rules = await compileYara(source, opts);
    scanner = new Scanner(rules);
    // NOTE: do NOT call scanner.setGlobal() here. In this yara-x build the
    // setGlobal path constructs a new WebAssembly.Memory per call (dozens per
    // scan with our 8 globals) and exhausts the renderer's memory. Globals are
    // already baked in at compile time by Compiler.defineGlobal() — same
    // values, same matches — so per-scan overrides are unnecessary.
    return scanner.scan(bytes instanceof Uint8Array ? bytes : Uint8Array.from(bytes));
  } catch (e) {
    noteWasmFailure(e);
    if (opts.throwOnError) throw e;
    return null;
  } finally {
    // wasm-bindgen objects hold wasm-heap memory until freed; without this a
    // session that compiles several large rulesets exhausts the wasm heap.
    try { scanner?.free(); } catch { /* already freed */ }
    try { rules?.free(); } catch { /* already freed */ }
  }
}

/** Default external variables for community rulesets (signature-base et al). */
export function defaultYaraGlobals(name = "sample.bin") {
  const base = String(name || "sample.bin");
  const ext = base.includes(".") ? base.split(".").pop() : "";
  const filepath = /[\\/]/.test(base) ? base : `C:\\samples\\${base}`;
  return {
    filename: base,
    filepath,
    extension: ext,
    filetype: "",
    owner: "",
    md5: "",
    sha1: "",
    sha256: "",
  };
}

/**
 * Normalize YARA-X output to the pure-JS engine's match shape.
 *
 * `private` rules are ruleset-internal helpers (YARA Forge ships helpers like
 * "any PE file" / "any non-Microsoft-signed PE") — they are not detections,
 * so they are filtered out unless `includePrivate` is set.
 */
/** Curated descriptions for well-known private helper rules with placeholder meta. */
const KNOWN_HELPER_DESCRIPTIONS = {
  ESET_Not_Ms_PRIVATE: "PE file without a Microsoft Authenticode signature (ESET helper rule used by Turla detections)",
  AVASTTI_EXE_PRIVATE: "Any valid PE file (Avast helper rule used by Manjusaka detections)",
  ESET_Is_Elf_PRIVATE: "Any ELF file (ESET helper rule)",
  ESET_Is_PE_PRIVATE: "Any PE file (ESET helper rule)",
  ESET_Is_Macho_PRIVATE: "Any Mach-O file (ESET helper rule)",
};

/**
 * Human description for a match: real meta description when present, curated
 * text for known helper rules, otherwise a labelled fallback.
 */
export function describeYaraRule(m) {
  const meta = m?.meta ?? {};
  const desc = m?.description ?? meta.description;
  if (desc && !/no description has been set/i.test(desc)) return desc;
  const known = KNOWN_HELPER_DESCRIPTIONS[m?.id];
  if (known) return known;
  const author = meta.author ? ` by ${meta.author}` : "";
  if (m?.isPrivate) return `helper rule${author} — private support rule used by other rules in this ruleset (not a standalone detection)`;
  if (meta.source_url) return `no description in the source rule — see ${meta.source_url}`;
  return null;
}

export function normalizeYaraMatches(result, { includePrivate = true } = {}) {
  if (!result) return [];
  return (result.matches ?? [])
    .filter((m) => includePrivate || !m.isPrivate)
    .map((m) => ({
      id: m.identifier,
      namespace: m.namespace,
      isPrivate: !!m.isPrivate,
      tags: m.tags ?? [],
      meta: Object.fromEntries((m.metadata ?? []).map((x) => [x.identifier, x.value])),
      strings: (m.patterns ?? []).map((p) => ({
        id: p.identifier,
        kind: p.kind,
        offsets: (p.matches ?? []).map((x) => x.offset),
      })),
    }));
}
