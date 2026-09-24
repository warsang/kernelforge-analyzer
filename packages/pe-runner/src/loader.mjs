/**
 * loader.mjs — real module loading for the userland PE harness.
 *
 * `opts.systemRoot` provides DLL images (Wine-derived system DLLs or any other
 * genuine PE) as `{ "kernel32.dll": Uint8Array }` (or a Map). LoadLibrary* maps
 * the image with the same manual mapper as the main executable, binds its
 * imports against already-loaded modules first (real EAT walk, forwarder
 * chains) and the modeled Win32 thunks otherwise, registers it in a real
 * PEB->Ldr chain (InLoadOrder/InMemoryOrder/InInitializationOrder lists), and
 * GetProcAddress resolves genuine export RVAs.
 */

import { mapPe, parsePe } from "@kernelforge/ntsim/src/pe.mjs";
import { listPeExports } from "./pe-exports.mjs";

export const MODULE_BASE_START = 0x0000000180000000n;
const PROT_EXECUTE_READWRITE = 0x40;

const u64 = (v) => BigInt.asUintN(64, BigInt(v ?? 0n));
export const moduleKey = (p) => String(p ?? "").split(/[\\/]/).pop().toLowerCase();
const stripExt = (n) => n.replace(/\.[^.]*$/, "");

/**
 * @param {{mem:object, mm:object|null, model:object, alloc:(n:number)=>bigint,
 *   resolveImport:(q:string)=>bigint, systemRoot?:object|Map, pebBase?:bigint,
 *   baseStart?:bigint}} env
 */
export function createModuleLoader({
  mem, mm, model, alloc, resolveImport,
  systemRoot = null, pebBase = 0x1000n, baseStart = MODULE_BASE_START,
}) {
  const modules = new Map(); // key -> {key, base, imageSize, entry, exports, name, bytes, ordinal}
  let nextBase = BigInt(baseStart);
  let handleSeq = 0x4000n;
  let ordinalSeq = 1n;

  const rootGet = (name) => {
    const key = moduleKey(name);
    if (!key) return null;
    if (systemRoot instanceof Map) return systemRoot.get(key) ?? systemRoot.get(name) ?? null;
    if (systemRoot && typeof systemRoot === "object") return systemRoot[key] ?? systemRoot[name] ?? null;
    return null;
  };

  const exportMap = (bytes) => {
    const byName = new Map();
    const byOrdinal = new Map();
    for (const e of listPeExports(bytes).entries) {
      if (e.name) byName.set(e.name.toLowerCase(), e);
      byOrdinal.set(e.ordinal, e);
    }
    return { byName, byOrdinal };
  };

  const resolveExport = (moduleRec, name) => {
    const key = String(name ?? "");
    const e = moduleRec.exports.byName.get(key.toLowerCase())
      ?? (/^\d+$/.test(key) ? moduleRec.exports.byOrdinal.get(Number(key)) : null);
    if (!e) return null;
    if (e.forwarder) {
      const dot = e.forwarder.lastIndexOf(".");
      if (dot > 0) {
        const dep = modules.get(moduleKey(e.forwarder.slice(0, dot)));
        if (dep) return resolveExport(dep, e.forwarder.slice(dot + 1));
      }
      return null;
    }
    return moduleRec.base + BigInt(e.rva);
  };

  /** Qualified import (`dll!name`) against loaded modules (real EAT). */
  const resolveExternal = (qualified) => {
    const s = String(qualified ?? "");
    const bang = s.lastIndexOf("!");
    if (bang < 0) return null;
    const rec = modules.get(moduleKey(s.slice(0, bang)));
    if (!rec) return null;
    return resolveExport(rec, s.slice(bang + 1));
  };

  const combinedResolve = (qualified) => resolveExternal(qualified) ?? resolveImport(qualified);

  function loadImage(name, bytes) {
    const key = moduleKey(name);
    if (!key) throw new Error(`bad module name "${name}"`);
    if (modules.has(key)) return modules.get(key);
    const image = bytes instanceof Uint8Array ? bytes : Uint8Array.from(bytes);
    const pe = parsePe(image);
    const base = (nextBase + 0xfffffn) & ~0xffffn;
    nextBase = base + BigInt(Math.ceil(pe.sizeOfImage / 0x1000) * 0x1000) + 0x100000n;

    if (mm) mm.map(base, BigInt(pe.sizeOfImage), { protect: PROT_EXECUTE_READWRITE });
    mapPe(image, mem, base, combinedResolve);

    const rec = {
      key,
      name: key,
      ordinal: ordinalSeq++,
      base,
      imageSize: pe.sizeOfImage,
      entry: base + BigInt(pe.entryRva),
      exports: exportMap(image),
      bytes: image,
    };
    modules.set(key, rec);
    rebuildLdr();
    return rec;
  }

  // ------------------------------------------------------------- PEB -> Ldr

  const mainRecRef = { value: null };
  let ldrVa = 0n;

  /** Register the main executable as the first loaded module. */
  function registerMain({ name, base, imageSize, entry, bytes }) {
    const rec = {
      key: moduleKey(name) || "main.exe",
      name: moduleKey(name) || "main.exe",
      ordinal: 0n,
      base: BigInt(base),
      imageSize,
      entry: BigInt(entry),
      exports: bytes ? exportMap(bytes) : { byName: new Map(), byOrdinal: new Map() },
      bytes,
    };
    mainRecRef.value = rec;
    rebuildLdr();
    return rec;
  }

  function rebuildLdr() {
    const list = [mainRecRef.value, ...modules.values()].filter(Boolean);
    if (!list.length) return;
    const ENTRY = 0x68;
    const dataVa = ldrVa || (ldrVa = alloc(0x50));
    const head = dataVa + 0x10n; // InLoadOrderModuleList
    const headMem = dataVa + 0x20n;
    const headInit = dataVa + 0x30n;

    mem.write(dataVa, new Uint8Array(0x50));
    mem.w32(dataVa, 0x50);
    mem.w8(dataVa + 4n, 1);

    const entries = list.map(() => alloc(ENTRY));
    const nameOffsets = list.map((rec) => {
      const va = alloc((rec.name.length + 1) * 2);
      mem.writeUtf16(va, rec.name);
      return va;
    });

    const writeUstr = (at, strVa) => {
      const len = (rec_len(strVa) ?? 0);
      mem.w16(at, len);
      mem.w16(at + 2n, len + 2);
      mem.w32(at + 4n, 0);
      mem.w64(at + 8n, strVa);
    };
    function rec_len(va) {
      let n = 0;
      try { while (n < 260 && mem.u16(va + BigInt(n * 2)) !== 0) n++; } catch { /* optional */ }
      return n * 2;
    }

    list.forEach((rec, i) => {
      const e = entries[i];
      const prev = entries[(i - 1 + list.length) % list.length];
      const next = entries[(i + 1) % list.length];
      mem.write(e, new Uint8Array(ENTRY));
      // InLoadOrderLinks / InMemoryOrderLinks / InInitializationOrderLinks
      for (const off of [0n, 0x10n, 0x20n]) {
        mem.w64(e + off, next + off);
        mem.w64(e + off + 8n, prev + off);
      }
      mem.w64(e + 0x30n, rec.base);
      mem.w64(e + 0x38n, rec.entry ?? 0n);
      mem.w32(e + 0x40n, rec.imageSize);
      writeUstr(e + 0x48n, nameOffsets[i]); // FullDllName
      writeUstr(e + 0x58n, nameOffsets[i]); // BaseDllName
    });
    mem.w64(head, entries[0]);
    mem.w64(head + 8n, entries[entries.length - 1]);
    mem.w64(headMem, entries[0] + 0x10n);
    mem.w64(headMem + 8n, entries[entries.length - 1] + 0x10n);
    mem.w64(headInit, entries[0] + 0x20n);
    mem.w64(headInit + 8n, entries[entries.length - 1] + 0x20n);

    if (pebBase >= 0n) mem.w64(pebBase + 0x18n, dataVa); // PEB->Ldr
  }

  // -------------------------------------------------------------- handlers

  const pushModuleArtifact = (rec) => {
    try { model.artifacts?.modules?.push?.({ action: "load", name: rec.name }); } catch { /* optional */ }
  };

  const findLoaded = (name) => {
    const key = moduleKey(name);
    if (!key) return null;
    return modules.get(key)
      ?? [...modules.values()].find((m) => stripExt(m.key) === stripExt(key))
      ?? null;
  };

  const handlers = {
    LoadLibraryA: (_c, [nameVa]) => doLoad(str(nameVa)),
    LoadLibraryW: (_c, [nameVa]) => doLoad(wstr(nameVa)),
    LoadLibraryExA: (_c, [nameVa]) => doLoad(str(nameVa)),
    LoadLibraryExW: (_c, [nameVa]) => doLoad(wstr(nameVa)),
    GetModuleHandleA: (_c, [nameVa]) => doGetHandle(str(nameVa)),
    GetModuleHandleW: (_c, [nameVa]) => doGetHandle(wstr(nameVa)),
    GetModuleHandleExA: (_c, [_flags, nameVa, outVa]) => {
      const h = doGetHandle(str(nameVa));
      if (u64(outVa)) { try { mem.w64(u64(outVa), h); } catch { /* optional */ } }
      return h ? 1n : 0n;
    },
    GetModuleHandleExW: (_c, [_flags, nameVa, outVa]) => {
      const h = doGetHandle(wstr(nameVa));
      if (u64(outVa)) { try { mem.w64(u64(outVa), h); } catch { /* optional */ } }
      return h ? 1n : 0n;
    },
    GetProcAddress: (_c, [h, nameVa]) => {
      const rec = [...modules.values()].find((m) => m.base === u64(h))
        ?? (mainRecRef.value && mainRecRef.value.base === u64(h) ? mainRecRef.value : null);
      // Ordinal imports pass the ordinal as a small integer "pointer".
      const name = u64(nameVa) < 0x10000n ? `#${u64(nameVa)}` : (() => { try { return str(nameVa); } catch { return ""; } })();
      if (rec && name) {
        const va = resolveExport(rec, name);
        if (va) return va;
      }
      // Unknown module/export: same provisioning as the modeled Win32 layer.
      return name ? resolveImport(name.replace(/^#/, "")) : 0n;
    },
    FreeLibrary: () => 1n,
    GetModuleFileNameA: (_c, [h, buf, size]) => writeFilePath(str, buf, size, h),
    GetModuleFileNameW: (_c, [h, buf, size]) => writeFilePath(wstr, buf, size, h),
  };

  function safeName(rec, nameVa) {
    try { return str(nameVa); } catch { return null; }
  }

  function writeFilePath(writer, buf, size, h) {
    const rec = [...modules.values()].find((m) => m.base === u64(h));
    const path = `C:\\kfsample\\${rec?.name ?? model.mainName ?? "sample.exe"}`;
    if (u64(buf)) {
      try {
        if (writer === wstr) mem.writeUtf16(u64(buf), path.slice(0, Number(u64(size)) - 1));
        else mem.write(u64(buf), new TextEncoder().encode(path.slice(0, Number(u64(size)) - 1)));
      } catch { /* optional */ }
    }
    return BigInt(path.length);
  }

  function doLoad(name) {
    const key = moduleKey(name);
    if (!key) return 0n;
    const already = findLoaded(name);
    if (already) return already.base;
    const bytes = rootGet(key);
    if (!bytes) {
      // Unknown module (no real image available): record and hand back a
      // synthetic handle so callers that only GetProcAddress keep working.
      pushModuleArtifact({ name: key });
      model.events.push({ name: "[loader] LoadLibrary miss (synthetic handle)", args: [], ret: handleSeq });
      return (handleSeq += 4n);
    }
    const rec = loadImage(key, bytes);
    pushModuleArtifact(rec);
    model.events.push({ name: "[loader] mapped module", args: [], ret: rec.base });
    return rec.base;
  }

  function doGetHandle(name) {
    if (!name) return mainRecRef.value?.base ?? model.mainModule ?? 0n;
    return findLoaded(name)?.base ?? (mainRecRef.value?.base ?? 0n);
  }

  const str = (va) => {
    try {
      let s = "";
      for (let i = 0; i < 260; i++) {
        const b = mem.u8(u64(va) + BigInt(i));
        if (b === 0 || b < 0x20 || b > 0x7e) break;
        s += String.fromCharCode(b);
      }
      return s;
    } catch { return ""; }
  };
  const wstr = (va) => {
    try {
      let s = "";
      for (let i = 0; i < 260; i++) {
        const c = mem.u16(u64(va) + BigInt(i * 2));
        if (c === 0 || c < 0x20) break;
        s += String.fromCharCode(c);
      }
      return s;
    } catch { return ""; }
  };

  model.loader = {
    loadImage,
    registerMain,
    resolveExport,
    resolveExternal,
    get: findLoaded,
    list: () => [...(mainRecRef.value ? [mainRecRef.value] : []), ...modules.values()].map((m) => ({
      name: m.name,
      base: `0x${m.base.toString(16)}`,
      imageSize: m.imageSize,
      exports: m.exports.byName.size,
    })),
    ldrPointer: () => ldrVa,
  };
  model.mainName = "sample.exe";

  return { handlers, loadImage, load: doLoad, registerMain, resolveExternal, modules, list: () => model.loader.list() };
}
