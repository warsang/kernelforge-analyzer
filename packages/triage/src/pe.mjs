/**
 * pe.mjs — static PE32+ facts for triage.
 *
 * Pure parsing + heuristics: headers, sections (+entropy), imports/exports,
 * TLS callbacks, overlay, Authenticode presence, imphash and anomaly flags
 * (RWX, high-entropy code, raw<virtual, packer section names, entry outside
 * sections, tiny import tables, non-canonical image base, ...).
 *
 * No emulation, no I/O; safe to run on hostile bytes.
 */

import { md5 } from "./md5.mjs";
import { entropyAt, shannonEntropy } from "./entropy.mjs";
import { extractStrings } from "./strings.mjs";

const SCN = {
  CNT_CODE: 0x00000020,
  CNT_INITIALIZED_DATA: 0x00000040,
  CNT_UNINITIALIZED_DATA: 0x00000080,
  MEM_DISCARDABLE: 0x02000000,
  MEM_NOT_PAGED: 0x08000000,
  MEM_SHARED: 0x10000000,
  MEM_EXECUTE: 0x20000000,
  MEM_READ: 0x40000000,
  MEM_WRITE: 0x80000000,
};

const SUBSYSTEMS = {
  0: "unknown", 1: "native", 2: "windows-gui", 3: "windows-cui",
  5: "os2-cui", 7: "posix-cui", 8: "native-windows", 9: "windows-ce",
  10: "efi-application", 11: "efi-boot-service", 12: "efi-runtime",
  13: "efi-rom", 14: "xbox", 16: "windows-boot",
};

const PACKER_SECTIONS = /^(?:upx[0-9!]?|\.upx|\.themida|\.vmp[0-9]?|\.aspack|\.adata|\.packed|\.petite|\.nsp[0-9]?|\.enigma|\.mpress[0-9]?|\.mp[0-9]?|\.arm|\.pdata~|\.winapi|\.sdata|\.taz|\.boom|\.ccg|\.pec[0-9]?|\.crypt|\.shrink[0-9]?|\.mprotect|\.obsidium|\.seau)/i;

const MACHINES = {
  0x014c: "i386", 0x8664: "x64", 0xaa64: "arm64", 0x01c4: "armv7",
  0x0200: "ia64", 0x01c0: "arm", 0x0ebc: "efi-bytecode",
};

const u8 = (b, o) => b[o];
const u16 = (b, o) => b[o] | (b[o + 1] << 8);
const u32 = (b, o) => (b[o] | (b[o + 1] << 8) | (b[o + 2] << 16) | (b[o + 3] << 24)) >>> 0;
const i32 = (b, o) => u32(b, o) | 0;
const u64 = (b, o) => {
  let v = 0n;
  for (let i = 7; i >= 0; i--) v = (v << 8n) | BigInt(b[o + i] ?? 0);
  return v;
};
const hex = (v, n = 0) => "0x" + BigInt(v).toString(16).padStart(n, "0");
const cstr = (b, o, max = 256) => {
  let s = "";
  for (let i = 0; i < max && o + i < b.length && b[o + i] !== 0; i++) s += String.fromCharCode(b[o + i]);
  return s;
};

function sectionName(b, o) {
  let s = "";
  for (let i = 0; i < 8 && b[o + i] !== 0; i++) s += String.fromCharCode(b[o + i]);
  return s;
}

/**
 * @param {Uint8Array} bytes
 * @param {{strings?:boolean, maxStrings?:number}} [opts]
 */
export function parsePeStatic(bytes, { strings = false, maxStrings = 1024 } = {}) {
  const b = bytes instanceof Uint8Array ? bytes : Uint8Array.from(bytes);
  if (b.length < 0x40 || u16(b, 0) !== 0x5a4d) throw new Error("not a PE (no MZ)");
  const lfanew = u32(b, 0x3c);
  if (lfanew + 24 > b.length || u32(b, lfanew) !== 0x00004550) throw new Error("not a PE (no PE signature)");

  const coff = lfanew + 4;
  const machine = u16(b, coff);
  const numSections = u16(b, coff + 2);
  const timestamp = u32(b, coff + 4);
  const sizeOfOptional = u16(b, coff + 16);
  const characteristics = u16(b, coff + 18);
  const opt = coff + 20;
  const magic = u16(b, opt);
  if (magic !== 0x20b) throw new Error(`not PE32+ (magic=${hex(magic)})`);

  const entryPointRva = u32(b, opt + 16);
  const imageBase = u64(b, opt + 24);
  const sectionAlignment = u32(b, opt + 32);
  const fileAlignment = u32(b, opt + 36);
  const sizeOfImage = u32(b, opt + 56);
  const sizeOfHeaders = u32(b, opt + 60);
  const checksum = u32(b, opt + 64);
  const subsystem = u16(b, opt + 68);
  const dllCharacteristics = u16(b, opt + 70);
  const numDirs = Math.min(u32(b, opt + 108), 16);
  const dir = (i) => (i < numDirs ? { rva: u32(b, opt + 112 + i * 8), size: u32(b, opt + 116 + i * 8) } : { rva: 0, size: 0 });

  const sections = [];
  const secStart = opt + sizeOfOptional;
  for (let i = 0; i < numSections; i++) {
    const o = secStart + i * 40;
    if (o + 40 > b.length) break;
    const rawSize = u32(b, o + 16);
    const rawPtr = u32(b, o + 20);
    const chars = u32(b, o + 36);
    const raw = rawSize > 0 && rawPtr + rawSize <= b.length
      ? b.subarray(rawPtr, rawPtr + rawSize)
      : new Uint8Array(0);
    sections.push({
      name: sectionName(b, o),
      virtualSize: u32(b, o + 8),
      virtualAddress: u32(b, o + 12),
      rawSize,
      rawPtr,
      characteristics: chars,
      flags: Object.entries(SCN).filter(([, v]) => (chars & v) !== 0).map(([k]) => k.replace(/^(CNT|MEM)_/, "").toLowerCase()),
      entropy: raw.length ? Number(shannonEntropy(raw).toFixed(3)) : 0,
    });
  }

  const rvaToOffset = (rva) => {
    if (rva === 0) return null;
    if (rva < sizeOfHeaders && rva < b.length) return rva;
    for (const s of sections) {
      if (rva >= s.virtualAddress && rva < s.virtualAddress + Math.max(s.virtualSize, s.rawSize)) {
        const off = s.rawPtr + (rva - s.virtualAddress);
        return off < b.length ? off : null;
      }
    }
    return null;
  };

  // ---- imports + imphash ----
  const importDir = dir(1);
  const imports = [];
  const imphashParts = [];
  if (importDir.rva) {
    let off = rvaToOffset(importDir.rva);
    if (off !== null) {
      for (let guard = 0; guard < 256 && off + 20 <= b.length; guard++, off += 20) {
        const oft = u32(b, off);
        const nameRva = u32(b, off + 12);
        const ft = u32(b, off + 16);
        if (!oft && !nameRva && !ft) break;
        const nameOff = rvaToOffset(nameRva);
        const dll = nameOff !== null ? cstr(b, nameOff, 128) : `rva${nameRva}`;
        const functions = [];
        const thunkRva = oft || ft;
        let tOff = rvaToOffset(thunkRva);
        if (tOff !== null) {
          for (let j = 0; j < 4096 && tOff + 8 <= b.length; j++, tOff += 8) {
            const thunk = u64(b, tOff);
            if (thunk === 0n) break;
            if ((thunk & 0x8000000000000000n) !== 0n) {
              functions.push(`ord${Number(thunk & 0xffffn)}`);
            } else {
              const fOff = rvaToOffset(Number(thunk & 0x7fffffffn));
              if (fOff === null || fOff + 2 > b.length) break;
              functions.push(cstr(b, fOff + 2, 128) || `rva${Number(thunk)}`);
            }
          }
        }
        imports.push({ dll, functions, count: functions.length });
        const dllKey = dll.replace(/\.(dll|sys|ocx|drv)$/i, "").toLowerCase();
        for (const fn of functions) imphashParts.push(`${dllKey}.${fn.toLowerCase()}`);
      }
    }
  }
  const imphash = imphashParts.length ? md5(new TextEncoder().encode(imphashParts.join(","))) : null;

  // ---- exports ----
  const expDir = dir(0);
  let exportNames = [];
  if (expDir.rva) {
    const o = rvaToOffset(expDir.rva);
    if (o !== null && o + 40 <= b.length) {
      const count = u32(b, o + 24);
      const namesRva = u32(b, o + 32);
      const nOff = rvaToOffset(namesRva);
      if (nOff !== null && count > 0 && count < 65536) {
        for (let i = 0; i < Math.min(count, 64); i++) {
          const nr = u32(b, nOff + i * 4);
          const no = rvaToOffset(nr);
          if (no !== null) exportNames.push(cstr(b, no, 128));
        }
      }
    }
  }

  // ---- TLS ----
  const tlsDir = dir(9);
  let tls = { present: false, callbacks: 0 };
  if (tlsDir.rva) {
    const o = rvaToOffset(tlsDir.rva);
    if (o !== null && o + 40 <= b.length) {
      const cbVa = u64(b, o + 24);
      tls.present = true;
      if (cbVa !== 0n) {
        // callback array lives in the image (VA = imageBase + rva)
        const cbRva = Number(cbVa - imageBase);
        let cOff = rvaToOffset(cbRva);
        if (cOff !== null) {
          for (let i = 0; i < 64 && cOff + 8 <= b.length; i++, cOff += 8) {
            if (u64(b, cOff) === 0n) break;
            tls.callbacks++;
          }
        }
      }
    }
  }

  // ---- overlay ----
  let maxEnd = sizeOfHeaders;
  for (const s of sections) maxEnd = Math.max(maxEnd, s.rawPtr + s.rawSize);
  const overlaySize = Math.max(0, b.length - maxEnd);
  const overlayEntropy = overlaySize > 0 ? Number(entropyAt(b, maxEnd, overlaySize).toFixed(3)) : 0;

  const certDir = dir(4); // VirtualAddress is a file offset for the security dir
  const hasCert = certDir.rva > 0 && certDir.size > 0;

  // ---- anomalies / packer hints ----
  const anomalies = [];
  const packerHints = [];
  const addAnomaly = (kind, detail) => anomalies.push({ kind, detail });
  for (const s of sections) {
    const exec = (s.characteristics & SCN.MEM_EXECUTE) !== 0;
    const write = (s.characteristics & SCN.MEM_WRITE) !== 0;
    if (exec && write) addAnomaly("rwx_section", `${s.name} is executable+writable`);
    if (exec && s.entropy > 7.2 && s.rawSize > 0x400) {
      addAnomaly("high_entropy_code", `${s.name} entropy ${s.entropy}`);
    }
    if (s.rawSize > 0 && s.virtualSize > s.rawSize * 2 && s.virtualSize > 0x1000) {
      addAnomaly("raw_lt_virtual", `${s.name} raw ${hex(s.rawSize)} vs virtual ${hex(s.virtualSize)}`);
    }
    if (PACKER_SECTIONS.test(s.name)) {
      packerHints.push(s.name);
      addAnomaly("packer_section", `${s.name} matches known packer naming`);
    }
    if (exec && (s.characteristics & SCN.MEM_DISCARDABLE) !== 0) addAnomaly("discardable_code", s.name);
  }
  const entrySection = sections.find((s) =>
    entryPointRva >= s.virtualAddress && entryPointRva < s.virtualAddress + Math.max(s.virtualSize, s.rawSize));
  if (entryPointRva && !entrySection) addAnomaly("entry_outside_sections", hex(entryPointRva));
  if (imageBase < 0x100000n || imageBase > (1n << 47n)) {
    addAnomaly("noncanonical_image_base", hex(imageBase));
  }
  if (timestamp === 0) addAnomaly("zero_timestamp", "TimeDateStamp=0");
  else if (timestamp > Math.floor(Date.now() / 1000) + 86400) addAnomaly("future_timestamp", hex(timestamp, 8));
  const dllCount = imports.length;
  if (dllCount === 0 && sizeOfImage > 0x10000) addAnomaly("no_imports", `image ${hex(sizeOfImage)}`);
  if (dllCount > 0 && dllCount <= 2 && sizeOfImage > 0x100000) {
    addAnomaly("few_imports_large_image", `${dllCount} dll(s) for ${hex(sizeOfImage)}`);
  }
  if (overlaySize > 0 && overlayEntropy > 7.2) addAnomaly("high_entropy_overlay", `${hex(overlaySize)} bytes @ ${overlayEntropy}`);
  if (tls.callbacks > 0) addAnomaly("tls_callbacks", `${tls.callbacks} callback(s)`);
  if (!hasCert) addAnomaly("unsigned", "no Authenticode certificate table");

  const out = {
    format: "pe",
    is64: true,
    machine,
    machineName: MACHINES[machine] ?? hex(machine),
    subsystem,
    subsystemName: SUBSYSTEMS[subsystem] ?? hex(subsystem),
    isDriver: subsystem === 1,
    timestamp,
    timestampISO: timestamp ? new Date(timestamp * 1000).toISOString() : null,
    imageBase: hex(imageBase),
    sizeOfImage,
    sizeOfHeaders,
    sectionAlignment,
    fileAlignment,
    entryPointRva,
    entrySection: entrySection?.name ?? null,
    checksum,
    dllCharacteristics: hex(dllCharacteristics),
    hasCert,
    overlaySize,
    overlayEntropy,
    sections,
    imports,
    dllCount,
    importCount: imphashParts.length,
    imphash,
    exports: { count: exportNames.length, names: exportNames },
    tls,
    anomalies,
    packerHints,
    fileSize: b.length,
  };
  if (strings) out.strings = extractStrings(b, { maxStrings });
  return out;
}
