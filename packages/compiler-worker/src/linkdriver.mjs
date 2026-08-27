/**
 * Driver build pipeline: COFF objects -> linked sections -> relocated PE .sys.
 *
 * resolveExternal(name) maps undefined symbols (e.g. DbgPrint) to absolute
 * addresses (ntsim API thunks). Relocations are applied at final layout time.
 */

import { parseCoff, linkSections, REL } from "./coff.mjs";
import { PeBuilder } from "@kernelforge/ntsim";

const PAGE = 4096;
const u32r = (b, o) => (b[o] | (b[o + 1] << 8) | (b[o + 2] << 16) | (b[o + 3] << 24)) >>> 0;

/**
 * @param {Uint8Array[]} objFiles raw .obj bytes
 * @param {(name: string) => bigint|null} resolveExternal
 * @param {bigint} preferredImageBase
 * @returns {{image: Uint8Array, entryRva: number, exports: Map<string,number>, resolvedImports: string[]}}
 */
export function linkDriver(objFiles, resolveExternal, preferredImageBase = 0x140000000n) {
  const objects = objFiles.map((b) => parseCoff(b));
  const { sections, symbols } = linkSections(objects);

  // section RVAs in final image
  const secOrder = [".text", ".rdata", ".data", ".bss"].filter((s) => sections.has(s));
  const rvas = new Map();
  let rvaCursor = 0x1000; // first page after headers
  for (const name of secOrder) {
    rvas.set(name, rvaCursor);
    rvaCursor += Math.ceil(sections.get(name).length / PAGE) * PAGE;
  }

  const symAddr = (name) => {
    const s = symbols.get(name);
    if (s) return preferredImageBase + BigInt(rvas.get(s.section)) + BigInt(s.offset);
    const ext = resolveExternal(name);
    return ext == null ? null : BigInt(ext); // normalize to BigInt
  };

  // apply relocations per object against final addresses
  // each object's section content was copied into the bucket; we must locate
  // where each object's copy landed. linkSections returns merged buffers only,
  // so we redo offset tracking here via a second lightweight pass.
  const track = new Map(); // objIndex -> Map(sectionIndex -> baseOffset)
  {
    const buckets = new Map();
    for (const n of secOrder) buckets.set(n, []);
    objects.forEach((obj, oi) => {
      const m = new Map();
      for (const s of obj.sections) {
        const arr = buckets.get(s.name);
        if (!arr) continue;
        const curLen = arr.reduce((a, c) => a + c.length, 0);
        const aligned = Math.ceil(curLen / 16) * 16;
        if (aligned > curLen) arr.push(new Uint8Array(aligned - curLen));
        arr.push(s.data);
        m.set(s.index, aligned);
      }
      track.set(oi, m);
    });
  }

  const unresolved = [];
  objects.forEach((obj, oi) => {
    const offs = track.get(oi);
    for (const s of obj.sections) {
      const baseOff = offs.get(s.index);
      if (baseOff === undefined) continue;
      const outBuf = sections.get(s.name);
      const secRva = rvas.get(s.name);

      for (const rel of s.relocs) {
        const sym = obj.byOrdinal
          ? obj.byOrdinal.get(rel.symIndex)
          : obj.symbolsByIndex[rel.symIndex];
        let targetAddr = null;

        if (sym && sym.sectionNumber > 0) {
          // internal symbol
          const tSecIdx = sym.sectionNumber - 1;
          const tSec = obj.sections.find((x) => x.index === tSecIdx);
          const tOff = offs.get(tSecIdx) ?? 0;
          targetAddr =
            preferredImageBase +
            BigInt(rvas.get(tSec.name)) +
            BigInt(tOff + sym.value);
        } else if (sym) {
          targetAddr = symAddr(sym.name);
        }
        if (targetAddr == null) {
          // unresolved external or dangling reference — record and skip
          unresolved.push(sym?.name ?? `<symidx ${rel.symIndex}>`);
          continue;
        }
        void baseOff;
        const patchAt = BigInt(secRva) + BigInt(rel.va); // RVA of field within section
        const fieldAbsInImage = preferredImageBase + patchAt;
        const bufOffsetInSection = rel.va; // relocs use section-relative offsets
        const fo = bufOffsetInSection;

        switch (rel.type) {
          case REL.REL32:
          case REL.REL32 + 1:
          case REL.REL32 + 2:
          case REL.REL32 + 3:
          case REL.REL32 + 4: {
            // rel to next instruction: disp = target - (field + 4).
            // BigInt end-to-end: bitwise ops would silently coerce through
            // Int32 and corrupt any target more than 2GB from the image
            // (e.g. pool/thunk regions above or below the load base).
            const nextInstr = fieldAbsInImage + 4n;
            const disp = BigInt(targetAddr) - nextInstr;
            const signed = BigInt.asIntN(32, disp);
            if (signed !== disp) {
              throw new Error(
                `REL32 out of range for ${sym?.name}: target 0x${targetAddr.toString(16)} ` +
                `is ${disp} bytes from field — cannot encode`,
              );
            }
            const u = BigInt.asUintN(32, disp);
            const b = outBuf; // patch in-place
            b[fo] = Number(u & 0xffn);
            b[fo + 1] = Number((u >> 8n) & 0xffn);
            b[fo + 2] = Number((u >> 16n) & 0xffn);
            b[fo + 3] = Number((u >> 24n) & 0xffn);
            break;
          }
          case REL.ABS: { // 64-bit absolute
            const bv = new Uint8Array(8);
            let x = BigInt(targetAddr);
            for (let i = 0; i < 8; i++) { bv[i] = Number(x & 0xffn); x >>= 8n; }
            outBuf.set(bv, fo);
            break;
          }
          case REL.ADDR32: {
            const v = Number(BigInt(targetAddr) & 0xffffffffn);
            outBuf[fo] = v & 0xff; outBuf[fo + 1] = (v >> 8) & 0xff;
            outBuf[fo + 2] = (v >> 16) & 0xff; outBuf[fo + 3] = (v >> 24) & 0xff;
            break;
          }
          case REL.SECREL:
          case REL.SECTION:
            break; // debug info — ignore
          default:
            throw new Error(`unsupported reloc type 0x${rel.type.toString(16)} -> ${sym?.name}`);
        }
      }
    }
  });

  if (unresolved.length) {
    throw new Error(`unresolved externals: ${[...new Set(unresolved)].join(", ")}`);
  }

  // find entry: prefer DriverEntry
  let entryName = "DriverEntry";
  if (!symbols.has(entryName)) entryName = "_DriverEntry@8";
  const entrySym = symbols.get(entryName);
  const entryRva = entrySym
    ? rvas.get(entrySym.section) + entrySym.offset
    : rvas.get(".text"); // fall back to start of text

  // collect exported names for the runtime
  const exportsMap = new Map();
  for (const [name, s] of symbols) {
    exportsMap.set(name, Number(preferredImageBase + BigInt(rvas.get(s.section)) + BigInt(s.offset)));
  }

  // emit PE
  const pb = new PeBuilder();
  pb.imageBase = preferredImageBase;
  for (const name of secOrder) pb.addSection(name, sections.get(name), name === ".text" ? 0x60000020 : 0xc0000040);
  const { image } = pb.build(entryRva);

  return { image, entryRva, exports: exportsMap, resolvedImports: [] };
}
