/**
 * harvest.mjs — file_operations harvesting for .ko
 * Two paths:
 *  1) dynamic: after init_module, deviceRegistry already holds fops -> getHarvestedOps
 *  2) static: scan .rodata/.data for file_operations-shaped blobs (heuristic)
 */
import { FILE_OPS_OFF } from "@kernelforge/linux-sim/src/file-ops.mjs";

export function harvestFileOpsStatic(imageBytes, parsed, opts={}){
  const cap=opts.maxOps ?? 32;
  const out=[];
  const seen=new Set();
  // Find alloc sections that could hold fops: .rodata, .data, .data.rel.ro
  const candidates = parsed.sections.filter(s=> s.name===".rodata" || s.name===".data" || s.name.includes(".rodata") || s.name===".data.rel.ro");
  // Also consider any SHF_ALLOC without EXEC
  const allocSecs = candidates.length ? candidates : parsed.sections.filter(s=> (s.flags & 0x2n) && !(s.flags & 0x4n));
  for(const sec of allocSecs){
    if(!sec.data) continue;
    const baseOffset = Number(sec.offset);
    const bytes=imageBytes;
    // Step by 8
    for(let off=0; off+FILE_OPS_OFF.SIZE <= sec.data.length; off+=8){
      // heuristic: check pointer count
      // In .rodata blob, many ptr fields should be in .text range (code) or zero/null
      // We'll count how many of the known function pointers are plausible code pointers
      // Since we don't have runtime addrs, check if those dwords are relocations? But static image still has zero at reloc sites? Actually ET_REL has zeroes with rela entries.
      // Alternative heuristic: Look for two or more non-zero 64-bit values that point inside .text's file offset range is tricky because relocs are not applied yet.
      // So static harvest without reloc application is weak. We instead check if this offset is a RELA target for fops? But we can use rela entries: if there's a R_X86_64_64 reloc that targets this offset and sym is a code symbol (STT_FUNC), then it's fops.
      // So search relas that patch this section at off + member offset
      let matches=0;
      for(const rela of parsed.relas){
        if(rela.targetSecIdx!==sec.idx) continue;
        const relOff=Number(rela.r_offset);
        for(const k of Object.values(FILE_OPS_OFF)){
          if(typeof k!=="number") continue;
          if(relOff===off+k){
            // check if sym is function
            if(rela.sym && (rela.sym.type===2 || rela.sym.name.includes("ioctl")||rela.sym.name.includes("read")||rela.sym.name.includes("write")||rela.sym.name.includes("mmap"))){
              matches++;
            } else if(rela.sym && rela.sym.type===2){
              matches++;
            }
          }
        }
      }
      if(matches>=2){
        const key=`${sec.name}:${off.toString(16)}`;
        if(seen.has(key)) continue;
        seen.add(key);
        out.push({ sec: sec.name, offset: off, rva: sec.addr + BigInt(off), dev: "static", op:"file_operations", fopsRva: sec.addr + BigInt(off), matches });
        if(out.length>=cap) return out;
      }
    }
  }
  return out;
}

export function harvestFileOps(imageBytes, parsed, kernel){
  // Dynamic first
  const dynamic=[];
  try{
    const { getHarvestedOps } = require ? require("@kernelforge/linux-sim") : {};
  }catch{}
  // We will let caller also collect kernel.deviceRegistry; this file only static.
  // This function is just static helper; dynamic is done via getHarvestedOps from file-ops.mjs
  return harvestFileOpsStatic(imageBytes, parsed);
}
