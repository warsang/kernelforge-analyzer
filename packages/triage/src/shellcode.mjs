/**
 * shellcode.mjs — static facts for raw x64 shellcode (Windows + Linux).
 *
 * Shellcode has no format to parse, so the useful evidence is code shape:
 * PIC get-PC sequences, PEB/Ldr access, EAT-hash loops, syscall stubs,
 * embedded second stages, API-hash constants and per-chunk entropy (the
 * packed-region view packer stubs hide behind).
 */

import { shannonEntropy } from "./entropy.mjs";
import { extractStrings } from "./strings.mjs";
import { detectApiHashes } from "./apihash.mjs";

const CHUNK = 256;

function countPattern(bytes, ...pat) {
  let n = 0;
  outer: for (let i = 0; i + pat.length <= bytes.length; i++) {
    for (let j = 0; j < pat.length; j++) {
      if (pat[j] !== null && bytes[i + j] !== pat[j]) continue outer;
    }
    n++;
  }
  return n;
}

/**
 * @param {Uint8Array} bytes raw shellcode buffer
 * @returns {object} shellcode facts for the report/state text
 */
export function shellcodeFacts(bytes) {
  const b = bytes instanceof Uint8Array ? bytes : Uint8Array.from(bytes);
  const entropy = Number(shannonEntropy(b).toFixed(3));

  // entropy by 256-byte chunk: the packed-region view (decoder stubs are
  // low-entropy code; encrypted payloads sit at 7.5-8.0)
  const entropyChunks = [];
  for (let off = 0; off < b.length && entropyChunks.length < 64; off += CHUNK) {
    const slice = b.subarray(off, Math.min(b.length, off + CHUNK));
    entropyChunks.push({ offset: off, entropy: Number(shannonEntropy(slice).toFixed(2)) });
  }
  const maxChunk = entropyChunks.reduce((a, c) => (c.entropy > a.entropy ? c : a), { entropy: 0, offset: 0 });

  const getpc = countPattern(b, 0xe8, 0x00, 0x00, 0x00, 0x00);
  const fnstenv = countPattern(b, 0xd9, 0x74, 0x24, 0xf4) + countPattern(b, 0x9b, 0xd9, 0x74, 0x24, 0xf4);
  // gs:[0x30]/[0x60]/[0x64] PEB/TEB access (both `mov r64, gs:[imm32]` forms)
  let pebAccess = 0;
  for (let i = 0; i + 9 <= b.length; i++) {
    if (b[i] === 0x65 && b[i + 1] === 0x48 && b[i + 2] === 0x8b && b[i + 4] === 0x25) {
      const imm = b[i + 5];
      if ((imm === 0x30 || imm === 0x60 || imm === 0x64) && b[i + 6] === 0 && b[i + 7] === 0 && b[i + 8] === 0) pebAccess++;
    }
    if (b[i] === 0x65 && b[i + 1] === 0x48 && b[i + 2] === 0x8b && b[i + 7] === 0x60 && b[i + 8] === 0) pebAccess++;
  }
  const rorImm = (imm) => countPattern(b, 0xc1, null, imm);
  const eatHash = Math.min(rorImm(0x0d), rorImm(0x07)); // paired ror13/ror7 loops (API hashing)
  const syscalls = {
    syscall: countPattern(b, 0x0f, 0x05),
    sysenter: countPattern(b, 0x0f, 0x34),
    int2e: countPattern(b, 0xcd, 0x2e),
    int2d: countPattern(b, 0xcd, 0x2d),
  };

  // embedded second stage: MZ whose e_lfanew points at a PE signature
  let embeddedPe = null;
  for (let i = 0; i + 0x40 < b.length; i++) {
    if (b[i] === 0x4d && b[i + 1] === 0x5a) {
      const lfanew = (b[i + 0x3c] | (b[i + 0x3d] << 8) | (b[i + 0x3e] << 16) | (b[i + 0x3f] << 24)) >>> 0;
      const pe = i + lfanew;
      if (lfanew > 0x3f && lfanew < 0x1000 && pe + 4 <= b.length &&
        b[pe] === 0x50 && b[pe + 1] === 0x45 && b[pe + 2] === 0 && b[pe + 3] === 0) {
        embeddedPe = i;
        break;
      }
    }
  }

  const apiHashes = detectApiHashes(b, { maxHits: 32 }).hits;
  const strings = extractStrings(b, { maxStrings: 256 }).interesting;

  return {
    os: null, // filled by the runner ("win" | "linux")
    entropy,
    entropyChunks,
    maxChunkEntropy: maxChunk.entropy || null,
    maxChunkOffset: maxChunk.entropy ? maxChunk.offset : null,
    getpc,
    fnstenv,
    pebAccess,
    eatHash,
    syscalls,
    embeddedPe,
    apiHashes,
    strings,
  };
}
