/**
 * stackstrings.mjs — reconstruct strings built one immediate at a time.
 *
 * Malware hides strings from static scanners by writing them to the stack
 * byte-by-byte (`mov byte ptr [rsp+N], imm8`). This is a conservative
 * x86-64 pattern scan (no full disassembler): collect immediate stores into
 * a stack-frame slot map, then read printable runs back out.
 *
 * Recognized forms:
 *   C6 44 24 dd ii            mov byte ptr [rsp+dd], ii
 *   C6 84 24 dd dd dd dd ii   mov byte ptr [rsp+dddd], ii
 *   C7 44 24 dd ii ii ii ii   mov dword ptr [rsp+dd], imm32
 *   C7 84 24 dd dd dd dd ...  mov dword ptr [rsp+dddd], imm32
 *   48 C7 44 24 dd ii ii ii ii  mov qword ptr [rsp+dd], imm32 (sign-extended)
 *   88 44 24 dd               mov [rsp+dd], al   (register value unknown)
 */

const MAX_SLOTS = 512;
const MAX_STRING = 512;

function readImm32(bytes, o) {
  return (bytes[o] | (bytes[o + 1] << 8) | (bytes[o + 2] << 16) | (bytes[o + 3] << 24)) >>> 0;
}

/**
 * @param {Uint8Array} bytes
 * @param {{minLength?:number, maxStrings?:number}} [opts]
 * @returns {{strings:Array<{value:string, offset:number, length:number}>, stores:number}}
 */
export function extractStackStrings(bytes, { minLength = 5, maxStrings = 128 } = {}) {
  const b = bytes instanceof Uint8Array ? bytes : Uint8Array.from(bytes);
  // absolute stack displacement -> byte value (unified across store widths)
  const byteMap = new Map();
  let stores = 0;

  const put = (disp, value) => {
    if (disp < 0 || disp > MAX_STRING || byteMap.size >= MAX_SLOTS * 8) return;
    byteMap.set(disp, value & 0xff);
    stores++;
  };

  for (let i = 0; i + 6 < b.length; i++) {
    // 48 C7 44 24 dd ii ii ii ii  (qword, imm32 sign-extended)
    if (b[i] === 0x48 && b[i + 1] === 0xc7 && b[i + 2] === 0x44 && b[i + 3] === 0x24) {
      const disp = b[i + 4];
      const imm = readImm32(b, i + 5);
      for (let k = 0; k < 4; k++) put(disp + k, imm >>> (k * 8));
      i += 8;
      continue;
    }
    // C7 44 24 dd ii ii ii ii  (dword, imm32)
    if (b[i] === 0xc7 && b[i + 1] === 0x44 && b[i + 2] === 0x24) {
      const disp = b[i + 3];
      const imm = readImm32(b, i + 4);
      for (let k = 0; k < 4; k++) put(disp + k, imm >>> (k * 8));
      i += 7;
      continue;
    }
    // C6 44 24 dd ii  (byte, imm8)
    if (b[i] === 0xc6 && b[i + 1] === 0x44 && b[i + 2] === 0x24) {
      put(b[i + 3], b[i + 4]);
      i += 4;
      continue;
    }
    // C6 84 24 dd dd dd dd ii  (byte, [rsp+disp32])
    if (b[i] === 0xc6 && b[i + 1] === 0x84 && b[i + 2] === 0x24) {
      const disp = readImm32(b, i + 3);
      if (disp <= 0x1000) put(disp, b[i + 7]);
      i += 7;
      continue;
    }
    // 88 44 24 dd  (mov [rsp+dd], al) — placeholder, value unknown
    if (b[i] === 0x88 && b[i + 1] === 0x44 && b[i + 2] === 0x24) {
      put(b[i + 3], 0);
      i += 3;
    }
  }

  // Extract printable runs over consecutive stack displacements.
  const disps = [...byteMap.keys()].sort((a, b2) => a - b2);
  const out = [];
  let run = "";
  let runStart = -1;
  let prev = -2;
  const flush = () => {
    if (run.length >= minLength && out.length < maxStrings) {
      out.push({ value: run, offset: runStart, length: run.length });
    }
    run = "";
    runStart = -1;
  };
  for (const disp of disps) {
    const c = byteMap.get(disp);
    const printable = c >= 0x20 && c <= 0x7e;
    if (printable && disp === prev + 1) {
      run += String.fromCharCode(c);
    } else if (printable) {
      flush();
      run = String.fromCharCode(c);
      runStart = disp;
    } else {
      flush();
    }
    prev = disp;
  }
  flush();
  return { strings: out, stores };
}
