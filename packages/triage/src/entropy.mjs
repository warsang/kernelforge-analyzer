/**
 * entropy.mjs — Shannon entropy over byte ranges (0..8 bits/byte).
 */

/** @param {Uint8Array} bytes @returns {number} */
export function shannonEntropy(bytes) {
  if (!bytes || bytes.length === 0) return 0;
  const counts = new Uint32Array(256);
  for (let i = 0; i < bytes.length; i++) counts[bytes[i]]++;
  let h = 0;
  const n = bytes.length;
  for (let i = 0; i < 256; i++) {
    if (!counts[i]) continue;
    const p = counts[i] / n;
    h -= p * Math.log2(p);
  }
  return h;
}

/** Entropy of `len` bytes at `off`, clamped to the buffer. */
export function entropyAt(bytes, off, len) {
  const start = Math.max(0, off | 0);
  const end = Math.min(bytes.length, start + Math.max(0, len | 0));
  return shannonEntropy(bytes.subarray(start, end));
}

/** Simple byte-histogram printability ratio (0..1). */
export function printableRatio(bytes) {
  if (!bytes?.length) return 0;
  let printable = 0;
  for (let i = 0; i < bytes.length; i++) {
    const b = bytes[i];
    if (b === 9 || b === 10 || b === 13 || (b >= 0x20 && b <= 0x7e)) printable++;
  }
  return printable / bytes.length;
}
