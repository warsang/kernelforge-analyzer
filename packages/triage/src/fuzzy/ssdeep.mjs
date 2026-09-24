/**
 * ssdeep.mjs — context-triggered piecewise hashing (spamsum), byte-exact
 * with the reference ssdeep implementation (fuzzy.c / sum_table.h).
 *
 * Ported from the reference C so digests are comparable with hashes produced
 * by ssdeep, VirusTotal and other spamsum consumers. Validated in tests
 * against vectors generated with the reference `fuzzy_hash_buf`.
 *
 * Pure JS, no I/O; one pass over the buffer.
 */

const ROLLING_WINDOW = 7;
const MIN_BLOCKSIZE = 3;
const HASH_INIT = 0x27;
const NUM_BLOCKHASHES = 31;
const SPAMSUM_LENGTH = 64;
const TOTAL_SIZE_MAX = MIN_BLOCKSIZE * 2 ** (NUM_BLOCKHASHES - 1) * SPAMSUM_LENGTH;

const B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

// sum_table[h][c] precomputed for h,c in [0,64): ((h * HASH_PRIME) ^ c) & 0x3f.
// The state is always < 64 because every table entry is 6-bit.
function sumHash(h, c) {
  return (((h * 0x01000193) ^ (c & 0x3f)) & 0x3f) >>> 0;
}

class SsdeepState {
  constructor() {
    this.bhstart = 0;
    this.bhend = 1;
    this.bhendlimit = NUM_BLOCKHASHES - 1;
    this.bh = [{ dindex: 0, digest: "", halfdigest: "", h: HASH_INIT, halfh: HASH_INIT }];
    this.totalSize = 0;
    this.fixedSize = 0;
    this.reduceBorder = MIN_BLOCKSIZE * SPAMSUM_LENGTH;
    this.flags = 0; // 1 = NEED_LASTHASH, 2 = SIZE_FIXED
    this.rollmask = 0;
    this.roll = { window: new Uint8Array(ROLLING_WINDOW), h1: 0, h2: 0, h3: 0, n: 0 };
    this.lasth = 0;
  }

  setTotalInputLength(len) {
    if (len > TOTAL_SIZE_MAX) throw new RangeError("ssdeep input too large");
    this.flags |= 2;
    this.fixedSize = len;
    let bi = 0;
    while (MIN_BLOCKSIZE * 2 ** bi * SPAMSUM_LENGTH < len) {
      bi++;
      if (bi === NUM_BLOCKHASHES - 2) break;
    }
    this.bhendlimit = bi + 1;
  }

  tryForkBlockhash() {
    const obh = this.bh[this.bhend - 1];
    if (this.bhend <= this.bhendlimit) {
      this.bh[this.bhend] = { dindex: 0, digest: "", halfdigest: "", h: obh.h, halfh: obh.halfh };
      this.bhend++;
    } else if (this.bhend === NUM_BLOCKHASHES && (this.flags & 1) === 0) {
      this.flags |= 1;
      this.lasth = obh.h;
    }
  }

  tryReduceBlockhash() {
    if (this.bhend - this.bhstart < 2) return;
    const size = (this.flags & 2) ? this.fixedSize : this.totalSize;
    if (this.reduceBorder >= size) return;
    if (this.bh[this.bhstart + 1].dindex < SPAMSUM_LENGTH / 2) return;
    this.bhstart++;
    this.reduceBorder *= 2;
    this.rollmask = (this.rollmask * 2 + 1) >>> 0;
  }

  step(c) {
    const roll = this.roll;
    roll.h2 = (roll.h2 - roll.h1 + ROLLING_WINDOW * c) >>> 0;
    roll.h1 = (roll.h1 + c - roll.window[roll.n]) >>> 0;
    roll.window[roll.n] = c;
    roll.n = (roll.n + 1) % ROLLING_WINDOW;
    roll.h3 = ((roll.h3 << 5) ^ c) >>> 0;

    const horg = (roll.h1 + roll.h2 + roll.h3 + 1) >>> 0;
    let h = Math.floor(horg / MIN_BLOCKSIZE);

    for (let i = this.bhstart; i < this.bhend; i++) {
      this.bh[i].h = sumHash(this.bh[i].h, c);
      this.bh[i].halfh = sumHash(this.bh[i].halfh, c);
    }
    if (this.flags & 1) this.lasth = sumHash(this.lasth, c);

    if (horg === 0) return;
    if ((h & this.rollmask) !== 0) return;
    if (horg % MIN_BLOCKSIZE) return;
    h >>>= this.bhstart;

    let i = this.bhstart;
    for (;;) {
      if (this.bh[i].dindex === 0) this.tryForkBlockhash();
      this.bh[i].digest += B64[this.bh[i].h];
      this.bh[i].halfdigest = B64[this.bh[i].halfh];
      if (this.bh[i].dindex < SPAMSUM_LENGTH - 1) {
        this.bh[i].dindex++;
        this.bh[i].h = HASH_INIT;
        if (this.bh[i].dindex < SPAMSUM_LENGTH / 2) {
          this.bh[i].halfh = HASH_INIT;
          this.bh[i].halfdigest = "";
        }
      } else {
        this.tryReduceBlockhash();
      }
      if (h & 1) break;
      h >>>= 1;
      i++;
      if (i >= this.bhend) break;
    }
  }

  update(bytes) {
    this.totalSize = Math.min(TOTAL_SIZE_MAX + 1, this.totalSize + bytes.length);
    for (let i = 0; i < bytes.length; i++) this.step(bytes[i]);
  }

  digest() {
    let bi = this.bhstart;
    const h = (this.roll.h1 + this.roll.h2 + this.roll.h3) >>> 0;
    while (MIN_BLOCKSIZE * 2 ** bi * SPAMSUM_LENGTH < this.totalSize) bi++;
    if (bi >= this.bhend) bi = this.bhend - 1;
    while (bi > this.bhstart && this.bh[bi].dindex < SPAMSUM_LENGTH / 2) bi--;

    const biBase = bi;
    let out = `${MIN_BLOCKSIZE * 2 ** bi}:`;
    let sz = this.bh[bi].dindex;
    out += this.bh[bi].digest.slice(0, sz);
    let ch = h !== 0 ? B64[this.bh[bi].h] : (this.bh[bi].digest[sz] ?? "");
    if (ch) out += ch;
    out += ":";
    if (bi < this.bhend - 1) {
      bi++;
      sz = this.bh[bi].dindex;
      if (sz > SPAMSUM_LENGTH / 2 - 1) sz = SPAMSUM_LENGTH / 2 - 1;
      out += this.bh[bi].digest.slice(0, sz);
      ch = h !== 0 ? B64[this.bh[bi].halfh] : (this.bh[bi].halfdigest || "");
      if (ch) out += ch;
    } else if (h !== 0) {
      // "nearly empty" second hash: first and last character.
      out += biBase === 0 ? B64[this.bh[0].h] : B64[this.lasth];
    }
    return out;
  }
}

/**
 * ssdeep digest of a buffer, byte-compatible with `fuzzy_hash_buf`.
 * @param {Uint8Array} bytes
 * @returns {string} "blocksize:hash1:hash2"
 */
export function ssdeep(bytes) {
  const buf = bytes instanceof Uint8Array ? bytes : Uint8Array.from(bytes);
  const st = new SsdeepState();
  st.setTotalInputLength(buf.length);
  st.update(buf);
  return st.digest();
}

/**
 * Edit-distance similarity between two ssdeep digests (0..100), same
 * semantics as `fuzzy_compare` (blocksize-compatible pairs only).
 */
export function ssdeepCompare(a, b) {
  const pa = parse(a), pb = parse(b);
  if (!pa || !pb) return 0;
  const bs = Math.min(pa.blockSize, pb.blockSize);
  if (Math.max(pa.blockSize, pb.blockSize) > bs * 2) return 0;
  const d = editDistance(pa.hash1, pb.hash1, 64);
  return d >= 0 ? Math.max(0, 100 - Math.floor((100 * d) / 64)) : 0;
}

function parse(sig) {
  const m = /^(\d+):([^:]*):(.*)$/.exec(String(sig ?? ""));
  if (!m) return null;
  return { blockSize: Number(m[1]), hash1: m[2], hash2: m[3] };
}

function editDistance(a, b, cap) {
  const la = a.length, lb = b.length;
  if (Math.abs(la - lb) > cap) return cap + 1;
  let prev = new Uint16Array(lb + 1);
  let cur = new Uint16Array(lb + 1);
  for (let j = 0; j <= lb; j++) prev[j] = j;
  for (let i = 1; i <= la; i++) {
    cur[0] = i;
    for (let j = 1; j <= lb; j++) {
      cur[j] = Math.min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1));
    }
    [prev, cur] = [cur, prev];
  }
  return prev[lb];
}
