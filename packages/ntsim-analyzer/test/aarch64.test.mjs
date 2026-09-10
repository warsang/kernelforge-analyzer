/**
 * AArch64 interpreter tests over hand-built fixtures (no toolchain).
 *
 * Fixtures are assembled inline as raw words: a dispatch-stub shaped
 * prologue (stp/mov/adrp/ldr/blr/ldp/br), UDF-alias padding words, a
 * logical-immediate mask case, and the MOV (to SP) alias.
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import { AArch64Interpreter, decodeBitmask } from "../src/aarch64.mjs";

function memFixture() {
  const pages = new Map();
  const read = (addr, len) => {
    const out = new Uint8Array(len);
    for (let i = 0; i < len; i++) {
      const a = BigInt(addr) + BigInt(i);
      const p = pages.get(((a >> 12n) << 12n).toString(16));
      if (!p) return out.subarray(0, i);
      out[i] = p[Number(a & 0xfffn)];
    }
    return out;
  };
  const write = (addr, bytes) => {
    for (let i = 0; i < bytes.length; i++) {
      const a = BigInt(addr) + BigInt(i);
      const b = ((a >> 12n) << 12n).toString(16);
      let p = pages.get(b);
      if (!p) { p = new Uint8Array(0x1000); pages.set(b, p); }
      p[Number(a & 0xfffn)] = bytes[i];
    }
  };
  return { read, write };
}

const STUB_BODY = "fd7bbfa9fd030091700b0090101640f900023fd6fd7bc1a860011fd6";

test("dispatch-stub shape: blr thunk event, tail br exits unmapped", () => {
  const { read, write } = memFixture();
  const BASE = 0x2000ab000n, STUB = 0x70000000n;
  write(BASE, Uint8Array.from(Buffer.from(STUB_BODY, "hex")));
  const slot = new Uint8Array(8);
  let t = STUB;
  for (let i = 0; i < 8; i++) { slot[i] = Number(t & 0xffn); t >>= 8n; }
  write(0x200217028n, slot);
  write(STUB, new Uint8Array([0, 0, 0, 0]));
  write(0x100000000n - 0x4000n, new Uint8Array(0x4000));
  const cpu = new AArch64Interpreter(read, write);
  cpu.sp = 0x100000000n - 0x100n;
  cpu.thunks.set(STUB, "dispatch_stub");
  const res = cpu.run(BASE, 64);
  assert.equal(res.status, "fetch-unmapped");
  assert.ok(cpu.events.some((e) => e.type === "API" && e.name === "dispatch_stub"));
  const mns = cpu.trace.map((tr) => tr.text.split(" ")[0]);
  assert.deepEqual(mns.slice(0, 5), ["stp", "mov", "adrp", "ldr", "blr"]);
});

test("UDF-alias padding words fault with low-16 immediate", () => {
  const { read, write } = memFixture();
  write(0x8000n, new Uint8Array([0x0f, 0x0b, 0x00, 0x00]));
  const cpu = new AArch64Interpreter(read, write);
  const res = cpu.run(0x8000n, 4);
  assert.equal(res.status, "udf");
  assert.match(res.detail, /0xb0f/);
});

test("logical-immediate bitmask decodes", () => {
  assert.equal(decodeBitmask(1, 60, 59, 64), 0xfffffffffffffff0n);
});

test("MOV (to SP) alias of ADD #0", () => {
  const { read, write } = memFixture();
  write(0x9000n, new Uint8Array([0xfd, 0x03, 0x00, 0x91]));
  const cpu = new AArch64Interpreter(read, write);
  cpu.sp = 0x1234n;
  cpu.run(0x9000n, 2);
  assert.equal(cpu.x[29], 0x1234n);
  assert.equal(cpu.trace[0].text.split(" ")[0], "mov");
});
