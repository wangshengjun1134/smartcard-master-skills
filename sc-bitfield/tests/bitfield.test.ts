// sc-bitfield tests: bit ordering, cross-byte fields, edge cases.

import { test } from "node:test";
import assert from "node:assert";
import { run } from "../scripts/bitfield.ts";
import { getBits, setBits, countBits, reverseBits, shiftBits, makeMask } from "../algorithms/bitfield.ts";
import { hexToBytes, bytesToHex } from "../algorithms/hex.ts";

const B = (h: string) => hexToBytes(h);

test("MSB order: high nibble and low nibble of A5", () => {
  assert.equal(run({ operation: "get", data: "A5", bit_offset: 0, bit_length: 4 }).hex, "0A");
  assert.equal(run({ operation: "get", data: "A5", bit_offset: 4, bit_length: 4 }).hex, "05");
});

test("LSB order: bit 0 is the least significant bit", () => {
  // Bit 0..3 of 0xA5 (1010 0101) are 1,0,1,0 -> weights 2^0..2^3 -> 0b0101 = 5.
  const r = run({ operation: "get", data: "A5", bit_offset: 0, bit_length: 4, bit_order: "lsb" });
  assert.equal(r.value, "5");
  assert.equal(r.hex, "05");
});

test("both bit orders read the full byte to the same value", () => {
  const a = run({ operation: "get", data: "A5", bit_offset: 0, bit_length: 8 });
  const b = run({ operation: "get", data: "A5", bit_offset: 0, bit_length: 8, bit_order: "lsb" });
  assert.equal(a.hex, "A5");
  assert.equal(b.hex, "A5");
});

test("fields may cross byte boundaries", () => {
  // 0x1234: bits 4..11 are 0x23.
  const r = run({ operation: "get", data: "1234", bit_offset: 4, bit_length: 8 });
  assert.equal(r.hex, "23");
  assert.equal(r.value, "35");
});

test("set only touches the addressed bits", () => {
  const r = run({ operation: "set", data: "A5", bit_offset: 0, bit_length: 4, value: 5 });
  assert.equal(r.data, "55"); // high nibble 0xA -> 0x5, low nibble untouched
  const s = run({ operation: "set", data: "FFFF", bit_offset: 4, bit_length: 8, value: 0 });
  assert.equal(s.data, "F00F");
});

test("set in LSB order writes the low nibble", () => {
  const r = run({ operation: "set", data: "A5", bit_offset: 0, bit_length: 4, value: 0x0f, bit_order: "lsb" });
  assert.equal(r.data, "AF"); // 0xA5 | 0x0F
});

test("set rejects a value that does not fit", () => {
  assert.throws(
    () => run({ operation: "set", data: "00", bit_offset: 0, bit_length: 4, value: 16 }),
    (e: any) => e.code === "INVALID_PARAMETER",
  );
});

test("count returns the population count", () => {
  assert.equal(run({ operation: "count", data: "A5" }).count, 4); // 1010 0101
  assert.equal(run({ operation: "count", data: "FF" }).count, 8);
  assert.equal(run({ operation: "count", data: "00" }).count, 0);
});

test("reverse flips the whole bit string", () => {
  assert.equal(run({ operation: "reverse", data: "01" }).data, "80"); // 00000001 -> 10000000
  assert.equal(run({ operation: "reverse", data: "12" }).data, "48"); // 00010010 -> 01001000
  // Reversing twice returns the original.
  assert.equal(run({ operation: "reverse", data: "48" }).data, "12");
});

test("shift fills with zeroes", () => {
  assert.equal(run({ operation: "shift", data: "1234", direction: "left", shift: 4 }).data, "2340");
  assert.equal(run({ operation: "shift", data: "1234", direction: "right", shift: 4 }).data, "0123");
  assert.equal(run({ operation: "shift", data: "1234", direction: "left", shift: 16 }).data, "0000");
});

test("mask generation and application", () => {
  assert.equal(run({ operation: "mask", data: "FFFF", bit_length: 12 }).data, "FFF0");
  assert.equal(run({ operation: "mask", data: "1234", mask: "FF0F" }).data, "1204");
  assert.throws(
    () => run({ operation: "mask", data: "1234", mask: "FF" }),
    (e: any) => e.code === "INVALID_PARAMETER",
  );
});

test("msb and lsb report the edge bits", () => {
  assert.equal(run({ operation: "msb", data: "80" }).bit, 1);
  assert.equal(run({ operation: "msb", data: "7F" }).bit, 0);
  assert.equal(run({ operation: "lsb", data: "01" }).bit, 1);
  assert.equal(run({ operation: "lsb", data: "FE" }).bit, 0);
  assert.equal(run({ operation: "msb", data: "1234" }).byte, "12");
  assert.equal(run({ operation: "lsb", data: "1234" }).byte, "34");
});

test("out-of-range fields are rejected", () => {
  assert.throws(
    () => run({ operation: "get", data: "A5", bit_offset: 4, bit_length: 8 }),
    (e: any) => e.code === "OUT_OF_RANGE",
  );
});

test("missing parameters are rejected", () => {
  assert.throws(
    () => run({ operation: "get", data: "A5" }),
    (e: any) => e.code === "MISSING_PARAMETER",
  );
  assert.throws(
    () => run({ operation: "nope", data: "A5" }),
    (e: any) => e.code === "UNSUPPORTED_OPERATION",
  );
  assert.throws(
    () => run({ operation: "get", data: "ZZ" }),
    (e: any) => e.code === "INVALID_HEX",
  );
});

test("low-level helpers agree with the CLI", () => {
  assert.equal(bytesToHex(makeMask(12, 2)), "FFF0");
  assert.equal(Number(getBits(B("1234"), 4, 8, "msb")), 0x23);
  assert.equal(bytesToHex(setBits(B("0000"), 0, 8, 255n, "msb")), "FF00");
  assert.equal(countBits(B("A5")), 4);
  assert.equal(bytesToHex(reverseBits(B("01"))), "80");
  assert.equal(bytesToHex(shiftBits(B("1234"), "left", 4)), "2340");
});

test("get and set round trip for every offset that fits a byte", () => {
  for (let off = 0; off + 4 <= 8; off++) {
    const got = getBits(B("A5"), off, 4, "msb");
    const back = setBits(B("00"), off, 4, got, "msb");
    assert.equal(Number(getBits(back, off, 4, "msb")), Number(got), `offset ${off}`);
  }
});
