// sc-padding tests: round trips, block-aligned edge cases, fail-closed unpadding.

import { test } from "node:test";
import assert from "node:assert";
import { run } from "../scripts/padding.ts";
import { pad, unpad, isValidPadding, PADDING_SCHEMES } from "../algorithms/padding.ts";
import { hexToBytes, bytesToHex } from "../algorithms/hex.ts";

const B = (hex: string): Uint8Array => hexToBytes(hex);

test("PKCS7 pads a full block when input is already aligned", () => {
  const out = run({ operation: "pad", algorithm: "PKCS7", data: "00112233445566778899AABBCCDDEEFF", block_size: 16 });
  assert.equal(out.data, "00112233445566778899AABBCCDDEEFF10101010101010101010101010101010");
});

test("PKCS7 pads to the block boundary otherwise", () => {
  const out = run({ operation: "pad", algorithm: "PKCS7", data: "0011223344", block_size: 16 });
  assert.equal(out.data, "00112233440B0B0B0B0B0B0B0B0B0B0B");
  assert.equal(out.data.length, 32);
});

test("ISO7816-4 appends 0x80 then zeros", () => {
  const out = run({ operation: "pad", algorithm: "ISO7816-4", data: "0011223344", block_size: 8 });
  assert.equal(out.data, "0011223344800000");
});

test("ISO9797-1-M1 adds nothing when already aligned, zeros otherwise", () => {
  const aligned = run({ operation: "pad", algorithm: "ISO9797-1-M1", data: "0011223344556677", block_size: 8 });
  assert.equal(aligned.data, "0011223344556677");
  const partial = run({ operation: "pad", algorithm: "ISO9797-1-M1", data: "0011", block_size: 8 });
  assert.equal(partial.data, "0011000000000000");
});

test("ANSI-X9.23 zero-fills and puts the length in the last byte", () => {
  const out = run({ operation: "pad", algorithm: "ANSI-X9.23", data: "0011223344", block_size: 8 });
  assert.equal(out.data, "0011223344000003");
});

test("round trip for every scheme that records a length", () => {
  for (const scheme of ["PKCS7", "ANSI-X9.23", "ISO7816-4", "ISO9797-1-M2"] as const) {
    const data = "0011223344";
    const padded = run({ operation: "pad", algorithm: scheme, data, block_size: 8 }).data as string;
    const back = run({ operation: "unpad", algorithm: scheme, data: padded, block_size: 8 }).data;
    assert.equal(back, data, `${scheme} round trip failed`);
  }
});

test("unpadding is fail-closed on malformed PKCS7", () => {
  // Last byte says 3, but the preceding bytes are not 0x03.
  assert.throws(
    () => run({ operation: "unpad", algorithm: "PKCS7", data: "00112233445566778899AABBCCDDEE03", block_size: 16 }),
    (e: any) => e.code === "INVALID_PADDING",
  );
  // Padding length 0 is invalid.
  assert.throws(
    () => run({ operation: "unpad", algorithm: "PKCS7", data: "00112233445566778899AABBCCDDEE00", block_size: 16 }),
    (e: any) => e.code === "INVALID_PADDING",
  );
});

test("unpadding rejects data that is not block aligned", () => {
  assert.throws(
    () => run({ operation: "unpad", algorithm: "PKCS7", data: "001122", block_size: 8 }),
    (e: any) => e.code === "INVALID_PADDING",
  );
});

test("unpad ISO7816-4 rejects input with no 0x80 boundary", () => {
  assert.throws(
    () => run({ operation: "unpad", algorithm: "ISO7816-4", data: "0011223344556677", block_size: 8 }),
    (e: any) => e.code === "INVALID_PADDING",
  );
});

test("validate reports false instead of throwing", () => {
  const bad = run({ operation: "validate", algorithm: "PKCS7", data: "00112233445566778899AABBCCDDEE03", block_size: 16 });
  assert.equal(bad.ok, true);
  assert.equal(bad.valid, false);
  const good = run({ operation: "validate", algorithm: "PKCS7", data: "00112233440B0B0B0B0B0B0B0B0B0B0B", block_size: 16 });
  assert.equal(good.valid, true);
});

test("block_size is mandatory and range-checked", () => {
  assert.throws(
    () => run({ operation: "pad", algorithm: "PKCS7", data: "0011" }),
    (e: any) => e.code === "MISSING_PARAMETER",
  );
  assert.throws(
    () => run({ operation: "pad", algorithm: "PKCS7", data: "0011", block_size: 0 }),
    (e: any) => e.code === "INVALID_PARAMETER",
  );
  assert.throws(
    () => run({ operation: "pad", algorithm: "PKCS7", data: "0011", block_size: 256 }),
    (e: any) => e.code === "INVALID_PARAMETER",
  );
});

test("unknown scheme and bad hex are rejected", () => {
  assert.throws(
    () => run({ operation: "pad", algorithm: "NOPE", data: "0011", block_size: 8 }),
    (e: any) => e.code === "UNSUPPORTED_ALGORITHM",
  );
  assert.throws(
    () => run({ operation: "pad", algorithm: "PKCS7", data: "ZZ", block_size: 8 }),
    (e: any) => e.code === "INVALID_HEX",
  );
});

test("scheme names are case insensitive", () => {
  const a = run({ operation: "pad", algorithm: "pkcs7", data: "0011223344", block_size: 8 });
  const b = run({ operation: "pad", algorithm: "PKCS7", data: "0011223344", block_size: 8 });
  assert.equal(a.data, b.data);
});

test("ZERO padding is ambiguous and documented as such", () => {
  // Trailing zeros of real data cannot be distinguished from padding.
  const out = run({ operation: "pad", algorithm: "ZERO", data: "001100", block_size: 8 });
  assert.equal(out.data, "0011000000000000");
  const back = run({ operation: "unpad", algorithm: "ZERO", data: "0011000000000000", block_size: 8 });
  assert.equal(back.data, "0011"); // loses the original trailing zero byte
});

test("all exported schemes are usable", () => {
  for (const s of PADDING_SCHEMES) {
    const padded = pad(B("0011"), 8, s);
    assert.equal(padded.length % 8, 0, `${s} produced a non-aligned output`);
    assert.equal(typeof isValidPadding(padded, 8, s), "boolean");
  }
});

test("byte-level equality between ISO7816-4 and ISO9797-1-M2 is intentional", () => {
  assert.equal(bytesToHex(pad(B("00112233"), 8, "ISO7816-4")), bytesToHex(pad(B("00112233"), 8, "ISO9797-1-M2")));
  // ...but they are distinct entries so callers can be explicit about intent.
  assert.ok(PADDING_SCHEMES.includes("ISO7816-4"));
  assert.ok(PADDING_SCHEMES.includes("ISO9797-1-M2"));
});
