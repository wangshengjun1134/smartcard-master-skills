// sc-checksum tests: standard "check" values for every algorithm + error cases.

import { test } from "node:test";
import assert from "node:assert";
import { readFileSync } from "node:fs";
import { run } from "../scripts/checksum.ts";
import { crcCompute, CRC_ALGORITHMS } from "../algorithms/crc.ts";
import { simpleCompute, SIMPLE_ALGORITHMS } from "../algorithms/simple.ts";
import { hexToBytes } from "../algorithms/util.ts";

const vectors: any[] = JSON.parse(
  readFileSync(new URL("./vectors/checksum.json", import.meta.url), "utf8"),
);

test("all documented algorithms match their vectors", () => {
  for (const v of vectors) {
    const r = run({ operation: "compute", algorithm: v.algorithm, data: v.data });
    assert.equal(r.ok, true, `${v.name}: ${JSON.stringify(r)}`);
    assert.equal(r.checksum, v.checksum, `${v.name}: got ${r.checksum}, want ${v.checksum}`);
  }
});

test("CRC-32 output width is 4 bytes and not truncated to zero", () => {
  // Regression guard: a 32-bit mask built with `1 << 32` evaluates to 1 in JS,
  // which silently zeroes every CRC-32 result.
  const r = run({ operation: "compute", algorithm: "CRC-32", data: "313233343536373839" });
  assert.equal(r.checksum.length, 8);
  assert.notEqual(r.checksum, "00000000");
});

test("CRC-8/MAXIM uses the reflected polynomial", () => {
  // Poly 0x31 is the MSB-first form; the reflected implementation needs 0x8C.
  assert.equal(CRC_ALGORITHMS["CRC-8/MAXIM"].poly, 0x8c);
  const r = run({ operation: "compute", algorithm: "CRC-8/MAXIM", data: "313233343536373839" });
  assert.equal(r.checksum, "A1");
});

test("LRC is the two's complement of the sum, XOR is a plain XOR", () => {
  const data = hexToBytes("313233343536373839");
  const xor = simpleCompute(data, SIMPLE_ALGORITHMS["XOR"]);
  const lrc = simpleCompute(data, SIMPLE_ALGORITHMS["LRC"]);
  assert.equal(xor, 0x31);
  // sum("123456789") = 477 -> 477 & 0xff = 0xDD -> 0x100 - 0xDD = 0x23
  assert.equal(lrc, 0x23);
  assert.notEqual(lrc, xor, "LRC and XOR must not collapse to the same definition");
});

// `run()` throws ChecksumError; the CLI entry converts it to the {ok:false}
// envelope. Tests therefore assert on the thrown error code.
function expectCode(fn: () => unknown, code: string): void {
  assert.throws(fn, (e: any) => e.code === code, `expected error code ${code}`);
}

test("verify accepts a correct checksum", () => {
  const ok = run({
    operation: "verify",
    algorithm: "CRC-32",
    data: "313233343536373839",
    checksum: "CBF43926",
  });
  assert.equal(ok.ok, true);
  assert.equal(ok.valid, true);
});

test("verify rejects a wrong checksum", () => {
  expectCode(
    () =>
      run({
        operation: "verify",
        algorithm: "CRC-32",
        data: "313233343536373839",
        checksum: "DEADBEEF",
      }),
    "CHECKSUM_MISMATCH",
  );
});

test("invalid hex is rejected", () => {
  expectCode(() => run({ operation: "compute", algorithm: "CRC-32", data: "ZZZ" }), "INVALID_HEX");
});

test("unknown algorithm is rejected", () => {
  expectCode(
    () => run({ operation: "compute", algorithm: "CRC-999", data: "00" }),
    "UNSUPPORTED_ALGORITHM",
  );
});

test("missing data is rejected", () => {
  expectCode(() => run({ operation: "compute", algorithm: "CRC-32" }), "MISSING_PARAMETER");
});

test("poly and init overrides are honoured", () => {
  const base = run({ operation: "compute", algorithm: "CRC-8", data: "313233" });
  const custom = run({
    operation: "compute",
    algorithm: "CRC-8",
    data: "313233",
    poly: 0x9b,
    init: 0xff,
    xorout: 0x00,
  });
  assert.equal(base.ok, true);
  assert.equal(custom.ok, true);
  assert.notEqual(base.checksum, custom.checksum);
  // Cross-check the override against a direct call with the same raw params.
  const manual = crcCompute(hexToBytes("313233"), { ...CRC_ALGORITHMS["CRC-8"], poly: 0x9b }, { init: 0xff, xorout: 0x00 });
  assert.equal(parseInt(custom.checksum, 16), manual);
});
