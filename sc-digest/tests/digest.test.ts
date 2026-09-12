import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { sm3 } from "../algorithms/sm3.ts";
import { nativeDigest, isNative, NATIVE_ALGOS } from "../algorithms/native.ts";
import { decodeData, hexToBytes, bytesToHex } from "../algorithms/util.ts";
import { run } from "../scripts/digest.ts";

const __dirname = fileURLToPath(new URL(".", import.meta.url));
const vectors = JSON.parse(readFileSync(__dirname + "vectors/digest.json", "utf8"));

test("SM3 official vectors (GM/T 0004)", () => {
  for (const [input, expected] of Object.entries(vectors.sm3)) {
    const bytes = input === "empty" ? new Uint8Array(0) : hexToBytes(Buffer.from(input).toString("hex"));
    const got = bytesToHex(sm3(bytes));
    assert.equal(got, expected);
  }
});

test("native algorithms known-answer vectors", () => {
  for (const [algo, cases] of Object.entries<any>(vectors.native)) {
    assert.ok(isNative(algo));
    for (const [input, expected] of Object.entries(cases)) {
      const bytes = input === "empty" ? new Uint8Array(0) : hexToBytes(Buffer.from(input).toString("hex"));
      const r = nativeDigest(algo, bytes);
      assert.equal(r.digest, expected, `algo=${algo} input=${input}`);
    }
  }
});

test("run() hash returns correct shape", () => {
  const r: any = run({ operation: "hash", algorithm: "SHA-256", data: "616263" });
  assert.equal(r.ok, true);
  assert.equal(r.algorithm, "SHA-256");
  assert.equal(r.digest, vectors.native["SHA-256"].abc);
  assert.equal(r.length, 32);
});

test("run() list returns all algorithms", () => {
  const r: any = run({ operation: "list" });
  assert.equal(r.ok, true);
  assert.ok(Array.isArray(r.algorithms));
  assert.ok(r.algorithms.includes("SM3"));
  assert.ok(r.algorithms.includes("SHA-256"));
  assert.equal(r.algorithms.length, Object.keys(NATIVE_ALGOS).length + 1);
});

test("encoding utf8 / ascii", () => {
  const r: any = run({ operation: "hash", algorithm: "SHA-256", data: "abc", encoding: "utf8" });
  assert.equal(r.digest, vectors.native["SHA-256"].abc);
  const r2: any = run({ operation: "hash", algorithm: "SHA-256", data: "abc", encoding: "ascii" });
  assert.equal(r2.digest, vectors.native["SHA-256"].abc);
});

function expectCode(fn: () => any, code: string): void {
  try {
    fn();
    assert.fail(`expected error with code ${code}, but call succeeded`);
  } catch (e: any) {
    assert.equal(e.code, code, `expected code ${code}, got ${e.code} (${e.message})`);
  }
}

test("missing parameter -> error", () => {
  expectCode(() => run({ operation: "hash", algorithm: "SHA-256" }), "MISSING_PARAMETER");
  expectCode(() => run({ operation: "hash", data: "616263" }), "MISSING_PARAMETER");
});

test("invalid hex -> error", () => {
  expectCode(() => decodeData("xyz", "hex"), "INVALID_HEX");
  expectCode(() => run({ operation: "hash", algorithm: "SHA-256", data: "xyz" }), "INVALID_HEX");
});

test("unknown algorithm -> UNSUPPORTED_ALGORITHM", () => {
  expectCode(() => run({ operation: "hash", algorithm: "SHA-999", data: "616263" }), "UNSUPPORTED_ALGORITHM");
});

test("unsupported operation -> error", () => {
  expectCode(() => run({ operation: "bogus", algorithm: "SHA-256", data: "616263" }), "UNSUPPORTED_OPERATION");
});
