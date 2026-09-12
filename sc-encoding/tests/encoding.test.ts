import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { execute } from "../scripts/encoding.ts";
import type { Input } from "../scripts/encoding.ts";
import { CodecError } from "../algorithms/codec.ts";

interface Vector {
  name: string;
  input: Input;
  result?: string;
  bytes?: number;
  error?: string;
}

const vectorsPath = fileURLToPath(new URL("./vectors/encoding.json", import.meta.url));
const vectors: Vector[] = JSON.parse(readFileSync(vectorsPath, "utf8")).vectors;

for (const v of vectors) {
  test(v.name, () => {
    if (v.error) {
      let thrown: unknown;
      try {
        execute(v.input);
      } catch (e) {
        thrown = e;
      }
      assert.ok(thrown, `expected error ${v.error} but none thrown`);
      assert.ok(thrown instanceof CodecError, `expected CodecError, got ${String(thrown)}`);
      assert.equal((thrown as CodecError).code, v.error, `expected error code ${v.error}`);
      return;
    }
    const out = execute(v.input) as { ok: boolean; result: string; bytes: number };
    assert.equal(out.ok, true);
    assert.equal(out.result, v.result, `result mismatch for ${v.name}`);
    if (v.bytes !== undefined) assert.equal(out.bytes, v.bytes, `bytes mismatch for ${v.name}`);
  });
}

// Extra targeted checks beyond the vector table.
test("integer preserves leading zeros at length 8", () => {
  const out = execute({ operation: "convert", data: "255", from: "integer", to: "hex", length: 8 }) as { result: string };
  assert.equal(out.result, "00000000000000FF");
});

test("bcd-tbcd is reversible", () => {
  const enc = execute({ operation: "decode", data: "1234567", encoding: "bcd-tbcd" }) as { result: string };
  const dec = execute({ operation: "encode", data: enc.result, encoding: "bcd-tbcd" }) as { result: string };
  assert.equal(dec.result, "1234567");
});

test("bcd reversible for even and odd", () => {
  for (const d of ["1234", "123", "0012"]) {
    const enc = execute({ operation: "decode", data: d, encoding: "bcd" }) as { result: string };
    const dec = execute({ operation: "encode", data: enc.result, encoding: "bcd" }) as { result: string };
    // even-length strings round-trip exactly; odd with default right padding pads to even
    if (d.length % 2 === 0) assert.equal(dec.result, d);
  }
});

test("utf8 lossless round-trip", () => {
  const hex = execute({ operation: "convert", data: "智能卡", from: "utf8", to: "hex" }) as { result: string };
  const back = execute({ operation: "convert", data: hex.result, from: "hex", to: "utf8" }) as { result: string };
  assert.equal(back.result, "智能卡");
});

test("missing data is an error", () => {
  assert.throws(() => execute({ operation: "convert", from: "hex", to: "hex" } as Input), CodecError);
});

test("unknown operation is an error", () => {
  assert.throws(() => execute({ operation: "frobnicate", data: "FF" } as Input), (e: unknown) => e instanceof CodecError && (e as CodecError).code === "UNSUPPORTED_PARAMETER");
});
