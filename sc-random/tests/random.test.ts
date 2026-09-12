// sc-random tests: output shape, formats, uniqueness, limits.

import { test } from "node:test";
import assert from "node:assert";
import { run } from "../scripts/random.ts";
import { generateRandom, generateUuid, render } from "../algorithms/random.ts";

test("generate returns the requested number of bytes", () => {
  const r = run({ operation: "generate", length: 16 }) as any;
  assert.equal(r.ok, true);
  assert.equal(r.values.length, 1);
  assert.equal(r.values[0].length, 32); // 16 bytes as hex
  assert.match(r.values[0], /^[0-9A-F]{32}$/);
});

test("challenge defaults to 8 bytes and nonce to 12", () => {
  assert.equal((run({ operation: "challenge" }) as any).length, 8);
  assert.equal((run({ operation: "nonce" }) as any).length, 12);
});

test("count produces that many distinct values", () => {
  const r = run({ operation: "generate", length: 8, count: 20 }) as any;
  assert.equal(r.values.length, 20);
  assert.equal(new Set(r.values).size, 20, "random values must not repeat");
});

test("all output formats render correctly", () => {
  const bytes = new Uint8Array([0x00, 0xff, 0x10]);
  assert.equal(render(bytes, "hex"), "00FF10");
  assert.equal(render(bytes, "base64"), Buffer.from(bytes).toString("base64"));
  assert.equal(render(bytes, "dec"), "65296"); // 0x00FF10 = 65296
  assert.equal(render(bytes, "bin"), "000000001111111100010000");
});

test("format parameter is honoured", () => {
  const r = run({ operation: "generate", length: 4, format: "base64" }) as any;
  assert.equal(r.format, "base64");
  assert.equal(Buffer.from(r.values[0], "base64").length, 4);
});

test("uuid produces RFC 4122/9562 version-4 UUIDs", () => {
  const r = run({ operation: "uuid", count: 5 }) as any;
  assert.equal(r.values.length, 5);
  for (const u of r.values) {
    assert.match(u, /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/);
  }
  assert.equal(new Set(r.values).size, 5);
});

test("limits are enforced", () => {
  assert.throws(
    () => run({ operation: "generate", length: 65537 }),
    (e: any) => e.code === "INVALID_PARAMETER",
  );
  assert.throws(
    () => run({ operation: "generate", count: 1025 }),
    (e: any) => e.code === "INVALID_PARAMETER",
  );
  assert.throws(
    () => run({ operation: "generate", length: 0 }),
    (e: any) => e.code === "INVALID_PARAMETER",
  );
});

test("unknown operation and bad format are rejected", () => {
  assert.throws(() => run({ operation: "dice" }), (e: any) => e.code === "UNSUPPORTED_OPERATION");
  assert.throws(
    () => run({ operation: "generate", format: "yaml" }),
    (e: any) => e.code === "INVALID_PARAMETER",
  );
});

test("output is unbiased enough to pass a basic sanity check", () => {
  // 4096 bytes -> each of the 256 byte values should appear at least once.
  const vals = generateRandom(1, 4096, "hex");
  const seen = new Set(vals);
  assert.ok(seen.size > 200, `only ${seen.size} distinct byte values in 4096 draws`);
});

test("generateRandom and generateUuid agree with the CLI defaults", () => {
  assert.equal(generateRandom(8, 2, "hex")[0].length, 16);
  assert.equal(generateUuid(1)[0].length, 36);
});
