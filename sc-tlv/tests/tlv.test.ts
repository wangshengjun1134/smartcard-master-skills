import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { execute } from "../scripts/tlv.ts";
import type { Input as InputType } from "../scripts/tlv.ts";
import { TlvError } from "../algorithms/parse.ts";

interface Vector {
  name: string;
  input: InputType;
  expect?: Record<string, unknown>;
  error?: string;
}

const vectorsPath = fileURLToPath(new URL("./vectors/tlv.json", import.meta.url));
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
      assert.ok(thrown instanceof TlvError, `expected TlvError, got ${String(thrown)}`);
      assert.equal((thrown as TlvError).code, v.error);
      return;
    }
    const out = execute(v.input) as Record<string, unknown>;
    assert.equal(out.ok, true);
    for (const key of Object.keys(v.expect as Record<string, unknown>)) {
      assert.deepEqual(out[key], (v.expect as Record<string, unknown>)[key], `field '${key}' mismatch for ${v.name}`);
    }
  });
}

// ---- explicit extra coverage ----
test("BER long-form length 0x81 0x80 = 128 bytes", () => {
  const data = "BF20" + "8180" + "00".repeat(128);
  const out = execute({ operation: "parse", data }) as { tree: { tag: string; length: number; constructed: boolean }[] };
  assert.equal(out.tree[0].tag, "BF20");
  assert.equal(out.tree[0].length, 128);
  assert.equal(out.tree[0].constructed, true);
});

test("pretty output attaches tag names and text tree", () => {
  const out = execute({ operation: "parse", data: "6F0A8408A000000003000000", pretty: true }) as {
    tree: { tag: string; name?: string }[];
    pretty: string;
  };
  assert.equal(out.tree[0].name, "FCI (File Control Information) Template");
  assert.ok(out.pretty.includes("6F"));
  assert.ok(out.pretty.includes("FCI"));
});

test("encode -> parse round-trip preserves structure", () => {
  const items = [
    { tag: "6F", children: [{ tag: "A5", children: [{ tag: "84", value: "A000000003000000" }] }] },
  ] as InputType["items"];
  const enc = execute({ operation: "encode", items }) as { data: string };
  const parsed = execute({ operation: "parse", data: enc.data }) as { tree: unknown[] };
  assert.equal(parsed.tree.length, 1);
});

test("set replaces value keeping position, delete removes", () => {
  const data = "8408A0000000030000009F0206000000001000";
  const replaced = execute({ operation: "set", data, tag: "84", value: "1111111111111111" }) as { data: string };
  assert.ok(replaced.data.startsWith("84081111111111111111"));
  const deleted = execute({ operation: "delete", data: replaced.data, tag: "9F02" }) as { data: string };
  assert.equal(deleted.data, "84081111111111111111");
});

test("find is not an error when missing", () => {
  const out = execute({ operation: "find", data: "8408A000000003000000", tag: "9F99" }) as { ok: boolean; found: boolean };
  assert.equal(out.ok, true);
  assert.equal(out.found, false);
});

test("unknown operation errors", () => {
  assert.throws(() => execute({ operation: "frobnicate", data: "" } as InputType), (e: unknown) => e instanceof TlvError && (e as TlvError).code === "UNSUPPORTED_PARAMETER");
});
