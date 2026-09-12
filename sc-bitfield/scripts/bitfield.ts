// sc-bitfield CLI entry.
//   node scripts/bitfield.ts --input '{"operation":"get","data":"A5","bit_offset":0,"bit_length":4}'
//   node scripts/bitfield.ts --input-file ./in.json
//   echo '{...}' | node scripts/bitfield.ts

import { readFileSync } from "node:fs";
import { pathToFileURL } from "node:url";
import { fail, SkillError } from "../algorithms/errors.ts";
import { hexToBytes, bytesToHex, isHex } from "../algorithms/hex.ts";
import {
  getBits,
  setBits,
  countBits,
  reverseBits,
  shiftBits,
  makeMask,
  applyMask,
  edgeBit,
  edgeByte,
  intToBytes,
  parseValue,
  normalizeBitOrder,
  totalBits,
  type BitOrder,
  type Direction,
} from "../algorithms/bitfield.ts";

function readInput(): unknown {
  const argv = process.argv.slice(2);
  let json: string | null = null;
  for (let i = 0; i < argv.length; i++) {
    if (argv[i] === "--input") json = argv[++i];
    else if (argv[i] === "--input-file") json = readFileSync(argv[++i], "utf8");
  }
  if (json === null) {
    // File descriptor 0: "/dev/stdin" does not exist on Windows.
    try {
      json = readFileSync(0, "utf8");
    } catch {
      json = null;
    }
  }
  if (json === null || json.trim() === "") {
    fail("MALFORMED_INPUT", "no input provided (use --input, --input-file, or stdin)");
  }
  try {
    return JSON.parse(json as string);
  } catch {
    return fail("MALFORMED_INPUT", "input is not valid JSON");
  }
}

function intField(v: unknown, name: string, min: number, max?: number): number {
  if (typeof v !== "number" || !Number.isInteger(v)) {
    fail("MISSING_PARAMETER", `${name} is required and must be an integer`);
  }
  if (v < min) fail("INVALID_PARAMETER", `${name} must be >= ${min}`);
  if (max !== undefined && v > max) fail("INVALID_PARAMETER", `${name} must be <= ${max}`);
  return v;
}

export function run(input: any): Record<string, unknown> {
  if (!input || typeof input !== "object") fail("MALFORMED_INPUT", "input must be a JSON object");

  const operation = String(input.operation ?? "").toLowerCase();
  const ops = ["get", "set", "extract", "insert", "mask", "shift", "count", "reverse", "msb", "lsb"];
  if (!ops.includes(operation)) {
    fail("UNSUPPORTED_OPERATION", `operation '${input.operation}' is not supported`);
  }
  if (typeof input.data !== "string") fail("MISSING_PARAMETER", "data is required");
  if (!isHex(input.data)) fail("INVALID_HEX", "data is not valid hex");
  const data = hexToBytes(input.data.toUpperCase());
  const order: BitOrder = normalizeBitOrder(input.bit_order);

  switch (operation) {
    case "get":
    case "extract": {
      const offset = intField(input.bit_offset, "bit_offset", 0);
      const length = intField(input.bit_length, "bit_length", 0);
      const v = getBits(data, offset, length, order);
      const outBytes = Math.ceil(length / 8);
      return {
        ok: true,
        operation,
        bit_order: order,
        value: v.toString(),
        bits: length,
        hex: bytesToHex(intToBytes(v, outBytes)),
      };
    }

    case "set":
    case "insert": {
      const offset = intField(input.bit_offset, "bit_offset", 0);
      const length = intField(input.bit_length, "bit_length", 0);
      const v = parseValue(input.value, length);
      return {
        ok: true,
        operation,
        bit_order: order,
        data: bytesToHex(setBits(data, offset, length, v, order)),
      };
    }

    case "mask": {
      if (typeof input.mask === "string") {
        return { ok: true, operation, data: bytesToHex(applyMask(data, input.mask.toUpperCase())) };
      }
      const length = intField(input.bit_length, "bit_length", 0, totalBits(data));
      return { ok: true, operation, bits: length, data: bytesToHex(makeMask(length, data.length)) };
    }

    case "shift": {
      const amount = intField(input.shift, "shift", 0);
      const dir = String(input.direction ?? "left").toLowerCase();
      if (dir !== "left" && dir !== "right") {
        fail("INVALID_PARAMETER", "direction must be 'left' or 'right'");
      }
      return {
        ok: true,
        operation,
        direction: dir as Direction,
        shift: amount,
        data: bytesToHex(shiftBits(data, dir as Direction, amount, order)),
      };
    }

    case "count":
      return { ok: true, operation, count: countBits(data), total_bits: totalBits(data) };

    case "reverse":
      return { ok: true, operation, data: bytesToHex(reverseBits(data, order)) };

    case "msb":
    case "lsb":
      return {
        ok: true,
        operation,
        bit: edgeBit(data, operation === "msb" ? "msb" : "lsb", order),
        byte: bytesToHex(new Uint8Array([edgeByte(data, operation === "msb" ? "msb" : "lsb")])),
      };
  }

  return fail("UNSUPPORTED_OPERATION", operation);
}

function main(): void {
  let out: Record<string, unknown>;
  try {
    out = run(readInput());
  } catch (e) {
    const err = e as Error;
    const code = e instanceof SkillError ? e.code : "INTERNAL_ERROR";
    process.exitCode = 1;
    process.stdout.write(JSON.stringify({ ok: false, error: { code, message: err.message } }) + "\n");
    return;
  }
  process.exitCode = 0;
  process.stdout.write(JSON.stringify(out) + "\n");
}

if (import.meta.url === pathToFileURL(process.argv[1]).href) {
  main();
}
