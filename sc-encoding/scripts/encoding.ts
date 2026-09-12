// sc-encoding CLI entry point.
// Usage:
//   node scripts/encoding.ts --input '{"operation":"...","data":"..."}'
//   node scripts/encoding.ts --input-file ./in.json
//   echo '{"operation":"..."}' | node scripts/encoding.ts

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { toBytes, fromBytes, CodecError } from "../algorithms/codec.ts";
import type { Options } from "../algorithms/codec.ts";

export interface Input {
  operation: string;
  data?: string;
  from?: string;
  to?: string;
  encoding?: string;
  length?: number;
  endian?: "big" | "little";
  bcd_padding?: "left" | "right";
}

function buildOptions(input: Input): Options {
  const opts: Options = {};
  if (input.length !== undefined) opts.length = input.length;
  if (input.endian !== undefined) opts.endian = input.endian;
  if (input.bcd_padding !== undefined) opts.bcd_padding = input.bcd_padding;
  return opts;
}

// Pure core: returns the result object or throws CodecError. No stdout/exit side effects.
export function execute(input: Input): Record<string, unknown> {
  const op = input.operation;
  if (!op) throw new CodecError("MISSING_PARAMETER", "operation is required");
  if (input.data === undefined || input.data === null) {
    throw new CodecError("MISSING_PARAMETER", "data is required");
  }
  const opts = buildOptions(input);
  const data = input.data;

  switch (op) {
    case "convert": {
      const from = input.from;
      const to = input.to;
      if (!from) throw new CodecError("MISSING_PARAMETER", "convert requires 'from'");
      if (!to) throw new CodecError("MISSING_PARAMETER", "convert requires 'to'");
      const bytes = toBytes(from, data, opts);
      const result = fromBytes(to, bytes, opts);
      return { ok: true, from, to, result, bytes: bytes.length };
    }
    case "decode": {
      const enc = input.encoding;
      if (!enc) throw new CodecError("MISSING_PARAMETER", "decode requires 'encoding' (source representation)");
      const bytes = toBytes(enc, data, opts);
      const result = fromBytes("hex", bytes, opts);
      return { ok: true, from: enc, to: "hex", result, bytes: bytes.length };
    }
    case "encode": {
      const enc = input.encoding;
      if (!enc) throw new CodecError("MISSING_PARAMETER", "encode requires 'encoding' (target representation)");
      const bytes = toBytes("hex", data, opts);
      const result = fromBytes(enc, bytes, opts);
      return { ok: true, from: "hex", to: enc, result, bytes: bytes.length };
    }
    default:
      throw new CodecError("UNSUPPORTED_PARAMETER", `unknown operation: ${op}`);
  }
}

function fail(code: string, message: string): never {
  process.stdout.write(JSON.stringify({ ok: false, error: { code, message } }) + "\n");
  process.exit(1);
}

function readStdin(): Promise<string> {
  return new Promise((resolve, reject) => {
    let data = "";
    process.stdin.setEncoding("utf8");
    process.stdin.on("data", (c) => (data += c));
    process.stdin.on("end", () => resolve(data));
    process.stdin.on("error", reject);
  });
}

function parseArgs(argv: string[]): { input?: string; file?: string } {
  let input: string | undefined;
  let file: string | undefined;
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--input") input = argv[++i];
    else if (a === "--input-file") file = argv[++i];
  }
  return { input, file };
}

async function main(): Promise<void> {
  const { input, file } = parseArgs(process.argv.slice(2));
  let raw = "";
  try {
    if (input !== undefined) raw = input;
    else if (file !== undefined) raw = readFileSync(file, "utf8");
    else raw = await readStdin();
  } catch (e) {
    fail("MALFORMED_INPUT", `cannot read input: ${(e as Error).message}`);
  }
  if (!raw || !raw.trim()) fail("MALFORMED_INPUT", "empty input");

  let parsed: Input;
  try {
    parsed = JSON.parse(raw);
  } catch {
    fail("MALFORMED_INPUT", "input is not valid JSON");
  }

  try {
    const result = execute(parsed);
    process.stdout.write(JSON.stringify(result) + "\n");
  } catch (e) {
    if (e instanceof CodecError) fail(e.code, e.message);
    fail("INTERNAL_ERROR", (e as Error).message);
  }
}

const invokedPath = process.argv[1] ? fileURLToPath(import.meta.url) : "";
if (process.argv[1] && (process.argv[1].endsWith("scripts/encoding.ts") || invokedPath === process.argv[1])) {
  main();
}
