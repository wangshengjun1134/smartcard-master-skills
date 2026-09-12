// sc-padding CLI entry.
//   node scripts/padding.ts --input '{"operation":"pad","algorithm":"PKCS7","data":"...","block_size":16}'
//   node scripts/padding.ts --input-file ./in.json
//   echo '{...}' | node scripts/padding.ts

import { readFileSync } from "node:fs";
import { pathToFileURL } from "node:url";
import { AppError, fail } from "../algorithms/errors.ts";
import { hexToBytes, bytesToHex, isHex } from "../algorithms/hex.ts";
import { pad, unpad, isValidPadding, normalizeScheme } from "../algorithms/padding.ts";

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

export function run(input: any): Record<string, unknown> {
  if (!input || typeof input !== "object") {
    fail("MALFORMED_INPUT", "input must be a JSON object");
  }
  const operation = input.operation;
  if (operation !== "pad" && operation !== "unpad" && operation !== "validate") {
    fail("UNSUPPORTED_OPERATION", `operation '${operation}' is not supported`);
  }
  if (typeof input.algorithm !== "string" || input.algorithm === "") {
    fail("MISSING_PARAMETER", "algorithm is required");
  }
  const scheme = normalizeScheme(input.algorithm);

  const blockSize = input.block_size;
  if (blockSize === undefined || blockSize === null) {
    fail("MISSING_PARAMETER", "block_size is required");
  }
  if (!Number.isInteger(blockSize) || blockSize < 1 || blockSize > 255) {
    fail("INVALID_PARAMETER", "block_size must be an integer between 1 and 255");
  }

  if (typeof input.data !== "string") fail("MISSING_PARAMETER", "data is required");
  if (!isHex(input.data)) fail("INVALID_HEX", "data is not valid hex");
  const data = hexToBytes(input.data);

  if (operation === "pad") {
    return {
      ok: true,
      algorithm: scheme,
      operation: "pad",
      block_size: blockSize,
      data: bytesToHex(pad(data, blockSize, scheme)),
    };
  }

  if (operation === "unpad") {
    // optional: for zero-based schemes (ISO9797-1-M1 / ZERO) the true payload
    // length cannot be inferred from the bytes; supplying it makes the removal
    // exact and verified instead of "strip all trailing zeros".
    let originalLength: number | undefined;
    if (input.original_length !== undefined && input.original_length !== null) {
      if (!Number.isInteger(input.original_length) || (input.original_length as number) < 0) {
        fail("INVALID_PARAMETER", "original_length must be a non-negative integer");
      }
      originalLength = input.original_length as number;
    }
    return {
      ok: true,
      algorithm: scheme,
      operation: "unpad",
      block_size: blockSize,
      data: bytesToHex(unpad(data, blockSize, scheme, originalLength)),
    };
  }

  // validate: never throws for malformed padding, just reports the boolean.
  return {
    ok: true,
    algorithm: scheme,
    operation: "validate",
    block_size: blockSize,
    valid: isValidPadding(data, blockSize, scheme),
  };
}

function main(): void {
  let out: Record<string, unknown>;
  try {
    out = run(readInput());
  } catch (e) {
    const err = e as Error;
    const code = (e as any).code ?? "INTERNAL_ERROR";
    process.exitCode = 1;
    process.stdout.write(
      JSON.stringify({ ok: false, error: { code, message: err.message } }) + "\n",
    );
    void AppError;
    return;
  }
  process.exitCode = 0;
  process.stdout.write(JSON.stringify(out) + "\n");
}

if (import.meta.url === pathToFileURL(process.argv[1]).href) {
  main();
}
