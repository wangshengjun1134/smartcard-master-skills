// sc-checksum CLI entry point.
// Usage:
//   node scripts/checksum.ts --input '{"operation":"compute","algorithm":"CRC-32","data":"313233343536373839"}'
//   node scripts/checksum.ts --input '{"operation":"verify","algorithm":"CRC-32","data":"...","checksum":"CBF43926"}'
import { readFileSync } from "node:fs";
import { pathToFileURL } from "node:url";
import { CRC_ALGORITHMS, crcCompute, isCrc } from "../algorithms/crc.ts";
import type { CrcParams } from "../algorithms/crc.ts";
import { SIMPLE_ALGORITHMS, simpleCompute, isSimple } from "../algorithms/simple.ts";
import { hexToBytes, intToHex, isHex, ChecksumError } from "../algorithms/util.ts";

function parseInput(argv: string[]): any {
  let input: string | null = null;
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--input") input = argv[++i];
    else if (a === "--input-file") input = readFileSync(argv[++i], "utf8");
  }
  if (input === null) {
    // Use file descriptor 0 directly: "/dev/stdin" is POSIX-only and does
    // not exist on Windows.
    try {
      const s = readFileSync(0, "utf8");
      if (s.trim() !== "") input = s;
    } catch {
      // no stdin
    }
  }
  if (input === null || input.trim() === "") {
    throw new ChecksumError("MALFORMED_INPUT", "no input provided (use --input, --input-file, or stdin)");
  }
  return JSON.parse(input);
}

function parseNumberOrHex(v: any): number {
  if (typeof v === "number") return v >>> 0;
  if (typeof v === "string") {
    const s = v.trim();
    const num = parseInt(s, s.startsWith("0x") || s.startsWith("0X") ? 16 : 10);
    if (Number.isNaN(num)) {
      // treat as hex literal
      if (isHex(s)) return parseInt(s, 16) >>> 0;
      throw new ChecksumError("INVALID_PARAMETER", `cannot parse numeric value '${v}'`);
    }
    return num >>> 0;
  }
  throw new ChecksumError("INVALID_PARAMETER", `cannot parse numeric value '${String(v)}'`);
}

export function run(input: any): any {
  if (!input || typeof input !== "object") {
    throw new ChecksumError("MALFORMED_INPUT", "input must be a JSON object");
  }
  const operation = input.operation;
  const isVerify = operation === "verify" || operation === "validate";
  const isCompute = operation === "compute" || operation === "checksum";
  if (!isVerify && !isCompute) {
    throw new ChecksumError("UNSUPPORTED_OPERATION", `operation '${operation}' is not supported`);
  }
  const algorithm = input.algorithm;
  if (typeof algorithm !== "string") {
    throw new ChecksumError("MISSING_PARAMETER", "algorithm is required");
  }
  if (typeof input.data !== "string") {
    throw new ChecksumError("MISSING_PARAMETER", "data is required");
  }
  if (!isHex(input.data)) {
    throw new ChecksumError("INVALID_HEX", "data is not valid hex");
  }
  const bytes = hexToBytes(input.data);

  const endian: "big" | "little" = (input.endian ?? "big") === "little" ? "little" : "big";

  let value: number;
  let width: number;

  if (isCrc(algorithm)) {
    const base: CrcParams = { ...CRC_ALGORITHMS[algorithm] };
    width = base.width;
    const eff: CrcParams = { ...base };
    if (input.init !== undefined) eff.init = parseNumberOrHex(input.init);
    if (input.xorout !== undefined) eff.xorout = parseNumberOrHex(input.xorout);
    if (input.poly !== undefined) eff.poly = parseNumberOrHex(input.poly);
    if (input.refin !== undefined) eff.refin = Boolean(input.refin);
    if (input.refout !== undefined) eff.refout = Boolean(input.refout);
    value = crcCompute(bytes, eff);
  } else if (isSimple(algorithm)) {
    width = SIMPLE_ALGORITHMS[algorithm].width;
    value = simpleCompute(bytes, SIMPLE_ALGORITHMS[algorithm]);
  } else {
    throw new ChecksumError("UNSUPPORTED_ALGORITHM", `algorithm '${algorithm}' is not supported`);
  }

  const nBytes = width / 8;
  const checksumHex = intToHex(value, nBytes, endian);

  if (isVerify) {
    if (typeof input.checksum !== "string") {
      throw new ChecksumError("MISSING_PARAMETER", "checksum is required for verify");
    }
    const expected = input.checksum.toUpperCase().replace(/^0X/, "");
    if (expected !== checksumHex) {
      throw new ChecksumError("CHECKSUM_MISMATCH", `expected ${checksumHex}, got ${expected}`);
    }
    return { ok: true, algorithm, checksum: checksumHex, width, valid: true };
  }

  return { ok: true, algorithm, checksum: checksumHex, width };
}

function main(): void {
  let inputObj: any;
  try {
    inputObj = parseInput(process.argv.slice(2));
  } catch (e) {
    const err = e as Error;
    const code = (e as any).code ?? "MALFORMED_INPUT";
    process.stdout.write(JSON.stringify({ ok: false, error: { code, message: err.message } }) + "\n");
    process.exit(1);
    return;
  }
  try {
    const out = run(inputObj);
    process.stdout.write(JSON.stringify(out) + "\n");
    process.exit(0);
  } catch (e) {
    const err = e as Error;
    const code = (e as any).code ?? "INTERNAL_ERROR";
    process.stdout.write(JSON.stringify({ ok: false, error: { code, message: err.message } }) + "\n");
    process.exit(1);
  }
}

const invokedDirectly =
  process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href;
if (invokedDirectly) {
  main();
}
