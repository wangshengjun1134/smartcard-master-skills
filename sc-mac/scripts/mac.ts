// sc-mac CLI entry. Reads JSON via --input, --input-file, or stdin. Prints JSON to stdout.

import { readFileSync } from "node:fs";
import { SkillError } from "../algorithms/errors.ts";
import { hexToBytes, bytesToHex } from "../algorithms/hex.ts";
import { computeMac, truncateMac, verifyMac, ALL_ALGORITHMS } from "../algorithms/mac.ts";

function readInput(): any {
  const argv = process.argv.slice(2);
  let jsonStr: string | null = null;
  for (let i = 0; i < argv.length; i++) {
    if (argv[i] === "--input") {
      jsonStr = argv[++i];
    } else if (argv[i] === "--input-file") {
      jsonStr = readFileSync(argv[++i], "utf8");
    }
  }
  if (jsonStr === null) {
    try {
      jsonStr = readFileSync(0, "utf8");
    } catch {
      jsonStr = "";
    }
  }
  if (!jsonStr || !jsonStr.trim()) {
    throw new SkillError("MALFORMED_INPUT", "no input provided");
  }
  try {
    return JSON.parse(jsonStr);
  } catch {
    throw new SkillError("MALFORMED_INPUT", "input is not valid JSON");
  }
}

function requireStr(obj: any, field: string): string {
  return requireStrOpt(obj, field, false);
}

// allowEmpty: `data` / `iv` may legitimately be an empty string (MAC over an
// empty message, zero IV); other fields must be non-empty.
function requireStrOpt(obj: any, field: string, allowEmpty: boolean): string {
  if (typeof obj[field] !== "string") {
    throw new SkillError("MISSING_PARAMETER", `field '${field}' is required`);
  }
  if (!allowEmpty && obj[field].length === 0) {
    throw new SkillError("MISSING_PARAMETER", `field '${field}' is required`);
  }
  return obj[field];
}

function run(): void {
  const input = readInput();
  if (typeof input !== "object" || input === null) {
    throw new SkillError("MALFORMED_INPUT", "input must be an object");
  }
  const operation = requireStr(input, "operation");
  const algorithm = requireStr(input, "algorithm");
  const keyHex = requireStr(input, "key");
  const dataHex = requireStrOpt(input, "data", true);

  if (operation !== "mac" && operation !== "verify") {
    throw new SkillError("UNSUPPORTED_OPERATION", operation);
  }
  if (!ALL_ALGORITHMS.includes(algorithm)) {
    throw new SkillError("UNSUPPORTED_ALGORITHM", algorithm);
  }
  try {
    hexToBytes(keyHex);
    hexToBytes(dataHex);
  } catch {
    throw new SkillError("INVALID_HEX", "key/data must be valid HEX");
  }

  const { mac, fullLength } = computeMac({
    algorithm,
    key: keyHex,
    data: dataHex,
    cipher: input.cipher,
    padding: input.padding,
    iv: input.iv,
    mac_length: input.mac_length,
  });
  const { out, truncated } = truncateMac(mac, input.mac_length);
  const macHex = bytesToHex(out);
  const outLen = out.length;

  if (operation === "mac") {
    process.stdout.write(
      JSON.stringify({
        ok: true,
        algorithm,
        mac: macHex,
        mac_length: outLen,
        truncated,
      }) + "\n",
    );
    return;
  }

  // verify
  const expectedRaw = input.expected;
  if (typeof expectedRaw !== "string") {
    throw new SkillError("MISSING_PARAMETER", "field 'expected' is required for verify");
  }
  let expected: string;
  try {
    expected = bytesToHex(hexToBytes(expectedRaw));
  } catch {
    throw new SkillError("INVALID_HEX", "expected must be valid HEX");
  }
  const res = verifyMac(
    {
      algorithm,
      key: keyHex,
      data: dataHex,
      cipher: input.cipher,
      padding: input.padding,
      iv: input.iv,
      mac_length: input.mac_length,
    },
    expectedRaw,
  );
  if (res.valid) {
    process.stdout.write(
      JSON.stringify({ ok: true, valid: true, expected: res.expected, actual: res.actual }) + "\n",
    );
  } else {
    process.stdout.write(
      JSON.stringify({
        ok: false,
        error: { code: "MAC_MISMATCH", message: "MAC verification failed" },
        expected: res.expected,
        actual: res.actual,
      }) + "\n",
    );
  }
}

try {
  run();
} catch (e) {
  // Use exitCode (not process.exit) so buffered stdout is flushed on pipes.
  process.exitCode = 1;
  if (e instanceof SkillError) {
    process.stdout.write(JSON.stringify({ ok: false, error: { code: e.code, message: e.message } }) + "\n");
  } else {
    const msg = e instanceof Error ? e.message : String(e);
    process.stdout.write(JSON.stringify({ ok: false, error: { code: "INTERNAL_ERROR", message: msg } }) + "\n");
  }
}
