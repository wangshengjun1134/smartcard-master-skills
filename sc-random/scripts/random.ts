// sc-random CLI entry.
//   node scripts/random.ts --input '{"operation":"generate","length":16,"count":2}'
//   node scripts/random.ts --input '{"operation":"challenge"}'      (8-byte card challenge)
//   node scripts/random.ts --input '{"operation":"nonce","format":"base64"}'
//   node scripts/random.ts --input '{"operation":"uuid"}'

import { readFileSync } from "node:fs";
import { pathToFileURL } from "node:url";
import {
  generateRandom,
  generateUuid,
  normalizeFormat,
  parseLength,
  parseCount,
} from "../algorithms/random.ts";

class SkillError extends Error {
  code: string;
  constructor(code: string, message?: string) {
    super(message ?? code);
    this.code = code;
  }
}

function fail(code: string, message?: string): never {
  throw new SkillError(code, message);
}

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

// Default lengths per operation (bytes).
const DEFAULT_LENGTH: Record<string, number> = {
  generate: 16,
  nonce: 12,
  challenge: 8, // typical smart-card external authenticate challenge
};

export function run(input: any): Record<string, unknown> {
  if (!input || typeof input !== "object") fail("MALFORMED_INPUT", "input must be a JSON object");
  const operation = String(input.operation ?? "").toLowerCase();
  if (!["generate", "nonce", "challenge", "uuid"].includes(operation)) {
    fail("UNSUPPORTED_OPERATION", `operation '${input.operation}' is not supported`);
  }
  const count = parseCount(input.count);
  const format = normalizeFormat(input.format);

  if (operation === "uuid") {
    return { ok: true, operation, count, values: generateUuid(count) };
  }

  const length = parseLength(input.length, DEFAULT_LENGTH[operation] ?? 16);
  return {
    ok: true,
    operation,
    format,
    length,
    count,
    values: generateRandom(length, count, format),
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
    process.stdout.write(JSON.stringify({ ok: false, error: { code, message: err.message } }) + "\n");
    return;
  }
  process.exitCode = 0;
  process.stdout.write(JSON.stringify(out) + "\n");
}

if (import.meta.url === pathToFileURL(process.argv[1]).href) {
  main();
}
