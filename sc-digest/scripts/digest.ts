// sc-digest CLI entry point.
// Usage:
//   node scripts/digest.ts --input '{"operation":"hash","algorithm":"SHA-256","data":"..."}'
//   node scripts/digest.ts --input-file ./in.json
//   echo '{"operation":"hash",...}' | node scripts/digest.ts
import { readFileSync } from "node:fs";
import { pathToFileURL } from "node:url";
import { nativeDigest, isNative, NATIVE_ALGOS } from "../algorithms/native.ts";
import { sm3Hex, SM3 } from "../algorithms/sm3.ts";
import { decodeData, DigestError } from "../algorithms/util.ts";

const SUPPORTED_ALGOS: string[] = [
  ...Object.keys(NATIVE_ALGOS),
  SM3,
];

function parseArgs(argv: string[]): any {
  let input: string | null = null;
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--input") {
      input = argv[++i];
    } else if (a === "--input-file") {
      const p = argv[++i];
      input = readFileSync(p, "utf8");
    }
  }
  if (input === null) {
    // Read piped stdin. Use file descriptor 0 directly: "/dev/stdin" is a
    // POSIX-only path and does not exist on Windows.
    try {
      input = readFileSync(0, "utf8");
    } catch {
      // no stdin available
    }
  }
  if (input === null || input.trim() === "") {
    throw new DigestError("MALFORMED_INPUT", "no input provided (use --input, --input-file, or stdin)");
  }
  return JSON.parse(input);
}

export function run(input: any): any {
  if (!input || typeof input !== "object") {
    throw new DigestError("MALFORMED_INPUT", "input must be a JSON object");
  }
  const operation = input.operation;
  if (operation === "list") {
    return { ok: true, algorithms: SUPPORTED_ALGOS };
  }
  if (operation !== "hash") {
    throw new DigestError("UNSUPPORTED_OPERATION", `operation '${operation}' is not supported`);
  }
  const algorithm = input.algorithm;
  if (typeof algorithm !== "string") {
    throw new DigestError("MISSING_PARAMETER", "algorithm is required");
  }
  if (typeof input.data !== "string") {
    throw new DigestError("MISSING_PARAMETER", "data is required");
  }
  const bytes = decodeData(input.data, input.encoding);
  let result: { digest: string; length: number };
  if (algorithm === SM3) {
    result = sm3Hex(bytes);
  } else if (isNative(algorithm)) {
    result = nativeDigest(algorithm, bytes);
  } else {
    throw new DigestError("UNSUPPORTED_ALGORITHM", `algorithm '${algorithm}' is not supported`);
  }
  return {
    ok: true,
    algorithm,
    digest: result.digest,
    length: result.length,
  };
}

function main(): void {
  let inputObj: any;
  try {
    inputObj = parseArgs(process.argv.slice(2));
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

// Only run as a standalone CLI, not when imported by tests.
const invokedDirectly =
  process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href;
if (invokedDirectly) {
  main();
}
