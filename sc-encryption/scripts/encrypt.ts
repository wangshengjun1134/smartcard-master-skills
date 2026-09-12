// sc-encryption CLI entry. Outputs a single JSON object to stdout.
import { readFileSync } from "node:fs";
import { emitSuccess, emitError, AppError } from "../algorithms/errors.ts";
import { run } from "../algorithms/engine.ts";

function readStdin(): Promise<string> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    process.stdin.on("data", (c) => chunks.push(c as Buffer));
    process.stdin.on("end", () => resolve(Buffer.concat(chunks).toString("utf8")));
    process.stdin.on("error", reject);
  });
}

async function main(): Promise<void> {
  const argv = process.argv.slice(2);
  let raw: string | undefined;
  let inputFile: string | undefined;

  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--input") {
      raw = argv[++i];
    } else if (a === "--input-file") {
      inputFile = argv[++i];
    }
  }

  if (raw === undefined && inputFile !== undefined) {
    raw = readFileSync(inputFile, "utf8");
  }
  if (raw === undefined) {
    // Read from stdin if it is not a TTY (piped input).
    if (!process.stdin.isTTY) {
      raw = await readStdin();
    }
  }
  if (raw === undefined || raw.trim() === "") {
    emitError(new AppError("MISSING_PARAMETER", "no --input, --input-file, or piped stdin provided"));
    return;
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    emitError(new AppError("MALFORMED_INPUT", "input is not valid JSON"));
    return;
  }

  try {
    const result = run(parsed);
    emitSuccess(result);
  } catch (e) {
    if (e instanceof AppError) {
      emitError(e);
    } else {
      emitError(new AppError("INTERNAL_ERROR", e instanceof Error ? e.message : String(e)));
    }
  }
}

main();
