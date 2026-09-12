// sc-key CLI entry.
//   node scripts/key.ts --input '{"operation":"generate","algorithm":"AES-256"}'
//   node scripts/key.ts --input '{"operation":"derive","algorithm":"HKDF","ikm":"...","hash":"SHA-256","keylen":32}'
//   node scripts/key.ts --input '{"operation":"wrap","algorithm":"AES-KW","kek":"...","data":"..."}'
//   node scripts/key.ts --input '{"operation":"kcv","algorithm":"KCV-CMAC","key":"..."}'

import { readFileSync } from "node:fs";
import { pathToFileURL } from "node:url";
import { randomBytes } from "node:crypto";
import { AppError, fromHex, toHex, adjustParity } from "../algorithms/util.ts";
import { aesKeyWrap, aesKeyUnwrap, aesKwpWrap, aesKwpUnwrap } from "../algorithms/aeskw.ts";
import { kdfPbkdf2, kdfHkdf, kdfScrypt, kdfX963, normalizeHash, describeParams } from "../algorithms/kdf.ts";
import { diversify, computeKcv, type DiversifyAlgo, type KcvAlgo } from "../algorithms/diversify.ts";

function fail(code: string, message: string): never {
  throw new AppError(code, message);
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

function optHex(v: unknown, name: string, def?: Buffer): Buffer {
  if (v === undefined || v === null || v === "") {
    if (def !== undefined) return def;
    return Buffer.alloc(0);
  }
  return fromHex(v);
}

function reqHex(v: unknown, name: string): Buffer {
  if (v === undefined || v === null || v === "") fail("MISSING_PARAMETER", `${name} is required`);
  return fromHex(v);
}

const GEN_SIZES: Record<string, number> = {
  "AES-128": 16,
  "AES-192": 24,
  "AES-256": 32,
  SM4: 16,
  "3DES": 24,
  "3DES-2KEY": 16,
  "HMAC-SHA256": 32,
  "HMAC-SHA512": 64,
};

function doGenerate(input: any): Record<string, unknown> {
  const algo = String(input.algorithm ?? "").toUpperCase();
  let length: number;
  if (algo === "GENERIC") {
    length = typeof input.length === "number" ? input.length : 32;
  } else if (algo in GEN_SIZES) {
    length = GEN_SIZES[algo];
    if (typeof input.length === "number" && input.length !== length) {
      fail("INVALID_PARAMETER", `${algo} keys are fixed at ${length} bytes`);
    }
  } else {
    fail("UNSUPPORTED_ALGORITHM", `cannot generate keys for '${input.algorithm}'`);
  }
  if (!Number.isInteger(length) || length < 1 || length > 4096) {
    fail("INVALID_PARAMETER", "length must be an integer between 1 and 4096");
  }
  let key = Buffer.from(randomBytes(length));
  // DES/3DES keys conventionally carry odd parity in the low bit.
  const paritied = algo.startsWith("3DES") ? input.parity !== false : input.parity === true;
  if (paritied) key = adjustParity(key);
  return { ok: true, operation: "generate", algorithm: algo, key: toHex(key), length: key.length };
}

function doDerive(input: any): Record<string, unknown> {
  const algo = String(input.algorithm ?? "").toUpperCase();
  const keylen = typeof input.keylen === "number" ? input.keylen : 32;
  if (!Number.isInteger(keylen) || keylen < 1 || keylen > 1024) {
    fail("INVALID_PARAMETER", "keylen must be an integer between 1 and 1024");
  }

  if (algo === "PBKDF2") {
    const hash = normalizeHash(input.hash ?? "SHA-256");
    const iters = typeof input.iterations === "number" ? input.iterations : 100000;
    const out = kdfPbkdf2(reqHex(input.password, "password"), optHex(input.salt), iters, keylen, hash);
    return {
      ok: true,
      operation: "derive",
      algorithm: algo,
      key: toHex(out),
      length: out.length,
      params: describeParams({ hash, iterations: iters, salt: toHex(optHex(input.salt)), keylen }),
    };
  }

  if (algo === "HKDF") {
    const hash = normalizeHash(input.hash ?? "SHA-256");
    const out = kdfHkdf(reqHex(input.ikm, "ikm"), optHex(input.salt), optHex(input.info), keylen, hash);
    return {
      ok: true,
      operation: "derive",
      algorithm: algo,
      key: toHex(out),
      length: out.length,
      params: describeParams({ hash, salt: toHex(optHex(input.salt)), info: toHex(optHex(input.info)), keylen }),
    };
  }

  if (algo === "SCRYPT") {
    const n = typeof input.n === "number" ? input.n : 16384;
    const r = typeof input.r === "number" ? input.r : 8;
    const p = typeof input.p === "number" ? input.p : 1;
    const out = kdfScrypt(reqHex(input.password, "password"), optHex(input.salt), keylen, n, r, p);
    return {
      ok: true,
      operation: "derive",
      algorithm: algo,
      key: toHex(out),
      length: out.length,
      params: describeParams({ N: n, r, p, salt: toHex(optHex(input.salt)), keylen }),
    };
  }

  if (algo === "X9.63-KDF") {
    const hash = normalizeHash(input.hash ?? "SHA-256");
    const out = kdfX963(reqHex(input.data, "data"), optHex(input.info), keylen, hash);
    return {
      ok: true,
      operation: "derive",
      algorithm: algo,
      key: toHex(out),
      length: out.length,
      params: describeParams({ hash, info: toHex(optHex(input.info)), keylen }),
    };
  }

  return fail("UNSUPPORTED_ALGORITHM", `unsupported derivation: ${input.algorithm}`);
}

function doDiversify(input: any): Record<string, unknown> {
  const algo = String(input.algorithm ?? "").toUpperCase() as DiversifyAlgo;
  if (!["NXP-AES128", "AES-ECB", "3DES"].includes(algo)) {
    fail("UNSUPPORTED_ALGORITHM", `unsupported diversification: ${input.algorithm}`);
  }
  const master = reqHex(input.key, "key");
  const data = reqHex(input.data, "data");
  const out = diversify(algo, master, data);
  return {
    ok: true,
    operation: "diversify",
    algorithm: algo,
    key: toHex(out),
    length: out.length,
    // Metadata only: the master key is never echoed.
    meta: { algorithm: algo, length: out.length, input_length: data.length },
  };
}

function doWrap(input: any, unwrap: boolean): Record<string, unknown> {
  const algo = String(input.algorithm ?? "").toUpperCase();
  const kek = reqHex(input.kek, "kek");
  const op = unwrap ? "unwrap" : "wrap";

  if (algo === "AES-KW") {
    if (unwrap) {
      const out = aesKeyUnwrap(kek, reqHex(input.data, "data"));
      return { ok: true, operation: op, algorithm: algo, key: toHex(out), length: out.length };
    }
    const out = aesKeyWrap(kek, reqHex(input.data, "data"));
    return { ok: true, operation: op, algorithm: algo, wrapped: toHex(out), length: out.length };
  }

  if (algo === "AES-KWP") {
    if (unwrap) {
      const out = aesKwpUnwrap(kek, reqHex(input.data, "data"));
      return { ok: true, operation: op, algorithm: algo, key: toHex(out), length: out.length };
    }
    const out = aesKwpWrap(kek, reqHex(input.data, "data"));
    return { ok: true, operation: op, algorithm: algo, wrapped: toHex(out), length: out.length };
  }

  return fail("UNSUPPORTED_ALGORITHM", `unsupported wrap algorithm: ${input.algorithm}`);
}

function doKcv(input: any): Record<string, unknown> {
  const algo = String(input.algorithm ?? "").toUpperCase() as KcvAlgo;
  if (!["KCV-ZERO", "KCV-CMAC", "KCV-SHA256"].includes(algo)) {
    fail("UNSUPPORTED_ALGORITHM", `unsupported KCV: ${input.algorithm}`);
  }
  const key = reqHex(input.key, "key");
  const out = computeKcv(algo, key);
  return {
    ok: true,
    operation: "kcv",
    algorithm: algo,
    kcv: toHex(out),
    meta: { algorithm: algo, key_length: key.length },
  };
}

export function run(input: any): Record<string, unknown> {
  if (!input || typeof input !== "object") fail("MALFORMED_INPUT", "input must be a JSON object");
  const op = String(input.operation ?? "").toLowerCase();
  switch (op) {
    case "generate":
      return doGenerate(input);
    case "derive":
      return doDerive(input);
    case "diversify":
      return doDiversify(input);
    case "wrap":
      return doWrap(input, false);
    case "unwrap":
      return doWrap(input, true);
    case "kcv":
      return doKcv(input);
    default:
      return fail("UNSUPPORTED_OPERATION", `operation '${input.operation}' is not supported`);
  }
}

function main(): void {
  let out: Record<string, unknown>;
  try {
    out = run(readInput());
  } catch (e) {
    const err = e as Error;
    const code = e instanceof AppError ? e.code : "INTERNAL_ERROR";
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
