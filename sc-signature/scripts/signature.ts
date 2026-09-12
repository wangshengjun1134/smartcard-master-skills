// sc-signature CLI entry. Single JSON-out contract; stdout is JSON only.
// Dispatch: sign / verify / generate across RSA, RSA-PSS, ECDSA, SM2, EdDSA.

import fs from "node:fs";
import { pathToFileURL } from "node:url";
import { CryptoError, hexToBuf, bufToHex, bigToFixedBuf } from "../algorithms/common.ts";
import { decodeSm2Signature, encodeSm2Signature } from "../algorithms/der.ts";
import * as rsa from "../algorithms/rsa.ts";
import * as ecdsa from "../algorithms/ecdsa.ts";
import * as eddsa from "../algorithms/eddsa.ts";
import {
  sm2Sign,
  sm2Verify,
  sm2Generate,
  parseSm2PrivateKey,
  parseSm2PublicKey,
  parseSm2Id,
} from "../algorithms/sm2.ts";

type Input = Record<string, any>;

// Canonical display name for each normalised (upper-case) algorithm id.
const DISPLAY_NAME: Record<string, string> = {
  RSA: "RSA",
  "RSA-PSS": "RSA-PSS",
  ECDSA: "ECDSA",
  SM2: "SM2",
  EDDSA: "EdDSA",
};

function validateBasic(input: Input): void {
  if (!input || typeof input !== "object") {
    throw new CryptoError("MALFORMED_INPUT", "input must be a JSON object");
  }
  if (!input.operation) throw new CryptoError("MISSING_PARAMETER", "operation is required");
  if (!input.algorithm) throw new CryptoError("MISSING_PARAMETER", "algorithm is required");
  if (!["sign", "verify", "generate"].includes(input.operation)) {
    throw new CryptoError("UNSUPPORTED_OPERATION", `unsupported operation: ${input.operation}`);
  }
}

function encOf(input: Input): "der" | "raw" {
  const enc = (input.signature_encoding ?? "der").toLowerCase();
  if (enc !== "der" && enc !== "raw") {
    throw new CryptoError("INVALID_PARAMETER", "signature_encoding must be der or raw");
  }
  return enc as "der" | "raw";
}

function doSign(algo: string, input: Input): any {
  if (!input.data) throw new CryptoError("MISSING_PARAMETER", "data is required");
  const data = hexToBuf(input.data);

  if (algo === "SM2") {
    if (input.hash && input.hash.toUpperCase() !== "SM3") {
      throw new CryptoError("INVALID_PARAMETER", "SM2 only uses SM3 digest");
    }
    if (!input.private_key) throw new CryptoError("MISSING_PARAMETER", "private_key is required");
    const d = parseSm2PrivateKey(input.private_key);
    const idBytes = parseSm2Id(input.sm2_id);
    const enc = encOf(input);
    const { r, s } = sm2Sign(d, data, idBytes);
    const signature =
      enc === "raw"
        ? bufToHex(Buffer.concat([bigToFixedBuf(r, 32), bigToFixedBuf(s, 32)]))
        : bufToHex(encodeSm2Signature(r, s));
    return { ok: true, algorithm: "SM2", signature, signature_encoding: enc };
  }

  if (algo === "EDDSA") {
    if (input.hash) throw new CryptoError("INVALID_PARAMETER", "EdDSA does not accept a hash parameter");
    if (!input.private_key) throw new CryptoError("MISSING_PARAMETER", "private_key is required");
    const res = eddsa.eddsaSign(input.private_key, data);
    return { ok: true, algorithm: "EdDSA", signature: res.signature };
  }

  if (algo === "RSA" || algo === "RSA-PSS") {
    if (!input.hash) throw new CryptoError("MISSING_PARAMETER", "hash is required for " + algo);
    if (!input.private_key) throw new CryptoError("MISSING_PARAMETER", "private_key is required");
    const sig = rsa.rsaSign(algo, input.private_key, data, input.hash, input.salt_length);
    return { ok: true, algorithm: algo, signature: bufToHex(sig) };
  }

  if (algo === "ECDSA") {
    if (!input.hash) throw new CryptoError("MISSING_PARAMETER", "hash is required for ECDSA");
    if (!input.private_key) throw new CryptoError("MISSING_PARAMETER", "private_key is required");
    const res = ecdsa.ecdsaSign(input.private_key, data, input.hash, input.curve, encOf(input));
    return { ok: true, algorithm: "ECDSA", signature: res.signature, signature_encoding: res.encoding };
  }

  throw new CryptoError("UNSUPPORTED_ALGORITHM", algo);
}

function doVerify(algo: string, input: Input): any {
  if (!input.data) throw new CryptoError("MISSING_PARAMETER", "data is required");
  if (!input.signature) throw new CryptoError("MISSING_PARAMETER", "signature is required");
  const data = hexToBuf(input.data);
  const sig = hexToBuf(input.signature);

  if (algo === "SM2") {
    if (input.hash && input.hash.toUpperCase() !== "SM3") {
      throw new CryptoError("INVALID_PARAMETER", "SM2 only uses SM3 digest");
    }
    if (!input.public_key) throw new CryptoError("MISSING_PARAMETER", "public_key is required");
    const pub = parseSm2PublicKey(input.public_key);
    const idBytes = parseSm2Id(input.sm2_id);
    const enc = encOf(input);
    let r: bigint, s: bigint;
    if (enc === "raw") {
      const half = sig.length / 2;
      if (half !== 32) throw new CryptoError("INVALID_SIGNATURE", "raw SM2 signature must be 64 bytes");
      r = 0n;
      s = 0n;
      for (const bt of sig.subarray(0, half)) r = (r << 8n) | BigInt(bt);
      for (const bt of sig.subarray(half)) s = (s << 8n) | BigInt(bt);
    } else {
      const ds = decodeSm2Signature(sig);
      r = ds.r;
      s = ds.s;
    }
    if (!sm2Verify(pub, data, idBytes, r, s)) {
      throw new CryptoError("SIGNATURE_INVALID", "SM2 signature verification failed");
    }
    return { ok: true, valid: true };
  }

  if (algo === "EDDSA") {
    if (input.hash) throw new CryptoError("INVALID_PARAMETER", "EdDSA does not accept a hash parameter");
    if (!input.public_key) throw new CryptoError("MISSING_PARAMETER", "public_key is required");
    if (!eddsa.eddsaVerify(input.public_key, data, sig)) {
      throw new CryptoError("SIGNATURE_INVALID", "EdDSA signature verification failed");
    }
    return { ok: true, valid: true };
  }

  if (algo === "RSA" || algo === "RSA-PSS") {
    if (!input.hash) throw new CryptoError("MISSING_PARAMETER", "hash is required for " + algo);
    if (!input.public_key) throw new CryptoError("MISSING_PARAMETER", "public_key is required");
    if (!rsa.rsaVerify(algo, input.public_key, data, input.hash, sig, input.salt_length)) {
      throw new CryptoError("SIGNATURE_INVALID", "RSA signature verification failed");
    }
    return { ok: true, valid: true };
  }

  if (algo === "ECDSA") {
    if (!input.hash) throw new CryptoError("MISSING_PARAMETER", "hash is required for ECDSA");
    if (!input.public_key) throw new CryptoError("MISSING_PARAMETER", "public_key is required");
    const ok = ecdsa.ecdsaVerify(
      input.public_key,
      data,
      input.hash,
      input.signature,
      input.curve,
      encOf(input),
    );
    if (!ok) throw new CryptoError("SIGNATURE_INVALID", "ECDSA signature verification failed");
    return { ok: true, valid: true };
  }

  throw new CryptoError("UNSUPPORTED_ALGORITHM", algo);
}

function doGenerate(algo: string, input: Input): any {
  // All generators return camelCase PEM fields; expose them as snake_case
  // so the output matches the input field naming.
  const norm = (r: { publicKeyPem: string; privateKeyPem: string }) => ({
    ok: true,
    algorithm: DISPLAY_NAME[algo] ?? algo,
    public_key: r.publicKeyPem,
    private_key: r.privateKeyPem,
  });
  if (algo === "SM2") return norm(sm2Generate());
  if (algo === "EDDSA") return norm(eddsa.eddsaGenerate(input.curve));
  if (algo === "RSA" || algo === "RSA-PSS") return norm(rsa.rsaGenerate());
  if (algo === "ECDSA") return norm(ecdsa.ecdsaGenerate(input.curve));
  throw new CryptoError("UNSUPPORTED_ALGORITHM", algo);
}

export function handle(input: Input): any {
  try {
    validateBasic(input);
    const op = input.operation;
    const algo = String(input.algorithm).toUpperCase();
    if (op === "generate") return doGenerate(algo, input);
    if (op === "sign") return doSign(algo, input);
    if (op === "verify") return doVerify(algo, input);
    throw new CryptoError("UNSUPPORTED_OPERATION", op);
  } catch (e) {
    if (e instanceof CryptoError) return { ok: false, error: { code: e.code, message: e.message } };
    return { ok: false, error: { code: "INTERNAL_ERROR", message: "unexpected error" } };
  }
}

function readInput(): Input {
  const argv = process.argv.slice(2);
  let json: string | undefined;
  for (let i = 0; i < argv.length; i++) {
    if (argv[i] === "--input") {
      json = argv[i + 1];
      i++;
    } else if (argv[i] === "--input-file") {
      json = fs.readFileSync(argv[i + 1], "utf8");
      i++;
    }
  }
  if (json === undefined) {
    if (process.stdin.isTTY) throw new CryptoError("MALFORMED_INPUT", "no input provided");
    try {
      json = fs.readFileSync(0, "utf8");
    } catch {
      json = undefined;
    }
  }
  if (json === undefined || json.trim() === "") {
    throw new CryptoError("MALFORMED_INPUT", "no input provided");
  }
  try {
    return JSON.parse(json) as Input;
  } catch {
    throw new CryptoError("MALFORMED_INPUT", "input is not valid JSON");
  }
}

function main(): void {
  const result = handle(readInput());
  // exitCode (not process.exit) lets buffered stdout flush on pipes.
  process.exitCode = result.ok ? 0 : 1;
  process.stdout.write(JSON.stringify(result) + "\n");
}

// Only run as the entry script. pathToFileURL normalises Windows drive
// letters and backslashes so the comparison works on every platform.
if (import.meta.url === pathToFileURL(process.argv[1]).href) {
  main();
}
