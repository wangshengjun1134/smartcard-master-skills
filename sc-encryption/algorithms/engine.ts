// Core dispatch for sc-encryption.
import { createCipheriv, createDecipheriv } from "node:crypto";
import { fail } from "./errors.ts";
import { hexToBytes, bytesToHex } from "./hex.ts";
import { pad, unpad } from "./padding.ts";
import type { PaddingScheme } from "./padding.ts";
import { sm4Ecb, sm4Cbc, sm4Ctr } from "./sm4.ts";

type Family = "aes" | "3des" | "sm4";
interface AlgInfo {
  blockSize: number;
  keyLen: number;
  family: Family;
}

const ALLOWED_PADDING = ["none", "pkcs7", "iso7816-4", "iso9797-1-m1", "iso9797-1-m2"];

function algInfo(algorithm: string): AlgInfo {
  switch (algorithm) {
    case "AES-128":
      return { blockSize: 16, keyLen: 16, family: "aes" };
    case "AES-192":
      return { blockSize: 16, keyLen: 24, family: "aes" };
    case "AES-256":
      return { blockSize: 16, keyLen: 32, family: "aes" };
    case "3DES":
      return { blockSize: 8, keyLen: 24, family: "3des" };
    case "3DES-2KEY":
      return { blockSize: 8, keyLen: 16, family: "3des" };
    case "SM4":
      return { blockSize: 16, keyLen: 16, family: "sm4" };
    default:
      fail("UNSUPPORTED_ALGORITHM", `unsupported algorithm: ${algorithm}`);
  }
}

function reqStr(input: Record<string, unknown>, field: string): string {
  const v = input[field];
  if (typeof v !== "string") fail("MISSING_PARAMETER", `missing or non-string field: ${field}`);
  return v;
}

function optStr(input: Record<string, unknown>, field: string): string | undefined {
  const v = input[field];
  if (v === undefined || v === null) return undefined;
  if (typeof v !== "string") fail("INVALID_PARAMETER", `field ${field} must be a string`);
  return v;
}

function validatePadding(v: unknown): PaddingScheme {
  if (typeof v !== "string" || !ALLOWED_PADDING.includes(v)) {
    fail("INVALID_PARAMETER", `invalid padding scheme: ${String(v)}`);
  }
  return v as PaddingScheme;
}

function expand3des2key(k: Uint8Array): Uint8Array {
  const out = new Uint8Array(24);
  out.set(k.subarray(0, 8), 0);
  out.set(k.subarray(8, 16), 8);
  out.set(k.subarray(0, 8), 16);
  return out;
}

export function run(input: unknown): Record<string, unknown> {
  if (typeof input !== "object" || input === null || Array.isArray(input)) {
    fail("MALFORMED_INPUT", "input must be a JSON object");
  }
  const req = input as Record<string, unknown>;

  const operation = reqStr(req, "operation");
  const algorithm = reqStr(req, "algorithm");
  const mode = reqStr(req, "mode");
  const dataHex = reqStr(req, "data");
  const keyHex = reqStr(req, "key");

  if (operation !== "encrypt" && operation !== "decrypt") {
    fail("INVALID_OPERATION", `operation must be encrypt or decrypt, got: ${operation}`);
  }

  const info = algInfo(algorithm);
  const key = hexToBytes(keyHex);
  if (key.length !== info.keyLen) {
    fail("INVALID_KEY_LENGTH", `key length must be ${info.keyLen} bytes for ${algorithm}, got ${key.length}`);
  }
  const keyBytes = algorithm === "3DES-2KEY" ? expand3des2key(key) : key;

  // ---- mode support matrix ----
  const isGcm = mode === "GCM";
  if (!["ECB", "CBC", "CTR", "GCM"].includes(mode)) {
    fail("UNSUPPORTED_MODE", `unsupported mode: ${mode}`);
  }
  if (isGcm && info.family !== "aes") {
    fail("UNSUPPORTED_MODE", "GCM is only supported for AES");
  }
  if (mode === "CTR" && info.family === "3des") {
    fail("UNSUPPORTED_MODE", "3DES-CTR is not available (node:crypto has no des-ede3-ctr); cannot support");
  }

  // ---- padding resolution ----
  const isStreamOrAead = mode === "CTR" || isGcm;
  let padding: PaddingScheme = "none";
  const padRaw = req["padding"];
  if (isStreamOrAead) {
    if (padRaw !== undefined && padRaw !== null) {
      fail("INVALID_PARAMETER", "padding is not accepted for CTR/GCM modes");
    }
  } else {
    if (padRaw === undefined || padRaw === null) {
      padding = "pkcs7";
    } else {
      padding = validatePadding(padRaw);
    }
  }

  // ---- IV / nonce / aad / tag ----
  let iv: Uint8Array | null = null;
  if (mode === "CBC" || mode === "CTR") {
    const ivHex = optStr(req, "iv");
    if (ivHex === undefined) fail("MISSING_PARAMETER", `iv is required for ${mode}`);
    iv = hexToBytes(ivHex);
    if (iv.length !== info.blockSize) {
      fail("INVALID_PARAMETER", `iv length must be ${info.blockSize} bytes for ${algorithm}`);
    }
  }

  let nonce: Uint8Array | null = null;
  let aad = new Uint8Array(0);
  let tag: Uint8Array | null = null;
  let tagLength = 16;
  if (isGcm) {
    const nonceHex = optStr(req, "nonce");
    if (nonceHex === undefined) fail("MISSING_PARAMETER", "nonce is required for GCM");
    nonce = hexToBytes(nonceHex);
    if (req["aad"] !== undefined) aad = hexToBytes(optStr(req, "aad") as string);
    if (operation === "decrypt") {
      const tagHex = optStr(req, "tag");
      if (tagHex === undefined) fail("MISSING_PARAMETER", "tag is required for GCM decrypt");
      tag = hexToBytes(tagHex);
    } else if (req["tag_length"] !== undefined) {
      tagLength = Number(req["tag_length"]);
      if (!Number.isInteger(tagLength) || tagLength < 4 || tagLength > 16) {
        fail("INVALID_PARAMETER", "tag_length must be an integer 4..16");
      }
    }
  }

  const data = hexToBytes(dataHex);

  // ---- dispatch ----
  if (isGcm) {
    return runGcm(operation, algorithm, mode, info, keyBytes, nonce as Uint8Array, aad, tag as Uint8Array | null, tagLength, data);
  }

  if (info.family === "sm4") {
    return runSm4(operation, algorithm, mode, keyBytes, iv as Uint8Array, padding, info.blockSize, data);
  }

  return runNodeBlock(operation, algorithm, mode, info, keyBytes, iv, padding, data);
}

function runGcm(
  operation: string,
  algorithm: string,
  mode: string,
  info: AlgInfo,
  keyBytes: Uint8Array,
  nonce: Uint8Array,
  aad: Uint8Array,
  tag: Uint8Array | null,
  tagLength: number,
  data: Uint8Array,
): Record<string, unknown> {
  const bits = info.keyLen * 8;
  const name = `aes-${bits}-gcm`;
  if (operation === "encrypt") {
    const c = createCipheriv(name, keyBytes, nonce, { authTagLength: tagLength });
    if (aad.length) c.setAAD(aad);
    const ct = Buffer.concat([c.update(data), c.final()]);
    const t = c.getAuthTag();
    return { algorithm, mode, ciphertext: bytesToHex(ct), nonce: bytesToHex(nonce), tag: bytesToHex(t) };
  }
  const d = createDecipheriv(name, keyBytes, nonce, { authTagLength: (tag as Uint8Array).length });
  if (aad.length) d.setAAD(aad);
  d.setAuthTag(tag as Uint8Array);
  try {
    const pt = Buffer.concat([d.update(data), d.final()]);
    return { algorithm, mode, plaintext: bytesToHex(pt) };
  } catch {
    fail("AUTHENTICATION_FAILED", "GCM tag verification failed");
  }
}

function runSm4(
  operation: string,
  algorithm: string,
  mode: string,
  keyBytes: Uint8Array,
  iv: Uint8Array,
  padding: PaddingScheme,
  blockSize: number,
  data: Uint8Array,
): Record<string, unknown> {
  if (operation === "encrypt") {
    let pt = data;
    if (padding !== "none") {
      pt = pad(data, blockSize, padding);
    } else if (mode !== "CTR" && data.length % blockSize !== 0) {
      fail("INVALID_PARAMETER", "data must be a multiple of block size when padding=none");
    }
    let ct: Uint8Array;
    if (mode === "ECB") ct = sm4Ecb(pt, keyBytes, true);
    else if (mode === "CBC") ct = sm4Cbc(pt, keyBytes, iv, true);
    else ct = sm4Ctr(pt, keyBytes, iv);
    const out: Record<string, unknown> = { algorithm, mode, ciphertext: bytesToHex(ct) };
    if (mode !== "ECB") out.iv = bytesToHex(iv);
    return out;
  }
  let pt: Uint8Array;
  if (mode === "ECB") pt = sm4Ecb(data, keyBytes, false);
  else if (mode === "CBC") pt = sm4Cbc(data, keyBytes, iv, false);
  else pt = sm4Ctr(data, keyBytes, iv);
  if (padding !== "none") pt = unpad(pt, blockSize, padding);
  return { algorithm, mode, plaintext: bytesToHex(pt) };
}

function runNodeBlock(
  operation: string,
  algorithm: string,
  mode: string,
  info: AlgInfo,
  keyBytes: Uint8Array,
  iv: Uint8Array | null,
  padding: PaddingScheme,
  data: Uint8Array,
): Record<string, unknown> {
  const base = info.family === "aes" ? `aes-${info.keyLen * 8}` : "des-ede3";
  const name = `${base}-${mode.toLowerCase()}`;
  // CTR is a stream mode: it never needs block-aligned input.
  const needsAlignment = mode !== "CTR";
  if (operation === "encrypt") {
    let pt = data;
    if (padding !== "none") {
      pt = pad(data, info.blockSize, padding);
    } else if (needsAlignment && data.length % info.blockSize !== 0) {
      fail("INVALID_PARAMETER", "data must be a multiple of block size when padding=none");
    }
    const c = createCipheriv(name, keyBytes, mode === "ECB" ? null : iv);
    c.setAutoPadding(false);
    const ct = Buffer.concat([c.update(pt), c.final()]);
    const out: Record<string, unknown> = { algorithm, mode, ciphertext: bytesToHex(ct) };
    if (iv) out.iv = bytesToHex(iv);
    return out;
  }
  const d = createDecipheriv(name, keyBytes, mode === "ECB" ? null : iv);
  d.setAutoPadding(false);
  const dec = Buffer.concat([d.update(data), d.final()]);
  let pt: Uint8Array = dec;
  if (padding !== "none") pt = unpad(dec, info.blockSize, padding);
  return { algorithm, mode, plaintext: bytesToHex(pt) };
}
