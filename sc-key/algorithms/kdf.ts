// Key derivation functions for sc-key (self-contained).
// PBKDF2 / HKDF / scrypt delegate to node:crypto; X9.63-KDF is implemented here.

import { pbkdf2Sync, hkdfSync, scryptSync, createHash } from "node:crypto";
import { sm3 } from "./sm3.ts";
import { AppError } from "./util.ts";

export type HashName = "SHA-1" | "SHA-224" | "SHA-256" | "SHA-384" | "SHA-512" | "SM3";

const NODE_HASH: Record<Exclude<HashName, "SM3">, string> = {
  "SHA-1": "sha1",
  "SHA-224": "sha224",
  "SHA-256": "sha256",
  "SHA-384": "sha384",
  "SHA-512": "sha512",
};

export function isHashName(v: unknown): v is HashName {
  return typeof v === "string" && (v in NODE_HASH || v.toUpperCase() === "SM3");
}

export function normalizeHash(v: unknown): HashName {
  if (typeof v !== "string") throw new AppError("MISSING_PARAMETER", "hash is required");
  const u = v.toUpperCase();
  if (u in NODE_HASH) return u as HashName;
  if (u === "SM3") return "SM3";
  throw new AppError("UNSUPPORTED_ALGORITHM", `unsupported hash: ${v}`);
}

function digestOne(hash: HashName, data: Buffer): Buffer {
  if (hash === "SM3") return sm3(data);
  return createHash(NODE_HASH[hash]).update(data).digest();
}

export function hashLength(hash: HashName): number {
  return digestOne(hash, Buffer.alloc(0)).length;
}

// ---------- PBKDF2 ----------
export function kdfPbkdf2(
  password: Buffer,
  salt: Buffer,
  iterations: number,
  keylen: number,
  hash: HashName,
): Buffer {
  if (hash === "SM3") {
    throw new AppError("UNSUPPORTED_ALGORITHM", "PBKDF2 with SM3 is not supported by node:crypto");
  }
  if (!Number.isInteger(iterations) || iterations < 1) {
    throw new AppError("INVALID_PARAMETER", "iterations must be a positive integer");
  }
  return pbkdf2Sync(password, salt, iterations, keylen, NODE_HASH[hash]);
}

// ---------- HKDF (RFC 5869) ----------
export function kdfHkdf(
  ikm: Buffer,
  salt: Buffer,
  info: Buffer,
  keylen: number,
  hash: HashName,
): Buffer {
  if (hash === "SM3") {
    // HKDF-Extract/Expand driven by self-implemented SM3.
    return hkdfSm3(ikm, salt, info, keylen);
  }
  return Buffer.from(hkdfSync(NODE_HASH[hash], ikm, salt, info, keylen));
}

function hkdfSm3(ikm: Buffer, salt: Buffer, info: Buffer, keylen: number): Buffer {
  const hLen = hashLength("SM3");
  if (keylen > 255 * hLen) {
    throw new AppError("INVALID_PARAMETER", "keylen too large for HKDF-SM3");
  }
  // Extract: prk = HMAC-SM3(salt, ikm)
  const prk = hmacSm3(salt.length ? salt : Buffer.alloc(hLen), ikm);
  // Expand
  const out: Buffer[] = [];
  let t = Buffer.alloc(0);
  let produced = 0;
  let counter = 1;
  while (produced < keylen) {
    t = hmacSm3(prk, Buffer.concat([t, info, Buffer.from([counter])]));
    out.push(t);
    produced += t.length;
    counter++;
  }
  return Buffer.concat(out).subarray(0, keylen);
}

function hmacSm3(key: Buffer, data: Buffer): Buffer {
  const B = 64;
  let k: Buffer = key;
  if (k.length > B) k = sm3(k);
  if (k.length < B) k = Buffer.concat([k, Buffer.alloc(B - k.length)]);
  const ipad = Buffer.alloc(B);
  const opad = Buffer.alloc(B);
  for (let i = 0; i < B; i++) {
    ipad[i] = k[i] ^ 0x36;
    opad[i] = k[i] ^ 0x5c;
  }
  return sm3(Buffer.concat([opad, sm3(Buffer.concat([ipad, data]))]));
}

// ---------- scrypt ----------
export function kdfScrypt(
  password: Buffer,
  salt: Buffer,
  keylen: number,
  n: number,
  r: number,
  p: number,
): Buffer {
  return scryptSync(password, salt, keylen, { N: n, r, p });
}

// ---------- X9.63 KDF (ANSI X9.63 / SEC 1 style counter KDF) ----------
// K = H(shared || counter32 || sharedInfo) concatenated until keylen bytes.
export function kdfX963(
  shared: Buffer,
  sharedInfo: Buffer,
  keylen: number,
  hash: HashName,
): Buffer {
  const hLen = hashLength(hash);
  const blocks = Math.ceil(keylen / hLen);
  if (blocks > 255) throw new AppError("INVALID_PARAMETER", "keylen too large for X9.63 KDF");
  const out: Buffer[] = [];
  for (let i = 1; i <= blocks; i++) {
    const counter = Buffer.from([0, 0, 0, i]);
    out.push(digestOne(hash, Buffer.concat([shared, counter, sharedInfo])));
  }
  return Buffer.concat(out).subarray(0, keylen);
}

// Describe the parameters used for a derivation, for audit logging.
export function describeParams(obj: Record<string, unknown>): Record<string, unknown> {
  return JSON.parse(JSON.stringify(obj));
}
