// Key diversification and key check values for sc-key (self-contained).
//
// Diversification algorithms are implemented EXPLICITLY here: each function
// states the construction it implements. Nothing is inferred.

import { createHash } from "node:crypto";
import { aesCmac } from "./cmac.ts";
import { aesEcbEncrypt, des3EcbEncrypt } from "./aes.ts";
import { adjustParity } from "./util.ts";
import { AppError } from "./util.ts";

// ---------- diversification ----------

// NXP / MIFARE DESFire style AES-128 diversification.
// Construction: T = AES-CMAC(masterKey, diversificationInput) then the derived
// key is assembled from two CMAC blocks over the input, concatenated and
// (for 16-byte keys) taken as the first 16 bytes. This is the widely used
// "AN10922-style" full-key diversification.
export function diversifyNxpAes128(masterKey: Buffer, input: Buffer): Buffer {
  if (masterKey.length !== 16) {
    throw new AppError("INVALID_KEY_LENGTH", "NXP-AES128 diversification needs a 16-byte master key");
  }
  if (input.length === 0) {
    throw new AppError("MISSING_PARAMETER", "diversification input is required");
  }
  const b1 = aesCmac(masterKey, Buffer.concat([Buffer.from([0x01]), input]));
  const b2 = aesCmac(masterKey, Buffer.concat([Buffer.from([0x02]), input]));
  return Buffer.concat([b1, b2]).subarray(0, 16);
}

// Simple, explicit AES-based diversification: AES-ECB(masterKey, inputBlock).
// `input` must be exactly one AES block (16 bytes).
export function diversifyAesEcb(masterKey: Buffer, input: Buffer): Buffer {
  if (masterKey.length !== 16 && masterKey.length !== 24 && masterKey.length !== 32) {
    throw new AppError("INVALID_KEY_LENGTH", "AES key must be 16/24/32 bytes");
  }
  if (input.length !== 16) {
    throw new AppError("INVALID_PARAMETER", "AES-ECB diversification input must be exactly 16 bytes");
  }
  return aesEcbEncrypt(masterKey, input);
}

// PC/SC-style 3DES diversification used by many payment schemes:
// left half  = 3DES-ECB(masterKey, input)
// right half = 3DES-ECB(masterKey, NOT(input))
// then DES parity bits are adjusted.
export function diversify3Des(masterKey: Buffer, input: Buffer): Buffer {
  if (input.length !== 8) {
    throw new AppError("INVALID_PARAMETER", "3DES diversification input must be exactly 8 bytes");
  }
  const inv = Buffer.from(input);
  for (let i = 0; i < inv.length; i++) inv[i] = ~inv[i] & 0xff;
  const left = des3EcbEncrypt(masterKey, input);
  const right = des3EcbEncrypt(masterKey, inv);
  return adjustParity(Buffer.concat([left, right]));
}

export type DiversifyAlgo = "NXP-AES128" | "AES-ECB" | "3DES";

export function diversify(algo: DiversifyAlgo, masterKey: Buffer, input: Buffer): Buffer {
  switch (algo) {
    case "NXP-AES128":
      return diversifyNxpAes128(masterKey, input);
    case "AES-ECB":
      return diversifyAesEcb(masterKey, input);
    case "3DES":
      return diversify3Des(masterKey, input);
  }
  throw new AppError("UNSUPPORTED_ALGORITHM", `unsupported diversification: ${algo}`);
}

// ---------- key check value ----------

// KCV-ZERO: encrypt a block of zeroes and take the first 3 bytes.
export function kcvZero(key: Buffer): Buffer {
  const block = Buffer.alloc(key.length >= 24 ? 8 : 16);
  const enc = key.length === 16 || key.length === 24 || key.length === 32
    ? aesEcbEncrypt(key, Buffer.alloc(16))
    : des3EcbEncrypt(key, block);
  return enc.subarray(0, 3);
}

// KCV-CMAC: AES-CMAC over 16 zero bytes, take the first 3 bytes (EMV style).
export function kcvCmac(key: Buffer): Buffer {
  if (key.length !== 16 && key.length !== 24 && key.length !== 32) {
    throw new AppError("INVALID_KEY_LENGTH", "KCV-CMAC requires an AES key (16/24/32 bytes)");
  }
  return aesCmac(key, Buffer.alloc(16)).subarray(0, 3);
}

// KCV-SHA256: first 3 bytes of SHA-256 over the key bytes.
// NOTE: this reveals a hash of the key; only use it where the scheme mandates it.
export function kcvSha256(key: Buffer): Buffer {
  return createHash("sha256").update(key).digest().subarray(0, 3);
}

export type KcvAlgo = "KCV-ZERO" | "KCV-CMAC" | "KCV-SHA256";

export function computeKcv(algo: KcvAlgo, key: Buffer): Buffer {
  switch (algo) {
    case "KCV-ZERO":
      return kcvZero(key);
    case "KCV-CMAC":
      return kcvCmac(key);
    case "KCV-SHA256":
      return kcvSha256(key);
  }
  throw new AppError("UNSUPPORTED_ALGORITHM", `unsupported KCV: ${algo}`);
}
