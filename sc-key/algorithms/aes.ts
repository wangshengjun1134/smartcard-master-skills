// aes.ts - raw block-cipher helpers backed by node:crypto ECB/CBC (no padding).
// AES-KW wrapping logic is implemented in aeskw.ts; here we only expose the
// primitive single-block operations the wrapping/KCV code needs.
import { createCipheriv, createDecipheriv } from "node:crypto";
import { AppError } from "./util.ts";

export function aesEcbEncrypt(key: Buffer, block: Buffer): Buffer {
  if (key.length !== 16 && key.length !== 24 && key.length !== 32) {
    throw new AppError("INVALID_KEY_LENGTH", "AES key must be 16/24/32 bytes");
  }
  if (block.length !== 16) {
    throw new AppError("INVALID_PARAMETER", "AES block must be 16 bytes");
  }
  const c = createCipheriv("aes-" + key.length * 8 + "-ecb", key, null);
  c.setAutoPadding(false);
  return Buffer.concat([c.update(block), c.final()]);
}

export function aesEcbDecrypt(key: Buffer, block: Buffer): Buffer {
  if (key.length !== 16 && key.length !== 24 && key.length !== 32) {
    throw new AppError("INVALID_KEY_LENGTH", "AES key must be 16/24/32 bytes");
  }
  if (block.length !== 16) {
    throw new AppError("INVALID_KEY_LENGTH", "AES block must be 16 bytes");
  }
  const d = createDecipheriv("aes-" + key.length * 8 + "-ecb", key, null);
  d.setAutoPadding(false);
  return Buffer.concat([d.update(block), d.final()]);
}

// 3DES single 8-byte block ECB. key is 16 (2-key) or 24 (3-key) bytes.
export function des3EcbEncrypt(key: Buffer, block: Buffer): Buffer {
  const algo = key.length === 24 ? "des-ede3" : key.length === 16 ? "des-ede" : null;
  if (!algo) {
    throw new AppError("INVALID_KEY_LENGTH", "3DES key must be 16 or 24 bytes");
  }
  if (block.length !== 8) {
    throw new AppError("INVALID_PARAMETER", "DES block must be 8 bytes");
  }
  const c = createCipheriv(algo, key, null);
  c.setAutoPadding(false);
  return Buffer.concat([c.update(block), c.final()]);
}

export function des3EcbDecrypt(key: Buffer, block: Buffer): Buffer {
  const algo = key.length === 24 ? "des-ede3" : key.length === 16 ? "des-ede" : null;
  if (!algo) {
    throw new AppError("INVALID_KEY_LENGTH", "3DES key must be 16 or 24 bytes");
  }
  if (block.length !== 8) {
    throw new AppError("INVALID_KEY_LENGTH", "DES block must be 8 bytes");
  }
  const d = createDecipheriv(algo, key, null);
  d.setAutoPadding(false);
  return Buffer.concat([d.update(block), d.final()]);
}

// 3DES-CBC with explicit IV (used by 3DES-KW).
export function des3CbcEncrypt(key: Buffer, iv: Buffer, data: Buffer): Buffer {
  const algo = key.length === 24 ? "des-ede3-cbc" : key.length === 16 ? "des-ede-cbc" : null;
  if (!algo) {
    throw new AppError("INVALID_KEY_LENGTH", "3DES key must be 16 or 24 bytes");
  }
  if (iv.length !== 8) {
    throw new AppError("INVALID_IV_LENGTH", "3DES IV must be 8 bytes");
  }
  const c = createCipheriv(algo, key, iv);
  c.setAutoPadding(false);
  return Buffer.concat([c.update(data), c.final()]);
}

export function des3CbcDecrypt(key: Buffer, iv: Buffer, data: Buffer): Buffer {
  const algo = key.length === 24 ? "des-ede3-cbc" : key.length === 16 ? "des-ede-cbc" : null;
  if (!algo) {
    throw new AppError("INVALID_KEY_LENGTH", "3DES key must be 16 or 24 bytes");
  }
  if (iv.length !== 8) {
    throw new AppError("INVALID_IV_LENGTH", "3DES IV must be 8 bytes");
  }
  const d = createDecipheriv(algo, key, iv);
  d.setAutoPadding(false);
  return Buffer.concat([d.update(data), d.final()]);
}
