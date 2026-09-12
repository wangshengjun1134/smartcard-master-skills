// Block cipher primitives used by CMAC / ISO9797 / 3DES-MAC / SM4-MAC.
// AES and 3DES use node:crypto ECB (single block, no padding). SM4 is self-implemented.

import { createCipheriv, createDecipheriv } from "node:crypto";
import { sm4EncryptBlock, sm4KeyExpand } from "./sm4.ts";
import { Des } from "./des.ts";
import { SkillError } from "./errors.ts";

export interface BlockCipher {
  blockSize: number; // bytes
  encryptBlock(block: Uint8Array): Uint8Array;
  decryptBlock(block: Uint8Array): Uint8Array;
}

// NOTE: `createCipheriv` ignores the {noPadding:true} option for ECB - padding
// stays ON and final() would emit an extra block. setAutoPadding(false) is the
// only reliable way to get raw single-block ECB.
function ecbOnce(algo: string, key: Uint8Array, block: Uint8Array): Uint8Array {
  const c = createCipheriv(algo, Buffer.from(key), null);
  c.setAutoPadding(false);
  const out = Buffer.concat([c.update(Buffer.from(block)), c.final()]);
  return new Uint8Array(out);
}

function ecbDecOnce(algo: string, key: Uint8Array, block: Uint8Array): Uint8Array {
  const c = createDecipheriv(algo, Buffer.from(key), null);
  c.setAutoPadding(false);
  const out = Buffer.concat([c.update(Buffer.from(block)), c.final()]);
  return new Uint8Array(out);
}

export function aesCipher(key: Uint8Array): BlockCipher {
  const n = key.length;
  const algo =
    n === 16 ? "aes-128-ecb" : n === 24 ? "aes-192-ecb" : n === 32 ? "aes-256-ecb" : "";
  if (!algo) throw new SkillError("INVALID_KEY_LENGTH", "AES key must be 16/24/32 bytes");
  return {
    blockSize: 16,
    encryptBlock: (b) => ecbOnce(algo, key, b),
    decryptBlock: (b) => ecbDecOnce(algo, key, b),
  };
}

// 3DES accepts 24-byte (K1||K2||K3) or 16-byte two-key (K1||K2||K1) keys.
// Two-key 3DES is common in smart cards, so it is expanded to 24 bytes here.
function expandDes3Key(key: Uint8Array): Buffer {
  if (key.length === 24) return Buffer.from(key);
  if (key.length === 16) return Buffer.concat([Buffer.from(key), Buffer.from(key.subarray(0, 8))]);
  throw new SkillError("INVALID_KEY_LENGTH", "3DES key must be 16 or 24 bytes");
}

function desAlgoFor(key: Uint8Array): { algo: string; k: Buffer } {
  if (key.length === 24) return { algo: "des-ede3-ecb", k: Buffer.from(key) };
  if (key.length === 16) return { algo: "des-ede-ecb", k: Buffer.from(key) }; // 2-key EDE
  throw new SkillError("INVALID_KEY_LENGTH", "3DES key must be 16 or 24 bytes");
}

export function des3Cipher(key: Uint8Array): BlockCipher {
  const { algo, k } = desAlgoFor(key);
  return {
    blockSize: 8,
    encryptBlock: (b) => ecbOnce(algo, k, b),
    decryptBlock: (b) => ecbDecOnce(algo, k, b),
  };
}

export function sm4BlockCipher(key: Uint8Array): BlockCipher {
  if (key.length !== 16) throw new SkillError("INVALID_KEY_LENGTH", "SM4 key must be 16 bytes");
  const rk = sm4KeyExpand(key);
  const rr = [...rk].reverse(); // SM4 decryption reuses the round keys in reverse order
  return {
    blockSize: 16,
    encryptBlock: (b) => sm4EncryptBlock(b, rk),
    decryptBlock: (b) => sm4EncryptBlock(b, rr),
  };
}

export function desBlockCipher(key: Uint8Array): BlockCipher {
  if (key.length !== 8) throw new SkillError("INVALID_KEY_LENGTH", "DES key must be 8 bytes");
  const d = new Des(key);
  return {
    blockSize: 8,
    encryptBlock: (b) => d.encryptBlock(b),
    decryptBlock: (b) => d.decryptBlock(b),
  };
}

export type CipherName = "AES" | "DES" | "3DES" | "SM4";

export function makeCipher(cipher: string, key: Uint8Array): BlockCipher {
  switch (cipher) {
    case "AES":
      return aesCipher(key);
    case "DES":
      return desBlockCipher(key);
    case "3DES":
      return des3Cipher(key);
    case "SM4":
      return sm4BlockCipher(key);
    default:
      throw new SkillError("UNSUPPORTED_CIPHER", `unsupported cipher: ${cipher}`);
  }
}
