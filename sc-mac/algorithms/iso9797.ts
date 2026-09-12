// ISO/IEC 9797-1 constructions over a block cipher (AES / 3DES / SM4).
//
// IMPORTANT: ISO/IEC 9797-1 defines TWO orthogonal dimensions:
//   * Padding Method 1/2/3  - how the data is padded before CBC-MAC
//   * MAC Algorithm 1..6    - how the chaining value is turned into a MAC
//
// The `ISO9797-1-Mn-MAC` names below refer to MAC Algorithm 1 (plain CBC-MAC)
// combined with Padding Method n, which is how the "M1/M2/M3" naming is
// commonly used in the smart-card / payment industry.
//
// Padding Method 1 (M1): right-pad with 0x00 up to a block multiple.
//   If the data is empty, pad with one FULL zero block (ISO/IEC 9797-1 note).
// Padding Method 2 (M2): append a single '1' bit (0x80 byte) then 0x00 up to
//   a block multiple. Always adds at least one byte.
// Padding Method 3 (M3): apply Padding Method 1, then LEFT-prepend a block
//   holding the bit length of the UNPADDED data (right-aligned in the block).
//
// `retailMac` implements MAC Algorithm 3 (a.k.a. Retail MAC / ANSI X9.19):
//   H   = CBC-MAC over the padded data using K
//   MAC = E_K( D_K'(H) )        (output transformation 3)
// K and K' are two independent keys; see `retailMac` for the accepted layouts.

import { makeCipher, type BlockCipher, type CipherName } from "./blockciphers.ts";
import { cbcMac } from "./cbc.ts";
import { SkillError } from "./errors.ts";

export type IsoMethod = 1 | 2 | 3;

/** Padding Method 1. Empty input becomes one full zero block (per the standard). */
export function isoPad1(data: Uint8Array, blockSize: number): Uint8Array {
  if (data.length === 0) return new Uint8Array(blockSize);
  const rem = data.length % blockSize;
  if (rem === 0) return data;
  const p = new Uint8Array(data.length + (blockSize - rem));
  p.set(data);
  return p;
}

/** Padding Method 2: 0x80 followed by 0x00 up to the block boundary. */
export function isoPad2(data: Uint8Array, blockSize: number): Uint8Array {
  const rem = data.length % blockSize;
  const padLen = rem === 0 ? blockSize : blockSize - rem;
  const p = new Uint8Array(data.length + padLen);
  p.set(data);
  p[data.length] = 0x80;
  return p;
}

/** Padding Method 3: Method 1 padding, prefixed with a block holding the bit length. */
export function isoPad3(data: Uint8Array, blockSize: number): Uint8Array {
  const body = isoPad1(data, blockSize);
  const out = new Uint8Array(blockSize + body.length);
  let v = BigInt(data.length) * 8n;
  for (let i = blockSize - 1; i >= 0; i--) {
    out[i] = Number(v & 0xffn);
    v >>= 8n;
    if (v === 0n) break;
  }
  out.set(body, blockSize);
  return out;
}

export function isoPad(method: IsoMethod, data: Uint8Array, blockSize: number): Uint8Array {
  if (method === 1) return isoPad1(data, blockSize);
  if (method === 2) return isoPad2(data, blockSize);
  return isoPad3(data, blockSize);
}

/**
 * MAC Algorithm 1 (CBC-MAC) with the requested padding method.
 * The IV defaults to all-zero, which is the standard behaviour for a MAC.
 */
export function iso9797Mac(
  method: IsoMethod,
  cipher: CipherName,
  key: Uint8Array,
  data: Uint8Array,
  iv: Uint8Array,
): Uint8Array {
  const bc = makeCipher(cipher, key);
  return cbcMac(bc, isoPad(method, data, bc.blockSize), iv);
}

/**
 * MAC Algorithm 3 - Retail MAC (ANSI X9.19).
 *
 *   H   = CBC-MAC_K(padded data)            (MAC algorithm 1)
 *   MAC = E_K( D_K'(H) )                    (output transformation 3)
 *
 * Key material:
 *   - `key` may be twice the single-cipher key length; the first half is K and
 *     the second half is K' (this is the usual "double-length key" layout).
 *   - Alternatively pass `key2` to give K' explicitly.
 *
 * `padding` selects Padding Method 1 ("m1", the usual choice for Retail MAC)
 * or Padding Method 2 ("m2").
 */
export function retailMac(
  cipher: CipherName,
  key: Uint8Array,
  data: Uint8Array,
  padding: "m1" | "m2" = "m1",
  key2?: Uint8Array,
  iv?: Uint8Array,
): Uint8Array {
  let k1 = key;
  let k2 = key2;
  if (!k2) {
    if (key.length % 2 !== 0) {
      throw new SkillError(
        "INVALID_KEY_LENGTH",
        "Retail MAC needs two keys: pass key2, or a key of twice the cipher key length",
      );
    }
    const half = key.length / 2;
    k1 = key.subarray(0, half);
    k2 = key.subarray(half);
  }
  const bc1: BlockCipher = makeCipher(cipher, k1);
  const bc2: BlockCipher = makeCipher(cipher, k2);
  const bs = bc1.blockSize;
  const padded = padding === "m2" ? isoPad2(data, bs) : isoPad1(data, bs);
  const h = cbcMac(bc1, padded, iv ?? new Uint8Array(bs));
  return bc1.encryptBlock(bc2.decryptBlock(h));
}
