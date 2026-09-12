// Dispatch: compute a full MAC (pre-truncation) for any supported algorithm.

import { hexToBytes, bytesToHex } from "./hex.ts";
import { SkillError } from "./errors.ts";
import { hmac, HMAC_ALGORITHMS } from "./hmac.ts";
import { cmac } from "./cmac.ts";
import { makeCipher, type CipherName } from "./blockciphers.ts";
import { cbcMac } from "./cbc.ts";
import { iso9797Mac, retailMac, type IsoMethod } from "./iso9797.ts";

export const ALL_ALGORITHMS: string[] = [
  ...HMAC_ALGORITHMS,
  "AES-CMAC",
  "3DES-CMAC",
  "3DES-MAC",
  "ISO9797-1-M1-MAC",
  "ISO9797-1-M2-MAC",
  "ISO9797-1-M3-MAC",
  "RETAIL-MAC",
  "SM4-MAC",
];

export interface MacInput {
  algorithm: string;
  key: string;
  data: string;
  cipher?: string;
  padding?: string;
  iv?: string;
  mac_length?: number;
}

function allZeroIv(n: number): Uint8Array {
  return new Uint8Array(n);
}

export function computeMac(input: MacInput): { mac: Uint8Array; fullLength: number } {
  const algo = input.algorithm;
  let key: Uint8Array;
  let data: Uint8Array;
  try {
    key = hexToBytes(input.key);
    data = hexToBytes(input.data);
  } catch {
    throw new SkillError("INVALID_HEX", "key/data must be valid HEX");
  }

  if (algo.startsWith("HMAC-")) {
    if (!HMAC_ALGORITHMS.includes(algo)) throw new SkillError("UNSUPPORTED_ALGORITHM", algo);
    const mac = hmac(algo, key, data);
    return { mac, fullLength: mac.length };
  }

  if (algo === "AES-CMAC") {
    const bc = makeCipher("AES", key);
    return { mac: cmac(bc, data), fullLength: bc.blockSize };
  }

  if (algo === "3DES-CMAC" || algo === "3DES-MAC") {
    const bc = makeCipher("3DES", key);
    if (algo === "3DES-CMAC") {
      return { mac: cmac(bc, data), fullLength: bc.blockSize };
    }
    // 3DES-MAC: plain CBC-MAC (zero-padded), IV default all-zero.
    const iv = input.iv ? hexToBytes(input.iv) : allZeroIv(bc.blockSize);
    return { mac: cbcMac(bc, data, iv), fullLength: bc.blockSize };
  }

  if (algo === "SM4-MAC") {
    const bc = makeCipher("SM4", key);
    const iv = input.iv ? hexToBytes(input.iv) : allZeroIv(bc.blockSize);
    return { mac: cbcMac(bc, data, iv), fullLength: bc.blockSize };
  }

  if (algo === "RETAIL-MAC") {
    // MAC algorithm 3 (Retail MAC / ANSI X9.19). Padding method: m1 (default) or m2.
    let cipher: CipherName = "3DES";
    if (input.cipher) {
      if (input.cipher === "AES" || input.cipher === "DES" ||
          input.cipher === "3DES" || input.cipher === "SM4") {
        cipher = input.cipher;
      } else {
        throw new SkillError("UNSUPPORTED_CIPHER", input.cipher);
      }
    }
    const padding = input.padding === "m2" ? "m2" : "m1";
    const iv = input.iv ? hexToBytes(input.iv) : undefined;
    const mac = retailMac(cipher, key, data, padding, undefined, iv);
    return { mac, fullLength: mac.length };
  }

  if (algo === "ISO9797-1-M1-MAC" || algo === "ISO9797-1-M2-MAC" || algo === "ISO9797-1-M3-MAC") {
    const method: IsoMethod =
      algo === "ISO9797-1-M1-MAC" ? 1 : algo === "ISO9797-1-M2-MAC" ? 2 : 3;
    let cipher: CipherName = "3DES";
    if (input.cipher) {
      if (input.cipher === "AES" || input.cipher === "3DES" || input.cipher === "SM4") {
        cipher = input.cipher;
      } else {
        throw new SkillError("UNSUPPORTED_CIPHER", input.cipher);
      }
    }
    // `padding` may override the initial pad scheme for M1/M2.
    void input.padding;
    const iv = input.iv ? hexToBytes(input.iv) : allZeroIv(makeCipher(cipher, key).blockSize);
    const mac = iso9797Mac(method, cipher, key, data, iv);
    return { mac, fullLength: makeCipher(cipher, key).blockSize };
  }

  throw new SkillError("UNSUPPORTED_ALGORITHM", algo);
}

export function truncateMac(mac: Uint8Array, macLength?: number): { out: Uint8Array; truncated: boolean } {
  if (macLength === undefined) return { out: mac, truncated: false };
  if (!Number.isInteger(macLength) || macLength < 0) {
    throw new SkillError("INVALID_PARAMETER", "mac_length must be a non-negative integer");
  }
  if (macLength > mac.length) {
    throw new SkillError("INVALID_PARAMETER", "mac_length exceeds full MAC length");
  }
  return { out: mac.subarray(0, macLength), truncated: macLength < mac.length };
}

// Verify a MAC: returns valid flag plus hex expected/actual (both upper-case).
export function verifyMac(
  input: MacInput,
  expectedHex: string,
): { valid: boolean; expected: string; actual: string } {
  const { mac } = computeMac(input);
  const { out } = truncateMac(mac, input.mac_length);
  const actual = bytesToHex(out);
  const expected = bytesToHex(hexToBytes(expectedHex));
  return { valid: expected.toUpperCase() === actual.toUpperCase(), expected, actual };
}
