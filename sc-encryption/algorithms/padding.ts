// Padding / unpadding for sc-encryption.
// Self-contained copy (sc-padding keeps its own identical copy).
// All unpadding is fail-closed: invalid padding never yields plaintext.
import { fail } from "./errors.ts";

export type PaddingScheme =
  | "none"
  | "pkcs7"
  | "iso7816-4"
  | "iso9797-1-m1"
  | "iso9797-1-m2";

// ---------- pad ----------
export function pad(data: Uint8Array, blockSize: number, scheme: PaddingScheme): Uint8Array {
  switch (scheme) {
    case "none":
      return data; // block-alignment is the caller's responsibility
    case "pkcs7":
      return padPkcs7(data, blockSize);
    case "iso7816-4":
      return padIso7816_4(data, blockSize);
    case "iso9797-1-m1":
      return padIso9797M1(data, blockSize);
    case "iso9797-1-m2":
      return padIso9797M2(data, blockSize);
  }
}

function padPkcs7(data: Uint8Array, blockSize: number): Uint8Array {
  const rem = data.length % blockSize;
  const padLen = rem === 0 ? blockSize : blockSize - rem;
  const out = new Uint8Array(data.length + padLen);
  out.set(data);
  out.fill(padLen, data.length);
  return out;
}

// ISO/IEC 7816-4 and ISO/IEC 9797-1 method 2 produce identical byte streams:
// append 0x80 then zero bytes until block-aligned. The difference is purely
// semantic/spec-origin (smart-card block padding vs. MAC padding method 2).
function padIso7816_4(data: Uint8Array, blockSize: number): Uint8Array {
  const rem = data.length % blockSize;
  const padLen = rem === 0 ? blockSize : blockSize - rem;
  const out = new Uint8Array(data.length + padLen);
  out.set(data);
  out[data.length] = 0x80;
  return out;
}

function padIso9797M1(data: Uint8Array, blockSize: number): Uint8Array {
  const rem = data.length % blockSize;
  if (rem === 0) return data; // method 1 adds nothing when already aligned
  const padLen = blockSize - rem;
  const out = new Uint8Array(data.length + padLen);
  out.set(data);
  return out; // zero-filled by default
}

function padIso9797M2(data: Uint8Array, blockSize: number): Uint8Array {
  // Identical byte-level output to ISO 7816-4 (see note above).
  return padIso7816_4(data, blockSize);
}

// ---------- unpad ----------
export function unpad(data: Uint8Array, blockSize: number, scheme: PaddingScheme): Uint8Array {
  if (scheme === "none") {
    if (data.length % blockSize !== 0) {
      fail("INVALID_PADDING", "data is not a multiple of block size");
    }
    return data;
  }
  if (data.length % blockSize !== 0) {
    fail("INVALID_PADDING", "padded data length is not a multiple of block size");
  }
  switch (scheme) {
    case "pkcs7":
      return unpadPkcs7(data, blockSize);
    case "iso7816-4":
    case "iso9797-1-m2":
      return unpadIso7816_4(data, blockSize);
    case "iso9797-1-m1":
      // Method 1 appends 0x00 only, so the boundary is not recoverable from the
      // bytes alone. Strip trailing zeros (same convention as sc-padding) so that
      // decrypt(pad(m)) == m for ordinary plaintext. A plaintext that itself ends
      // in 0x00 cannot be recovered exactly - an inherent limitation of zero
      // padding, documented in README.
      return unpadZero(data);
  }
}

function unpadZero(data: Uint8Array): Uint8Array {
  let i = data.length - 1;
  while (i >= 0 && data[i] === 0x00) i--;
  return data.subarray(0, i + 1);
}

function unpadPkcs7(data: Uint8Array, blockSize: number): Uint8Array {
  const n = data[data.length - 1];
  if (n < 1 || n > blockSize) {
    fail("INVALID_PADDING", "PKCS7 padding length out of range");
  }
  for (let i = data.length - n; i < data.length; i++) {
    if (data[i] !== n) fail("INVALID_PADDING", "PKCS7 padding bytes inconsistent");
  }
  return data.subarray(0, data.length - n);
}

function unpadIso7816_4(data: Uint8Array, blockSize: number): Uint8Array {
  let i = data.length - 1;
  while (i >= 0 && data[i] === 0x00) i--;
  if (i < 0 || data[i] !== 0x80) {
    fail("INVALID_PADDING", "ISO 7816-4 / 9797-1-M2: no 0x80 boundary found");
  }
  // Everything after the 0x80 marker must be zero (verified by the scan above).
  return data.subarray(0, i);
}
