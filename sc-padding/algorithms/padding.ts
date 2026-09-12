// Padding / unpadding for sc-padding.
// Self-contained copy (sc-encryption keeps its own copy; skills must not
// import each other because users may install them selectively).
// All unpadding is fail-closed: invalid padding never yields data.
import { fail } from "./errors.ts";

export type PaddingScheme =
  | "ISO7816-4"
  | "ISO9797-1-M1"
  | "ISO9797-1-M2"
  | "PKCS7"
  | "ANSI-X9.23"
  | "ZERO";

export const PADDING_SCHEMES: PaddingScheme[] = [
  "ISO7816-4",
  "ISO9797-1-M1",
  "ISO9797-1-M2",
  "PKCS7",
  "ANSI-X9.23",
  "ZERO",
];

export function normalizeScheme(s: string): PaddingScheme {
  const u = s.toUpperCase().replace(/_/g, "-");
  const match = PADDING_SCHEMES.find((x) => x === u);
  if (!match) fail("UNSUPPORTED_ALGORITHM", `padding scheme '${s}' is not supported`);
  return match;
}

// ---------- pad ----------

export function pad(data: Uint8Array, blockSize: number, scheme: PaddingScheme): Uint8Array {
  assertBlockSize(blockSize);
  switch (scheme) {
    case "ISO7816-4":
      return padIso7816_4(data, blockSize);
    case "ISO9797-1-M1":
      return padIso9797M1(data, blockSize);
    case "ISO9797-1-M2":
      // Byte-identical to ISO 7816-4; kept distinct for spec traceability.
      return padIso7816_4(data, blockSize);
    case "PKCS7":
      return padPkcs7(data, blockSize);
    case "ANSI-X9.23":
      return padAnsiX923(data, blockSize);
    case "ZERO":
      return padZero(data, blockSize);
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
  const out = new Uint8Array(data.length + blockSize - rem);
  out.set(data);
  return out; // zero-filled
}

function padAnsiX923(data: Uint8Array, blockSize: number): Uint8Array {
  const rem = data.length % blockSize;
  const padLen = rem === 0 ? blockSize : blockSize - rem;
  const out = new Uint8Array(data.length + padLen);
  out.set(data);
  out[out.length - 1] = padLen; // only the last byte carries the length
  return out;
}

function padZero(data: Uint8Array, blockSize: number): Uint8Array {
  const rem = data.length % blockSize;
  if (rem === 0) return data;
  const out = new Uint8Array(data.length + blockSize - rem);
  out.set(data);
  return out;
}

// ---------- unpad ----------

export function unpad(
  data: Uint8Array,
  blockSize: number,
  scheme: PaddingScheme,
  originalLength?: number,
): Uint8Array {
  assertBlockSize(blockSize);
  if (data.length === 0) fail("INVALID_PADDING", "data is empty");
  if (data.length % blockSize !== 0) {
    fail("INVALID_PADDING", "padded data length is not a multiple of block size");
  }
  switch (scheme) {
    case "ISO7816-4":
    case "ISO9797-1-M2":
      return unpadIso7816_4(data);
    case "ISO9797-1-M1":
    case "ZERO":
      // Both schemes append 0x00 only, so the boundary is NOT recoverable from
      // the bytes alone. Pass `originalLength` for an exact, verified recovery;
      // without it we strip trailing zeros, which destroys genuine trailing
      // zero bytes of the payload. See README for the ambiguity warning.
      return unpadZero(data, originalLength);
    case "PKCS7":
      return unpadPkcs7(data, blockSize);
    case "ANSI-X9.23":
      return unpadAnsiX923(data, blockSize);
    case "ZERO":
      return unpadZero(data);
  }
}

function unpadPkcs7(data: Uint8Array, blockSize: number): Uint8Array {
  const n = data[data.length - 1];
  if (n < 1 || n > blockSize) fail("INVALID_PADDING", "PKCS7 padding length out of range");
  for (let i = data.length - n; i < data.length; i++) {
    if (data[i] !== n) fail("INVALID_PADDING", "PKCS7 padding bytes inconsistent");
  }
  return data.subarray(0, data.length - n);
}

function unpadAnsiX923(data: Uint8Array, blockSize: number): Uint8Array {
  const n = data[data.length - 1];
  if (n < 1 || n > blockSize) fail("INVALID_PADDING", "ANSI X9.23 padding length out of range");
  for (let i = data.length - n; i < data.length - 1; i++) {
    if (data[i] !== 0x00) fail("INVALID_PADDING", "ANSI X9.23 padding bytes must be zero");
  }
  return data.subarray(0, data.length - n);
}

function unpadIso7816_4(data: Uint8Array): Uint8Array {
  let i = data.length - 1;
  while (i >= 0 && data[i] === 0x00) i--;
  if (i < 0 || data[i] !== 0x80) {
    fail("INVALID_PADDING", "ISO 7816-4 / 9797-1-M2: no 0x80 boundary found");
  }
  return data.subarray(0, i);
}

function unpadZero(data: Uint8Array, originalLength?: number): Uint8Array {
  // Exact mode: the caller supplies the true payload length, so the padding can
  // be verified instead of guessed.
  if (originalLength !== undefined) {
    if (!Number.isInteger(originalLength) || originalLength < 0 || originalLength > data.length) {
      fail("INVALID_PARAMETER", "original_length out of range");
    }
    for (let i = originalLength; i < data.length; i++) {
      if (data[i] !== 0x00) {
        fail("INVALID_PADDING", "bytes after original_length are not zero padding");
      }
    }
    return data.subarray(0, originalLength);
  }
  // Ambiguous by nature: trailing zero bytes of real data are indistinguishable
  // from padding. Strip all trailing zeros (and document the risk in README).
  let i = data.length - 1;
  while (i >= 0 && data[i] === 0x00) i--;
  return data.subarray(0, i + 1);
}

// ---------- validate ----------

// Returns true when `data` carries well-formed padding for the scheme.
// Never throws for malformed input: it simply reports false.
export function isValidPadding(
  data: Uint8Array,
  blockSize: number,
  scheme: PaddingScheme,
): boolean {
  if (blockSize < 1 || blockSize > 255) return false;
  if (data.length === 0 || data.length % blockSize !== 0) return false;
  try {
    unpad(data, blockSize, scheme);
    return true;
  } catch {
    return false;
  }
}

function assertBlockSize(blockSize: number): void {
  if (!Number.isInteger(blockSize) || blockSize < 1 || blockSize > 255) {
    fail("INVALID_PARAMETER", "block_size must be an integer between 1 and 255");
  }
}
