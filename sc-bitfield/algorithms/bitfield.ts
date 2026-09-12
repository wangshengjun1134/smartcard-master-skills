// Bit and byte field operations for sc-bitfield (self-contained).
//
// Bit numbering: by default bit 0 is the MOST significant bit of byte 0
// (MSB-first, the convention used by smart-card / EMV data objects).
// Pass bit_order="lsb" to number bits from the least significant bit instead.

import { fail } from "./errors.ts";
import { hexToBytes, bytesToHex } from "./hex.ts";

export type BitOrder = "msb" | "lsb";
export type Direction = "left" | "right";

export function normalizeBitOrder(v: unknown): BitOrder {
  if (v === undefined || v === null) return "msb";
  const s = String(v).toLowerCase();
  if (s !== "msb" && s !== "lsb") fail("INVALID_PARAMETER", "bit_order must be 'msb' or 'lsb'");
  return s;
}

function requireInt(v: unknown, name: string, min: number, max?: number): number {
  if (typeof v !== "number" || !Number.isInteger(v)) {
    fail("MISSING_PARAMETER", `${name} is required and must be an integer`);
  }
  if (v < min) fail("INVALID_PARAMETER", `${name} must be >= ${min}`);
  if (max !== undefined && v > max) fail("INVALID_PARAMETER", `${name} must be <= ${max}`);
  return v;
}

// Physical bit index inside the byte array for logical bit `i`.
function physical(data: Uint8Array, i: number, order: BitOrder): { byte: number; mask: number } {
  if (order === "msb") {
    return { byte: i >> 3, mask: 0x80 >>> (i & 7) };
  }
  // LSB-first across the whole buffer: bit 0 is bit 0 of the LAST byte? No --
  // here LSB-first means bit 0 is the least significant bit of byte 0.
  return { byte: i >> 3, mask: 1 << (i & 7) };
}

export function totalBits(data: Uint8Array): number {
  return data.length * 8;
}

function checkRange(data: Uint8Array, offset: number, length: number): void {
  if (offset + length > totalBits(data)) {
    fail("OUT_OF_RANGE", `field [${offset}, ${offset + length}) exceeds ${totalBits(data)} bits`);
  }
}

// Read `length` bits starting at `offset`, returned as a BigInt.
export function getBits(
  data: Uint8Array,
  offset: number,
  length: number,
  order: BitOrder,
): bigint {
  checkRange(data, offset, length);
  if (length === 0) return 0n;
  let v = 0n;
  if (order === "msb") {
    // bit `offset` is the most significant bit of the field.
    for (let i = 0; i < length; i++) {
      const { byte, mask } = physical(data, offset + i, order);
      v = (v << 1n) | (data[byte] & mask ? 1n : 0n);
    }
  } else {
    // bit `offset` has weight 2^0, so the LAST bit read is the most significant.
    for (let i = length - 1; i >= 0; i--) {
      const { byte, mask } = physical(data, offset + i, order);
      v = (v << 1n) | (data[byte] & mask ? 1n : 0n);
    }
  }
  return v;
}

// Write `value` into `length` bits at `offset`. Returns a copy; input untouched.
export function setBits(
  data: Uint8Array,
  offset: number,
  length: number,
  value: bigint,
  order: BitOrder,
): Uint8Array {
  checkRange(data, offset, length);
  if (length < 0) fail("INVALID_PARAMETER", "bit_length must be >= 0");
  if (length > 0 && value < 0n) fail("INVALID_PARAMETER", "value must be non-negative");
  if (length > 0 && value >= 1n << BigInt(length)) {
    fail("INVALID_PARAMETER", `value does not fit in ${length} bits`);
  }
  const out = new Uint8Array(data);
  for (let i = 0; i < length; i++) {
    // For MSB order the first bit written carries the highest weight; for LSB
    // order bit `offset + i` carries weight 2^i.
    const bit =
      order === "msb"
        ? (value >> BigInt(length - 1 - i)) & 1n
        : (value >> BigInt(i)) & 1n;
    const { byte, mask } = physical(out, offset + i, order);
    if (bit) out[byte] |= mask;
    else out[byte] &= ~mask & 0xff;
  }
  return out;
}

// Number of set bits (population count).
export function countBits(data: Uint8Array): number {
  let n = 0;
  for (const b of data) {
    let x = b;
    while (x) {
      n += x & 1;
      x >>= 1;
    }
  }
  return n;
}

// Reverse the entire bit string (bit 0 becomes the last bit).
export function reverseBits(data: Uint8Array, order: BitOrder = "msb"): Uint8Array {
  const n = totalBits(data);
  let v = getBits(data, 0, n, order);
  let r = 0n;
  for (let i = 0; i < n; i++) {
    r = (r << 1n) | (v & 1n);
    v >>= 1n;
  }
  return setBits(new Uint8Array(data.length), 0, n, r, order);
}

// Shift the whole bit string; vacated bits are filled with zeroes.
export function shiftBits(
  data: Uint8Array,
  direction: Direction,
  amount: number,
  order: BitOrder = "msb",
): Uint8Array {
  const n = totalBits(data);
  if (amount < 0) fail("INVALID_PARAMETER", "shift must be >= 0");
  if (amount >= n) return new Uint8Array(data.length);
  const v = getBits(data, 0, n, order);
  const moved = direction === "left" ? (v << BigInt(amount)) : (v >> BigInt(amount));
  const mask = (1n << BigInt(n)) - 1n;
  return setBits(new Uint8Array(data.length), 0, n, moved & mask, order);
}

// Build a mask of `bits` bits, rendered as `bytes` bytes.
export function makeMask(bits: number, bytes: number): Uint8Array {
  requireInt(bits, "bit_length", 0, bytes * 8);
  const out = new Uint8Array(bytes);
  for (let i = 0; i < bits; i++) {
    const byte = i >> 3;
    out[byte] |= 0x80 >>> (i & 7);
  }
  return out;
}

// Apply a mask: result = data & mask (both same length).
export function applyMask(data: Uint8Array, maskHex: string): Uint8Array {
  const mask = hexToBytes(maskHex);
  if (mask.length !== data.length) {
    fail("INVALID_PARAMETER", "mask length must equal data length");
  }
  const out = new Uint8Array(data.length);
  for (let i = 0; i < data.length; i++) out[i] = data[i] & mask[i];
  return out;
}

// Most / least significant bit of the whole buffer, under `order`.
export function edgeBit(data: Uint8Array, which: "msb" | "lsb", order: BitOrder): number {
  if (data.length === 0) fail("INVALID_PARAMETER", "data is empty");
  const n = totalBits(data);
  const idx = which === "msb" ? 0 : n - 1;
  return Number(getBits(data, idx, 1, order));
}

// Most / least significant byte.
export function edgeByte(data: Uint8Array, which: "msb" | "lsb"): number {
  if (data.length === 0) fail("INVALID_PARAMETER", "data is empty");
  return which === "msb" ? data[0] : data[data.length - 1];
}

// Render a BigInt as exactly `byteLen` big-endian bytes (preserving leading zeros).
export function intToBytes(v: bigint, byteLen: number): Uint8Array {
  const out = new Uint8Array(byteLen);
  let x = v;
  for (let i = byteLen - 1; i >= 0; i--) {
    out[i] = Number(x & 0xffn);
    x >>= 8n;
  }
  return out;
}

export function parseValue(v: unknown, length: number): bigint {
  if (typeof v === "number") {
    if (!Number.isInteger(v)) fail("INVALID_PARAMETER", "value must be an integer");
    return BigInt(v);
  }
  if (typeof v === "string") {
    const s = v.trim();
    if (/^-?\d+$/.test(s)) return BigInt(s);
    if (/^0x[0-9a-fA-F]+$/.test(s)) return BigInt(s);
    // Treat as HEX bytes.
    const b = hexToBytes(s.toUpperCase());
    let acc = 0n;
    for (const byte of b) acc = (acc << 8n) | BigInt(byte);
    return acc;
  }
  fail("MISSING_PARAMETER", "value is required (integer, decimal string, or hex)");
}

export { hexToBytes, bytesToHex, requireInt };
