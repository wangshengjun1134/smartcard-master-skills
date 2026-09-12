// HEX (uppercase, no 0x prefix) <-> bytes helpers.
import { AppError, fail } from "./errors.ts";

const HEX_RE = /^([0-9A-Fa-f]{2})*$/;

export function hexToBytes(hex: string): Uint8Array {
  if (typeof hex !== "string" || !HEX_RE.test(hex)) {
    fail("INVALID_HEX", "expected even-length uppercase/lowercase hex string");
  }
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(hex.substring(i * 2, i * 2 + 2), 16);
  }
  return out;
}

export function bytesToHex(bytes: Uint8Array): string {
  let s = "";
  for (let i = 0; i < bytes.length; i++) {
    s += bytes[i].toString(16).padStart(2, "0");
  }
  return s.toUpperCase();
}
