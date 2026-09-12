// sc-random: cryptographically secure randomness.
//
// Every operation is backed by node:crypto randomBytes(), which draws from the
// operating system entropy source. Math.random() is NEVER used anywhere in
// this skill -- it is not cryptographically secure.
//
// Honest scoping note: this skill provides a CSPRNG interface. It does not
// implement a TRNG, and it does not expose a seeded DRBG. See README.

import { randomBytes, randomUUID } from "node:crypto";

export type Format = "hex" | "base64" | "dec" | "bin";

export const MAX_LENGTH = 65536;
export const MAX_COUNT = 1024;

export function normalizeFormat(v: unknown): Format {
  if (v === undefined || v === null) return "hex";
  const s = String(v).toLowerCase();
  if (s !== "hex" && s !== "base64" && s !== "dec" && s !== "bin") {
    throw Object.assign(new Error("format must be hex, base64, dec or bin"), {
      code: "INVALID_PARAMETER",
    });
  }
  return s;
}

export function render(bytes: Uint8Array, format: Format): string {
  switch (format) {
    case "hex":
      return Buffer.from(bytes).toString("hex").toUpperCase();
    case "base64":
      return Buffer.from(bytes).toString("base64");
    case "dec": {
      let v = 0n;
      for (const b of bytes) v = (v << 8n) | BigInt(b);
      return v.toString(10);
    }
    case "bin":
      return Array.from(bytes)
        .map((b) => b.toString(2).padStart(8, "0"))
        .join("");
  }
}

export function generateRandom(length: number, count: number, format: Format): string[] {
  const out: string[] = [];
  for (let i = 0; i < count; i++) out.push(render(randomBytes(length), format));
  return out;
}

// A UUID v4 is 16 random bytes with version/variant bits set (RFC 4122 / 9562).
export function generateUuid(count: number): string[] {
  const out: string[] = [];
  for (let i = 0; i < count; i++) out.push(randomUUID());
  return out;
}

export function parseLength(v: unknown, defaultLen: number): number {
  if (v === undefined || v === null) return defaultLen;
  if (typeof v !== "number" || !Number.isInteger(v)) {
    throw Object.assign(new Error("length must be an integer"), { code: "INVALID_PARAMETER" });
  }
  if (v < 1) throw Object.assign(new Error("length must be >= 1"), { code: "INVALID_PARAMETER" });
  if (v > MAX_LENGTH) {
    throw Object.assign(new Error(`length must be <= ${MAX_LENGTH}`), { code: "INVALID_PARAMETER" });
  }
  return v;
}

export function parseCount(v: unknown): number {
  if (v === undefined || v === null) return 1;
  if (typeof v !== "number" || !Number.isInteger(v)) {
    throw Object.assign(new Error("count must be an integer"), { code: "INVALID_PARAMETER" });
  }
  if (v < 1) throw Object.assign(new Error("count must be >= 1"), { code: "INVALID_PARAMETER" });
  if (v > MAX_COUNT) {
    throw Object.assign(new Error(`count must be <= ${MAX_COUNT}`), { code: "INVALID_PARAMETER" });
  }
  return v;
}
