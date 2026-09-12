// Shared helpers: hex conversion and the typed error used for CLI contracts.

export const HEX_RE = /^([0-9A-Fa-f]{2})*$/;

export function hexToBuf(h: string): Buffer {
  if (!HEX_RE.test(h)) {
    throw new CryptoError("INVALID_HEX", "data/key must be an even-length hex string");
  }
  return Buffer.from(h, "hex");
}

export function bufToHex(b: Buffer): string {
  return b.toString("hex").toUpperCase();
}

export function bigToFixedBuf(v: bigint, len: number): Buffer {
  let hex = v.toString(16);
  if (hex.length > len * 2) hex = hex.slice(-len * 2);
  hex = hex.padStart(len * 2, "0");
  return Buffer.from(hex, "hex");
}

export function bufToBig(buf: Buffer): bigint {
  let v = 0n;
  for (const bt of buf) v = (v << 8n) | BigInt(bt);
  return v;
}

const HASH_MAP: Record<string, string> = {
  "SHA-256": "sha256",
  "SHA-384": "sha384",
  "SHA-512": "sha512",
};

export function normalizeHash(h: string): string {
  const v = HASH_MAP[h.toUpperCase()];
  if (!v) throw new CryptoError("UNSUPPORTED_HASH", `unsupported hash: ${h}`);
  return v;
}

export function hashOutLen(h: string): number {
  return h.toUpperCase() === "SHA-512" ? 64 : h.toUpperCase() === "SHA-384" ? 48 : 32;
}

export class CryptoError extends Error {
  code: string;
  constructor(code: string, message: string) {
    super(message);
    this.name = "CryptoError";
    this.code = code;
  }
}
