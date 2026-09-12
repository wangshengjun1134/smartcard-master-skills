// util.ts - hex / buffer helpers and error types (sc-key, self-contained)
// No cross-skill imports allowed.

export class AppError extends Error {
  code: string;
  constructor(code: string, message: string) {
    super(message);
    this.code = code;
    this.name = "AppError";
  }
}

export function fromHex(s: unknown): Buffer {
  if (typeof s !== "string") {
    throw new AppError("INVALID_HEX", "hex input must be a string");
  }
  const t = s.trim();
  if (t.length % 2 !== 0) {
    throw new AppError("INVALID_HEX", "hex string has odd length");
  }
  if (t.length > 0 && !/^([0-9A-Fa-f]{2})*$/.test(t)) {
    throw new AppError("INVALID_HEX", "hex string contains invalid characters");
  }
  return Buffer.from(t, "hex");
}

export function toHex(b: Buffer): string {
  return b.toString("hex").toUpperCase();
}

// 3DES / DES odd-parity adjustment: each byte has an odd number of 1 bits.
export function adjustParity(key: Buffer): Buffer {
  const out = Buffer.from(key);
  for (let i = 0; i < out.length; i++) {
    let b = out[i];
    let ones = 0;
    for (let k = 1; k < 8; k++) {
      ones += (b >> k) & 1;
    }
    if (ones % 2 === 0) {
      b |= 0x01;
    } else {
      b &= 0xfe;
    }
    out[i] = b;
  }
  return out;
}

export function xorBuffers(a: Buffer, b: Buffer): Buffer {
  if (a.length !== b.length) {
    throw new AppError("INTERNAL_ERROR", "xor length mismatch");
  }
  const out = Buffer.alloc(a.length);
  for (let i = 0; i < a.length; i++) {
    out[i] = a[i] ^ b[i];
  }
  return out;
}
