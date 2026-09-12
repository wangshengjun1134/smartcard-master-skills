// Hex / byte helpers (self-contained, no external deps).

export function isHex(s: string): boolean {
  return /^[0-9A-Fa-f]*$/.test(s) && s.length % 2 === 0;
}

export function hexToBytes(hex: string): Uint8Array {
  const s = hex.length % 2 === 0 ? hex : "0" + hex;
  const out = new Uint8Array(s.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(s.substr(i * 2, 2), 16);
  }
  return out;
}

export function bytesToHex(bytes: Uint8Array): string {
  let s = "";
  for (const b of bytes) s += b.toString(16).padStart(2, "0");
  return s.toUpperCase();
}

// Serialize an integer `value` into `nBytes` bytes (big or little endian),
// preserving leading zero bytes. Returns uppercase hex.
export function intToHex(value: number, nBytes: number, endian: "big" | "little"): string {
  const bytes = new Uint8Array(nBytes);
  for (let i = 0; i < nBytes; i++) {
    const shift = (nBytes - 1 - i) * 8; // big-endian order
    const b = (value >> shift) & 0xff;
    if (endian === "big") bytes[i] = b;
    else bytes[nBytes - 1 - i] = b;
  }
  return bytesToHex(bytes);
}

export class ChecksumError extends Error {
  code: string;
  constructor(code: string, message: string) {
    super(message);
    this.code = code;
  }
}
