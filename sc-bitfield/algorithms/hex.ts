// Hex helpers for sc-bitfield (self-contained).

export function isHex(s: unknown): s is string {
  return typeof s === "string" && /^([0-9A-Fa-f]{2})*$/.test(s);
}

export function hexToBytes(hex: string): Uint8Array {
  if (!isHex(hex)) throw new Error("INVALID_HEX");
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.substring(i * 2, i * 2 + 2), 16);
  return out;
}

export function bytesToHex(bytes: Uint8Array): string {
  let s = "";
  for (const b of bytes) s += b.toString(16).padStart(2, "0");
  return s.toUpperCase();
}
