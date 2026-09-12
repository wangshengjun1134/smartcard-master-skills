// HEX encoding/decoding helpers. No external deps.

export function hexToBytes(hex: string): Uint8Array {
  const s = hex.trim();
  if (s.length % 2 !== 0) throw new Error("INVALID_HEX");
  if (!/^[0-9A-Fa-f]*$/.test(s)) throw new Error("INVALID_HEX");
  const out = new Uint8Array(s.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(s.substr(i * 2, 2), 16);
  }
  return out;
}

export function bytesToHex(b: Uint8Array): string {
  let s = "";
  for (let i = 0; i < b.length; i++) {
    s += b[i].toString(16).padStart(2, "0");
  }
  return s.toUpperCase();
}

export function concatBytes(...parts: Uint8Array[]): Uint8Array {
  let len = 0;
  for (const p of parts) len += p.length;
  const out = new Uint8Array(len);
  let off = 0;
  for (const p of parts) {
    out.set(p, off);
    off += p.length;
  }
  return out;
}
