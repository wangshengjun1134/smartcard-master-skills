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

// Decode the `data` input according to `encoding`:
//  - "hex" (default): data is a hex string -> bytes
//  - "utf8": data is literal UTF-8 text
//  - "ascii": data is literal ASCII text
export function decodeData(data: string, encoding?: string): Uint8Array {
  const enc = (encoding ?? "hex").toLowerCase();
  if (enc === "hex") {
    if (!isHex(data)) {
      throw new DigestError("INVALID_HEX", "data is not valid hex");
    }
    return hexToBytes(data);
  }
  if (enc === "utf8") {
    return new TextEncoder().encode(data);
  }
  if (enc === "ascii") {
    const out = new Uint8Array(data.length);
    for (let i = 0; i < data.length; i++) {
      const c = data.charCodeAt(i) & 0x7f;
      out[i] = c;
    }
    return out;
  }
  throw new DigestError("UNSUPPORTED_ENCODING", `encoding '${encoding}' is not supported`);
}

export class DigestError extends Error {
  code: string;
  constructor(code: string, message: string) {
    super(message);
    this.code = code;
  }
}
