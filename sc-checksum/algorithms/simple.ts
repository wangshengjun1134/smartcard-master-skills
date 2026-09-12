// Non-cryptographic simple checksums: XOR, LRC, SUM-8, SUM-16.
//
// Definitions used here (they differ between standards, so they are stated
// explicitly and are covered by tests):
//   XOR    : byte-wise XOR of all bytes, single byte result.
//            This is the form used by ISO/IEC 7816-3 T=1 (the LRC byte there
//            is a plain XOR, despite the name).
//   LRC    : two's complement of the 8-bit sum, i.e. (0x100 - (sum & 0xff)) & 0xff,
//            so that sum(data) + LRC == 0 (mod 256). This is ISO 1155 LRC-8.
//   SUM-8  : (sum of all bytes) mod 2^8.
//   SUM-16 : (sum of all bytes) mod 2^16 (byte order = `endian`).

export interface SimpleParams {
  width: number; // 8 or 16
  kind: "xor" | "lrc" | "sum8" | "sum16";
}

export const SIMPLE_ALGORITHMS: Record<string, SimpleParams> = {
  "XOR":      { width: 8,  kind: "xor" },
  "LRC":      { width: 8,  kind: "lrc" },
  "SUM-8":    { width: 8,  kind: "sum8" },
  "SUM-16":   { width:16,  kind: "sum16" },
};

export function isSimple(algo: string): boolean {
  return Object.prototype.hasOwnProperty.call(SIMPLE_ALGORITHMS, algo);
}

export function simpleCompute(data: Uint8Array, p: SimpleParams): number {
  const xor = () => {
    let acc = 0;
    for (const b of data) acc ^= b;
    return acc;
  };
  const sum = () => {
    let acc = 0;
    for (const b of data) acc += b;
    return acc;
  };
  switch (p.kind) {
    case "xor":
      return xor() & 0xff;
    case "lrc":
      // Two's complement of the 8-bit sum (ISO 1155).
      return (0x100 - (sum() & 0xff)) & 0xff;
    case "sum8":
      return sum() & 0xff;
    case "sum16":
      return sum() & 0xffff;
  }
}

export function isSimpleAlgo(algo: string): boolean {
  return isSimple(algo);
}
