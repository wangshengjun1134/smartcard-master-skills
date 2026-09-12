// Table-driven CRC. Parameterized over width/poly/init/refin/refout/xorout.
// The `poly` values stored in the algorithm table are exactly as the caller
// provides (reflected poly for reflected algorithms, normal poly otherwise),
// so the same routine handles both reflected and non-reflected variants.

export interface CrcParams {
  width: number;
  poly: number;
  init: number;
  refin: boolean;
  refout: boolean;
  xorout: number;
}

export const CRC_ALGORITHMS: Record<string, CrcParams> = {
  "CRC-8":           { width: 8,  poly: 0x07,       init: 0x00,       refin: false, refout: false, xorout: 0x00 },
  "CRC-8/MAXIM":     { width: 8,  poly: 0x8C,       init: 0x00,       refin: true,  refout: true,  xorout: 0x00 },
  "CRC-16/CCITT-FALSE": { width: 16, poly: 0x1021,  init: 0xFFFF,     refin: false, refout: false, xorout: 0x0000 },
  "CRC-16/IBM":      { width: 16, poly: 0xA001,     init: 0x0000,     refin: true,  refout: true,  xorout: 0x0000 },
  "CRC-16/XMODEM":   { width: 16, poly: 0x1021,     init: 0x0000,     refin: false, refout: false, xorout: 0x0000 },
  "CRC-32":          { width: 32, poly: 0xEDB88320, init: 0xFFFFFFFF, refin: true,  refout: true,  xorout: 0xFFFFFFFF },
  "CRC-32C":         { width: 32, poly: 0x82F63B78, init: 0xFFFFFFFF, refin: true,  refout: true,  xorout: 0xFFFFFFFF },
};

function reflect8(x: number): number {
  let r = 0;
  for (let i = 0; i < 8; i++) {
    r = (r << 1) | (x & 1);
    x >>= 1;
  }
  return r & 0xff;
}

function reflectWidth(x: number, width: number): number {
  let r = 0;
  for (let i = 0; i < width; i++) {
    r = (r << 1) | (x & 1);
    x >>= 1;
  }
  return r;
}

// NOTE: `(1 << width) - 1` does NOT work for width === 32 -- JavaScript
// shift counts are taken modulo 32, so `1 << 32` evaluates to 1. Always use
// this helper to build the width mask.
export function widthMask(width: number): number {
  return width >= 32 ? 0xffffffff : (1 << width) - 1;
}

// Build the 256-entry lookup table for the given parameters.
function buildTable(p: CrcParams): number[] {
  const mask = widthMask(p.width);
  const table = new Array<number>(256);
  if (p.refin) {
    for (let n = 0; n < 256; n++) {
      let c = n;
      for (let k = 0; k < 8; k++) {
        c = (c & 1) ? ((c >>> 1) ^ p.poly) : (c >>> 1);
      }
      table[n] = c & mask;
    }
  } else {
    // Unsigned top bit: `1 << 31` is negative as a signed int32.
    const topbit = p.width >= 32 ? 0x80000000 : 1 << (p.width - 1);
    for (let n = 0; n < 256; n++) {
      let c = n << (p.width - 8);
      for (let k = 0; k < 8; k++) {
        c = (c & topbit) ? ((c << 1) ^ p.poly) : (c << 1);
        c &= mask;
      }
      table[n] = c & mask;
    }
  }
  return table;
}

// Compute CRC over `data` bytes using parameters `p`.
// `initOverride`/`xoroutOverride`/`polyOverride` allow caller overrides.
export function crcCompute(
  data: Uint8Array,
  p: CrcParams,
  overrides?: { init?: number; xorout?: number; poly?: number },
): number {
  const poly = overrides?.poly ?? p.poly;
  const init = overrides?.init ?? p.init;
  const xorout = overrides?.xorout ?? p.xorout;
  const width = p.width;
  const mask = widthMask(width);
  const params: CrcParams = { ...p, poly };
  const table = buildTable(params);

  let crc = init & mask;
  if (params.refin) {
    for (const byte of data) {
      crc = ((crc >>> 8) ^ table[(crc ^ byte) & 0xff]) & mask;
      crc &= mask;
    }
  } else {
    const shift = width - 8;
    for (const byte of data) {
      const idx = ((crc >>> shift) ^ byte) & 0xff;
      crc = ((crc << 8) ^ table[idx]) & mask;
    }
  }
  crc = (crc ^ xorout) & mask;
  // If refout differs from refin (unusual), reflect the final value.
  if (params.refout !== params.refin) {
    crc = reflectWidth(crc, width);
  }
  // Normalise to an unsigned value: a 32-bit `& 0xffffffff` yields a signed int32.
  return width >= 32 ? crc >>> 0 : crc & mask;
}

export function isCrc(algo: string): boolean {
  return Object.prototype.hasOwnProperty.call(CRC_ALGORITHMS, algo);
}
