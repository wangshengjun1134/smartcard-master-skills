// aeskw.ts - key wrapping primitives (self-implemented wrapping logic).
//  - aesKeyWrap / aesKeyUnwrap : RFC 3394 AES Key Wrap
//  - aesKwpWrap / aesKwpUnwrap : RFC 5649 AES Key Wrap with Padding
//  - des3KeyWrap / des3KeyUnwrap : simplified 3DES-CBC + IV wrap (see README)
import { aesEcbEncrypt, aesEcbDecrypt, des3CbcEncrypt, des3CbcDecrypt } from "./aes.ts";
import { xorBuffers } from "./util.ts";
import { AppError } from "./util.ts";

const A6 = Buffer.from("A6A6A6A6A6A6A6A6", "hex"); // RFC 3394 default IV
const KWP_AIV_HI = Buffer.from("A65959A6", "hex"); // RFC 5649 constant high half

function tBuf(t: number): Buffer {
  const b = Buffer.alloc(8);
  // t fits in 64 bits; write as big-endian
  b.writeUInt32BE(Math.floor(t / 0x100000000), 0);
  b.writeUInt32BE(t >>> 0, 4);
  return b;
}

// RFC 3394 wrap with caller-supplied initial value A (8 bytes).
function rfc3394Wrap(kek: Buffer, data: Buffer, A: Buffer): Buffer {
  if (data.length % 8 !== 0) {
    throw new AppError("INVALID_PARAMETER", "RFC3394 plaintext must be a multiple of 8 bytes");
  }
  const n = data.length / 8;
  const R: Buffer[] = [];
  for (let i = 0; i < n; i++) R.push(Buffer.from(data.subarray(i * 8, i * 8 + 8)));
  let a = Buffer.from(A);
  for (let j = 0; j < 6; j++) {
    for (let i = 0; i < n; i++) {
      const B = aesEcbEncrypt(kek, Buffer.concat([a, R[i]]));
      a = xorBuffers(B.subarray(0, 8), tBuf(i + 1 + n * j));
      R[i] = Buffer.from(B.subarray(8, 16));
    }
  }
  return Buffer.concat([a, ...R]);
}

// Core RFC 3394 unwrap that returns BOTH the recovered AIV and the plaintext,
// without applying any integrity check. Callers decide what A means.
function rfc3394UnwrapRaw(kek: Buffer, wrapped: Buffer): { a: Buffer; data: Buffer } {
  if (wrapped.length % 8 !== 0 || wrapped.length < 16) {
    throw new AppError("INVALID_PARAMETER", "RFC3394 wrapped data must be >=16 bytes and a multiple of 8");
  }
  const n = wrapped.length / 8 - 1;
  let a = Buffer.from(wrapped.subarray(0, 8));
  const R: Buffer[] = [];
  for (let i = 0; i < n; i++) R.push(Buffer.from(wrapped.subarray((i + 1) * 8, (i + 2) * 8)));
  for (let j = 5; j >= 0; j--) {
    for (let i = n - 1; i >= 0; i--) {
      const t = tBuf(i + 1 + n * j);
      const B = aesEcbDecrypt(kek, Buffer.concat([xorBuffers(a, t), R[i]]));
      a = Buffer.from(B.subarray(0, 8));
      R[i] = Buffer.from(B.subarray(8, 16));
    }
  }
  return { a, data: Buffer.concat(R) };
}

function rfc3394Unwrap(kek: Buffer, wrapped: Buffer, expectedA: Buffer): Buffer {
  const { a, data } = rfc3394UnwrapRaw(kek, wrapped);
  if (!a.equals(expectedA)) {
    throw new AppError("INTEGRITY_CHECK_FAILED", "RFC3394 integrity check failed (A != A6A6A6A6A6A6A6A6)");
  }
  return data;
}

export function aesKeyWrap(kek: Buffer, data: Buffer): Buffer {
  if (kek.length !== 16 && kek.length !== 24 && kek.length !== 32) {
    throw new AppError("INVALID_KEY_LENGTH", "AES KEK must be 16/24/32 bytes");
  }
  return rfc3394Wrap(kek, data, A6);
}

export function aesKeyUnwrap(kek: Buffer, wrapped: Buffer): Buffer {
  if (kek.length !== 16 && kek.length !== 24 && kek.length !== 32) {
    throw new AppError("INVALID_KEY_LENGTH", "AES KEK must be 16/24/32 bytes");
  }
  return rfc3394Unwrap(kek, wrapped, A6);
}

// RFC 5649 AES-KWP
export function aesKwpWrap(kek: Buffer, data: Buffer): Buffer {
  if (kek.length !== 16 && kek.length !== 24 && kek.length !== 32) {
    throw new AppError("INVALID_KEY_LENGTH", "AES KEK must be 16/24/32 bytes");
  }
  if (data.length < 1) {
    throw new AppError("INVALID_PARAMETER", "key data must be at least 1 byte");
  }
  const m = data.length;
  const padLen = (8 - (m % 8)) % 8;
  const padded = Buffer.concat([data, Buffer.alloc(padLen)]);
  const n = padded.length / 8;
  const A = Buffer.alloc(8);
  KWP_AIV_HI.copy(A, 0);
  A.writeUInt32BE(m, 4); // MLI = original octet length (big-endian, low half)
  if (n === 1) {
    return aesEcbEncrypt(kek, Buffer.concat([A, padded]));
  }
  return rfc3394Wrap(kek, padded, A);
}

export function aesKwpUnwrap(kek: Buffer, wrapped: Buffer): Buffer {
  if (kek.length !== 16 && kek.length !== 24 && kek.length !== 32) {
    throw new AppError("INVALID_KEY_LENGTH", "AES KEK must be 16/24/32 bytes");
  }
  let A: Buffer;
  let padded: Buffer;
  if (wrapped.length === 16) {
    const dec = aesEcbDecrypt(kek, wrapped);
    A = dec.subarray(0, 8);
    padded = Buffer.from(dec.subarray(8, 16));
  } else {
    // The AIV is data-dependent here, so the RFC 3394 constant check must NOT
    // be applied -- recover A and validate it as an RFC 5649 AIV instead.
    const { a, data } = rfc3394UnwrapRaw(kek, wrapped);
    A = a;
    padded = data;
  }
  // validate AIV
  if (!A.subarray(0, 4).equals(KWP_AIV_HI)) {
    throw new AppError("INTEGRITY_CHECK_FAILED", "RFC5649 AIV constant check failed");
  }
  const m = A.readUInt32BE(4);
  const n = padded.length / 8;
  if (!(8 * (n - 1) < m && m <= 8 * n)) {
    throw new AppError("INTEGRITY_CHECK_FAILED", "RFC5649 MLI range check failed");
  }
  const tailPad = 8 * n - m;
  if (tailPad > 0) {
    const tail = padded.subarray(padded.length - tailPad);
    for (const b of tail) {
      if (b !== 0) {
        throw new AppError("INTEGRITY_CHECK_FAILED", "RFC5649 padding bytes not zero");
      }
    }
  }
  return Buffer.from(padded.subarray(0, m));
}

// Simplified 3DES key wrap: 3DES-CBC(KEK, IV, data). IV is required.
export function des3KeyWrap(kek: Buffer, iv: Buffer, data: Buffer): Buffer {
  return des3CbcEncrypt(kek, iv, data);
}

export function des3KeyUnwrap(kek: Buffer, iv: Buffer, wrapped: Buffer): Buffer {
  try {
    return des3CbcDecrypt(kek, iv, wrapped);
  } catch (e) {
    throw new AppError("INTEGRITY_CHECK_FAILED", "3DES-KW unwrap failed");
  }
}
