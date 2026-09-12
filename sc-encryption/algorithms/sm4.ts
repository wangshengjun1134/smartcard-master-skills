// SM4 (GM/T 0002-2012) pure TypeScript implementation.
// 128-bit block & key, 32 rounds. Verified against the official vector:
//   key     0123456789abcdeffedcba9876543210
//   plaintext 0123456789abcdeffedcba9876543210
//   ciphertext 681edf34d206965e86b3e94f536e4246

const SBOX: number[] = [
  0xd6, 0x90, 0xe9, 0xfe, 0xcc, 0xe1, 0x3d, 0xb7, 0x16, 0xb6, 0x14, 0xc2, 0x28, 0xfb, 0x2c, 0x05,
  0x2b, 0x67, 0x9a, 0x76, 0x2a, 0xbe, 0x04, 0xc3, 0xaa, 0x44, 0x13, 0x26, 0x49, 0x86, 0x06, 0x99,
  0x9c, 0x42, 0x50, 0xf4, 0x91, 0xef, 0x98, 0x7a, 0x33, 0x54, 0x0b, 0x43, 0xed, 0xcf, 0xac, 0x62,
  0xe4, 0xb3, 0x1c, 0xa9, 0xc9, 0x08, 0xe8, 0x95, 0x80, 0xdf, 0x94, 0xfa, 0x75, 0x8f, 0x3f, 0xa6,
  0x47, 0x07, 0xa7, 0xfc, 0xf3, 0x73, 0x17, 0xba, 0x83, 0x59, 0x3c, 0x19, 0xe6, 0x85, 0x4f, 0xa8,
  0x68, 0x6b, 0x81, 0xb2, 0x71, 0x64, 0xda, 0x8b, 0xf8, 0xeb, 0x0f, 0x4b, 0x70, 0x56, 0x9d, 0x35,
  0x1e, 0x24, 0x0e, 0x5e, 0x63, 0x58, 0xd1, 0xa2, 0x25, 0x22, 0x7c, 0x3b, 0x01, 0x21, 0x78, 0x87,
  0xd4, 0x00, 0x46, 0x57, 0x9f, 0xd3, 0x27, 0x52, 0x4c, 0x36, 0x02, 0xe7, 0xa0, 0xc4, 0xc8, 0x9e,
  0xea, 0xbf, 0x8a, 0xd2, 0x40, 0xc7, 0x38, 0xb5, 0xa3, 0xf7, 0xf2, 0xce, 0xf9, 0x61, 0x15, 0xa1,
  0xe0, 0xae, 0x5d, 0xa4, 0x9b, 0x34, 0x1a, 0x55, 0xad, 0x93, 0x32, 0x30, 0xf5, 0x8c, 0xb1, 0xe3,
  0x1d, 0xf6, 0xe2, 0x2e, 0x82, 0x66, 0xca, 0x60, 0xc0, 0x29, 0x23, 0xab, 0x0d, 0x53, 0x4e, 0x6f,
  0xd5, 0xdb, 0x37, 0x45, 0xde, 0xfd, 0x8e, 0x2f, 0x03, 0xff, 0x6a, 0x72, 0x6d, 0x6c, 0x5b, 0x51,
  0x8d, 0x1b, 0xaf, 0x92, 0xbb, 0xdd, 0xbc, 0x7f, 0x11, 0xd9, 0x5c, 0x41, 0x1f, 0x10, 0x5a, 0xd8,
  0x0a, 0xc1, 0x31, 0x88, 0xa5, 0xcd, 0x7b, 0xbd, 0x2d, 0x74, 0xd0, 0x12, 0xb8, 0xe5, 0xb4, 0xb0,
  0x89, 0x69, 0x97, 0x4a, 0x0c, 0x96, 0x77, 0x7e, 0x65, 0xb9, 0xf1, 0x09, 0xc5, 0x6e, 0xc6, 0x84,
  0x18, 0xf0, 0x7d, 0xec, 0x3a, 0xdc, 0x4d, 0x20, 0x79, 0xee, 0x5f, 0x3e, 0xd7, 0xcb, 0x39, 0x48,
];

const FK: number[] = [0xa3b1bac6, 0x56aa3350, 0x677d9197, 0xb27022dc];

const CK: number[] = (() => {
  const arr: number[] = [];
  for (let i = 0; i < 32; i++) {
    let v = 0;
    for (let j = 0; j < 4; j++) {
      const b = ((4 * i + j) * 7) % 256;
      v = (v << 8) | b;
    }
    arr.push(v >>> 0);
  }
  return arr;
})();

function rotl(x: number, n: number): number {
  return ((x << n) | (x >>> (32 - n))) >>> 0;
}

function sboxWord(x: number): number {
  let out = 0;
  out |= SBOX[(x >>> 24) & 0xff] << 24;
  out |= SBOX[(x >>> 16) & 0xff] << 16;
  out |= SBOX[(x >>> 8) & 0xff] << 8;
  out |= SBOX[x & 0xff];
  return out >>> 0;
}

// tau: S-box on each of the four bytes.
function tau(x: number): number {
  return sboxWord(x);
}

// L: linear transform of the round function.
function L(x: number): number {
  return (x ^ rotl(x, 2) ^ rotl(x, 10) ^ rotl(x, 18) ^ rotl(x, 24)) >>> 0;
}

// L': linear transform of the key schedule.
function Lp(x: number): number {
  return (x ^ rotl(x, 13) ^ rotl(x, 23)) >>> 0;
}

function T(x: number): number {
  return L(tau(x));
}

function Tp(x: number): number {
  return Lp(tau(x));
}

function bytesToWord(b: Uint8Array, off: number): number {
  return ((b[off] << 24) | (b[off + 1] << 16) | (b[off + 2] << 8) | b[off + 3]) >>> 0;
}

function wordsFromBytes(b: Uint8Array): number[] {
  const out: number[] = [];
  for (let i = 0; i < b.length; i += 4) out.push(bytesToWord(b, i));
  return out;
}

function wordToBytes(w: number): Uint8Array {
  return new Uint8Array([(w >>> 24) & 0xff, (w >>> 16) & 0xff, (w >>> 8) & 0xff, w & 0xff]);
}

export function sm4KeySchedule(key: Uint8Array): number[] {
  const mk = wordsFromBytes(key);
  const k: number[] = [
    (mk[0] ^ FK[0]) >>> 0,
    (mk[1] ^ FK[1]) >>> 0,
    (mk[2] ^ FK[2]) >>> 0,
    (mk[3] ^ FK[3]) >>> 0,
  ];
  const rk: number[] = [];
  for (let i = 0; i < 32; i++) {
    const r = (k[i] ^ Tp(k[i + 1] ^ k[i + 2] ^ k[i + 3] ^ CK[i])) >>> 0;
    k.push(r);
    rk.push(r);
  }
  return rk;
}

// Encrypt one 16-byte block. `rk` may be reversed for decryption.
export function sm4CryptBlock(block: Uint8Array, rk: number[]): Uint8Array {
  const x = wordsFromBytes(block);
  for (let i = 0; i < 32; i++) {
    const v = (x[i] ^ T(x[i + 1] ^ x[i + 2] ^ x[i + 3] ^ rk[i])) >>> 0;
    x.push(v);
  }
  // Reverse transformation R: output words are (X35, X34, X33, X32).
  const out = new Uint8Array(16);
  out.set(wordToBytes(x[35]), 0);
  out.set(wordToBytes(x[34]), 4);
  out.set(wordToBytes(x[33]), 8);
  out.set(wordToBytes(x[32]), 12);
  return out;
}

export function sm4EncryptBlock(block: Uint8Array, rk: number[]): Uint8Array {
  return sm4CryptBlock(block, rk);
}

export function sm4DecryptBlock(block: Uint8Array, rk: number[]): Uint8Array {
  return sm4CryptBlock(block, [...rk].reverse());
}

// ---------- modes ----------
function xorBytes(a: Uint8Array, b: Uint8Array): Uint8Array {
  const out = new Uint8Array(a.length);
  for (let i = 0; i < a.length; i++) out[i] = a[i] ^ b[i];
  return out;
}

function addCounter(counter: Uint8Array): Uint8Array {
  const out = new Uint8Array(counter);
  for (let i = out.length - 1; i >= 0; i--) {
    if (out[i] === 0xff) {
      out[i] = 0;
    } else {
      out[i]++;
      break;
    }
  }
  return out;
}

export function sm4Ecb(data: Uint8Array, key: Uint8Array, encrypt: boolean): Uint8Array {
  const rk = sm4KeySchedule(key);
  const bs = 16;
  const out = new Uint8Array(data.length);
  for (let off = 0; off < data.length; off += bs) {
    const block = data.subarray(off, off + bs);
    const res = encrypt ? sm4EncryptBlock(block, rk) : sm4DecryptBlock(block, rk);
    out.set(res, off);
  }
  return out;
}

export function sm4Cbc(data: Uint8Array, key: Uint8Array, iv: Uint8Array, encrypt: boolean): Uint8Array {
  const rk = sm4KeySchedule(key);
  const bs = 16;
  const out = new Uint8Array(data.length);
  let prev = iv;
  for (let off = 0; off < data.length; off += bs) {
    const block = data.subarray(off, off + bs);
    if (encrypt) {
      const xored = xorBytes(block, prev);
      const res = sm4EncryptBlock(xored, rk);
      out.set(res, off);
      prev = res;
    } else {
      const res = sm4DecryptBlock(block, rk);
      const plain = xorBytes(res, prev);
      out.set(plain, off);
      prev = block;
    }
  }
  return out;
}

export function sm4Ctr(data: Uint8Array, key: Uint8Array, iv: Uint8Array): Uint8Array {
  const rk = sm4KeySchedule(key);
  const bs = 16;
  const out = new Uint8Array(data.length);
  let counter = new Uint8Array(iv);
  for (let off = 0; off < data.length; off += bs) {
    const keystream = sm4EncryptBlock(counter, rk);
    const chunk = data.subarray(off, Math.min(off + bs, data.length));
    for (let i = 0; i < chunk.length; i++) out[off + i] = chunk[i] ^ keystream[i];
    counter = addCounter(counter);
  }
  return out;
}
