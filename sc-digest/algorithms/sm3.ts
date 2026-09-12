// SM3 (GB/T 32905 / GM/T 0004-2012) — pure TypeScript + BigInt implementation.
// No dependency on node:crypto (Node does not provide SM3 natively).
import { bytesToHex } from "./util.ts";

const MASK: bigint = (1n << 32n) - 1n;
const IV: bigint[] = [
  0x7380166fn, 0x4914b2b9n, 0x172442d7n, 0xda8a0600n,
  0xa96f30bcn, 0x163138aan, 0xe38dee4dn, 0xb0fb0e4en,
];

function rotl(x: bigint, n: number): bigint {
  x = x & MASK;
  n = n & 31;
  if (n === 0) return x;
  return ((x << BigInt(n)) | (x >> BigInt(32 - n))) & MASK;
}

function ff(j: number, x: bigint, y: bigint, z: bigint): bigint {
  if (j < 16) return (x ^ y ^ z) & MASK;
  return ((x & y) | (x & z) | (y & z)) & MASK;
}

function gg(j: number, x: bigint, y: bigint, z: bigint): bigint {
  if (j < 16) return (x ^ y ^ z) & MASK;
  return ((x & y) | ((~x & MASK) & z)) & MASK;
}

function p0(x: bigint): bigint {
  return (x ^ rotl(x, 9) ^ rotl(x, 17)) & MASK;
}

function p1(x: bigint): bigint {
  return (x ^ rotl(x, 15) ^ rotl(x, 23)) & MASK;
}

function tj(j: number): bigint {
  const base = j < 16 ? 0x79cc4519n : 0x7a879d8an;
  return rotl(base, j);
}

// One compression round over a 512-bit (16 word) block.
function compress(v: bigint[], block: Uint8Array): bigint[] {
  const W: bigint[] = new Array(68);
  for (let i = 0; i < 16; i++) {
    let w = 0n;
    for (let b = 0; b < 4; b++) w = (w << 8n) | BigInt(block[i * 4 + b]);
    W[i] = w & MASK;
  }
  for (let j = 16; j < 68; j++) {
    W[j] = p1(W[j - 16] ^ W[j - 9] ^ rotl(W[j - 3], 15)) ^ rotl(W[j - 13], 7) ^ W[j - 6];
    W[j] = W[j] & MASK;
  }
  const Wp: bigint[] = new Array(64);
  for (let j = 0; j < 64; j++) Wp[j] = (W[j] ^ W[j + 4]) & MASK;

  let [A, B, C, D, E, F, G, H] = v;
  for (let j = 0; j < 64; j++) {
    const ss1 = rotl(rotl(A, 12) + E + tj(j), 7);
    const ss2 = ss1 ^ rotl(A, 12);
    const tt1 = (ff(j, A, B, C) + D + ss2 + Wp[j]) & MASK;
    const tt2 = (gg(j, E, F, G) + H + ss1 + W[j]) & MASK;
    D = C;
    C = rotl(B, 9);
    B = A;
    A = tt1;
    H = G;
    G = rotl(F, 19);
    F = E;
    E = p0(tt2);
  }
  return [
    A ^ v[0], B ^ v[1], C ^ v[2], D ^ v[3],
    E ^ v[4], F ^ v[5], G ^ v[6], H ^ v[7],
  ].map((x) => x & MASK);
}

// message must be a byte array
export function sm3(bytes: Uint8Array): Uint8Array {
  // Padding: append 0x80, then zeros, then 64-bit big-endian bit length,
  // so total length is a multiple of 64 bytes.
  const bitLen = BigInt(bytes.length) * 8n;
  const withOne = bytes.length + 1;
  const padZeros = (56 - (withOne % 64) + 64) % 64;
  const totalLen = withOne + padZeros + 8;
  const msg = new Uint8Array(totalLen);
  msg.set(bytes, 0);
  msg[bytes.length] = 0x80;
  // 64-bit big-endian bit length
  for (let i = 0; i < 8; i++) {
    msg[totalLen - 1 - i] = Number((bitLen >> BigInt(8 * i)) & 0xffn);
  }

  let v = IV.slice();
  for (let off = 0; off < msg.length; off += 64) {
    v = compress(v, msg.subarray(off, off + 64));
  }
  const out = new Uint8Array(32);
  for (let i = 0; i < 8; i++) {
    const w = v[i];
    for (let b = 0; b < 4; b++) {
      out[i * 4 + b] = Number((w >> BigInt(8 * (3 - b))) & 0xffn);
    }
  }
  return out;
}

export function sm3Hex(bytes: Uint8Array): { digest: string; length: number } {
  return { digest: bytesToHex(sm3(bytes)), length: 32 };
}

export const SM3 = "SM3";
