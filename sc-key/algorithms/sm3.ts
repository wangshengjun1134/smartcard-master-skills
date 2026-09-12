// sm3.ts - SM3 hash (GM/T 0004), self-implemented with 32-bit word arithmetic.
// Validated against Python hashlib sm3 reference vectors.

function rotl(x: number, n: number): number {
  return (((x << n) | (x >>> (32 - n))) >>> 0);
}

function xor(a: number, b: number): number {
  return (a ^ b) >>> 0;
}

function add(...xs: number[]): number {
  let s = 0;
  for (const x of xs) s = (s + x) >>> 0;
  return s >>> 0;
}

const IV = [
  0x7380166f, 0x4914b2b9, 0x172442d7, 0xda8a0600,
  0xa96f30bc, 0x163138aa, 0xe38dee4d, 0xb0fb0e4e,
];

const T0 = 0x79cc4519;
const T1 = 0x7a879d8a;

function ff(j: number, x: number, y: number, z: number): number {
  return j >= 0 && j <= 15 ? xor(xor(x, y), z) : ((x & y) | (x & z) | (y & z)) >>> 0;
}
function gg(j: number, x: number, y: number, z: number): number {
  return j >= 0 && j <= 15 ? xor(xor(x, y), z) : ((x & y) | (~x & z)) >>> 0;
}
function p0(x: number): number {
  return xor(xor(x, rotl(x, 9)), rotl(x, 17));
}
function p1(x: number): number {
  return xor(xor(x, rotl(x, 15)), rotl(x, 23));
}

export function sm3(msg: Buffer): Buffer {
  const m = Buffer.from(msg);
  const bitLen = m.length * 8;
  // padding
  const k = (56 - ((m.length + 1) % 64) + 64) % 64;
  const padded = Buffer.alloc(m.length + 1 + k + 8);
  m.copy(padded, 0);
  padded[m.length] = 0x80;
  // length in bits, big-endian 64-bit
  const hi = Math.floor(bitLen / 0x100000000);
  const lo = bitLen >>> 0;
  padded[padded.length - 8] = (hi >>> 24) & 0xff;
  padded[padded.length - 7] = (hi >>> 16) & 0xff;
  padded[padded.length - 6] = (hi >>> 8) & 0xff;
  padded[padded.length - 5] = hi & 0xff;
  padded[padded.length - 4] = (lo >>> 24) & 0xff;
  padded[padded.length - 3] = (lo >>> 16) & 0xff;
  padded[padded.length - 2] = (lo >>> 8) & 0xff;
  padded[padded.length - 1] = lo & 0xff;

  let V = IV.slice();
  for (let off = 0; off < padded.length; off += 64) {
    const B = padded.subarray(off, off + 64);
    const W = new Array(68).fill(0);
    for (let j = 0; j < 16; j++) {
      W[j] = (B.readUInt32BE(j * 4) >>> 0);
    }
    for (let j = 16; j < 68; j++) {
      W[j] = p1(xor(xor(W[j - 16], W[j - 9]), rotl(W[j - 3], 15))) ^ rotl(W[j - 13], 7) ^ W[j - 6];
      W[j] = W[j] >>> 0;
    }
    const Wp = new Array(64).fill(0);
    for (let j = 0; j < 64; j++) {
      Wp[j] = xor(W[j], W[j + 4]);
    }

    let A = V[0], Bv = V[1], C = V[2], D = V[3], E = V[4], F = V[5], G = V[6], Hh = V[7];
    for (let j = 0; j < 64; j++) {
      const Tj = j <= 15 ? T0 : T1;
      const SS1 = rotl(add(rotl(A, 12), E, rotl(Tj, j)), 7);
      const SS2 = xor(SS1, rotl(A, 12));
      const TT1 = add(ff(j, A, Bv, C), D, SS2, Wp[j]);
      const TT2 = add(gg(j, E, F, G), Hh, SS1, W[j]);
      D = C;
      C = rotl(Bv, 9);
      Bv = A;
      A = TT1;
      Hh = G;
      G = rotl(F, 19);
      F = E;
      E = p0(TT2);
    }
    V = [
      xor(A, V[0]), xor(Bv, V[1]), xor(C, V[2]), xor(D, V[3]),
      xor(E, V[4]), xor(F, V[5]), xor(G, V[6]), xor(Hh, V[7]),
    ];
  }

  const out = Buffer.alloc(32);
  for (let i = 0; i < 8; i++) {
    out.writeUInt32BE(V[i] >>> 0, i * 4);
  }
  return out;
}
