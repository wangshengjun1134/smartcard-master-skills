// SM3 (GM/T 0004-2012) hash, pure TypeScript.
// Verified against GM/T 0004 vectors:
//   sm3("")    = 1ab21d8355cfa17f8e61194831e81a8f22bec8c728fefb747ed035eb5082aa2b
//   sm3("abc") = 66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0

function rotl(x: number, n: number): number {
  x = x >>> 0;
  return ((x << n) | (x >>> (32 - n))) >>> 0;
}

function P0(x: number): number {
  return (x ^ rotl(x, 9) ^ rotl(x, 17)) >>> 0;
}

function P1(x: number): number {
  return (x ^ rotl(x, 15) ^ rotl(x, 23)) >>> 0;
}

function readWord(buf: Uint8Array, off: number): number {
  return ((buf[off] << 24) | (buf[off + 1] << 16) | (buf[off + 2] << 8) | buf[off + 3]) >>> 0;
}

function writeWord(buf: Uint8Array, off: number, w: number): void {
  buf[off] = (w >>> 24) & 0xff;
  buf[off + 1] = (w >>> 16) & 0xff;
  buf[off + 2] = (w >>> 8) & 0xff;
  buf[off + 3] = w & 0xff;
}

const IV: number[] = [
  0x7380166f, 0x4914b2b9, 0x172442d7, 0xda8a0600,
  0xa96f30bc, 0x163138aa, 0xe38dee4d, 0xb0fb0e4e,
];

function pad(msg: Uint8Array): Uint8Array {
  const l = msg.length;
  const bitLen = l * 8;
  const rem = (l + 1) % 64;
  const k = rem <= 56 ? 56 - rem : 64 - rem + 56;
  const total = l + 1 + k + 8;
  const out = new Uint8Array(total);
  out.set(msg);
  out[l] = 0x80;
  let v = BigInt(bitLen);
  for (let i = 7; i >= 0; i--) {
    out[total - 8 + i] = Number(v & 0xffn);
    v >>= 8n;
  }
  return out;
}

export function sm3(data: Buffer): Buffer {
  const V = IV.slice();
  const padded = pad(data);
  for (let off = 0; off < padded.length; off += 64) {
    const B = padded.subarray(off, off + 64);
    let A = V[0], Bb = V[1], C = V[2], D = V[3], E = V[4], F = V[5], G = V[6], H = V[7];
    const W: number[] = new Array(68);
    const Wp: number[] = new Array(64);
    for (let i = 0; i < 16; i++) W[i] = readWord(B, i * 4);
    for (let j = 16; j < 68; j++) {
      W[j] = (P1((W[j - 16] ^ W[j - 9] ^ rotl(W[j - 3], 15)) >>> 0) ^ rotl(W[j - 13], 7) ^ W[j - 6]) >>> 0;
    }
    for (let j = 0; j < 64; j++) Wp[j] = (W[j] ^ W[j + 4]) >>> 0;
    for (let j = 0; j < 64; j++) {
      const Tj = j < 16 ? 0x79cc4519 : 0x7a879d8a;
      const FF = j < 16 ? ((A ^ Bb ^ C) >>> 0) : (((A & Bb) | (A & C) | (Bb & C)) >>> 0);
      const GG = j < 16 ? ((E ^ F ^ G) >>> 0) : (((E & F) | ((~E >>> 0) & G)) >>> 0);
      const SS1 = rotl((((rotl(A, 12) + E) >>> 0) + rotl(Tj, j)) >>> 0, 7);
      const SS2 = (SS1 ^ rotl(A, 12)) >>> 0;
      const TT1 = (FF + D + SS2 + Wp[j]) >>> 0;
      const TT2 = (GG + H + SS1 + W[j]) >>> 0;
      D = C;
      C = rotl(Bb, 9);
      Bb = A;
      A = TT1;
      H = G;
      G = rotl(F, 19);
      F = E;
      E = P0(TT2);
    }
    V[0] = (V[0] ^ A) >>> 0;
    V[1] = (V[1] ^ Bb) >>> 0;
    V[2] = (V[2] ^ C) >>> 0;
    V[3] = (V[3] ^ D) >>> 0;
    V[4] = (V[4] ^ E) >>> 0;
    V[5] = (V[5] ^ F) >>> 0;
    V[6] = (V[6] ^ G) >>> 0;
    V[7] = (V[7] ^ H) >>> 0;
  }
  const out = Buffer.alloc(32);
  for (let i = 0; i < 8; i++) writeWord(out, i * 4, V[i]);
  return out;
}
