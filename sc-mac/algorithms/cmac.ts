// CMAC (ISO/IEC 9797-6 / NIST SP 800-38B / RFC 4493) over an arbitrary block cipher.

import type { BlockCipher } from "./blockciphers.ts";

function xorInto(a: Uint8Array, b: Uint8Array): void {
  for (let i = 0; i < a.length; i++) a[i] ^= b[i];
}

// Multiply by x in GF(2^b), with reduction constant Rb appended if MSB was set.
function doubleBlock(inp: Uint8Array, blockSize: number): Uint8Array {
  const out = new Uint8Array(blockSize);
  let carry = 0;
  for (let i = blockSize - 1; i >= 0; i--) {
    const nb = (inp[i] << 1) | carry;
    out[i] = nb & 0xff;
    carry = inp[i] & 0x80 ? 1 : 0;
  }
  if (inp[0] & 0x80) {
    // Rb: 0x87 for 128-bit blocks, 0x1B for 64-bit blocks.
    out[blockSize - 1] ^= blockSize === 16 ? 0x87 : 0x1b;
  }
  return out;
}

export function cmac(cipher: BlockCipher, data: Uint8Array): Uint8Array {
  const b = cipher.blockSize;
  const zero = new Uint8Array(b);
  const L = cipher.encryptBlock(zero);
  const K1 = doubleBlock(L, b);
  const K2 = doubleBlock(K1, b);

  const blocks: Uint8Array[] = [];
  if (data.length === 0) {
    // Empty message: pad a single block with 0x80 then zeros, XOR K2.
    const lb = new Uint8Array(b);
    lb[0] = 0x80;
    xorInto(lb, K2);
    blocks.push(lb);
  } else {
    const rem = data.length % b;
    const full = Math.floor(data.length / b);
    for (let i = 0; i < full; i++) {
      const blk = data.slice(i * b, (i + 1) * b);
      // K1 is applied only to the final block when the message length is an
      // exact multiple of the block size (i.e. there is no trailing partial block).
      if (rem === 0 && i === full - 1) xorInto(blk, K1);
      blocks.push(blk);
    }
    if (rem !== 0) {
      const lb = new Uint8Array(b);
      lb.set(data.subarray(full * b));
      lb[rem] = 0x80;
      xorInto(lb, K2);
      blocks.push(lb);
    }
  }

  let iv = new Uint8Array(b);
  for (const blk of blocks) {
    xorInto(iv, blk);
    iv = cipher.encryptBlock(iv);
  }
  return iv;
}
