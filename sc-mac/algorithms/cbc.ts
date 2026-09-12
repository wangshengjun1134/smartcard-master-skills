// Raw CBC-MAC over a block cipher. Input is zero-padded to a block multiple
// (one zero block if empty). IV defaults to all-zero (caller supplies iv).

import type { BlockCipher } from "./blockciphers.ts";

function xorBlocks(a: Uint8Array, b: Uint8Array): Uint8Array {
  const out = new Uint8Array(a.length);
  for (let i = 0; i < a.length; i++) out[i] = a[i] ^ b[i];
  return out;
}

// Plain CBC-MAC: zero-pad data to block multiple, then CBC encrypt, return last block.
export function cbcMac(cipher: BlockCipher, data: Uint8Array, iv: Uint8Array): Uint8Array {
  const b = cipher.blockSize;
  let v = iv.slice();
  if (data.length === 0) {
    return cipher.encryptBlock(v);
  }
  const rem = data.length % b;
  const padded = new Uint8Array(data.length + (rem === 0 ? 0 : b - rem));
  padded.set(data);
  for (let i = 0; i < padded.length; i += b) {
    v = cipher.encryptBlock(xorBlocks(v, padded.subarray(i, i + b)));
  }
  return v;
}
