// cmac.ts - AES-CMAC (NIST SP 800-38B), self-implemented Feistel subkey logic.
// Used for KCV-CMAC and NXP AES128 diversification.
import { aesEcbEncrypt } from "./aes.ts";
import { xorBuffers as xorB } from "./util.ts";

const Rb = Buffer.from("00000000000000000000000000000087", "hex");

function lsl1(buf: Buffer): Buffer {
  const out = Buffer.alloc(buf.length);
  let carry = 0;
  for (let i = buf.length - 1; i >= 0; i--) {
    out[i] = ((buf[i] << 1) | carry) & 0xff;
    carry = (buf[i] >> 7) & 1;
  }
  return out;
}

function xor(a: Buffer, b: Buffer): Buffer {
  return xorB(a, b);
}

export function aesCmac(key: Buffer, msg: Buffer): Buffer {
  const L = aesEcbEncrypt(key, Buffer.alloc(16));
  let K1 = lsl1(L);
  if (L[0] & 0x80) K1 = xor(K1, Rb);
  let K2 = lsl1(K1);
  if (K1[0] & 0x80) K2 = xor(K2, Rb);

  let data: Buffer;
  let lastKey: Buffer;
  if (msg.length === 0) {
    data = Buffer.concat([Buffer.from([0x80]), Buffer.alloc(15)]);
    lastKey = K2;
  } else if (msg.length % 16 === 0) {
    data = msg;
    lastKey = K1;
  } else {
    const pad = Buffer.alloc(16 - (msg.length % 16));
    pad[0] = 0x80;
    data = Buffer.concat([msg, pad]);
    lastKey = K2;
  }

  let X = Buffer.alloc(16);
  const n = data.length / 16;
  for (let i = 0; i < n; i++) {
    const block = data.subarray(i * 16, i * 16 + 16);
    let Y = xor(X, block);
    if (i === n - 1) Y = xor(Y, lastKey);
    X = aesEcbEncrypt(key, Y);
  }
  return X;
}
