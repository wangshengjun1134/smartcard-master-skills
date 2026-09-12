// HMAC family. All except SM3 delegate to node:crypto. HMAC-SM3 uses self-implemented SM3.

import { createHmac } from "node:crypto";
import { sm3 } from "./sm3.ts";
import { concatBytes } from "./hex.ts";

const HASH_ALGO: Record<string, string> = {
  "HMAC-MD5": "md5",
  "HMAC-SHA1": "sha1",
  "HMAC-SHA224": "sha224",
  "HMAC-SHA256": "sha256",
  "HMAC-SHA384": "sha384",
  "HMAC-SHA512": "sha512",
};

export const HMAC_ALGORITHMS: string[] = [
  "HMAC-MD5",
  "HMAC-SHA1",
  "HMAC-SHA224",
  "HMAC-SHA256",
  "HMAC-SHA384",
  "HMAC-SHA512",
  "HMAC-SM3",
];

function hmacSm3(key: Uint8Array, data: Uint8Array): Uint8Array {
  const B = 64; // SM3 block size
  let k = key;
  if (k.length > B) k = sm3(k);
  if (k.length < B) {
    const p = new Uint8Array(B);
    p.set(k);
    k = p;
  }
  const ipad = new Uint8Array(B);
  const opad = new Uint8Array(B);
  for (let i = 0; i < B; i++) {
    ipad[i] = k[i] ^ 0x36;
    opad[i] = k[i] ^ 0x5c;
  }
  const inner = sm3(concatBytes(ipad, data));
  return sm3(concatBytes(opad, inner));
}

export function hmac(algorithm: string, key: Uint8Array, data: Uint8Array): Uint8Array {
  if (algorithm === "HMAC-SM3") return hmacSm3(key, data);
  const algo = HASH_ALGO[algorithm];
  if (!algo) throw new Error("UNSUPPORTED_ALGORITHM");
  const h = createHmac(algo, Buffer.from(key));
  h.update(Buffer.from(data));
  return new Uint8Array(h.digest());
}
