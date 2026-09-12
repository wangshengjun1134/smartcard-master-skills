// Algorithms backed by node:crypto createHash.
import { createHash } from "node:crypto";
import { DigestError } from "./util.ts";

// Map the canonical (caller-facing, all-caps) algorithm name to the
// node:crypto internal name used by createHash().
export const NATIVE_ALGOS: Record<string, string> = {
  "MD5": "md5",
  "SHA-1": "sha1",
  "SHA-224": "sha224",
  "SHA-256": "sha256",
  "SHA-384": "sha384",
  "SHA-512": "sha512",
  "SHA-512/224": "sha512-224",
  "SHA-512/256": "sha512-256",
  "SHA3-224": "sha3-224",
  "SHA3-256": "sha3-256",
  "SHA3-384": "sha3-384",
  "SHA3-512": "sha3-512",
};

export function isNative(algo: string): boolean {
  return Object.prototype.hasOwnProperty.call(NATIVE_ALGOS, algo);
}

// Returns hex digest (uppercase) and byte length.
export function nativeDigest(algo: string, bytes: Uint8Array): { digest: string; length: number } {
  const name = NATIVE_ALGOS[algo];
  if (!name) {
    throw new DigestError("UNSUPPORTED_ALGORITHM", `algorithm '${algo}' is not supported`);
  }
  const h = createHash(name);
  h.update(bytes);
  const buf = h.digest();
  // bytesToHex returns uppercase
  return { digest: buf.toString("hex").toUpperCase(), length: buf.length };
}
