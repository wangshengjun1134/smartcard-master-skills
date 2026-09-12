// ECDSA signing/verification via node:crypto, with DER/raw signature encoding.

import crypto from "node:crypto";
import { CryptoError, normalizeHash, bigToFixedBuf, bufToHex } from "./common.ts";
import { decodeSm2Signature, encodeSm2Signature } from "./der.ts";

export function ecCurveName(curve?: string): string {
  switch ((curve ?? "P-256").toUpperCase()) {
    case "P-256":
    case "PRIME256V1":
      return "prime256v1";
    case "P-384":
      return "secp384r1";
    case "P-521":
      return "secp521r1";
    case "SECP256K1":
      return "secp256k1";
    default:
      throw new CryptoError("UNSUPPORTED_CURVE", `unsupported ECDSA curve: ${curve}`);
  }
}

export function ecFieldBytes(curve?: string): number {
  switch ((curve ?? "P-256").toUpperCase()) {
    case "P-256":
    case "PRIME256V1":
    case "SECP256K1":
      return 32;
    case "P-384":
      return 48;
    case "P-521":
      return 66;
    default:
      return 32;
  }
}

export function ecdsaSign(
  privateKeyPem: string,
  data: Buffer,
  hash: string,
  curve: string | undefined,
  encoding: "der" | "raw",
): { signature: string; encoding: string } {
  const key = crypto.createPrivateKey(privateKeyPem);
  const h = normalizeHash(hash);
  const der = crypto.sign(h, data, key);
  if (encoding === "raw") {
    const { r, s } = decodeSm2Signature(der);
    const len = ecFieldBytes(curve);
    const raw = Buffer.concat([bigToFixedBuf(r, len), bigToFixedBuf(s, len)]);
    return { signature: bufToHex(raw), encoding: "raw" };
  }
  return { signature: bufToHex(der), encoding: "der" };
}

export function ecdsaVerify(
  publicKeyPem: string,
  data: Buffer,
  hash: string,
  signatureHex: string,
  curve: string | undefined,
  encoding: "der" | "raw",
): boolean {
  const key = crypto.createPublicKey(publicKeyPem);
  const h = normalizeHash(hash);
  let der: Buffer;
  if (encoding === "raw") {
    const raw = Buffer.from(signatureHex, "hex");
    const len = ecFieldBytes(curve);
    if (raw.length !== len * 2) {
      throw new CryptoError("INVALID_SIGNATURE", "raw signature length mismatch");
    }
    const r = raw.subarray(0, len);
    const s = raw.subarray(len);
    let rv = 0n;
    for (const bt of r) rv = (rv << 8n) | BigInt(bt);
    let sv = 0n;
    for (const bt of s) sv = (sv << 8n) | BigInt(bt);
    der = encodeSm2Signature(rv, sv);
  } else {
    der = Buffer.from(signatureHex, "hex");
  }
  return crypto.verify(h, data, key, der);
}

export function ecdsaGenerate(curve: string | undefined): { publicKeyPem: string; privateKeyPem: string } {
  const name = ecCurveName(curve);
  const kp = crypto.generateKeyPairSync("ec", { namedCurve: name });
  return {
    publicKeyPem: kp.publicKey.export({ type: "spki", format: "pem" }) as string,
    privateKeyPem: kp.privateKey.export({ type: "sec1", format: "pem" }) as string,
  };
}
