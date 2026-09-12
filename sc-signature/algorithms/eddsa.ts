// EdDSA (Ed25519 / Ed448) signing/verification via node:crypto.
// EdDSA is prehashed by definition: the caller must NOT pass a `hash` parameter.

import crypto from "node:crypto";
import { CryptoError, bufToHex } from "./common.ts";

export function edCurveName(curve?: string): string {
  const c = (curve ?? "Ed25519").toUpperCase();
  if (c === "ED25519") return "ed25519";
  if (c === "ED448") return "ed448";
  throw new CryptoError("UNSUPPORTED_CURVE", `unsupported EdDSA curve: ${curve}`);
}

export function eddsaSign(privateKeyPem: string, data: Buffer): { signature: string } {
  const key = crypto.createPrivateKey(privateKeyPem);
  const sig = crypto.sign(null, data, key);
  return { signature: bufToHex(sig) };
}

export function eddsaVerify(publicKeyPem: string, data: Buffer, signature: Buffer): boolean {
  const key = crypto.createPublicKey(publicKeyPem);
  return crypto.verify(null, data, key, signature);
}

export function eddsaGenerate(curve: string | undefined): { publicKeyPem: string; privateKeyPem: string } {
  const name = edCurveName(curve);
  const kp = crypto.generateKeyPairSync(name);
  return {
    publicKeyPem: kp.publicKey.export({ type: "spki", format: "pem" }) as string,
    privateKeyPem: kp.privateKey.export({ type: "pkcs8", format: "pem" }) as string,
  };
}
