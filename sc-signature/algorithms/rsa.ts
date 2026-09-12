// RSA PKCS#1 v1.5 and RSA-PSS signing/verification via node:crypto.

import crypto from "node:crypto";
import { CryptoError, normalizeHash, hashOutLen, bufToHex } from "./common.ts";

export function rsaSign(
  algorithm: "RSA" | "RSA-PSS",
  privateKeyPem: string,
  data: Buffer,
  hash: string,
  saltLength?: number,
): Buffer {
  const key = crypto.createPrivateKey(privateKeyPem);
  const h = normalizeHash(hash);
  if (algorithm === "RSA-PSS") {
    const salt = saltLength != null ? saltLength : hashOutLen(hash);
    return crypto.sign(h, data, {
      key,
      padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
      saltLength: salt,
    });
  }
  return crypto.sign(h, data, key);
}

export function rsaVerify(
  algorithm: "RSA" | "RSA-PSS",
  publicKeyPem: string,
  data: Buffer,
  hash: string,
  signature: Buffer,
  saltLength?: number,
): boolean {
  const key = crypto.createPublicKey(publicKeyPem);
  const h = normalizeHash(hash);
  if (algorithm === "RSA-PSS") {
    const salt = saltLength != null ? saltLength : hashOutLen(hash);
    return crypto.verify(h, data, {
      key,
      padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
      saltLength: salt,
    }, signature);
  }
  return crypto.verify(h, data, key, signature);
}

export function rsaGenerate(modulusLength = 2048): { publicKeyPem: string; privateKeyPem: string } {
  const kp = crypto.generateKeyPairSync("rsa", { modulusLength });
  return {
    publicKeyPem: kp.publicKey.export({ type: "spki", format: "pem" }) as string,
    privateKeyPem: kp.privateKey.export({ type: "pkcs8", format: "pem" }) as string,
  };
}
