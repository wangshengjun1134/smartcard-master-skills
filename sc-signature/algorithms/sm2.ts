// SM2 (GM/T 0003.2-2012) digital signature over the sm2p256v1 curve.
// Fully self-implemented with BigInt (Node does not provide SM2).
// Includes SM3 digest + ZA user identity + key PEM (SEC1 / SPKI) build & parse.

import crypto from "node:crypto";
import { sm3 } from "./sm3.ts";
import {
  parseDer,
  derSeq,
  derInt,
  derOctet,
  derBitString,
  derContext,
  derOid,
  encodeSm2Signature,
  decodeSm2Signature,
  pemEncode,
  pemDecode,
} from "./der.ts";
import { CryptoError, bigToFixedBuf, bufToBig } from "./common.ts";

const p = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFFn;
const a = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFCn;
const b = 0x28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93n;
const n = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123n;
const Gx = 0x32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7n;
const Gy = 0xBC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0n;
const G = { x: Gx, y: Gy };

// SM2 curve OID 1.2.156.10197.1.301
const SM2_OID = [0x2a, 0x81, 0x1c, 0x4f, 0x55, 0x01, 0x82, 0x2d];
// id-ecPublicKey 1.2.840.10045.2.1
const EC_PUBKEY_OID = [0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01];

export interface Point {
  x: bigint;
  y: bigint;
}

const INF: Point | null = null;

// Modular inverse over the field prime p (used by point arithmetic).
function modInv(x: bigint): bigint {
  let val = ((x % p) + p) % p;
  let oldR = val;
  let r = p;
  let oldS = 1n;
  let s = 0n;
  while (r !== 0n) {
    const q = oldR / r;
    const tmpR = oldR - q * r;
    oldR = r;
    r = tmpR;
    const tmpS = oldS - q * s;
    oldS = s;
    s = tmpS;
  }
  return ((oldS % p) + p) % p;
}

// Modular inverse over the group order n (used by signature arithmetic).
// NOTE: this must NOT reuse modInv() -- n and p are different moduli.
function modInvN(x: bigint): bigint {
  const v = ((x % n) + n) % n;
  let oldR = v;
  let r = n;
  let oldS = 1n;
  let s = 0n;
  while (r !== 0n) {
    const q = oldR / r;
    const tmpR = oldR - q * r;
    oldR = r;
    r = tmpR;
    const tmpS = oldS - q * s;
    oldS = s;
    s = tmpS;
  }
  if (oldR !== 1n) throw new CryptoError("INTERNAL_ERROR", "value is not invertible mod n");
  return ((oldS % n) + n) % n;
}

function ecAdd(P: Point | null, Q: Point | null): Point | null {
  if (!P) return Q;
  if (!Q) return P;
  if (P.x === Q.x && (P.y + Q.y) % p === 0n) return INF; // P == -Q
  let lam: bigint;
  if (P.x === Q.x && P.y === Q.y) {
    lam = (3n * P.x * P.x + a) * modInv(2n * P.y) % p;
  } else {
    lam = (Q.y - P.y) * modInv(((Q.x - P.x) % p + p) % p) % p;
  }
  const x3 = (lam * lam - P.x - Q.x) % p;
  const y3 = (lam * (P.x - x3) - P.y) % p;
  return { x: (x3 + p) % p, y: (y3 + p) % p };
}

function ecMul(k: bigint, P: Point): Point | null {
  let R: Point | null = INF;
  let add: Point | null = P;
  while (k > 0n) {
    if (k & 1n) R = ecAdd(R, add);
    add = ecAdd(add, add);
    k >>= 1n;
  }
  return R;
}

function onCurve(P: Point): boolean {
  const lhs = (P.y * P.y) % p;
  const rhs = (P.x * P.x * P.x + a * P.x + b) % p;
  return (((lhs - rhs) % p) + p) % p === 0n;
}

// Parse sm2_id as UTF-8 text (the GM/T 0003.5 Annex A example defines ID_A by
// its ASCII encoding, so the default "1234567812345678" is ASCII bytes 0x31..).
// A hex string may be passed with an explicit "hex:" prefix.
export function parseSm2Id(id?: string): Buffer {
  const idStr = id ?? "1234567812345678";
  if (idStr.startsWith("hex:")) {
    const hexPart = idStr.slice(4);
    if (!/^([0-9A-Fa-f]{2})*$/.test(hexPart)) {
      throw new CryptoError("INVALID_HEX", "sm2_id hex payload must be even-length hex");
    }
    return Buffer.from(hexPart, "hex");
  }
  return Buffer.from(idStr, "utf8");
}

export function sm2Za(idBytes: Buffer, pub: Point): Buffer {
  const entlBuf = Buffer.alloc(2);
  entlBuf.writeUInt16BE(idBytes.length * 8, 0);
  const m = Buffer.concat([
    entlBuf,
    idBytes,
    bigToFixedBuf(a, 32),
    bigToFixedBuf(b, 32),
    bigToFixedBuf(Gx, 32),
    bigToFixedBuf(Gy, 32),
    bigToFixedBuf(pub.x, 32),
    bigToFixedBuf(pub.y, 32),
  ]);
  return sm3(m);
}

function sm2E(za: Buffer, msg: Buffer): bigint {
  const h = sm3(Buffer.concat([za, msg]));
  let e = 0n;
  for (const bt of h) e = (e << 8n) | BigInt(bt);
  return e % n;
}

function randomScalar(): bigint {
  for (;;) {
    const buf = crypto.randomBytes(32);
    let k = 0n;
    for (const bt of buf) k = (k << 8n) | BigInt(bt);
    k = k % n;
    if (k > 0n) return k;
  }
}

export interface Sm2Sig {
  r: bigint;
  s: bigint;
}

// Sign with private scalar d. kFixed is for deterministic test vectors only.
export function sm2Sign(
  d: bigint,
  msg: Buffer,
  idBytes: Buffer,
  kFixed?: bigint,
): Sm2Sig {
  const pub = ecMul(d, G);
  if (!pub) throw new CryptoError("INTERNAL_ERROR", "invalid SM2 private key");
  const za = sm2Za(idBytes, pub);
  const e = sm2E(za, msg);
  for (;;) {
    const k = kFixed ?? randomScalar();
    const P1 = ecMul(k, G);
    if (!P1) continue;
    const r = (e + P1.x) % n;
    if (r === 0n || (r + k) % n === 0n) {
      if (kFixed) throw new CryptoError("INTERNAL_ERROR", "fixed k produced invalid r");
      continue;
    }
    const d1 = (1n + d) % n;
    const s = (((modInvN(d1) * (k - (r * d) % n)) % n) + n) % n;
    if (s === 0n) {
      if (kFixed) throw new CryptoError("INTERNAL_ERROR", "fixed k produced invalid s");
      continue;
    }
    return { r, s };
  }
}

export function sm2Verify(
  pub: Point,
  msg: Buffer,
  idBytes: Buffer,
  r: bigint,
  s: bigint,
): boolean {
  if (r <= 0n || r >= n || s <= 0n || s >= n) return false;
  if (!onCurve(pub)) return false;
  const za = sm2Za(idBytes, pub);
  const e = sm2E(za, msg);
  const t = (r + s) % n;
  if (t === 0n) return false;
  const P1 = ecAdd(ecMul(s, G), ecMul(t, pub));
  if (!P1) return false;
  const R = (e + P1.x) % n;
  return R === r;
}

function pointFromScalar(d: bigint): Point {
  const P = ecMul(d, G);
  if (!P) throw new CryptoError("INTERNAL_ERROR", "degenerate key");
  return P;
}

export function sm2PublicKey(d: bigint): Point {
  return pointFromScalar(d);
}

function buildSec1Private(d: bigint, pub: Point): Buffer {
  const dBytes = bigToFixedBuf(d, 32);
  const pointBytes = Buffer.concat([
    Buffer.from([0x04]),
    bigToFixedBuf(pub.x, 32),
    bigToFixedBuf(pub.y, 32),
  ]);
  return derSeq([
    derInt(1n),
    derOctet(dBytes),
    derContext(0, derOid(SM2_OID)),
    derContext(1, derBitString(pointBytes, 0)),
  ]);
}

function buildSpkiPublic(pub: Point): Buffer {
  const pointBytes = Buffer.concat([
    Buffer.from([0x04]),
    bigToFixedBuf(pub.x, 32),
    bigToFixedBuf(pub.y, 32),
  ]);
  const algId = derSeq([derOid(EC_PUBKEY_OID), derOid(SM2_OID)]);
  return derSeq([algId, derBitString(pointBytes, 0)]);
}

export function sm2Generate(): { publicKeyPem: string; privateKeyPem: string } {
  let d = randomScalar();
  const pub = pointFromScalar(d);
  return {
    privateKeyPem: pemEncode(buildSec1Private(d, pub), "EC PRIVATE KEY"),
    publicKeyPem: pemEncode(buildSpkiPublic(pub), "PUBLIC KEY"),
  };
}

export function parseSm2PrivateKey(pem: string): bigint {
  const der = pemDecode(pem);
  const node = parseDer(der);
  if (node.tag !== 0x30 || !node.children) {
    throw new CryptoError("INVALID_KEY", "not a valid SM2 private key");
  }
  const extractDFromSec1 = (nd: ReturnType<typeof parseDer>): bigint => {
    if (!nd.children || nd.children.length < 2) {
      throw new CryptoError("INVALID_KEY", "malformed SEC1 private key");
    }
    if (nd.children[1].tag === 0x04) return bufToBig(nd.children[1].content);
    throw new CryptoError("INVALID_KEY", "missing private key octet string");
  };
  // SEC1: children[1] is the OCTET STRING private key.
  if (node.children[1] && node.children[1].tag === 0x04) {
    return extractDFromSec1(node);
  }
  // PKCS#8: children[2] is OCTET STRING carrying inner SEC1 DER.
  if (node.children.length >= 3 && node.children[2].tag === 0x04) {
    const inner = parseDer(node.children[2].content);
    return extractDFromSec1(inner);
  }
  throw new CryptoError("INVALID_KEY", "unsupported SM2 private key format");
}

export function parseSm2PublicKey(pem: string): Point {
  const der = pemDecode(pem);
  const node = parseDer(der);
  let bitString: Buffer | null = null;
  if (node.tag === 0x30 && node.children) {
    for (const c of node.children) {
      if (c.tag === 0x03) bitString = c.content;
    }
  }
  if (!bitString) throw new CryptoError("INVALID_KEY", "not a valid SM2 public key");
  const pointBytes = bitString.subarray(1); // skip unused-bits byte
  if (pointBytes[0] !== 0x04 || pointBytes.length !== 65) {
    throw new CryptoError("INVALID_KEY", "unsupported SM2 point encoding");
  }
  const x = bufToBig(pointBytes.subarray(1, 33));
  const y = bufToBig(pointBytes.subarray(33, 65));
  const P = { x, y };
  if (!onCurve(P)) throw new CryptoError("INVALID_KEY", "point not on SM2 curve");
  return P;
}

export { encodeSm2Signature, decodeSm2Signature };
