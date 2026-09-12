// sc-signature tests: official SM2 KAT + round-trips for every algorithm.
// Keys are generated in-process and never printed.

import { test } from "node:test";
import assert from "node:assert";
import { readFileSync } from "node:fs";
import { handle } from "../scripts/signature.ts";
import { sm2Sign, sm2Verify, sm2PublicKey, sm2Za, sm2Generate, parseSm2Id } from "../algorithms/sm2.ts";
import { bufToHex } from "../algorithms/common.ts";
import { sm3 } from "../algorithms/sm3.ts";

const v = JSON.parse(
  readFileSync(new URL("./vectors/sm2.json", import.meta.url), "utf8"),
);

const hx = (x: bigint): string => x.toString(16).toUpperCase().padStart(64, "0");

// ---------- SM3 primitive ----------

test("SM3 matches GM/T 0004", () => {
  assert.equal(
    bufToHex(sm3(Buffer.from("616263", "hex"))),
    "66C7F0F462EEEDD9D1F2D46BDC10E4E24167C4875CF2F7A2297DA02B8F4BA8E0",
  );
  assert.equal(
    bufToHex(sm3(Buffer.alloc(0))),
    "1AB21D8355CFA17F8E61194831E81A8F22BEC8C728FEFB747ED035EB5082AA2B",
  );
});

// ---------- SM2 official vector ----------

test("SM2 public key matches GM/T 0003", () => {
  const d = BigInt("0x" + v.privateKeyD);
  const pub = sm2PublicKey(d);
  assert.equal(hx(pub.x), v.publicKeyX);
  assert.equal(hx(pub.y), v.publicKeyY);
});

test("SM2 ZA matches GM/T 0003", () => {
  const pub = { x: BigInt("0x" + v.publicKeyX), y: BigInt("0x" + v.publicKeyY) };
  assert.equal(bufToHex(sm2Za(Buffer.from(v.id, "ascii"), pub)), v.za);
});

test("SM2 signature matches GM/T 0003 with fixed k", () => {
  const d = BigInt("0x" + v.privateKeyD);
  const k = BigInt("0x" + v.k);
  const msg = Buffer.from(v.messageAscii, "ascii");
  const sig = sm2Sign(d, msg, Buffer.from(v.id, "ascii"), k);
  assert.equal(hx(sig.r), v.r);
  assert.equal(hx(sig.s), v.s);
});

test("SM2 verifies the official vector and rejects tampering", () => {
  const pub = { x: BigInt("0x" + v.publicKeyX), y: BigInt("0x" + v.publicKeyY) };
  const r = BigInt("0x" + v.r);
  const s = BigInt("0x" + v.s);
  const id = Buffer.from(v.id, "ascii");
  assert.equal(sm2Verify(pub, Buffer.from(v.messageAscii, "ascii"), id, r, s), true);
  assert.equal(sm2Verify(pub, Buffer.from("tampered", "ascii"), id, r, s), false);
  assert.equal(sm2Verify(pub, Buffer.from(v.messageAscii, "ascii"), id, r, s + 1n), false);
});

// ---------- round trips via the CLI handler ----------

test("SM2 generate/sign/verify round trip (DER and raw)", () => {
  const gen = handle({ operation: "generate", algorithm: "SM2" });
  assert.equal(gen.ok, true, JSON.stringify(gen));
  const data = "6162636461626364";
  for (const enc of ["der", "raw"]) {
    const signed = handle({
      operation: "sign",
      algorithm: "SM2",
      private_key: gen.private_key,
      data,
      signature_encoding: enc,
    });
    assert.equal(signed.ok, true, JSON.stringify(signed));
    const checked = handle({
      operation: "verify",
      algorithm: "SM2",
      public_key: gen.public_key,
      data,
      signature: signed.signature,
      signature_encoding: enc,
    });
    assert.equal(checked.ok, true, JSON.stringify(checked));
    assert.equal(checked.valid, true);
  }
});

test("tampered SM2 signature is rejected", () => {
  const gen = handle({ operation: "generate", algorithm: "SM2" });
  const data = "6162636461626364";
  const signed = handle({ operation: "sign", algorithm: "SM2", private_key: gen.private_key, data });
  const sig = Buffer.from(signed.signature, "hex");
  sig[sig.length - 1] ^= 0x01; // flip a bit in s
  const checked = handle({
    operation: "verify",
    algorithm: "SM2",
    public_key: gen.public_key,
    data,
    signature: bufToHex(sig),
  });
  assert.equal(checked.ok, false);
  assert.equal(checked.error.code, "SIGNATURE_INVALID");
});

test("ECDSA P-256 round trip (DER and raw)", () => {
  const gen = handle({ operation: "generate", algorithm: "ECDSA", curve: "P-256" });
  assert.equal(gen.ok, true, JSON.stringify(gen));
  const data = "48656C6C6F2C20654364736121";
  for (const enc of ["der", "raw"]) {
    const signed = handle({
      operation: "sign",
      algorithm: "ECDSA",
      private_key: gen.private_key,
      data,
      hash: "SHA-256",
      curve: "P-256",
      signature_encoding: enc,
    });
    assert.equal(signed.ok, true, JSON.stringify(signed));
    const checked = handle({
      operation: "verify",
      algorithm: "ECDSA",
      public_key: gen.public_key,
      data,
      signature: signed.signature,
      hash: "SHA-256",
      curve: "P-256",
      signature_encoding: enc,
    });
    assert.equal(checked.ok, true, JSON.stringify(checked));
  }
});

test("RSA and RSA-PSS round trip", () => {
  const gen = handle({ operation: "generate", algorithm: "RSA" });
  assert.equal(gen.ok, true, JSON.stringify(gen));
  const data = "48656C6C6F2C2052534121";
  for (const algo of ["RSA", "RSA-PSS"]) {
    const signed = handle({
      operation: "sign",
      algorithm: algo,
      private_key: gen.private_key,
      data,
      hash: "SHA-256",
    });
    assert.equal(signed.ok, true, JSON.stringify(signed));
    const checked = handle({
      operation: "verify",
      algorithm: algo,
      public_key: gen.public_key,
      data,
      signature: signed.signature,
      hash: "SHA-256",
    });
    assert.equal(checked.ok, true, JSON.stringify(checked));
    assert.equal(checked.valid, true);
  }
});

test("Ed25519 round trip", () => {
  const gen = handle({ operation: "generate", algorithm: "EdDSA", curve: "Ed25519" });
  assert.equal(gen.ok, true, JSON.stringify(gen));
  const data = "48656C6C6F2C20656464736121";
  const signed = handle({ operation: "sign", algorithm: "EdDSA", private_key: gen.private_key, data });
  assert.equal(signed.ok, true, JSON.stringify(signed));
  const checked = handle({
    operation: "verify",
    algorithm: "EdDSA",
    public_key: gen.public_key,
    data,
    signature: signed.signature,
  });
  assert.equal(checked.ok, true, JSON.stringify(checked));
});

// ---------- parameter validation ----------

test("missing hash is rejected for RSA and ECDSA (never inferred)", () => {
  const rsaGen = handle({ operation: "generate", algorithm: "RSA" });
  const r = handle({ operation: "sign", algorithm: "RSA", private_key: rsaGen.private_key, data: "00" });
  assert.equal(r.ok, false);
  assert.equal(r.error.code, "MISSING_PARAMETER");

  const ecGen = handle({ operation: "generate", algorithm: "ECDSA", curve: "P-256" });
  const e = handle({ operation: "sign", algorithm: "ECDSA", private_key: ecGen.private_key, data: "00" });
  assert.equal(e.ok, false);
  assert.equal(e.error.code, "MISSING_PARAMETER");
});

test("EdDSA rejects an explicit hash parameter", () => {
  const gen = handle({ operation: "generate", algorithm: "EdDSA", curve: "Ed25519" });
  const r = handle({
    operation: "sign",
    algorithm: "EdDSA",
    private_key: gen.private_key,
    data: "00",
    hash: "SHA-256",
  });
  assert.equal(r.ok, false);
  assert.equal(r.error.code, "INVALID_PARAMETER");
});

test("SM2 rejects a non-SM3 hash", () => {
  const gen = handle({ operation: "generate", algorithm: "SM2" });
  const r = handle({
    operation: "sign",
    algorithm: "SM2",
    private_key: gen.private_key,
    data: "00",
    hash: "SHA-256",
  });
  assert.equal(r.ok, false);
  assert.equal(r.error.code, "INVALID_PARAMETER");
});

test("unsupported operation and algorithm are rejected", () => {
  const a = handle({ operation: "encrypt", algorithm: "SM2" });
  assert.equal(a.ok, false);
  assert.equal(a.error.code, "UNSUPPORTED_OPERATION");
  const b = handle({ operation: "sign", algorithm: "NOPE", data: "00" });
  assert.equal(b.ok, false);
  assert.equal(b.error.code, "UNSUPPORTED_ALGORITHM");
});

test("sm2_id affects the ZA and therefore the signature", () => {
  const gen = handle({ operation: "generate", algorithm: "SM2" });
  const data = "616263";
  const s1 = handle({ operation: "sign", algorithm: "SM2", private_key: gen.private_key, data: data, sm2_id: "1234567812345678" });
  const s2 = handle({ operation: "sign", algorithm: "SM2", private_key: gen.private_key, data: data, sm2_id: "4142434445464748" });
  assert.equal(s1.ok, true);
  assert.equal(s2.ok, true);
  // ECDSA-style random k means signatures differ anyway; assert both verify with their own id.
  for (const [s, id] of [[s1, "1234567812345678"], [s2, "4142434445464748"]] as const) {
    const r = handle({ operation: "verify", algorithm: "SM2", public_key: gen.public_key, data: data, signature: (s as any).signature, sm2_id: id });
    assert.equal(r.ok, true, JSON.stringify(r));
  }
  // And fails when verified under the wrong id.
  const wrong = handle({ operation: "verify", algorithm: "SM2", public_key: gen.public_key, data: data, signature: s1.signature, sm2_id: "4142434445464748" });
  assert.equal(wrong.ok, false);
});
