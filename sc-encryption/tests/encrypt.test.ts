import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { run } from "../algorithms/engine.ts";
import { unpad } from "../algorithms/padding.ts";
import { AppError } from "../algorithms/errors.ts";

const KAT_PATH = fileURLToPath(new URL("./vectors/kat.json", import.meta.url));
const KAT = JSON.parse(readFileSync(KAT_PATH, "utf8"));

interface Res {
  ok: boolean;
  value?: Record<string, unknown>;
  code?: string;
}
function runCatch(input: Record<string, unknown>): Res {
  try {
    return { ok: true, value: run(input) };
  } catch (e) {
    if (e instanceof AppError) return { ok: false, code: e.code };
    throw e;
  }
}

test("all KAT encryption vectors match expected ciphertext/tag", () => {
  for (const v of KAT) {
    const { name, expectCiphertext, expectTag, ...rest } = v;
    const r = runCatch(rest);
    assert.equal(r.ok, true, `${name}: expected success`);
    const out = r.value as Record<string, string>;
    assert.equal(out.ciphertext, expectCiphertext, `${name}: ciphertext mismatch`);
    if (expectTag) assert.equal(out.tag, expectTag, `${name}: tag mismatch`);
  }
});

test("decrypt round-trips every KAT back to plaintext", () => {
  for (const v of KAT) {
    const { name, expectCiphertext, expectTag, data, ...rest } = v;
    const decryptInput: Record<string, unknown> = {
      ...rest,
      operation: "decrypt",
      data: expectCiphertext,
    };
    if (expectTag) decryptInput.tag = expectTag;
    const r = runCatch(decryptInput);
    assert.equal(r.ok, true, `${name}: decrypt failed`);
    assert.equal((r.value as Record<string, string>).plaintext, data.toUpperCase(), `${name}: plaintext mismatch`);
  }
});

test("missing IV for CBC/CTR -> MISSING_PARAMETER", () => {
  assert.equal(
    runCatch({ operation: "encrypt", algorithm: "AES-128", mode: "CBC", key: "00".repeat(16), data: "00".repeat(16) }).code,
    "MISSING_PARAMETER",
  );
  assert.equal(
    runCatch({ operation: "encrypt", algorithm: "SM4", mode: "CTR", key: "00".repeat(16), data: "00".repeat(16) }).code,
    "MISSING_PARAMETER",
  );
});

test("wrong key length -> INVALID_KEY_LENGTH", () => {
  assert.equal(
    runCatch({ operation: "encrypt", algorithm: "AES-128", mode: "ECB", key: "00".repeat(32), data: "00".repeat(16) }).code,
    "INVALID_KEY_LENGTH",
  );
  assert.equal(
    runCatch({ operation: "encrypt", algorithm: "3DES", mode: "ECB", key: "00".repeat(16), data: "00".repeat(8) }).code,
    "INVALID_KEY_LENGTH",
  );
});

test("invalid hex -> INVALID_HEX", () => {
  assert.equal(
    runCatch({ operation: "encrypt", algorithm: "AES-128", mode: "ECB", key: "00".repeat(16), data: "0" }).code,
    "INVALID_HEX",
  );
  assert.equal(
    runCatch({ operation: "encrypt", algorithm: "AES-128", mode: "ECB", key: "00".repeat(16), data: "ZZ" }).code,
    "INVALID_HEX",
  );
});

test("unsupported algorithm -> UNSUPPORTED_ALGORITHM", () => {
  assert.equal(
    runCatch({ operation: "encrypt", algorithm: "DES", mode: "ECB", key: "00".repeat(8), data: "00".repeat(8) }).code,
    "UNSUPPORTED_ALGORITHM",
  );
});

test("3DES-CTR and SM4-GCM unsupported -> UNSUPPORTED_MODE", () => {
  assert.equal(
    runCatch({ operation: "encrypt", algorithm: "3DES", mode: "CTR", key: "00".repeat(24), iv: "00".repeat(8), data: "00".repeat(8) }).code,
    "UNSUPPORTED_MODE",
  );
  assert.equal(
    runCatch({ operation: "encrypt", algorithm: "3DES", mode: "GCM", key: "00".repeat(24), nonce: "00".repeat(12), data: "00" }).code,
    "UNSUPPORTED_MODE",
  );
  assert.equal(
    runCatch({ operation: "encrypt", algorithm: "SM4", mode: "GCM", key: "00".repeat(16), nonce: "00".repeat(12), data: "00" }).code,
    "UNSUPPORTED_MODE",
  );
});

test("padding passed to CTR -> INVALID_PARAMETER", () => {
  assert.equal(
    runCatch({ operation: "encrypt", algorithm: "AES-128", mode: "CTR", key: "00".repeat(16), iv: "00".repeat(16), data: "00".repeat(16), padding: "pkcs7" }).code,
    "INVALID_PARAMETER",
  );
});

test("ECB with padding=none and unaligned data -> INVALID_PARAMETER", () => {
  assert.equal(
    runCatch({ operation: "encrypt", algorithm: "AES-128", mode: "ECB", key: "00".repeat(16), data: "00".repeat(17), padding: "none" }).code,
    "INVALID_PARAMETER",
  );
});

test("padding fail-closed: PKCS7 garbage never yields plaintext", () => {
  // ECB AES-128 with 2 blocks; flip last byte so PKCS7 length is 255 > blockSize.
  const key = "00".repeat(16);
  const enc = runCatch({ operation: "encrypt", algorithm: "AES-128", mode: "ECB", key, data: "11".repeat(10), padding: "pkcs7" });
  assert.equal(enc.ok, true);
  const ct = (enc.value as Record<string, string>).ciphertext;
  const flipped = ct.substring(0, ct.length - 2) + "ff";
  assert.equal(
    runCatch({ operation: "decrypt", algorithm: "AES-128", mode: "ECB", key, data: flipped, padding: "pkcs7" }).code,
    "INVALID_PADDING",
  );
});

test("padding fail-closed: ISO 7816-4 with no 0x80 -> INVALID_PADDING", () => {
  const key = "00".repeat(16);
  // All-zero block cannot contain a 0x80 boundary.
  assert.equal(
    runCatch({ operation: "decrypt", algorithm: "AES-128", mode: "ECB", key, data: "00".repeat(16), padding: "iso7816-4" }).code,
    "INVALID_PADDING",
  );
});

test("padding fail-closed: ISO 9797-1-M1 unaligned -> INVALID_PADDING", () => {
  // M1 cannot recover length; unpadding requires block-aligned input.
  assert.throws(
    () => unpad(new Uint8Array(17), 16, "iso9797-1-m1"),
    (e: Error) => e instanceof AppError && e.code === "INVALID_PADDING",
  );
  // all-zero block has no 0x80 boundary for iso7816-4
  assert.throws(
    () => unpad(new Uint8Array(16), 16, "iso7816-4"),
    (e: Error) => e instanceof AppError && e.code === "INVALID_PADDING",
  );
});

test("GCM decrypt verifies tag; tampered ciphertext -> AUTHENTICATION_FAILED (no plaintext leak)", () => {
  const base = {
    operation: "decrypt" as const,
    algorithm: "AES-128" as const,
    mode: "GCM" as const,
    key: "feffe9928665731c6d6a8f9467308308",
    nonce: "cafebabefacedbaddecaf888",
    aad: "feedfacedeadbeeffeedfacedeadbeefabaddad2",
    tag: "5BC94FBC3221A5DB94FAE95AE7121A47",
    data: "42831EC2217774244B7221B784D0D49CE3AA212F2C02A4E035C17E2329ACA12E21D514B25466931C7D8F6A5AAC84AA051BA30B396A0AAC973D58E091",
  };
  const good = runCatch({ ...base });
  assert.equal(good.ok, true);
  // Tamper one byte of ciphertext.
  const bad = { ...base, data: "42831EC2217774244B7221B784D0D49CE3AA212F2C02A4E035C17E2329ACA12F21D514B25466931C7D8F6A5AAC84AA051BA30B396A0AAC973D58E091" };
  const res = runCatch(bad);
  assert.equal(res.ok, false);
  assert.equal(res.code, "AUTHENTICATION_FAILED");
});

test("round-trip across padding schemes (AES-128 CBC)", () => {
  const key = "2b7e151628aed2a6abf7158809cf4f3c";
  const iv = "000102030405060708090a0b0c0d0e0f";
  // Unaligned plaintext: pkcs7 / iso7816-4 / iso9797-1-m2 can all be unpadded.
  const pt = "4142434445464748494a4b4c4d4e4f505152535455565758595a6162636465666768696a";
  for (const scheme of ["pkcs7", "iso7816-4", "iso9797-1-m2"] as const) {
    const enc = runCatch({ operation: "encrypt", algorithm: "AES-128", mode: "CBC", key, iv, data: pt, padding: scheme });
    assert.equal(enc.ok, true, `${scheme} encrypt`);
    const dec = runCatch({ operation: "decrypt", algorithm: "AES-128", mode: "CBC", key, iv, data: (enc.value as Record<string, string>).ciphertext, padding: scheme });
    assert.equal(dec.ok, true, `${scheme} decrypt`);
    assert.equal((dec.value as Record<string, string>).plaintext, pt.toUpperCase());
  }
});

test("ISO 9797-1-M1 round-trips only when already block-aligned (padding is non-removable)", () => {
  const key = "2b7e151628aed2a6abf7158809cf4f3c";
  const iv = "000102030405060708090a0b0c0d0e0f";
  const pt = "4142434445464748494a4b4c4d4e4f50"; // 16 bytes, block-aligned
  const enc = runCatch({ operation: "encrypt", algorithm: "AES-128", mode: "CBC", key, iv, data: pt, padding: "iso9797-1-m1" });
  assert.equal(enc.ok, true);
  const dec = runCatch({ operation: "decrypt", algorithm: "AES-128", mode: "CBC", key, iv, data: (enc.value as Record<string, string>).ciphertext, padding: "iso9797-1-m1" });
  assert.equal(dec.ok, true);
  assert.equal((dec.value as Record<string, string>).plaintext, pt.toUpperCase());
});

test("3DES-2KEY expands correctly and matches 3DES full key", () => {
  const pt = "0123456789abcdef";
  const k3 = "133457799BBCDFF1133457799BBCDFF1133457799BBCDFF1";
  const k2 = "133457799BBCDFF1133457799BBCDFF1";
  const a = runCatch({ operation: "encrypt", algorithm: "3DES", mode: "CBC", key: k3, iv: "0000000000000000", data: pt });
  const b = runCatch({ operation: "encrypt", algorithm: "3DES-2KEY", mode: "CBC", key: k2, iv: "0000000000000000", data: pt });
  assert.equal((a.value as Record<string, string>).ciphertext, (b.value as Record<string, string>).ciphertext);
});
