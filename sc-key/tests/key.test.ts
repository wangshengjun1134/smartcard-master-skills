// sc-key tests: RFC 3394 / RFC 5869 / PBKDF2 / GM-T vectors, plus error paths.

import { test } from "node:test";
import assert from "node:assert";
import { readFileSync } from "node:fs";
import { hkdfSync, pbkdf2Sync } from "node:crypto";
import { run } from "../scripts/key.ts";
import { aesKeyWrap, aesKeyUnwrap, aesKwpWrap, aesKwpUnwrap } from "../algorithms/aeskw.ts";
import { kdfHkdf, kdfPbkdf2, kdfX963 } from "../algorithms/kdf.ts";
import { computeKcv, diversify } from "../algorithms/diversify.ts";
import { sm3 } from "../algorithms/sm3.ts";
import { fromHex, toHex, adjustParity } from "../algorithms/util.ts";

const V = JSON.parse(readFileSync(new URL("./vectors/key.json", import.meta.url), "utf8"));
const H = (s: string) => fromHex(s);

// ---------- AES key wrap (RFC 3394) ----------

test("AES-KW matches all RFC 3394 vectors", () => {
  for (const t of V.aeskw) {
    const w = toHex(aesKeyWrap(H(t.kek), H(t.key)));
    assert.equal(w, t.wrapped, `${t.name}: wrap mismatch`);
    const back = toHex(aesKeyUnwrap(H(t.kek), H(t.wrapped)));
    assert.equal(back, t.key.toUpperCase(), `${t.name}: unwrap mismatch`);
  }
});

test("AES-KW unwrap detects a corrupted integrity check", () => {
  const kek = H("000102030405060708090A0B0C0D0E0F");
  const good = aesKeyWrap(kek, H("00112233445566778899AABBCCDDEEFF"));
  const bad = Buffer.from(good);
  bad[0] ^= 0xff; // corrupt the first byte of the A value
  assert.throws(() => aesKeyUnwrap(kek, bad), (e: any) => e.code === "INTEGRITY_CHECK_FAILED");
});

test("AES-KWP round trips arbitrary-length keys", () => {
  const kek = H("000102030405060708090A0B0C0D0E0F1011121314151617");
  for (const len of [1, 7, 16, 20, 32]) {
    const key = Buffer.alloc(len, 0xa5);
    const wrapped = aesKwpWrap(kek, key);
    assert.equal(wrapped.length % 8, 0, "KWP output must be a multiple of 8");
    assert.equal(toHex(aesKwpUnwrap(kek, wrapped)), toHex(key));
  }
});

// ---------- KDF ----------

test("HKDF matches RFC 5869 TC1 and TC3", () => {
  for (const t of V.hkdf) {
    const out = kdfHkdf(H(t.ikm), H(t.salt), H(t.info), t.okm.length / 2, t.hash);
    assert.equal(toHex(out), t.okm, `${t.name} mismatch`);
  }
});

test("HKDF agrees with node:crypto for non-standard parameters", () => {
  const ikm = H("0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B");
  const salt = H("000102030405060708090A0B0C0D0E0F");
  const info = H("F0F1F2F3F4F5F6F7F8F9");
  const mine = kdfHkdf(ikm, salt, info, 42, "SHA-256");
  const theirs = Buffer.from(hkdfSync("sha256", ikm, salt, info, 42));
  assert.equal(toHex(mine), toHex(theirs));
});

test("PBKDF2 matches the reference vector and node:crypto", () => {
  for (const t of V.pbkdf2) {
    const out = kdfPbkdf2(H(t.password), H(t.salt), t.iterations, t.keylen, t.hash);
    assert.equal(toHex(out), t.key, `${t.name} mismatch`);
  }
  const mine = kdfPbkdf2(H("70617373776F7264"), H("73616C74"), 2048, 32, "SHA-256");
  const theirs = pbkdf2Sync(H("70617373776F7264"), H("73616C74"), 2048, 32, "sha256");
  assert.equal(toHex(mine), toHex(theirs));
});

test("HKDF-SM3 is self-consistent and differs from HKDF-SHA256", () => {
  const ikm = H("0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B");
  const a = kdfHkdf(ikm, H("0001020304050607"), H("F0F1"), 32, "SM3");
  const b = kdfHkdf(ikm, H("0001020304050607"), H("F0F1"), 32, "SHA-256");
  assert.equal(a.length, 32);
  assert.notEqual(toHex(a), toHex(b));
  // Deterministic.
  assert.equal(toHex(kdfHkdf(ikm, H("0001020304050607"), H("F0F1"), 32, "SM3")), toHex(a));
});

test("X9.63 KDF is deterministic and length-flexible", () => {
  const shared = H("00112233445566778899AABBCCDDEEFF");
  const a = kdfX963(shared, H("AABB"), 16, "SHA-256");
  const b = kdfX963(shared, H("AABB"), 32, "SHA-256");
  assert.equal(toHex(a), toHex(b).slice(0, 32), "longer output extends the shorter one");
  assert.equal(kdfX963(shared, H("AABB"), 16, "SHA-256").toString("hex"), a.toString("hex"));
});

// ---------- SM3 ----------

test("SM3 matches GM/T 0004", () => {
  for (const t of V.sm3) {
    assert.equal(toHex(sm3(H(t.data))), t.hash, `${t.name} mismatch`);
  }
});

// ---------- generate ----------

test("generate produces the right key sizes", () => {
  const sizes: Record<string, number> = { "AES-128": 16, "AES-192": 24, "AES-256": 32, SM4: 16, "3DES": 24 };
  for (const [algo, len] of Object.entries(sizes)) {
    const r = run({ operation: "generate", algorithm: algo }) as any;
    assert.equal(r.ok, true, JSON.stringify(r));
    assert.equal(r.length, len);
    assert.equal(r.key.length, len * 2);
  }
});

test("generate returns different keys on each call", () => {
  const a = (run({ operation: "generate", algorithm: "AES-256" }) as any).key;
  const b = (run({ operation: "generate", algorithm: "AES-256" }) as any).key;
  assert.notEqual(a, b);
});

test("generate rejects a wrong length for a fixed-size algorithm", () => {
  assert.throws(
    () => run({ operation: "generate", algorithm: "AES-128", length: 32 }),
    (e: any) => e.code === "INVALID_PARAMETER",
  );
});

test("3DES keys are generated with odd parity", () => {
  const key = H((run({ operation: "generate", algorithm: "3DES" }) as any).key);
  assert.equal(toHex(adjustParity(key)), toHex(key));
});

// ---------- KCV ----------

test("KCV is deterministic and 3 bytes", () => {
  const key = "000102030405060708090A0B0C0D0E0F";
  for (const algo of ["KCV-ZERO", "KCV-CMAC", "KCV-SHA256"]) {
    const a = run({ operation: "kcv", algorithm: algo, key }) as any;
    const b = run({ operation: "kcv", algorithm: algo, key }) as any;
    assert.equal(a.kcv, b.kcv);
    assert.equal(a.kcv.length, 6);
  }
});

test("different KCV algorithms give different values", () => {
  const key = "000102030405060708090A0B0C0D0E0F";
  const vals = ["KCV-ZERO", "KCV-CMAC", "KCV-SHA256"].map(
    (a) => (run({ operation: "kcv", algorithm: a, key }) as any).kcv,
  );
  assert.equal(new Set(vals).size, 3);
});

// ---------- diversification ----------

test("diversification is deterministic and input dependent", () => {
  const master = H("000102030405060708090A0B0C0D0E0F");
  const a = diversify("NXP-AES128", master, H("0102030405060708"));
  const b = diversify("NXP-AES128", master, H("0102030405060708"));
  const c = diversify("NXP-AES128", master, H("0102030405060709"));
  assert.equal(toHex(a), toHex(b));
  assert.notEqual(toHex(a), toHex(c));
});

test("diversification output length is correct", () => {
  const master = H("000102030405060708090A0B0C0D0E0F");
  assert.equal(diversify("NXP-AES128", master, H("0102030405060708")).length, 16);
  assert.equal(diversify("AES-ECB", master, H("0102030405060708090A0B0C0D0E0F10")).length, 16);
  assert.equal(diversify("3DES", H("0102030405060708090A0B0C0D0E0F101112131415161718"), H("0102030405060708")).length, 16);
});

test("diversify never echoes the master key", () => {
  const master = "000102030405060708090A0B0C0D0E0F";
  const r = run({ operation: "diversify", algorithm: "NXP-AES128", key: master, data: "0102030405060708" }) as any;
  const serialised = JSON.stringify(r);
  assert.ok(!serialised.includes(master), "master key must not appear in the output");
});

// ---------- CLI plumbing & errors ----------

test("wrap and unwrap round trip through the CLI", () => {
  const kek = "000102030405060708090A0B0C0D0E0F";
  const key = "00112233445566778899AABBCCDDEEFF";
  const w = run({ operation: "wrap", algorithm: "AES-KW", kek, data: key }) as any;
  assert.equal(w.wrapped, "1FA68B0A8112B447AEF34BD8FB5A7B829D3E862371D2CFE5");
  const u = run({ operation: "unwrap", algorithm: "AES-KW", kek, data: w.wrapped }) as any;
  assert.equal(u.key, key);
});

test("derive records its parameters for audit", () => {
  const r = run({
    operation: "derive",
    algorithm: "PBKDF2",
    password: "70617373776F7264",
    salt: "73616C74",
    iterations: 1000,
    keylen: 32,
    hash: "SHA-256",
  }) as any;
  assert.equal(r.ok, true);
  assert.equal(r.params.iterations, 1000);
  assert.equal(r.params.hash, "SHA-256");
  assert.equal(r.params.keylen, 32);
});

test("missing required fields are rejected", () => {
  assert.throws(
    () => run({ operation: "wrap", algorithm: "AES-KW", data: "00" }),
    (e: any) => e.code === "MISSING_PARAMETER",
  );
  assert.throws(
    () => run({ operation: "kcv", algorithm: "KCV-CMAC" }),
    (e: any) => e.code === "MISSING_PARAMETER",
  );
  assert.throws(
    () => run({ operation: "teleport", algorithm: "AES-KW" }),
    (e: any) => e.code === "UNSUPPORTED_OPERATION",
  );
  assert.throws(
    () => run({ operation: "wrap", algorithm: "ROT13", kek: "00", data: "00" }),
    (e: any) => e.code === "UNSUPPORTED_ALGORITHM",
  );
});

test("invalid hex is rejected", () => {
  assert.throws(
    () => run({ operation: "kcv", algorithm: "KCV-CMAC", key: "ZZZZ" }),
    (e: any) => e.code === "INVALID_HEX",
  );
});
