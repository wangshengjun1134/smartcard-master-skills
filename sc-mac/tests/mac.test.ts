// sc-mac tests: official KAT vectors + independent cross-check against node:crypto.

import { test } from "node:test";
import assert from "node:assert";
import { readFileSync } from "node:fs";
import { createHmac, createCipheriv } from "node:crypto";
import { computeMac, truncateMac, verifyMac, ALL_ALGORITHMS } from "../algorithms/mac.ts";
import { sm3 } from "../algorithms/sm3.ts";
import { retailMac, iso9797Mac, isoPad1, isoPad2 } from "../algorithms/iso9797.ts";
import { Des } from "../algorithms/des.ts";
import { hexToBytes, bytesToHex, concatBytes } from "../algorithms/hex.ts";

const V = (name: string): any[] =>
  JSON.parse(readFileSync(new URL(`./vectors/${name}`, import.meta.url), "utf8"));

// ---------- official vectors ----------

test("HMAC family matches RFC 4231 test case 1", () => {
  for (const v of V("hmac.json")) {
    const { mac } = computeMac({ algorithm: v.algorithm, key: v.key, data: v.data });
    assert.equal(bytesToHex(mac), v.mac.toUpperCase(), `${v.name} mismatch`);
  }
});

test("AES-CMAC matches RFC 4493", () => {
  for (const v of V("cmac.json")) {
    const { mac } = computeMac({ algorithm: "AES-CMAC", key: v.key, data: v.data });
    assert.equal(bytesToHex(mac), v.mac.toUpperCase(), `${v.name} mismatch`);
  }
});

test("SM3 matches GM/T 0004", () => {
  for (const v of V("sm3.json")) {
    assert.equal(bytesToHex(sm3(hexToBytes(v.data))), v.hash.toUpperCase(), `${v.name} mismatch`);
  }
});

test("SM4 block cipher matches GM/T 0002", () => {
  const v = V("sm4.json")[0];
  // Single-block SM4-MAC with zero IV == raw SM4 ECB encryption of that block.
  const { mac } = computeMac({ algorithm: "SM4-MAC", key: v.key, data: v.plaintext });
  assert.equal(bytesToHex(mac), v.ciphertext.toUpperCase());
});

// ---------- independent cross-check against node:crypto ----------

// Plain CBC-MAC implemented directly on top of node:crypto (independent path).
function refCbcMac(cipher: string, keyHex: string, dataHex: string): string {
  const key = Buffer.from(keyHex, "hex");
  const blockSize = cipher.startsWith("aes") ? 16 : 8;
  const padded = Buffer.from(dataHex, "hex");
  assert.equal(padded.length % blockSize, 0, "ref helper expects pre-padded data");
  const ci = createCipheriv(cipher, key, Buffer.alloc(blockSize === 16 ? 16 : 8));
  ci.setAutoPadding(false);
  const out = Buffer.concat([ci.update(padded), ci.final()]);
  return out.subarray(out.length - blockSize).toString("hex").toUpperCase();
}

const K24 = "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF";

test("3DES-MAC cross-check vs node:crypto des-ede3-cbc", () => {
  const data = "4869205468657265"; // exactly one 8-byte block
  const { mac } = computeMac({ algorithm: "3DES-MAC", key: K24, data });
  assert.equal(bytesToHex(mac), refCbcMac("des-ede3-cbc", K24, data));
});

test("two-key 3DES (16-byte) is expanded to K1||K2||K1", () => {
  const k16 = "0123456789ABCDEF0123456789ABCDEF";
  const expanded = k16 + k16.slice(0, 16); // K1||K2||K1
  const data = "4869205468657265";
  const a = computeMac({ algorithm: "3DES-MAC", key: k16, data });
  const b = computeMac({ algorithm: "3DES-MAC", key: expanded, data });
  assert.equal(bytesToHex(a.mac), bytesToHex(b.mac));
  assert.equal(bytesToHex(a.mac), refCbcMac("des-ede3-cbc", expanded, data));
});

test("ISO9797-1 M1 equals zero-padded CBC-MAC", () => {
  const data = "4869205468657265";
  const a = computeMac({ algorithm: "ISO9797-1-M1-MAC", cipher: "3DES", key: K24, data });
  assert.equal(bytesToHex(a.mac), refCbcMac("des-ede3-cbc", K24, data));
});

test("ISO9797-1 M2 equals 0x80-padded CBC-MAC", () => {
  const data = "4869205468657265";
  const padded = data + "8000000000000000"; // 0x80 then zeros to 16 bytes
  const a = computeMac({ algorithm: "ISO9797-1-M2-MAC", cipher: "3DES", key: K24, data });
  assert.equal(bytesToHex(a.mac), refCbcMac("des-ede3-cbc", K24, padded));
});

test("ISO9797-1 M1 and M2 differ for block-aligned input", () => {
  const data = "4869205468657265";
  const m1 = computeMac({ algorithm: "ISO9797-1-M1-MAC", cipher: "3DES", key: K24, data });
  const m2 = computeMac({ algorithm: "ISO9797-1-M2-MAC", cipher: "3DES", key: K24, data });
  assert.notEqual(bytesToHex(m1.mac), bytesToHex(m2.mac));
});

test("HMAC-SM3 matches node HMAC structure with self SM3", () => {
  // Independent recomputation of HMAC using the local SM3 primitive.
  const key = hexToBytes("0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B");
  const data = hexToBytes("4869205468657265");
  const B = 64;
  const k = new Uint8Array(B);
  k.set(key.length > B ? sm3(key) : key);
  const ipad = new Uint8Array(B);
  const opad = new Uint8Array(B);
  for (let i = 0; i < B; i++) {
    ipad[i] = k[i] ^ 0x36;
    opad[i] = k[i] ^ 0x5c;
  }
  const inner = sm3(new Uint8Array([...ipad, ...data]));
  const expect = bytesToHex(sm3(new Uint8Array([...opad, ...inner])));
  const { mac } = computeMac({ algorithm: "HMAC-SM3", key: "0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B", data: "4869205468657265" });
  assert.equal(bytesToHex(mac), expect);
});

// ---------- truncation semantics ----------

test("mac_length truncates from the left and reports truncated", () => {
  const input = { algorithm: "HMAC-SHA256", key: "0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B", data: "4869205468657265" };
  const full = bytesToHex(computeMac(input).mac);
  const { out, truncated } = truncateMac(computeMac(input).mac, 8);
  assert.equal(bytesToHex(out), full.slice(0, 16));
  assert.equal(truncated, true);
});

test("mac_length larger than full MAC is rejected", () => {
  const mac = computeMac({ algorithm: "HMAC-SHA256", key: "0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B", data: "4869205468657265" }).mac;
  assert.throws(() => truncateMac(mac, 64), /mac_length exceeds/);
});

// ---------- verify operation ----------

test("verify returns valid for correct MAC and mismatch otherwise", () => {
  const input = { algorithm: "HMAC-SHA256", key: "0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B", data: "4869205468657265" };
  const full = bytesToHex(computeMac(input).mac);
  assert.equal(verifyMac(input, full).valid, true);
  const bad = verifyMac(input, "0000000000000000000000000000000000000000000000000000000000000000");
  assert.equal(bad.valid, false);
  assert.equal(bad.actual, full);
});

// ---------- error handling ----------

test("invalid hex is rejected", () => {
  assert.throws(
    () => computeMac({ algorithm: "HMAC-SHA256", key: "ZZ", data: "4869" }),
    (e: any) => e.code === "INVALID_HEX",
  );
});

test("unsupported algorithm is rejected", () => {
  assert.throws(
    () => computeMac({ algorithm: "NOPE-MAC", key: "00", data: "00" }),
    (e: any) => e.code === "UNSUPPORTED_ALGORITHM",
  );
});

test("wrong key length for AES-CMAC is rejected", () => {
  assert.throws(
    () => computeMac({ algorithm: "AES-CMAC", key: "00112233", data: "0011" }),
    (e: any) => e.code === "INVALID_KEY_LENGTH",
  );
});

test("algorithm registry covers the documented set", () => {
  for (const a of [
    "HMAC-MD5", "HMAC-SHA1", "HMAC-SHA224", "HMAC-SHA256", "HMAC-SHA384",
    "HMAC-SHA512", "HMAC-SM3", "AES-CMAC", "3DES-CMAC", "3DES-MAC",
    "ISO9797-1-M1-MAC", "ISO9797-1-M2-MAC", "ISO9797-1-M3-MAC", "RETAIL-MAC", "SM4-MAC",
  ]) {
    assert.ok(ALL_ALGORITHMS.includes(a), `missing ${a}`);
  }
});

// ---------------------------------------------------------------------------
// ISO/IEC 9797-1: padding methods vs MAC algorithms.
//
// M1/M2/M3 name the PADDING METHOD used with MAC algorithm 1 (CBC-MAC).
// Padding method 3 = zero pad, then LEFT-prepend a block holding the bit
// length of the unpadded data. (An earlier revision wrongly appended a length
// block and re-encrypted, matching neither the padding method nor algorithm 3.)
// ---------------------------------------------------------------------------
test("ISO9797-1 M3 is padding method 3: length block is prepended, not appended", () => {
  const key = "000102030405060708090A0B0C0D0E0F";
  const data = "00112233";
  // Independent construction: L || pad1(data)
  const bitLen = 8 * 4; // 32 bits
  const expected = iso9797Mac(
    3, "AES", hexToBytes(key),
    hexToBytes(data), new Uint8Array(16),
  );
  // The padded input must be: 16-byte length block (right aligned 32) || data
  // padded to 16 -> we verify indirectly: M3 differs from M1 for the same input
  const m1 = iso9797Mac(1, "AES", hexToBytes(key), hexToBytes(data), new Uint8Array(16));
  assert.notEqual(bytesToHex(expected), bytesToHex(m1));
  assert.equal(bitLen, 32);
  // and it must equal CBC-MAC over (lengthBlock || data)
  const lb = new Uint8Array(16);
  lb[15] = 32;
  const body = new Uint8Array(16);
  body.set(hexToBytes(data));
  const manual = iso9797Mac(1, "AES", hexToBytes(key), concatBytes(lb, body), new Uint8Array(16));
  assert.equal(bytesToHex(expected), bytesToHex(manual));
});

test("padding method 1 turns empty input into one full zero block", () => {
  assert.equal(isoPad1(new Uint8Array(0), 8).length, 8);
  assert.equal(isoPad1(new Uint8Array(0), 16).length, 16);
  assert.equal(bytesToHex(isoPad1(hexToBytes("0011"), 8)), "0011000000000000");
});

test("padding method 2 always adds at least one byte", () => {
  assert.equal(bytesToHex(isoPad2(hexToBytes("0011223344556677"), 8)), "00112233445566778000000000000000");
});

test("RETAIL-MAC matches the published 2-key single-DES vector (X9.19, pad m2)", () => {
  // Source: ISO 9797-1 algorithm 3 / JavaCard ALG_DES_MAC8_ISO9797_1_M2_ALG3
  //   data 72C29C2371CC9BDB65B779B8E8D37B29ECC154AA56A8799FAE2F498F76ED92F2
  //   key  7962D9ECE03D1ACD4C76089DCE131543
  //   mac  5F1448EEA8AD90A7
  const mac = retailMac(
    "DES",
    hexToBytes("7962D9ECE03D1ACD4C76089DCE131543"),
    hexToBytes("72C29C2371CC9BDB65B779B8E8D37B29ECC154AA56A8799FAE2F498F76ED92F2"),
    "m2",
  );
  assert.equal(bytesToHex(mac), "5F1448EEA8AD90A7");
});

test("RETAIL-MAC is reachable through the public dispatch API", () => {
  const r = computeMac({
    algorithm: "RETAIL-MAC",
    cipher: "DES",
    key: "7962D9ECE03D1ACD4C76089DCE131543",
    data: "72C29C2371CC9BDB65B779B8E8D37B29ECC154AA56A8799FAE2F498F76ED92F2",
    padding: "m2",
  });
  assert.equal(bytesToHex(r.mac), "5F1448EEA8AD90A7");
});

test("RETAIL-MAC output transformation is E_K1(D_K2(H)), not a bare CBC-MAC", () => {
  const key = "7962D9ECE03D1ACD4C76089DCE131543";
  const data = "0011223344556677";
  const retail = bytesToHex(retailMac("DES", hexToBytes(key), hexToBytes(data), "m1"));
  // CBC-MAC alone (algorithm 1 + padding method 1) must differ
  const plain = bytesToHex(iso9797Mac(1, "DES", hexToBytes(key.slice(0, 16)), hexToBytes(data), new Uint8Array(8)));
  assert.notEqual(retail, plain);
});

test("single DES matches NIST known-answer vectors", () => {
  const cases = [
    ["133457799BBCDFF1", "0123456789ABCDEF", "85E813540F0AB405"],
    ["0000000000000000", "0000000000000000", "8CA64DE9C1B123A7"],
    ["FFFFFFFFFFFFFFFF", "FFFFFFFFFFFFFFFF", "7359B2163E4EDC58"],
  ] as const;
  for (const [k, p, want] of cases) {
    const got = new Des(hexToBytes(k)).encryptBlock(hexToBytes(p));
    assert.equal(bytesToHex(got), want, `DES(${k}, ${p})`);
  }
});

test("single DES round trips", () => {
  for (const k of ["133457799BBCDFF1", "7962D9ECE03D1ACD", "0123456789ABCDEF"]) {
    const d = new Des(hexToBytes(k));
    const pt = hexToBytes("0011223344556677");
    assert.equal(bytesToHex(d.decryptBlock(d.encryptBlock(pt))), "0011223344556677");
  }
});
