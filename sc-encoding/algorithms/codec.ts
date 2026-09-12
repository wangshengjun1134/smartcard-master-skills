// sc-encoding — codecs for all supported representations.
// Each representation exposes two primitives:
//   toBytes(rep, str)  : parse a string in `rep` into raw bytes
//   fromBytes(rep, b)  : format raw bytes into a string in `rep`
// convert = toBytes(from) then fromBytes(to).
// decode  = toBytes(from) then hex;  encode = toBytes(hex) then fromBytes(to).

export type Rep =
  | "hex"
  | "ascii"
  | "utf8"
  | "utf-8"
  | "latin1"
  | "base64"
  | "base64url"
  | "bcd"
  | "bcd-tbcd"
  | "integer"
  | "binary";

export interface Options {
  length?: number;
  endian?: "big" | "little";
  bcd_padding?: "left" | "right";
}

export class CodecError extends Error {
  code: string;
  constructor(code: string, message: string) {
    super(message);
    this.code = code;
    this.name = "CodecError";
  }
}

const BASE64_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const BASE64URL_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

function normRep(r: string): Rep {
  if (r === "utf-8") return "utf8";
  return r as Rep;
}

// ---------- hex ----------
function hexToBytes(s: string): Uint8Array {
  if (s.length % 2 !== 0) throw new CodecError("INVALID_HEX", "hex string must have even length");
  if (s.length > 0 && !/^[0-9A-Fa-f]+$/.test(s)) throw new CodecError("INVALID_HEX", "invalid hex character");
  const out = new Uint8Array(s.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(s.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

function bytesToHex(b: Uint8Array): string {
  let s = "";
  for (let i = 0; i < b.length; i++) {
    s += b[i].toString(16).padStart(2, "0").toUpperCase();
  }
  return s;
}

// ---------- ascii (0x00-0x7F) ----------
function asciiToBytes(s: string): Uint8Array {
  const out = new Uint8Array(s.length);
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (c > 0x7f) throw new CodecError("INVALID_INPUT", "ascii requires characters in range 0x00-0x7F");
    out[i] = c;
  }
  return out;
}

function asciiFromBytes(b: Uint8Array): string {
  let s = "";
  for (let i = 0; i < b.length; i++) {
    if (b[i] > 0x7f) throw new CodecError("INVALID_INPUT", "byte out of ascii range 0x00-0x7F");
    s += String.fromCharCode(b[i]);
  }
  return s;
}

// ---------- latin1 (0x00-0xFF) ----------
function latin1ToBytes(s: string): Uint8Array {
  const out = new Uint8Array(s.length);
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (c > 0xff) throw new CodecError("INVALID_INPUT", "latin1 requires characters in range 0x00-0xFF");
    out[i] = c;
  }
  return out;
}

function latin1FromBytes(b: Uint8Array): string {
  let s = "";
  for (let i = 0; i < b.length; i++) s += String.fromCharCode(b[i]);
  return s;
}

// ---------- utf8 ----------
function utf8ToBytes(s: string): Uint8Array {
  return new TextEncoder().encode(s);
}

function utf8FromBytes(b: Uint8Array): string {
  return new TextDecoder("utf-8", { fatal: true }).decode(b);
}

// ---------- base64 / base64url ----------
function b64decode(str: string, urlSafe: boolean): Uint8Array {
  const alphabet = urlSafe ? BASE64URL_CHARS : BASE64_CHARS;
  const rev = new Int16Array(256).fill(-1);
  for (let i = 0; i < alphabet.length; i++) rev[alphabet.charCodeAt(i)] = i;
  // '=' is only legal as trailing padding; reject any other placement.
  const m = str.match(/^([^=]*)(=*)$/);
  if (!m) throw new CodecError("INVALID_BASE64", "invalid base64 padding");
  const data = m[1];
  const pad = m[2];
  if (data.length % 4 === 1) throw new CodecError("INVALID_BASE64", "invalid base64 length");
  if (data.length === 0 && pad.length > 0) throw new CodecError("INVALID_BASE64", "invalid base64: padding only");
  for (let i = 0; i < data.length; i++) {
    if (rev[data.charCodeAt(i)] < 0) throw new CodecError("INVALID_BASE64", "invalid base64 character");
  }
  const out: number[] = [];
  for (let i = 0; i < data.length; i += 4) {
    const c0 = rev[data.charCodeAt(i)];
    const c1 = rev[data.charCodeAt(i + 1)];
    const c2 = i + 2 < data.length ? rev[data.charCodeAt(i + 2)] : -1;
    const c3 = i + 3 < data.length ? rev[data.charCodeAt(i + 3)] : -1;
    if (c0 < 0 || c1 < 0) throw new CodecError("INVALID_BASE64", "invalid base64 character");
    if (c2 < 0 && c3 >= 0) throw new CodecError("INVALID_BASE64", "invalid base64 padding");
    out.push((c0 << 2) | (c1 >> 4));
    if (c2 >= 0) out.push(((c1 & 0x0f) << 4) | (c2 >> 2));
    if (c3 >= 0) out.push(((c2 & 0x03) << 6) | c3);
  }
  return new Uint8Array(out);
}

function b64encode(bytes: Uint8Array, urlSafe: boolean): string {
  const alphabet = urlSafe ? BASE64URL_CHARS : BASE64_CHARS;
  let s = "";
  for (let i = 0; i < bytes.length; i += 3) {
    const b0 = bytes[i];
    const b1 = i + 1 < bytes.length ? bytes[i + 1] : 0;
    const b2 = i + 2 < bytes.length ? bytes[i + 2] : 0;
    const n = (b0 << 16) | (b1 << 8) | b2;
    s += alphabet[(n >> 18) & 0x3f];
    s += alphabet[(n >> 12) & 0x3f];
    if (i + 1 < bytes.length) s += alphabet[(n >> 6) & 0x3f];
    if (i + 2 < bytes.length) s += alphabet[n & 0x3f];
  }
  if (!urlSafe) {
    const rem = bytes.length % 3;
    if (rem === 1) s += "==";
    else if (rem === 2) s += "=";
  }
  return s;
}

// ---------- binary (0/1 string) ----------
function binaryToBytes(s: string): Uint8Array {
  if (s.length % 8 !== 0) throw new CodecError("INVALID_INPUT", "binary string length must be a multiple of 8");
  if (s.length > 0 && !/^[01]+$/.test(s)) throw new CodecError("INVALID_INPUT", "binary string must contain only 0/1");
  const out = new Uint8Array(s.length / 8);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(s.slice(i * 8, i * 8 + 8), 2);
  }
  return out;
}

function bytesToBinary(b: Uint8Array): string {
  let s = "";
  for (let i = 0; i < b.length; i++) s += b[i].toString(2).padStart(8, "0");
  return s;
}

// ---------- integer (unsigned big-endian/little-endian) ----------
function integerToBytes(s: string, opts: Options): Uint8Array {
  let v: bigint;
  try {
    if (s.startsWith("0x") || s.startsWith("0X")) v = BigInt(s);
    else {
      if (!/^[0-9]+$/.test(s)) throw new CodecError("INVALID_INPUT", "integer must be an unsigned decimal string");
      v = BigInt(s);
    }
  } catch (e) {
    if (e instanceof CodecError) throw e;
    throw new CodecError("INVALID_INPUT", "invalid integer value");
  }
  if (v < 0n) throw new CodecError("INVALID_INPUT", "integer must be non-negative");
  const little = opts.endian === "little";
  if (opts.length !== undefined) {
    const len = opts.length;
    if (len < 0 || !Number.isInteger(len)) throw new CodecError("INVALID_INPUT", "length must be a non-negative integer");
    const bytes = new Uint8Array(len);
    let tmp = v;
    for (let i = 0; i < len; i++) {
      const idx = little ? i : len - 1 - i;
      bytes[idx] = Number(tmp & 0xffn);
      tmp >>= 8n;
    }
    if (tmp !== 0n) throw new CodecError("INVALID_INPUT", "integer value exceeds specified length");
    return bytes;
  }
  if (v === 0n) return new Uint8Array([0]);
  const arr: number[] = [];
  let tmp = v;
  while (tmp > 0n) {
    arr.push(Number(tmp & 0xffn));
    tmp >>= 8n;
  }
  return new Uint8Array(little ? arr : arr.reverse());
}

function integerFromBytes(b: Uint8Array, opts: Options): string {
  const little = opts.endian === "little";
  let v = 0n;
  if (little) {
    for (let i = b.length - 1; i >= 0; i--) v = (v << 8n) | BigInt(b[i]);
  } else {
    for (let i = 0; i < b.length; i++) v = (v << 8n) | BigInt(b[i]);
  }
  return v.toString(10);
}

// ---------- BCD (8421) ----------
function bcdToBytes(s: string, opts: Options): Uint8Array {
  if (s.length > 0 && !/^[0-9]+$/.test(s)) throw new CodecError("INVALID_BCD", "BCD digits must be 0-9");
  const padding = opts.bcd_padding ?? "right";
  let digits = s;
  if (digits.length % 2 !== 0) {
    digits = padding === "right" ? "0" + digits : digits + "0";
  }
  if (opts.length !== undefined) {
    const need = opts.length * 2;
    if (digits.length > need) throw new CodecError("INVALID_BCD", "BCD data exceeds specified length");
    digits = padding === "right" ? digits.padStart(need, "0") : digits.padEnd(need, "0");
  }
  const out = new Uint8Array(digits.length / 2);
  for (let i = 0; i < out.length; i++) {
    const hi = digits.charCodeAt(i * 2) - 48;
    const lo = digits.charCodeAt(i * 2 + 1) - 48;
    out[i] = (hi << 4) | lo;
  }
  return out;
}

function bytesToBcd(b: Uint8Array): string {
  let s = "";
  for (let i = 0; i < b.length; i++) {
    s += ((b[i] >> 4) & 0xf).toString();
    s += (b[i] & 0xf).toString();
  }
  return s;
}

// ---------- TBCD (compressed BCD, nibble swapped) ----------
function tbcdCharToNibble(c: string): number {
  if (c >= "0" && c <= "9") return c.charCodeAt(0) - 48;
  if (c === "*") return 0x0a;
  if (c === "#") return 0x0b;
  if (c === "a") return 0x0c;
  if (c === "b") return 0x0d;
  if (c === "c") return 0x0e;
  throw new CodecError("INVALID_BCD", "invalid TBCD character (allowed: 0-9 * # a b c)");
}

function nibbleToTbcdChar(n: number): string {
  if (n <= 9) return n.toString();
  if (n === 0x0a) return "*";
  if (n === 0x0b) return "#";
  if (n === 0x0c) return "a";
  if (n === 0x0d) return "b";
  if (n === 0x0e) return "c";
  return ""; // 0x0F padding
}

function tbcdToBytes(s: string): Uint8Array {
  const out: number[] = [];
  let i = 0;
  while (i < s.length) {
    const c1 = tbcdCharToNibble(s[i]); // low nibble
    if (i + 1 < s.length) {
      const c2 = tbcdCharToNibble(s[i + 1]); // high nibble
      out.push((c2 << 4) | c1);
      i += 2;
    } else {
      out.push((0x0f << 4) | c1); // trailing padding nibble
      i += 1;
    }
  }
  return new Uint8Array(out);
}

function bytesToTbcd(b: Uint8Array): string {
  let s = "";
  for (let i = 0; i < b.length; i++) {
    const lo = b[i] & 0x0f;
    const hi = (b[i] >> 4) & 0x0f;
    const loC = nibbleToTbcdChar(lo);
    if (loC === "") continue;
    s += loC;
    const hiC = nibbleToTbcdChar(hi);
    if (hiC === "") break; // 0x0F padding -> end of digit string
    s += hiC;
  }
  return s;
}

// ---------- registry ----------
export function toBytes(rep: string, data: string, opts: Options): Uint8Array {
  const r = normRep(rep);
  switch (r) {
    case "hex": return hexToBytes(data);
    case "ascii": return asciiToBytes(data);
    case "utf8": return utf8ToBytes(data);
    case "latin1": return latin1ToBytes(data);
    case "base64": return b64decode(data, false);
    case "base64url": return b64decode(data, true);
    case "binary": return binaryToBytes(data);
    case "bcd": return bcdToBytes(data, opts);
    case "bcd-tbcd": return tbcdToBytes(data);
    case "integer": return integerToBytes(data, opts);
    default: throw new CodecError("UNSUPPORTED_PARAMETER", `unknown representation: ${rep}`);
  }
}

export function fromBytes(rep: string, bytes: Uint8Array, opts: Options): string {
  const r = normRep(rep);
  switch (r) {
    case "hex": return bytesToHex(bytes);
    case "ascii": return asciiFromBytes(bytes);
    case "utf8": return utf8FromBytes(bytes);
    case "latin1": return latin1FromBytes(bytes);
    case "base64": return b64encode(bytes, false);
    case "base64url": return b64encode(bytes, true);
    case "binary": return bytesToBinary(bytes);
    case "bcd": return bytesToBcd(bytes);
    case "bcd-tbcd": return bytesToTbcd(bytes);
    case "integer": return integerFromBytes(bytes, opts);
    default: throw new CodecError("UNSUPPORTED_PARAMETER", `unknown representation: ${rep}`);
  }
}
