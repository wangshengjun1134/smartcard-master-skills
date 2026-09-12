// sc-tlv — TLV parse / encode / query engine (BER, SIMPLE, RAW).
// Pure module: all functions throw TlvError on malformed input (fail-closed).
// No dependency on any other sc-* skill.

export type Format = "ber" | "simple" | "raw";

export interface ParseOptions {
  format: Format;
  tagBytes: number;
  lengthBytes: number;
}

export interface TlvNode {
  tag: string; // uppercase hex
  length: number; // byte length of value
  value: string; // uppercase hex of the value bytes
  constructed: boolean;
  children: TlvNode[];
  name?: string; // only present when pretty + known tag
}

export class TlvError extends Error {
  code: string;
  constructor(code: string, message: string) {
    super(message);
    this.code = code;
    this.name = "TlvError";
  }
}

function hexToBytes(s: string): Uint8Array {
  if (s.length % 2 !== 0) throw new TlvError("INVALID_HEX", "hex string must have even length");
  if (s.length > 0 && !/^[0-9A-Fa-f]+$/.test(s)) throw new TlvError("INVALID_HEX", "invalid hex character");
  const out = new Uint8Array(s.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(s.slice(i * 2, i * 2 + 2), 16);
  return out;
}

function bytesToHex(b: Uint8Array): string {
  let s = "";
  for (let i = 0; i < b.length; i++) s += b[i].toString(16).padStart(2, "0").toUpperCase();
  return s;
}

export function toHex(b: Uint8Array): string {
  return bytesToHex(b);
}

// ---------- tag / length readers ----------

function readTag(bytes: Uint8Array, offset: number, opts: ParseOptions): { tag: string; constructed: boolean; next: number } {
  if (offset >= bytes.length) throw new TlvError("MALFORMED_TLV", "truncated tag");
  if (opts.format === "ber") {
    const first = bytes[offset];
    const constructed = (first & 0x20) !== 0;
    if ((first & 0x1f) === 0x1f) {
      // multi-byte tag: continue while high bit set
      let next = offset + 1;
      let count = 1;
      while (next < bytes.length && (bytes[next] & 0x80) !== 0) {
        next++;
        count++;
        if (count > 8) throw new TlvError("MALFORMED_TLV", "tag too long");
      }
      if (next >= bytes.length) throw new TlvError("MALFORMED_TLV", "truncated multi-byte tag");
      next++; // consume the final tag byte (high bit clear)
      return { tag: bytesToHex(bytes.subarray(offset, next)), constructed, next };
    }
    return { tag: bytesToHex(bytes.subarray(offset, offset + 1)), constructed, next: offset + 1 };
  }
  // simple / raw: fixed tag byte count
  if (offset + opts.tagBytes > bytes.length) throw new TlvError("MALFORMED_TLV", "truncated tag");
  const first = bytes[offset];
  const constructed = (first & 0x20) !== 0;
  return { tag: bytesToHex(bytes.subarray(offset, offset + opts.tagBytes)), constructed, next: offset + opts.tagBytes };
}

function readLength(bytes: Uint8Array, offset: number, opts: ParseOptions): { length: number; next: number } {
  if (opts.format === "ber") {
    if (offset >= bytes.length) throw new TlvError("MALFORMED_TLV", "truncated length");
    const l0 = bytes[offset];
    if (l0 < 0x80) return { length: l0, next: offset + 1 };
    if (l0 === 0x80) throw new TlvError("UNSUPPORTED_LENGTH_FORM", "indefinite length form is not supported");
    if (l0 === 0xff) throw new TlvError("MALFORMED_TLV", "reserved length byte 0xFF");
    const n = l0 & 0x7f; // 1..4 per spec
    if (n > 4) throw new TlvError("MALFORMED_TLV", "long-form length with more than 4 bytes");
    if (offset + 1 + n > bytes.length) throw new TlvError("MALFORMED_TLV", "truncated long-form length");
    let len = 0;
    for (let i = 0; i < n; i++) len = (len << 8) | bytes[offset + 1 + i];
    return { length: len, next: offset + 1 + n };
  }
  if (opts.format === "simple") {
    if (offset >= bytes.length) throw new TlvError("MALFORMED_TLV", "truncated length");
    return { length: bytes[offset], next: offset + 1 };
  }
  // raw: fixed length byte count
  if (offset + opts.lengthBytes > bytes.length) throw new TlvError("MALFORMED_TLV", "truncated length");
  let len = 0;
  for (let i = 0; i < opts.lengthBytes; i++) len = (len << 8) | bytes[offset + i];
  return { length: len, next: offset + opts.lengthBytes };
}

function readElement(bytes: Uint8Array, offset: number, opts: ParseOptions, nameOf: (t: string) => string | undefined): { node: TlvNode; next: number } {
  const tagRes = readTag(bytes, offset, opts);
  const lenRes = readLength(bytes, tagRes.next, opts);
  const valueStart = lenRes.next;
  const valueEnd = valueStart + lenRes.length;
  if (valueEnd > bytes.length) throw new TlvError("MALFORMED_TLV", "length exceeds remaining bytes");
  const valueBytes = bytes.subarray(valueStart, valueEnd);
  let children: TlvNode[] = [];
  if (tagRes.constructed && lenRes.length > 0) {
    children = parseList(valueBytes, opts, nameOf);
  }
  const node: TlvNode = {
    tag: tagRes.tag,
    length: lenRes.length,
    value: bytesToHex(valueBytes),
    constructed: tagRes.constructed,
    children,
  };
  if (tagRes.constructed && nameOf) {
    const nm = nameOf(tagRes.tag);
    if (nm) node.name = nm;
  }
  return { node, next: valueEnd };
}

function parseList(bytes: Uint8Array, opts: ParseOptions, nameOf: (t: string) => string | undefined): TlvNode[] {
  const nodes: TlvNode[] = [];
  let off = 0;
  while (off < bytes.length) {
    const res = readElement(bytes, off, opts, nameOf);
    nodes.push(res.node);
    off = res.next;
  }
  if (off !== bytes.length) throw new TlvError("MALFORMED_TLV", "trailing bytes after TLV elements");
  return nodes;
}

// ---------- public parse ----------

export function parseTlv(hex: string, opts: ParseOptions, nameOf?: (t: string) => string | undefined): TlvNode[] {
  if (hex.length === 0) return [];
  const bytes = hexToBytes(hex);
  return parseList(bytes, opts, nameOf ?? ((_t: string) => undefined));
}

// ---------- encode ----------

function encodeLength(length: number, opts: ParseOptions): Uint8Array {
  if (opts.format === "ber") {
    if (length < 0x80) return new Uint8Array([length]);
    const arr: number[] = [];
    let tmp = length;
    while (tmp > 0) {
      arr.push(tmp & 0xff);
      tmp >>= 8;
    }
    arr.reverse();
    if (arr.length > 4) throw new TlvError("MALFORMED_TLV", "length requires more than 4 bytes");
    return new Uint8Array([0x80 | arr.length, ...arr]);
  }
  if (opts.format === "simple") {
    if (length > 0xff) throw new TlvError("INVALID_INPUT", "SIMPLE-TLV length exceeds 1 byte");
    return new Uint8Array([length]);
  }
  // raw
  const arr: number[] = [];
  let tmp = length;
  for (let i = 0; i < opts.lengthBytes; i++) {
    arr.push(tmp & 0xff);
    tmp >>= 8;
  }
  arr.reverse();
  if (tmp !== 0) throw new TlvError("INVALID_INPUT", "RAW-TLV length exceeds configured length bytes");
  return new Uint8Array(arr);
}

function encodeNode(node: TlvNode, opts: ParseOptions): Uint8Array {
  const tagBytes = hexToBytes(node.tag);
  if (tagBytes.length === 0) throw new TlvError("INVALID_INPUT", "empty tag");
  if (node.constructed) tagBytes[0] |= 0x20;
  else tagBytes[0] &= ~0x20;

  let valueBytes: Uint8Array;
  if (node.constructed) valueBytes = encodeList(node.children, opts);
  else valueBytes = hexToBytes(node.value || "");

  const lenBytes = encodeLength(valueBytes.length, opts);
  const out = new Uint8Array(tagBytes.length + lenBytes.length + valueBytes.length);
  out.set(tagBytes, 0);
  out.set(lenBytes, tagBytes.length);
  out.set(valueBytes, tagBytes.length + lenBytes.length);
  return out;
}

export function encodeList(nodes: TlvNode[], opts: ParseOptions): Uint8Array {
  const parts: Uint8Array[] = [];
  let total = 0;
  for (const n of nodes) {
    const e = encodeNode(n, opts);
    parts.push(e);
    total += e.length;
  }
  const out = new Uint8Array(total);
  let off = 0;
  for (const p of parts) {
    out.set(p, off);
    off += p.length;
  }
  return out;
}

// ---------- queries ----------

export function findNode(nodes: TlvNode[], tag: string, prefix: string): { node: TlvNode; path: string } | null {
  const want = tag.toUpperCase();
  for (const n of nodes) {
    const path = prefix ? prefix + "/" + n.tag : n.tag;
    if (n.tag.toUpperCase() === want) return { node: n, path };
    if (n.children.length) {
      const r = findNode(n.children, tag, path);
      if (r) return r;
    }
  }
  return null;
}

export function flatten(nodes: TlvNode[], prefix: string, acc: { path: string; tag: string; value: string }[]): void {
  for (const n of nodes) {
    const path = prefix ? prefix + "/" + n.tag : n.tag;
    if (!n.constructed) acc.push({ path, tag: n.tag, value: n.value });
    if (n.children.length) flatten(n.children, path, acc);
  }
}

export function setFirst(nodes: TlvNode[], tag: string, value: string): boolean {
  const want = tag.toUpperCase();
  for (let i = 0; i < nodes.length; i++) {
    if (nodes[i].tag.toUpperCase() === want) {
      nodes[i] = { tag: nodes[i].tag, length: value.length / 2, value, constructed: false, children: [] };
      return true;
    }
  }
  for (const n of nodes) {
    if (n.children.length && setFirst(n.children, tag, value)) return true;
  }
  return false;
}

export function deleteFirst(nodes: TlvNode[], tag: string): boolean {
  const want = tag.toUpperCase();
  for (let i = 0; i < nodes.length; i++) {
    if (nodes[i].tag.toUpperCase() === want) {
      nodes.splice(i, 1);
      return true;
    }
  }
  for (const n of nodes) {
    if (n.children.length && deleteFirst(n.children, tag)) return true;
  }
  return false;
}

// ---------- helpers for pretty printing ----------

export function prettyTree(nodes: TlvNode[], indent: string): string {
  let s = "";
  for (const n of nodes) {
    let line = indent + n.tag;
    if (n.constructed) line += " (constructed)";
    if (n.name) line += " [" + n.name + "]";
    line += " len=" + n.length;
    if (!n.constructed) line += " = " + n.value;
    s += line + "\n";
    if (n.children.length) s += prettyTree(n.children, indent + "  ");
  }
  return s;
}
