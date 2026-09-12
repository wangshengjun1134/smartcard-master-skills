// Minimal ASN.1 DER codec (only what sc-signature needs) + PEM wrapping.
// Used for SM2 signature (SEQUENCE of two INTEGERs) and SM2 key PEMs.

export interface DerNode {
  tag: number;
  content: Buffer;
  children: DerNode[] | null;
}

function encodeLength(len: number): Buffer {
  if (len < 0x80) return Buffer.from([len]);
  const out: number[] = [];
  let l = len;
  while (l > 0) {
    out.unshift(l & 0xff);
    l = l >>> 8;
  }
  return Buffer.from([0x80 | out.length, ...out]);
}

function tlv(tag: number, content: Buffer): Buffer {
  return Buffer.concat([Buffer.from([tag]), encodeLength(content.length), content]);
}

export function derSeq(children: Buffer[]): Buffer {
  return tlv(0x30, Buffer.concat(children));
}

export function derInt(n: bigint): Buffer {
  if (n < 0n) throw new Error("negative INTEGER not supported");
  let hex = n.toString(16);
  if (hex.length % 2 === 1) hex = "0" + hex;
  let bytes = Buffer.from(hex, "hex");
  if (bytes[0] & 0x80) bytes = Buffer.concat([Buffer.from([0x00]), bytes]);
  // strip unnecessary leading zero bytes (keep one if it is the only byte)
  let start = 0;
  while (start < bytes.length - 1 && bytes[start] === 0x00 && !(bytes[start + 1] & 0x80)) {
    start++;
  }
  bytes = bytes.subarray(start);
  return tlv(0x02, bytes);
}

export function derOctet(buf: Buffer): Buffer {
  return tlv(0x04, buf);
}

export function derBitString(buf: Buffer, unused: number = 0): Buffer {
  return tlv(0x03, Buffer.concat([Buffer.from([unused]), buf]));
}

export function derContext(tagNo: number, content: Buffer): Buffer {
  return tlv(0xa0 | (tagNo & 0x1f), content);
}

export function derNull(): Buffer {
  return Buffer.from([0x05, 0x00]);
}

export function derOid(contentBytes: number[]): Buffer {
  return tlv(0x06, Buffer.from(contentBytes));
}

export function derReadInt(node: DerNode): bigint {
  let v = 0n;
  for (const bt of node.content) v = (v << 8n) | BigInt(bt);
  return v;
}

export function parseDer(buf: Buffer): DerNode {
  const { node } = parseOne(buf, 0);
  return node;
}

function parseOne(buf: Buffer, start: number): { node: DerNode; next: number } {
  let pos = start;
  const tag = buf[pos++];
  let len = buf[pos++];
  if (len & 0x80) {
    const n = len & 0x7f;
    len = 0;
    for (let i = 0; i < n; i++) {
      len = (len << 8) | buf[pos++];
    }
  }
  const content = buf.subarray(pos, pos + len);
  pos += len;

  let children: DerNode[] | null = null;
  if ((tag & 0x20) !== 0) {
    children = [];
    let c = 0;
    while (c < content.length) {
      const r = parseOne(content, c);
      children.push(r.node);
      c = r.next;
    }
  }
  return { node: { tag, content, children }, next: pos };
}

// ---- SM2 signature (r, s) as DER SEQUENCE { INTEGER r, INTEGER s } ----

export function encodeSm2Signature(r: bigint, s: bigint): Buffer {
  return derSeq([derInt(r), derInt(s)]);
}

export function decodeSm2Signature(der: Buffer): { r: bigint; s: bigint } {
  const node = parseDer(der);
  if (node.tag !== 0x30 || !node.children || node.children.length !== 2) {
    throw new Error("malformed SM2 signature DER");
  }
  return { r: derReadInt(node.children[0]), s: derReadInt(node.children[1]) };
}

// ---- PEM ----

export function pemEncode(der: Buffer, label: string): string {
  const b64 = der.toString("base64");
  const lines = b64.match(/.{1,64}/g) ?? [];
  return `-----BEGIN ${label}-----\n${lines.join("\n")}\n-----END ${label}-----\n`;
}

export function pemDecode(pem: string): Buffer {
  const cleaned = pem
    .replace(/-----BEGIN [^-]+-----/, "")
    .replace(/-----END [^-]+-----/, "")
    .replace(/\s+/g, "");
  return Buffer.from(cleaned, "base64");
}
