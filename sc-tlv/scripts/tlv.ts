// sc-tlv CLI entry point.
// Usage:
//   node scripts/tlv.ts --input '{"operation":"parse","data":"6F0A8408A000000003000000"}'
//   node scripts/tlv.ts --input-file ./in.json
//   echo '{"operation":"..."}' | node scripts/tlv.ts

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import {
  parseTlv,
  encodeList,
  findNode,
  flatten,
  setFirst,
  deleteFirst,
  prettyTree,
  toHex,
  TlvError,
} from "../algorithms/parse.ts";
import type { ParseOptions, TlvNode, Format } from "../algorithms/parse.ts";
import { tagName } from "../algorithms/tags.ts";

interface Item {
  tag: string;
  value?: string;
  children?: Item[];
}

interface Input {
  operation: string;
  data?: string;
  items?: Item[];
  tag?: string;
  value?: string;
  format?: string;
  pretty?: boolean;
  preserve_order?: boolean;
  tag_bytes?: number;
  length_bytes?: number;
}

const FORMATS: Format[] = ["ber", "simple", "raw"];

function buildItem(it: Item): TlvNode {
  if (it.children) {
    const children = it.children.map(buildItem);
    return { tag: it.tag, length: 0, value: "", constructed: true, children };
  }
  const value = it.value ?? "";
  return { tag: it.tag, length: value.length / 2, value, constructed: false, children: [] };
}

function buildOptions(input: Input): ParseOptions {
  const format = (input.format ?? "ber") as Format;
  if (!FORMATS.includes(format)) throw new TlvError("UNSUPPORTED_PARAMETER", `unknown format: ${input.format}`);
  return {
    format,
    tagBytes: input.tag_bytes ?? 1,
    lengthBytes: input.length_bytes ?? 1,
  };
}

export function execute(input: Input): Record<string, unknown> {
  const op = input.operation;
  if (!op) throw new TlvError("MISSING_PARAMETER", "operation is required");
  const opts = buildOptions(input);
  const nameOf = (t: string) => tagName(t);

  switch (op) {
    case "parse": {
      if (input.data === undefined) throw new TlvError("MISSING_PARAMETER", "parse requires 'data'");
      const tree = parseTlv(input.data, opts, input.pretty ? nameOf : undefined);
      const out: Record<string, unknown> = { ok: true, format: opts.format, tree };
      if (input.pretty) out.pretty = prettyTree(tree, "");
      return out;
    }
    case "encode": {
      if (!input.items) throw new TlvError("MISSING_PARAMETER", "encode requires 'items'");
      const nodes = input.items.map(buildItem);
      const bytes = encodeList(nodes, opts);
      return { ok: true, data: toHex(bytes) };
    }
    case "find": {
      if (input.data === undefined) throw new TlvError("MISSING_PARAMETER", "find requires 'data'");
      if (!input.tag) throw new TlvError("MISSING_PARAMETER", "find requires 'tag'");
      const tree = parseTlv(input.data, opts);
      const r = findNode(tree, input.tag, "");
      if (r) return { ok: true, tag: input.tag.toUpperCase(), found: true, value: r.node.value, path: r.path };
      return { ok: true, tag: input.tag.toUpperCase(), found: false, value: "", path: "" };
    }
    case "flatten": {
      if (input.data === undefined) throw new TlvError("MISSING_PARAMETER", "flatten requires 'data'");
      const tree = parseTlv(input.data, opts);
      const acc: { path: string; tag: string; value: string }[] = [];
      flatten(tree, "", acc);
      return { ok: true, items: acc };
    }
    case "set": {
      if (input.data === undefined) throw new TlvError("MISSING_PARAMETER", "set requires 'data'");
      if (!input.tag) throw new TlvError("MISSING_PARAMETER", "set requires 'tag'");
      if (input.value === undefined) throw new TlvError("MISSING_PARAMETER", "set requires 'value'");
      const tree = parseTlv(input.data, opts);
      const found = setFirst(tree, input.tag, input.value);
      if (!found) {
        tree.push({ tag: input.tag.toUpperCase(), length: input.value.length / 2, value: input.value, constructed: false, children: [] });
      }
      return { ok: true, data: toHex(encodeList(tree, opts)) };
    }
    case "delete": {
      if (input.data === undefined) throw new TlvError("MISSING_PARAMETER", "delete requires 'data'");
      if (!input.tag) throw new TlvError("MISSING_PARAMETER", "delete requires 'tag'");
      const tree = parseTlv(input.data, opts);
      deleteFirst(tree, input.tag);
      return { ok: true, data: toHex(encodeList(tree, opts)) };
    }
    default:
      throw new TlvError("UNSUPPORTED_PARAMETER", `unknown operation: ${op}`);
  }
}

function fail(code: string, message: string): never {
  process.stdout.write(JSON.stringify({ ok: false, error: { code, message } }) + "\n");
  process.exit(1);
}

function readStdin(): Promise<string> {
  return new Promise((resolve, reject) => {
    let data = "";
    process.stdin.setEncoding("utf8");
    process.stdin.on("data", (c) => (data += c));
    process.stdin.on("end", () => resolve(data));
    process.stdin.on("error", reject);
  });
}

function parseArgs(argv: string[]): { input?: string; file?: string } {
  let input: string | undefined;
  let file: string | undefined;
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--input") input = argv[++i];
    else if (a === "--input-file") file = argv[++i];
  }
  return { input, file };
}

async function main(): Promise<void> {
  const { input, file } = parseArgs(process.argv.slice(2));
  let raw = "";
  try {
    if (input !== undefined) raw = input;
    else if (file !== undefined) raw = readFileSync(file, "utf8");
    else raw = await readStdin();
  } catch (e) {
    fail("MALFORMED_INPUT", `cannot read input: ${(e as Error).message}`);
  }
  if (!raw || !raw.trim()) fail("MALFORMED_INPUT", "empty input");

  let parsed: Input;
  try {
    parsed = JSON.parse(raw);
  } catch {
    fail("MALFORMED_INPUT", "input is not valid JSON");
  }

  try {
    const result = execute(parsed);
    process.stdout.write(JSON.stringify(result) + "\n");
  } catch (e) {
    if (e instanceof TlvError) fail(e.code, e.message);
    fail("INTERNAL_ERROR", (e as Error).message);
  }
}

const invokedPath = process.argv[1] ? fileURLToPath(import.meta.url) : "";
if (process.argv[1] && (process.argv[1].endsWith("scripts/tlv.ts") || invokedPath === process.argv[1])) {
  main();
}
