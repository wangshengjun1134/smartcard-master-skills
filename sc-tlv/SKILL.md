# sc-tlv

TLV parse / encode / query for smart-card and EMV data.

## Operations

`parse`
`encode`
`find`
`set`
`delete`
`flatten`

## Formats

`ber` (default, BER-TLV) `simple` (1-byte tag + 1-byte length) `raw` (configurable tag/length bytes)

## Input

| Field | Type | Required | Description |
|---|---|---|---|
| operation | string | yes | parse / encode / find / set / delete / flatten |
| data | hex | parse/find/set/delete/flatten | TLV bytes |
| items | array | encode | nodes: {"tag","value"} or {"tag","children":[...]} |
| tag | hex | find/set/delete | target tag |
| value | hex | set | new value |
| format | string | no | ber / simple / raw (default ber) |
| pretty | bool | no | attach tag names + text tree on parse |
| preserve_order | bool | no | default true (keep order) |
| tag_bytes | int | no | RAW format tag size (default 1) |
| length_bytes | int | no | RAW format length size (default 1) |

## Output

```json
{
  "ok": true,
  "format": "ber",
  "tree": [{ "tag": "6F", "length": 20, "value": "...", "constructed": true, "children": [] }]
}
```

## Rules

- Binary I/O: HEX (uppercase). Tags are hex strings.
- Constructed TLV: tag bit5 (0x20) set -> value recursively parsed into `children`.
- BER length: short form 0x00-0x7F; long form 0x80|N (N 1..4). 0x80 (indefinite) -> `UNSUPPORTED_LENGTH_FORM`; 0xFF reserved -> `MALFORMED_TLV`.
- `find` not found -> `ok:true, found:false` (not an error).
- Parsing is fail-closed: truncated / over-long / illegal length -> `MALFORMED_TLV`.
- Tag dictionary (algorithms/tags.ts) is metadata only; parsing never depends on it.
