# sc-bitfield

Bit and byte field operations on binary data.

## Operations

`get`
`set`
`extract`
`insert`
`mask`
`shift`
`count`
`reverse`
`msb`
`lsb`

## Algorithms

Bit field primitives: mask, shift, extract, insert, popcount, bit reversal.

## Input

| Field | Type | Required | Description |
|---|---|---|---|
| operation | string | yes | one of Operations above |
| data | hex | yes | input bytes |
| bit_offset | integer | get/set/extract/insert | start bit index (0-based) |
| bit_length | integer | get/set/extract/insert/mask | field width in bits |
| value | integer or hex | set/insert | value to write |
| direction | string | shift | `left` (default) or `right` |
| shift | integer | shift | number of bits |
| mask | hex | mask (optional) | apply this mask instead of generating one |
| bit_order | string | no | `msb` (default) or `lsb` |

## Output

```json
{ "ok": true, "operation": "get", "bit_order": "msb", "value": "35", "bits": 8, "hex": "23" }
```

`set`/`insert`/`shift`/`reverse`/`mask` return `"data": "HEX"`; `count` returns `"count": N`.

## Rules

- Binary input/output: HEX (uppercase).
- `bit_order` default is `msb`: bit 0 is the most significant bit of byte 0.
- `bit_order=lsb`: bit 0 is the least significant bit of byte 0 (weight 2^0).
- Out-of-range fields return `OUT_OF_RANGE`; they are never silently truncated.
- `set` only modifies the addressed bits; all other bits are preserved.
