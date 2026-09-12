# sc-encoding

Encoding and data-representation conversion for smart-card tooling.

## Operations

`encode`
`decode`
`convert`

## Representations

`hex` `ascii` `utf8` (=`utf-8`) `latin1` `base64` `base64url` `bcd` `bcd-tbcd` `integer` `binary`

## Input

| Field | Type | Required | Description |
|---|---|---|---|
| operation | string | yes | encode / decode / convert |
| data | string | yes | input value (semantics depend on operation) |
| from | string | convert | source representation |
| to | string | convert | target representation |
| encoding | string | encode/decode | target (encode) or source (decode) representation |
| length | integer | no | fixed byte length for integer / bcd |
| endian | string | no | big (default) or little, for integer |
| bcd_padding | string | no | left or right (default), odd-length BCD padding |

## Output

```json
{
  "ok": true,
  "from": "hex",
  "to": "utf8",
  "result": "...",
  "bytes": 4
}
```

## Rules

- Binary input/output: HEX (uppercase).
- `convert` requires explicit `from` and `to`; no implicit inference.
- `integer` uses unsigned BigInt; minimal bytes unless `length` given (0 -> "00", leading zeros preserved).
- `bcd` default padding is `right` (left-pad odd digit string with 0); `bcd-tbcd` swaps nibbles, `*`=0A `#`=0B `a`-`c`=0C-0E, 0F padding.
- Invalid hex/base64/bcd/input -> `ok:false` with error code.
- UTF-8 round-trip is lossless; ASCII only accepts 0x00-0x7F.
