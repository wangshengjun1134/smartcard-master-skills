# sc-padding

Block padding, unpadding and validation.

## Operations

`pad`
`unpad`
`validate`

## Algorithms

`ISO7816-4`
`ISO9797-1-M1`
`ISO9797-1-M2`
`PKCS7`
`ANSI-X9.23`
`ZERO`

## Input

| Field | Type | Required | Description |
|---|---|---|---|
| operation | string | yes | `pad` / `unpad` / `validate` |
| algorithm | string | yes | one of Algorithms above (case-insensitive) |
| data | hex | yes | input bytes |
| block_size | integer | yes | block size in bytes (1-255) |

## Output

```json
{
  "ok": true,
  "algorithm": "PKCS7",
  "operation": "pad",
  "block_size": 16,
  "data": "HEX"
}
```

`validate` returns `{"ok":true,"valid":true|false}` — it never fails on malformed padding.

## Rules

- Binary input/output: HEX (uppercase).
- `block_size` is mandatory whenever the scheme is block-based.
- Unpadding must fail closed: malformed padding returns `INVALID_PADDING`, never data.
- `ISO7816-4` and `ISO9797-1-M2` produce identical bytes but are distinct schemes.
- `ZERO` padding is ambiguous — trailing zeros of real data cannot be recovered.
