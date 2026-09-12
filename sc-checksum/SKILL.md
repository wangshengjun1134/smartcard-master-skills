# sc-checksum

Non-cryptographic checksum computation and verification.

## Operations

`compute`
`verify`

## Algorithms

`CRC-8`
`CRC-8/MAXIM`
`CRC-16/CCITT-FALSE`
`CRC-16/IBM`
`CRC-16/XMODEM`
`CRC-32`
`CRC-32C`
`LRC`
`XOR`
`SUM-8`
`SUM-16`

## Input

| Field | Type | Required | Description |
|---|---|---|---|
| operation | string | yes | `compute` or `verify` |
| algorithm | string | yes | one of Algorithms above |
| data | hex | yes | input bytes |
| checksum | hex | yes (verify) | expected checksum |
| init | integer | no | override initial value |
| xorout | integer | no | override final XOR value |
| poly | integer | no | override polynomial (CRC only) |
| endian | string | no | `big` (default) or `little`, for multi-byte output |

## Output

```json
{
  "ok": true,
  "algorithm": "CRC-32",
  "checksum": "HEX",
  "width": 32
}
```

`verify` adds `"valid": true`; a mismatch returns `ok:false` with code `CHECKSUM_MISMATCH`.

## Rules

- Binary input/output: HEX (uppercase).
- Output width is fixed per algorithm: CRC-8 1 byte, CRC-16 2 bytes, CRC-32 4 bytes.
- A checksum is not a MAC: it provides no security against deliberate tampering.
- `LRC` (two's complement of the sum) and `XOR` (byte-wise XOR) are different algorithms.
