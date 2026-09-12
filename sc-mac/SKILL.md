# sc-mac

Message Authentication Code generation and verification.

## Operations

`mac`
`verify`

## Algorithms

`HMAC-MD5`
`HMAC-SHA1`
`HMAC-SHA224`
`HMAC-SHA256`
`HMAC-SHA384`
`HMAC-SHA512`
`HMAC-SM3`
`AES-CMAC`
`3DES-CMAC`
`3DES-MAC`
`ISO9797-1-M1-MAC`
`ISO9797-1-M2-MAC`
`ISO9797-1-M3-MAC`
`SM4-MAC`

## Input

| Field | Type | Required | Description |
|---|---|---|---|
| operation | string | yes | `mac` or `verify` |
| algorithm | string | yes | one of Algorithms above |
| key | hex | yes | MAC key (AES 16/24/32, 3DES 16/24, SM4 16 bytes) |
| data | hex | yes | message; may be empty |
| cipher | string | no | block cipher for ISO9797: `AES` / `3DES` / `SM4` (default `3DES`) |
| iv | hex | no | CBC-MAC initial vector; defaults to all-zero |
| mac_length | integer | no | truncation length in bytes, taken from the left |
| expected | hex | no | required for `verify` |

## Output

```json
{
  "ok": true,
  "algorithm": "AES-CMAC",
  "mac": "HEX",
  "mac_length": 16,
  "truncated": false
}
```

`verify` returns `{"ok":true,"valid":true,"expected":"HEX","actual":"HEX"}`.
A mismatch returns `ok:false` with code `MAC_MISMATCH`.

## Rules

- Binary input/output: HEX (uppercase).
- Never log keys.
- Do not infer missing cryptographic parameters.
- `mac_length` is MAC truncation (leftmost bytes), not digest truncation.
- ISO9797 Method 1/2/3 differ only in padding and finalisation; they are not interchangeable.
