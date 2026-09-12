# sc-key

Key generation, derivation, diversification, wrapping and check values.

## Operations

`generate`
`derive`
`diversify`
`wrap`
`unwrap`
`kcv`

## Algorithms

generate: `AES-128` `AES-192` `AES-256` `3DES` `SM4` `HMAC-SHA256` `HMAC-SHA512` `GENERIC`
derive: `PBKDF2` `HKDF` `SCRYPT` `X9.63-KDF`
diversify: `NXP-AES128` `AES-ECB` `3DES`
wrap/unwrap: `AES-KW` `AES-KWP`
kcv: `KCV-ZERO` `KCV-CMAC` `KCV-SHA256`

## Input

| Field | Type | Required | Description |
|---|---|---|---|
| operation | string | yes | one of Operations above |
| algorithm | string | yes | one of Algorithms above |
| key | hex | diversify/kcv | master key or key to check |
| kek | hex | wrap/unwrap | key-encryption key |
| data | hex | wrap/unwrap/diversify | key material or diversification input |
| ikm / password | hex | derive | input key material |
| salt / info | hex | derive | optional, algorithm dependent |
| hash | string | derive | `SHA-1`/`SHA-224`/`SHA-256`/`SHA-384`/`SHA-512`/`SM3` |
| keylen | integer | derive | output length in bytes |
| iterations | integer | PBKDF2 | iteration count |
| length | integer | generate | only for `GENERIC` |

## Output

```json
{ "ok": true, "operation": "generate", "algorithm": "AES-256", "key": "HEX", "length": 32 }
```

`derive` also returns `params` describing the derivation for audit.
`diversify` and `kcv` return metadata only; the master key is never echoed.

## Rules

- Binary input/output: HEX (uppercase).
- Never log or echo secret key material.
- Diversification algorithms are explicit implementations, never implicit.
- `unwrap` validates integrity and fails closed (`INTEGRITY_CHECK_FAILED`).
- Do not infer missing derivation parameters; return an error instead.
