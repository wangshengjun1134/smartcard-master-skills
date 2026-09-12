# sc-encryption

Symmetric encryption/decryption for smart-card cryptographic workflows.

## Operations

`encrypt`
`decrypt`

## Algorithms

`AES-128`
`AES-192`
`AES-256`
`3DES`
`3DES-2KEY`
`SM4`

## Modes

`ECB`
`CBC`
`CTR`
`GCM`

## Input

| Field | Type | Required | Description |
|---|---|---|---|
| operation | string | yes | encrypt or decrypt |
| algorithm | string | yes | AES-128/192/256, 3DES, 3DES-2KEY, SM4 |
| mode | string | yes | ECB, CBC, CTR, GCM |
| key | hex | yes | Cipher key |
| data | hex | yes | Plaintext (encrypt) / ciphertext (decrypt) |
| iv | hex | CBC/CTR | Initialization vector / counter block |
| nonce | hex | GCM | Nonce (default length 12) |
| aad | hex | GCM opt | Additional authenticated data |
| tag | hex | GCM decrypt | Authentication tag |
| tag_length | int | GCM enc opt | Tag length (4..16, default 16) |
| padding | string | ECB/CBC opt | none/pkcs7/iso7816-4/iso9797-1-m1/iso9797-1-m2 (default pkcs7) |

## Output

```json
{ "ok": true, "algorithm": "AES-128", "mode": "CBC", "ciphertext": "HEX", "iv": "HEX" }
```

## Rules

- Binary input/output: HEX (uppercase).
- Never log keys. Error messages never contain key material.
- Do not infer missing cryptographic parameters (no default IV/nonce).
- ECB is not a safe default; prefer CBC/CTR/GCM.
- 3DES-CTR and all GCM for non-AES (e.g. SM4-GCM, 3DES-GCM) are unsupported (UNSUPPORTED_MODE).
- GCM decrypt verifies the tag before returning plaintext; on mismatch returns AUTHENTICATION_FAILED.
- Padding is fail-closed: invalid padding never yields plaintext.
