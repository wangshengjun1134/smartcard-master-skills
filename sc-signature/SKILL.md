# sc-signature

Digital signature generation and verification.

## Operations

`sign`
`verify`
`generate`

## Algorithms

`RSA`
`RSA-PSS`
`ECDSA`
`SM2`
`EdDSA`

## Input

| Field | Type | Required | Description |
|---|---|---|---|
| operation | string | yes | `sign` / `verify` / `generate` |
| algorithm | string | yes | one of Algorithms above |
| data | hex | yes | message to sign (sign/verify) |
| private_key | PEM | sign | PEM private key |
| public_key | PEM | verify | PEM public key |
| signature | hex | verify | signature to check |
| hash | string | conditional | `SHA-256`/`SHA-384`/`SHA-512`/`SM3`; required for RSA and ECDSA |
| curve | string | no | ECDSA: `P-256`/`P-384`/`P-521`/`secp256k1`; EdDSA: `Ed25519`/`Ed448` |
| salt_length | integer | no | RSA-PSS salt length; defaults to hash length |
| signature_encoding | string | no | `der` (default) or `raw` (r||s), for ECDSA/SM2 |
| sm2_id | string | no | SM2 user identifier; defaults to `1234567812345678` |

## Output

```json
{
  "ok": true,
  "algorithm": "SM2",
  "signature": "HEX",
  "signature_encoding": "der"
}
```

`verify` returns `{"ok":true,"valid":true}`; a bad signature returns `ok:false` with code `SIGNATURE_INVALID`.
`generate` returns `{"ok":true,"public_key":"PEM","private_key":"PEM"}`.

## Rules

- Binary input/output: HEX (uppercase); keys are PEM.
- Never log private keys.
- Do not infer missing cryptographic parameters: `hash` is mandatory for RSA and ECDSA.
- Signature encoding (`der`/`raw`) is distinct from key encoding (PEM/DER).
- SM2 always uses SM3 and a user identifier; the identifier changes the result.
- `verify` failure is a normal outcome, not an internal error.
