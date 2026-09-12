# sc-digest

Cryptographic hash / digest computation.

## Operations

`hash`
`list`

## Algorithms

`MD5`
`SHA-1`
`SHA-224`
`SHA-256`
`SHA-384`
`SHA-512`
`SHA-512/224`
`SHA-512/256`
`SHA3-224`
`SHA3-256`
`SHA3-384`
`SHA3-512`
`SM3`

## Input

| Field | Type | Required | Description |
|---|---|---|---|
| operation | string | yes | `hash` or `list` |
| algorithm | string | yes (hash) | one of Algorithms above |
| data | string | yes (hash) | message to hash |
| encoding | string | no | `hex` (default), `utf8`, `ascii`, `base64` — how to interpret `data` |

## Output

```json
{
  "ok": true,
  "algorithm": "SHA-256",
  "digest": "HEX",
  "length": 32
}
```

## Rules

- Binary output: HEX (uppercase).
- `encoding` controls how `data` is decoded; it never changes the output format.
- Do not infer a missing `algorithm` — return `MISSING_PARAMETER`.
- MD5 and SHA-1 are legacy; prefer SHA-256 or SHA3-256 for new designs.
