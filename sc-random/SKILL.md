# sc-random

Cryptographically secure random bytes, nonces, card challenges and UUIDs.

## Operations

`generate`
`nonce`
`challenge`
`uuid`

## Algorithms

CSPRNG (OS entropy source via `node:crypto` `randomBytes`), UUID v4 (RFC 4122/9562).

## Input

| Field | Type | Required | Description |
|---|---|---|---|
| operation | string | yes | one of Operations above |
| length | integer | no | bytes per value; default 16 (`nonce` 12, `challenge` 8) |
| count | integer | no | how many values; default 1 (max 1024) |
| format | string | no | `hex` (default), `base64`, `dec`, `bin` |

## Output

```json
{ "ok": true, "operation": "generate", "format": "hex", "length": 16, "count": 1, "values": ["HEX"] }
```

## Rules

- Output encoding: HEX uppercase by default.
- Backed by a CSPRNG only. No seeding, no deterministic mode, no TRNG claim.
- `length` max 65536, `count` max 1024.
- Never generate keys or nonces with a non-cryptographic RNG.
