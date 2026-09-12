# SmartCard Master Skills

面向智能卡 / EMV / 国密场景的**密码学与数据编解码技能集**。每个技能是一个**完全独立**的 TypeScript 模块，通过统一的 JSON 契约调用，可直接作为 Agent 的原子能力使用。

```
11 个技能 · 零第三方依赖 · 211 个单元测试 · 1988 条第三方交叉验证 · 0 失败
```

---

## 目录

- [特性](#特性)
- [环境要求](#环境要求)
- [快速开始](#快速开始)
- [技能清单](#技能清单)
- [目录结构](#目录结构)
- [统一调用契约](#统一调用契约)
- [技能详解](#技能详解)
- [测试与验证](#测试与验证)
- [设计原则](#设计原则)
- [已知限制](#已知限制)
- [扩展新技能](#扩展新技能)

---

## 特性

**零第三方依赖。** 全部基于 Node.js 内置模块（`node:crypto` / `node:fs` / `node:url`），配合 Node 22 原生 TypeScript 类型剥离直接运行。没有 `npm install`，没有依赖树，没有供应链风险。

**技能完全独立。** 每个技能自包含，`sc-mac` 不 import `sc-digest`，`sc-encryption` 不 import `sc-padding`。SM3、SM4、padding 等公共算法在需要的技能里各存一份——这是刻意的，因为用户可能只安装其中一两个技能。

**经过第三方交叉验证。** 不是"自己证明自己"：所有密码学输出都与 **Python `cryptography` 45** 和 **OpenSSL 3.5.7** 这两个完全独立的实现逐条比对（详见[测试与验证](#测试与验证)）。

**国密完整支持。** SM2 / SM3 / SM4 均为纯 TypeScript 自实现（Node 不提供 SM2 曲线，SM4 也已用 OpenSSL 独立验证），全部通过 GM/T 官方测试向量。

**Fail-closed 设计。** 畸形输入一律显式报错，绝不静默返回错误结果。去填充、GCM 认证、密钥解封、TLV 解析全部失败即止。

**不猜测密码学参数。** 缺失的 IV、hash、盐长度等一律返回 `MISSING_PARAMETER`，绝不使用"合理默认值"——在密码学里，猜测的参数就是漏洞。

---

## 环境要求

| 项目 | 要求 |
|---|---|
| Node.js | **>= 22.6**（原生 TS 类型剥离）。已在 **22.22.2** 上完整验证 |
| 依赖 | 无。`package.json` 仅声明 `"type": "module"` |
| 可选（仅验证用） | Python + `cryptography`、OpenSSL —— 运行交叉验证套件时才需要 |

> Node 22.6 起支持 `--experimental-strip-types`，22.18 起默认启用。低于 22.6 需改用 tsx/ts-node。

---

## 快速开始

无需构建，直接运行：

```bash
cd sc-digest
node scripts/digest.ts --input '{"operation":"hash","algorithm":"SM3","data":"616263"}'
```

```json
{"ok":true,"algorithm":"SM3","digest":"66C7F0F462EEEDD9D1F2D46BDC10E4E24167C4875CF2F7A2297DA02B8F4BA8E0","length":32}
```

三种输入方式等价：

```bash
node scripts/mac.ts --input '{"operation":"mac","algorithm":"AES-CMAC","key":"...","data":"..."}'
node scripts/mac.ts --input-file ./in.json
echo '{"operation":"mac",...}' | node scripts/mac.ts
```

以 `sc-mac` 计算 AES-CMAC（RFC 4493 空消息向量）为例：

```bash
cd sc-mac
node scripts/mac.ts --input '{"operation":"mac","algorithm":"AES-CMAC","key":"2B7E151628AED2A6ABF7158809CF4F3C","data":""}'
```

```json
{"ok":true,"algorithm":"AES-CMAC","mac":"BB1D6929E95937287FA37D129B756746","mac_length":16,"truncated":false}
```

---

## 技能清单

| 技能 | 能力 | 操作 | 算法 | 测试 |
|---|---|---|---|---|
| [sc-digest](#sc-digest) | 摘要 | `hash` `list` | MD5 / SHA-1 / SHA-2 / SHA-3 / **SM3**（13 种） | 9 |
| [sc-mac](#sc-mac) | MAC | `mac` `verify` | HMAC / CMAC / CBC-MAC / ISO9797-1 / Retail MAC / **SM4-MAC** | 25 |
| [sc-encryption](#sc-encryption) | 对称加解密 | `encrypt` `decrypt` | AES / 3DES / **SM4** × ECB / CBC / CTR / GCM | 16 |
| [sc-signature](#sc-signature) | 签名验签 | `sign` `verify` `generate` | RSA / RSA-PSS / ECDSA / **SM2** / EdDSA | 15 |
| [sc-key](#sc-key) | 密钥管理 | `generate` `derive` `diversify` `wrap` `unwrap` `kcv` | PBKDF2 / HKDF / scrypt / X9.63 / AES-KW(P) / 分散 / KCV | 22 |
| [sc-random](#sc-random) | 随机数 | `generate` `nonce` `challenge` `uuid` | CSPRNG、UUID v4 | 10 |
| [sc-encoding](#sc-encoding) | 编码转换 | `encode` `decode` `convert` | HEX / ASCII / UTF-8 / Base64 / BCD / TBCD / Integer / Binary | 44 |
| [sc-tlv](#sc-tlv) | TLV | `parse` `encode` `find` `set` `delete` `flatten` | BER-TLV / SIMPLE-TLV / RAW-TLV | 28 |
| [sc-checksum](#sc-checksum) | 非密码校验 | `compute` `verify` | CRC-8/16/32 全参数化、LRC、XOR、SUM | 10 |
| [sc-padding](#sc-padding) | 填充 | `pad` `unpad` `validate` | ISO7816-4 / ISO9797-1 M1·M2 / PKCS#7 / X9.23 / ZERO | 16 |
| [sc-bitfield](#sc-bitfield) | 位操作 | `get` `set` `extract` `insert` `mask` `shift` `count` `reverse` `msb` `lsb` | MSB/LSB 双位序 | 16 |
| ~~sc-asn1~~ | ASN.1 编解码 | — | 尚未实现（复杂度高，已预留目录） | — |

---

## 目录结构

每个技能结构完全一致：

```
sc-mac/
├── SKILL.md                  # 给 Agent 加载的极简契约（< 60 行）
├── schema.json               # 机器可读的输入输出契约（JSON Schema 2020-12）
├── scripts/
│   └── mac.ts                # CLI 入口：解析 JSON → 调用算法 → 输出 JSON
├── algorithms/               # 算法实现，按算法族拆分
│   ├── hmac.ts
│   ├── cmac.ts
│   ├── iso9797.ts
│   ├── sm3.ts
│   └── sm4.ts
├── tests/
│   ├── vectors/*.json        # 标准测试向量（RFC / NIST / GM/T）
│   └── mac.test.ts           # node --test 单元测试
└── README.md                 # 开发人员文档，不加载给 Agent
```

**为什么 `SKILL.md` 和 `README.md` 分开？** `SKILL.md` 只保留 Purpose / Operations / Algorithms / Input / Output / Rules，控制在 60 行内，直接进 Agent 上下文。`README.md` 记录实现细节、规范依据、边界约定，供人查阅——不占用 Agent 的上下文预算。

---

## 统一调用契约

### 输入

所有技能接受同一个 JSON 对象，通过 `--input` / `--input-file` / stdin 传入。二进制数据一律用 **大写 HEX 字符串**表示，密钥用 PEM 字符串。

### 成功输出

```json
{ "ok": true, "...": "技能特定字段" }
```

### 错误输出

```json
{ "ok": false, "error": { "code": "UNSUPPORTED_ALGORITHM", "message": "algorithm 'SHA-999' is not supported" } }
```

进程退出码：成功 `0`，失败 `1`。

### 统一错误码

| 错误码 | 含义 |
|---|---|
| `MISSING_PARAMETER` | 缺少必填参数。**不会**用默认值填充 |
| `INVALID_PARAMETER` | 参数存在但取值非法 |
| `INVALID_HEX` / `INVALID_BASE64` / `INVALID_BCD` | 输入数据格式错误 |
| `INVALID_KEY_LENGTH` / `INVALID_KEY` / `INVALID_IV_LENGTH` | 密钥或 IV 长度不符 |
| `UNSUPPORTED_ALGORITHM` / `UNSUPPORTED_MODE` / `UNSUPPORTED_CIPHER` / `UNSUPPORTED_CURVE` / `UNSUPPORTED_HASH` / `UNSUPPORTED_ENCODING` / `UNSUPPORTED_OPERATION` | 不支持的算法/模式/参数 |
| `INVALID_PADDING` | 填充非法（去填充 fail-closed） |
| `AUTHENTICATION_FAILED` | GCM tag 校验失败，**不返回明文** |
| `MAC_MISMATCH` / `CHECKSUM_MISMATCH` / `SIGNATURE_INVALID` | 校验失败（正常结果，非内部错误） |
| `INTEGRITY_CHECK_FAILED` | 密钥解封完整性校验失败 |
| `MALFORMED_TLV` / `MALFORMED_INPUT` | 结构化数据解析失败 |
| `UNSUPPORTED_LENGTH_FORM` | BER-TLV 不定长（智能卡场景不支持） |
| `OUT_OF_RANGE` | 位/字节字段越界 |
| `INTERNAL_ERROR` | 未预期的内部错误 |

> **校验失败 ≠ 内部错误。** `MAC_MISMATCH`、`SIGNATURE_INVALID` 这类是**期望中的业务结果**，用 `ok:false` + 专用错误码表达，与真正的异常区分开。

---

## 技能详解

### sc-digest

摘要计算。MD5 / SHA-1 / SHA-2 / SHA-3 走 `node:crypto`；**SM3 为纯 TS 自实现**（GM/T 0004）。

```bash
cd sc-digest
node scripts/digest.ts --input '{"operation":"hash","algorithm":"SHA-256","data":"616263"}'
node scripts/digest.ts --input '{"operation":"hash","algorithm":"SM3","data":"616263"}'
# SM3("abc") = 66C7F0F4...4BA8E0  ✓ GM/T 0004 官方向量
```

`encoding` 字段控制 **data 如何被解码**（`hex` 默认 / `utf8` / `ascii` / `base64`），不改变输出格式。

算法：`MD5` `SHA-1` `SHA-224` `SHA-256` `SHA-384` `SHA-512` `SHA-512/224` `SHA-512/256` `SHA3-224` `SHA3-256` `SHA3-384` `SHA3-512` `SM3`

---

### sc-mac

MAC 生成与校验，是本项目中算法覆盖最完整的技能。

**算法**

| 族 | 算法名 |
|---|---|
| HMAC | `HMAC-MD5` `HMAC-SHA1` `HMAC-SHA224` `HMAC-SHA256` `HMAC-SHA384` `HMAC-SHA512` `HMAC-SM3` |
| CMAC | `AES-CMAC` `3DES-CMAC`（RFC 4493 / NIST SP 800-38B 自实现） |
| CBC-MAC | `3DES-MAC` `SM4-MAC` |
| ISO 9797-1 | `ISO9797-1-M1-MAC` `ISO9797-1-M2-MAC` `ISO9797-1-M3-MAC` |
| Retail MAC | `RETAIL-MAC`（ANSI X9.19 / ISO 9797-1 MAC Algorithm 3） |

**关于 ISO/IEC 9797-1 的重要说明**

标准里 **Padding Method** 和 **MAC Algorithm** 是两个独立维度，容易混淆：

- **Padding Method**：1 = 补零；2 = 加 `0x80` 后补零；3 = 补零后**在前面**加长度块
- **MAC Algorithm**：1 = CBC-MAC；2 = 带输出变换的 CBC-MAC；3 = **Retail MAC**，输出变换为 `E_K1(D_K2(H))`，需要**两个独立密钥**

本技能把这两种语义都正确实现了，且 `RETAIL-MAC` 支持 `cipher` = `DES`（单 DES，银行卡主流）/ `3DES`。

```bash
cd sc-mac
# RFC 4493 AES-CMAC
node scripts/mac.ts --input '{"operation":"mac","algorithm":"AES-CMAC","key":"2B7E151628AED2A6ABF7158809CF4F3C","data":""}'
# 公开 Retail MAC 向量（单 DES，K1||K2）→ 5F1448EEA8AD90A7
node scripts/mac.ts --input '{"operation":"mac","algorithm":"RETAIL-MAC","cipher":"DES","key":"7962D9ECE03D1ACD4C76089DCE131543","data":"72C29C2371CC9BDB65B779B8E8D37B29ECC154AA56A8799FAE2F498F76ED92F2","padding":"m2"}'
```

**`mac_length` 是 MAC 截断**（取最左 N 字节），**不是**摘要截断。EMV / 银联场景常见的 4 字节或 8 字节 MAC 就是这种截断。

**CBC-MAC 的 IV 默认为全零**——这是 MAC 的标准行为，与加密场景（禁止默认 IV）不同。

---

### sc-encryption

对称加解密。

**算法**：`AES-128` `AES-192` `AES-256` `3DES` `3DES-2KEY` `SM4`（SM4 纯 TS 自实现 + OpenSSL 交叉验证）
**模式**：`ECB` `CBC` `CTR` `GCM`

```bash
cd sc-encryption
node scripts/encrypt.ts --input '{"operation":"encrypt","algorithm":"AES-128","mode":"CBC","key":"0123456789ABCDEF0123456789ABCDEF","data":"0011223344556677","iv":"000102030405060708090A0B0C0D0E0F","padding":"pkcs7"}'
# {"ok":true,"algorithm":"AES-128","mode":"CBC","ciphertext":"1948D2300730EA290FA1E7D9E26687EE","iv":"000102030405060708090A0B0C0D0E0F"}
```

**关键规则**

- ECB / CBC 未指定 padding 时默认 `pkcs7`；**CTR / GCM 为流/AEAD 模式，不接受 padding**（传了报 `INVALID_PARAMETER`）
- GCM 解密**先校验 tag 再返回明文**，失败返回 `AUTHENTICATION_FAILED` 且不输出任何明文
- 缺失 IV / nonce 直接报错，**不默认全零**
- 去填充 fail-closed，非法填充绝不产出明文
- `3DES-CTR`、`SM4-GCM`、`3DES-GCM` 不支持，返回 `UNSUPPORTED_MODE`（不是实现取舍，是底层确实不提供）
- ECB 不作为推荐默认值——README 中明确写了风险

---

### sc-signature

数字签名。RSA / RSA-PSS / ECDSA / EdDSA 走 `node:crypto`；**SM2 为完整自实现**（SM3 + sm2p256v1 曲线 BigInt 运算 + ZA 用户标识）。

```bash
cd sc-signature
node scripts/signature.ts --input '{"operation":"generate","algorithm":"SM2"}'
```

**字段**

| 字段 | 说明 |
|---|---|
| `hash` | RSA / ECDSA **必填**（`SHA-256` / `SHA-384` / `SHA-512` / `SM3`）。缺失直接报错，**不默认 SHA-256** |
| `curve` | ECDSA：`P-256` `P-384` `P-521` `secp256k1`；EdDSA：`Ed25519` `Ed448` |
| `signature_encoding` | `der`（默认）或 `raw`（r‖s 定长拼接），适用 ECDSA / SM2 |
| `sm2_id` | SM2 的 ZA 用户标识，默认 `1234567812345678`。**该值会改变签名结果** |
| `salt_length` | RSA-PSS 盐长，缺省用 hash 长度 |

**签名编码 ≠ 密钥编码。** `signature_encoding` 管的是 r‖s 的序列化方式，与 PEM/DER 密钥格式是两回事。

**SM2 已通过 GM/T 0003 官方向量确定性验证**：ZA、r、s 三项全部精确匹配，且篡改消息后验签正确拒绝。

---

### sc-key

密钥全生命周期管理。

| 操作 | 算法 |
|---|---|
| `generate` | `AES-128` `AES-192` `AES-256` `3DES` `SM4` `HMAC-SHA256` `HMAC-SHA512` `GENERIC` |
| `derive` | `PBKDF2` `HKDF` `SCRYPT` `X9.63-KDF` |
| `diversify` | `NXP-AES128` `AES-ECB` `3DES` |
| `wrap` / `unwrap` | `AES-KW`（RFC 3394）`AES-KWP`（RFC 5649） |
| `kcv` | `KCV-ZERO` `KCV-CMAC` `KCV-SHA256` |

```bash
cd sc-key
# RFC 3394 向量
node scripts/key.ts --input '{"operation":"wrap","algorithm":"AES-KW","kek":"000102030405060708090A0B0C0D0E0F","data":"00112233445566778899AABBCCDDEEFF"}'
# → 1FA68B0A8112B447AEF34BD8FB5A7B829D3E862371D2CFE5  ✓
node scripts/key.ts --input '{"operation":"diversify","algorithm":"NXP-AES128","key":"000102030405060708090A0B0C0D0E0F","data":"0102030405060708"}'
node scripts/key.ts --input '{"operation":"kcv","algorithm":"KCV-CMAC","key":"000102030405060708090A0B0C0D0E0F"}'
```

**关键规则**

- 输出支持 `meta`（算法、长度、KCV、profile、version），但**绝不回显主密钥本身**
- `derive` 返回派生参数摘要（hash / iterations / salt / info / keylen），便于审计
- 分散算法都是**显式实现**，每个算法在 `algorithms/diversify.ts` 里有独立函数，不做隐式推断
- 3DES 密钥生成后做奇偶校验位调整
- `unwrap` 做 RFC 3394 的 `A6A6A6A6A6A6A6A6` 完整性校验，失败返回 `INTEGRITY_CHECK_FAILED`
- 随机数一律 `randomBytes`，**禁止 `Math.random`**

---

### sc-random

CSPRNG 随机数、nonce、卡片挑战数、UUID v4。

```bash
cd sc-random
node scripts/random.ts --input '{"operation":"challenge"}'                          # 8 字节卡片挑战
node scripts/random.ts --input '{"operation":"nonce"}'                              # 12 字节
node scripts/random.ts --input '{"operation":"generate","length":16,"count":3}'
node scripts/random.ts --input '{"operation":"uuid"}'                               # UUID v4
```

**诚实的能力声明**：本技能**只提供 CSPRNG**（`node:crypto` 的 `randomBytes`，来自操作系统熵源）。**不声称 TRNG**，不提供可播种的确定性模式。底层 OpenSSL 使用 NIST SP 800-90A DRBG，本技能只是其接口封装。

`length` 上限 65536，`count` 上限 1024。

---

### sc-encoding

编码与数据表示转换。

**表示**：`hex` `ascii` `utf8` `latin1` `base64` `base64url` `bcd` `bcd-tbcd` `integer` `binary`

```bash
cd sc-encoding
node scripts/encoding.ts --input '{"operation":"convert","data":"48656C6C6F","from":"hex","to":"utf8"}'
# {"ok":true,"from":"hex","to":"utf8","result":"Hello","bytes":5}
```

**关键规则**

- `convert` **必须显式给出 `from` 和 `to`**，不做隐式推断
- **保留前导零字节**：整数 1 按 4 字节输出是 `00000001`，不是 `01`
- **区分数值与字节串**：`integer` 是无符号 BigInt 语义，与 HEX 字节串不同
- `bcd` 奇数位默认**右靠**（`bcd_padding=right`，左侧补 0），可用 `bcd_padding=left` 切换
- `bcd-tbcd` 交换 nibble，`*`=0x0A `#`=0x0B `a`-`c`=0x0C-0x0E，填充 0x0F
- `base64url` 用 `-` `_` 且无 padding；`base64` 标准带 `=`
- ASCII 只接受 0x00-0x7F，越界报错；UTF-8 往返无损

---

### sc-tlv

TLV 解析与构造，面向 EMV / 智能卡数据。

**格式**：`ber`（默认，BER-TLV）`simple`（1 字节 tag + 1 字节 length）`raw`（可配置 tag/length 字节数）

```bash
cd sc-tlv
node scripts/tlv.ts --input '{"operation":"parse","data":"6F0A8408A000000003000000"}'
node scripts/tlv.ts --input '{"operation":"find","data":"6F0A8408A000000003000000","tag":"84"}'
# {"ok":true,"tag":"84","found":true,"value":"A000000003000000","path":"6F/84"}
```

**关键规则**

- **支持构造 TLV 与嵌套树**：tag 首字节 bit5（0x20）置位 → value 递归解析为 `children`
- **BER 长度完整支持**：短形式 0x00-0x7F；长形式 `0x80|N`（N ∈ 1..4）；`0x80` 不定长返回 `UNSUPPORTED_LENGTH_FORM`；`0xFF` 保留值报 `MALFORMED_TLV`
- 支持多字节 tag（如 `9F02`）
- **`find` 未命中不是错误** —— 返回 `ok:true, found:false`
- **解析 fail-closed**：截断、超长、非法长度编码 → `MALFORMED_TLV`，绝不静默截断
- **Tag 字典只是元数据**：`algorithms/tags.ts` 里的 EMV tag 名称映射仅用于 `pretty` 输出显示，**解析器本身不依赖它**
- 默认保持原始顺序（`preserve_order=true`）；`set` 已存在的 tag 替换值并保持位置，不存在的追加到末尾

---

### sc-checksum

非密码学校验和。CRC 采用**参数化表驱动**，width / poly / init / refin / refout / xorout 全部可覆盖。

**算法**：`CRC-8` `CRC-8/MAXIM` `CRC-16/CCITT-FALSE` `CRC-16/IBM` `CRC-16/XMODEM` `CRC-32` `CRC-32C` `LRC` `XOR` `SUM-8` `SUM-16`

```bash
cd sc-checksum
node scripts/checksum.ts --input '{"operation":"compute","algorithm":"CRC-32","data":"313233343536373839"}'
# {"ok":true,"algorithm":"CRC-32","checksum":"CBF43926","width":32}
```

全部 7 个 CRC 的 `"123456789"` 标准 check 值均已验证：CRC-32 `CBF43926`、CRC-32C `E3069283`、CCITT-FALSE `29B1`、IBM `BB3D`、XMODEM `31C3`、CRC-8 `F4`、MAXIM `A1`。

**LRC 与 XOR 是不同的算法**：LRC 采用 ISO 1155 定义（字节和的二进制补码），XOR 是逐字节异或。二者不要混用。

> **校验和不是 MAC。** CRC / LRC / XOR 只能检测随机误码，**对蓄意篡改没有任何防护能力**。

---

### sc-padding

块填充、去填充与校验。

**方案**：`ISO7816-4` `ISO9797-1-M1` `ISO9797-1-M2` `PKCS7` `ANSI-X9.23` `ZERO`

```bash
cd sc-padding
node scripts/padding.ts --input '{"operation":"pad","algorithm":"PKCS7","data":"0011223344","block_size":16}'
# {"ok":true,"algorithm":"PKCS7","operation":"pad","block_size":16,"data":"00112233440B0B0B0B0B0B0B0B0B0B0B"}
```

| 方案 | 填充规则 |
|---|---|
| `ISO7816-4` | 追加 `0x80` 再补 `0x00` 至块长倍数 |
| `ISO9797-1-M1` | 仅补 `0x00` 至块长倍数（已是倍数则不补） |
| `ISO9797-1-M2` | 追加 `0x80` 再补 `0x00` |
| `PKCS7` | 补 N 个字节，每字节值为 N；已是倍数则**再补一整块** |
| `ANSI-X9.23` | 补 N-1 个 `0x00`，最后一个字节 = N |
| `ZERO` | 补 `0x00` |

**重要：补零方案的固有歧义**

`ISO9797-1-M1` 和 `ZERO` 在字节层面等价，都**无法可靠还原原始长度**——区分不了"数据末尾的 `00`"和"填充的 `00`"。本技能的处理是：

- 去填充时剥离尾部所有零字节，**并在 README 中明确标注该歧义风险**
- 需要精确还原时，传入 `original_length` 参数

`ISO7816-4` 与 `ISO9797-1-M2` 产生**相同的字节**，但规范来源不同，二者作为独立方案保留。

**去填充 fail-closed**：长度非块长倍数、PKCS7 字节值不等于长度、ISO7816-4 找不到 `0x80` 分界等 → `INVALID_PADDING`，绝不返回错误数据。

---

### sc-bitfield

位与字节字段操作。

**操作**：`get` `set` `extract` `insert` `mask` `shift` `count` `reverse` `msb` `lsb`

```bash
cd sc-bitfield
node scripts/bitfield.ts --input '{"operation":"get","data":"A5","bit_offset":0,"bit_length":4}'
# {"ok":true,"operation":"get","bit_order":"msb","value":"10","bits":4,"hex":"0A"}
```

**两种位序**

- `bit_order=msb`（默认）：bit 0 是字节 0 的最高位
- `bit_order=lsb`：bit 0 是字节 0 的最低位（权重 2⁰）

两种模式都有测试覆盖。跨字节边界的 get/set、越界访问（`OUT_OF_RANGE`）、`set` 对其他位的保持性均已验证。

---

## 测试与验证

**我们不相信"自己证明自己"。** 每个技能都经过三层验证。

### 第一层：单元测试 — 211 项

每个技能自带 `tests/*.test.ts`，用 Node 内置测试运行器执行：

```bash
cd sc-mac
node --test tests/mac.test.ts
```

跑全部技能：

```bash
for d in sc-*; do
  [ -d "$d/tests" ] || continue
  (cd "$d" && node --test tests/*.test.ts)
done
```

| 技能 | 通过 | 技能 | 通过 |
|---|---|---|---|
| sc-encoding | 44 | sc-bitfield | 16 |
| sc-tlv | 28 | sc-padding | 16 |
| sc-key | 22 | sc-encryption | 16 |
| sc-mac | 25 | sc-signature | 15 |
| sc-digest | 9 | sc-random | 10 |
| sc-checksum | 10 | **合计** | **211** |

测试向量来源：RFC 3394 / RFC 4231 / RFC 4493 / RFC 5869、NIST KAT、GM/T 0002 / 0003 / 0004、FIPS 180-4 / 202、公开 Retail MAC 向量。

### 第二层：第三方交叉验证 — 1988 项

这是准确性的核心保障。参考值由**完全独立于 Node** 的两个实现生成：

- **Python `cryptography` 45** —— HMAC、CMAC、AES-KW、HKDF、PBKDF2、scrypt、ECDSA、RSA、Ed25519
- **OpenSSL 3.5.7 CLI** —— SM3、SM4（Node 不提供，正好独立验证我们的自实现）
- **自写 Python 逐位参考 DES** —— 单 DES（cryptography 45 已移除），通过 3 个 NIST KAT 自检

验证套件位于 `_verify/`（`gen_refs.py` 生成参考值 → `verify_crypto.ts` 逐条比对）：

```
PASS  sc-checksum/CRC              147/147
PASS  sc-checksum/SIMPLE            84/84
PASS  sc-digest                    274/274
PASS  sc-digest/SM3-vs-node         21/21
PASS  sc-encryption                506/506
PASS  sc-encryption/GCM-tag        126/126
PASS  sc-encryption/SM4             61/61
PASS  sc-key/AES-KW                 18/18
PASS  sc-key/HKDF                   36/36
PASS  sc-key/PBKDF2                  6/6
PASS  sc-key/SCRYPT                  1/1
PASS  sc-key/X9.63                 12/12
PASS  sc-mac/CMAC                   84/84
PASS  sc-mac/DES                     3/3
PASS  sc-mac/DES-RETAIL            28/28
PASS  sc-mac/HMAC                  147/147
PASS  sc-mac/ISO9797              126/126
PASS  sc-mac/ISO9797-api          126/126
PASS  sc-mac/RETAIL                85/85
PASS  sc-mac/RETAIL-api            84/84
PASS  sc-signature/ECDSA             6/6
PASS  sc-signature/Ed25519           1/1
PASS  sc-signature/RSA               2/2
PASS  sc-signature/cross-py          4/4
TOTAL pass=1988 fail=0
```

签名部分做了**双向**验证：Python 签名 → Node 验签，以及 Node 签名 → Python 验签。

### 第三层：模糊与属性测试 — 28 组

`_verify/verify_logic.ts` 用随机数据驱动不变式检查（默认 400 轮迭代）：

```bash
cd _verify
node verify_logic.ts 400
```

覆盖的属性：

- 加解密还原：随机算法 × 模式 × 填充，明文 → 密文 → 明文必须一致
- 填充还原：`pad` → `unpad` 必须回到原数据
- TLV 还原：随机嵌套 TLV `encode` → `parse` 结构等价
- 编码还原：所有表示两两互转无损失
- 位字段保持性：`set` 后未涉及的位不得改变
- CRC 与逐位参考实现在随机数据上逐条比对
- 非法输入必须 fail-closed

### 验证发现并修复的真实缺陷

交叉验证不是走过场——它抓到了这些真问题：

| 缺陷 | 说明 |
|---|---|
| SM2 模逆用错模数 | `modInv` 用了域素数 `p` 而非群阶 `n`，导致签名 s 值全错 |
| SM3 实现损坏 | sc-signature 中的 SM3 与已验证版本不一致，导致 ZA 错误 |
| ISO 9797-1 语义混淆 | 把 padding method 当成了 MAC algorithm，M3 两头不靠 |
| CRC-32 / CRC-32C 恒返回 0 | `(1 << 32) - 1` 在 JS 中溢出为 0 |
| AES-KWP unwrap 永远失败 | 先用全零 A 做校验，真正的 AIV 校验到不了 |
| CTR 被强制块对齐 | CTR 是流模式，不应要求块对齐 |
| 入口判断在 Windows 失效 | `import.meta.url` 是 `file:///D:/...` 而 `argv[1]` 带反斜杠，脚本静默不执行 |
| stdin 读 `/dev/stdin` | Windows 无此路径 |
| `bit_order=lsb` 位权重搞反 | 取低 4 位返回了高位的值 |
| ECB 的 `final()` 陷阱 | Node 的 `createCipheriv` 对 ECB **无论传什么选项都会启用 padding**，`final()` 会多吐一个填充块。必须 `setAutoPadding(false)` |

最后一条尤其值得记住：原代码只取 `update()` 是"歪打正着"恰好正确，加上 `final()` 反而制造了 bug——**是交叉验证立刻抓到了这个回归**。

---

## 设计原则

**密码原语不自己造轮子。** AES / 3DES / RSA / ECDSA / EdDSA / SHA-2 / SHA-3 / HMAC / PBKDF2 / HKDF / scrypt 全部调用 `node:crypto`，不复制大型密码项目源码。只有 Node 确实不提供的（SM2、SM3、SM4、CMAC、单 DES、AES-KW、Retail MAC）才自实现，且每个都配标准测试向量。

**基础能力可以直接实现。** TLV、Encoding、Padding、Bitfield、CRC 这类非密码学逻辑不引入依赖，直接写清楚。

**参数不得由 Agent 猜测。** 缺失的 IV、hash、盐长度、曲线等一律报错。让调用方显式指定，比给一个"看起来合理"的默认值安全得多。

**密钥绝不出现在日志、错误信息或输出中。** 错误 message 只描述问题，不回显任何密钥材料。

**错误必须显式返回。** 不允许静默降级、不允许截断、不允许吞异常。校验失败与内部错误用不同的错误码区分。

**测试向量不进 SKILL.md。** 向量放 `tests/vectors/`，保持 Agent 上下文干净。

---

## 已知限制

**sc-asn1 尚未实现。** ASN.1 / BER / DER / OID 编解码复杂度较高，目录已预留。实现时可复用 `docs/_skill_build_spec.md` 中的构建规范（记录了 Node 22 TS 的语法限制、目录约定与 CLI 契约）。

**补零填充不可逆。** `ISO9797-1-M1` 与 `ZERO` 无法可靠还原原始长度，这是算法固有性质。需要精确还原时请传 `original_length`。

**不支持的模式**：`3DES-CTR`、`SM4-GCM`、`3DES-GCM` 返回 `UNSUPPORTED_MODE`——底层运行时确实不提供，不是实现取舍。

**BER-TLV 不支持不定长**（`0x80`），智能卡场景不使用该形式，遇到返回 `UNSUPPORTED_LENGTH_FORM`。

**HKDF 只收录了 RFC 5869 的 TC1 和 TC3。** TC2 的期望值未能可靠核对，宁可不收录也不写入未经验证的数据。

**sc-random 只提供 CSPRNG，** 不声称 TRNG，不提供可播种的确定性 DRBG 模式。

---

## 扩展新技能

1. 复制任一现有技能的目录结构
2. 编写 `SKILL.md`，严格控制在 60 行内，只保留 Purpose / Operations / Algorithms / Input / Output / Rules
3. 编写 `schema.json`（JSON Schema 2020-12），定义参数契约
4. `algorithms/` 下按算法族拆文件，`scripts/` 下写入口
5. 补 `tests/vectors/*.json` + `tests/*.test.ts`，**向量必须真实跑通再写入**
6. 在 `_verify/` 中加入对应的交叉验证（如涉及密码学）

**硬性约束**

- 不得 import 其他技能的任何文件——公共算法请各存一份
- 不得引入第三方 npm 依赖
- 所有二进制 I/O 用大写 HEX
- 去填充 / 认证 / 解析必须 fail-closed

**不要写没验证过的向量。** 这个项目里已经出现过两次子代理编造测试向量的情况，都靠交叉验证才发现。宁可少收录，也不要假数据自欺。

---

## 许可与免责

本项目是密码学工具集，用于开发、测试与互操作性验证。**使用者需自行评估其是否符合所在司法辖区的密码产品合规要求**（如国内的商用密码相关法规）。在生产环境使用前，建议进行独立的安全评估。
