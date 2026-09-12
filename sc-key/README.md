# sc-key

密钥生成、派生、分散、封装与校验值（KCV）技能。纯 TypeScript，零第三方依赖：PBKDF2/HKDF/scrypt 使用 `node:crypto`，AES-KW/KWP、X9.63-KDF、分散算法、SM3 为自实现。

## 运行

要求 Node.js >= 22.18（原生 TypeScript 类型剥离，无需编译）。

```bash
node scripts/key.ts --input '{"operation":"generate","algorithm":"AES-256"}'
node scripts/key.ts --input '{"operation":"wrap","algorithm":"AES-KW","kek":"...","data":"..."}'
node scripts/key.ts --input-file ./in.json
echo '{...}' | node scripts/key.ts
```

## 参数

按 operation 区分：

| operation | 必填 | 可选 |
|---|---|---|
| `generate` | algorithm | length（仅 `GENERIC`）、parity |
| `derive` | algorithm | ikm/password、salt、info、hash、keylen、iterations、N/r/p |
| `diversify` | algorithm、key、data | — |
| `wrap` / `unwrap` | algorithm、kek、data | — |
| `kcv` | algorithm、key | — |

## 算法

### 生成

| algorithm | 长度 |
|---|---|
| `AES-128` / `AES-192` / `AES-256` | 16 / 24 / 32 字节 |
| `SM4` | 16 字节 |
| `3DES` / `3DES-2KEY` | 24 / 16 字节 |
| `HMAC-SHA256` / `HMAC-SHA512` | 32 / 64 字节 |
| `GENERIC` | 由 `length` 指定 |

`3DES` 密钥默认做**奇校验位调整**（每个字节的最低位置为奇校验），符合 DES/3DES 惯例；传 `"parity": false` 可关闭。

### 派生

| algorithm | 说明 |
|---|---|
| `PBKDF2` | `node:crypto` pbkdf2Sync，需 `hash`、`iterations`、`salt` |
| `HKDF` | RFC 5869 Extract-then-Expand；`hash` 支持 SM3（自实现 HMAC-SM3） |
| `SCRYPT` | `node:crypto` scryptSync，参数 `N`/`r`/`p` |
| `X9.63-KDF` | ANSI X9.63 / SEC 1 计数器 KDF：`H(shared ‖ counter32 ‖ sharedInfo)` |

派生结果会附带 `params` 字段（hash、salt、info、iterations、keylen 等），便于审计与复现——**注意 `params` 不含任何秘密材料**。

### 分散（diversify）

分散算法全部是**显式实现**，每个函数都在代码注释中写明所依据的构造，不做任何隐式推断：

| algorithm | 构造 |
|---|---|
| `NXP-AES128` | `AES-CMAC(master, 0x01‖input)` 与 `AES-CMAC(master, 0x02‖input)` 拼接后取前 16 字节（AN10922 风格全密钥分散） |
| `AES-ECB` | `AES-ECB(master, input)`，input 必须恰好 16 字节 |
| `3DES` | 左半 = `3DES-ECB(master, input)`，右半 = `3DES-ECB(master, NOT(input))`，最后做奇校验调整；input 必须 8 字节 |

> **互操作性提醒**：各家卡商/支付组织的分散算法命名与细节差异很大。`NXP-AES128` 的构造是行业常见做法，但对接具体项目前**必须**用对方提供的测试向量验证。

### 封装

| algorithm | 说明 |
|---|---|
| `AES-KW` | RFC 3394，输入必须是 ≥16 字节且为 8 的倍数，含 A6A6…A6 完整性校验 |
| `AES-KWP` | RFC 5649，支持任意长度（≥1 字节），含 AIV 常量与 MLI 长度校验 |

### KCV

| algorithm | 说明 |
|---|---|
| `KCV-ZERO` | 用密钥加密全零块，取前 3 字节 |
| `KCV-CMAC` | `AES-CMAC(key, 16 个零字节)` 取前 3 字节（EMV 常用） |
| `KCV-SHA256` | `SHA-256(key)` 取前 3 字节 |

> **安全提示**：KCV 会泄露密钥的 3 字节派生信息。只在方案明确要求时使用，并避免把 KCV 暴露给不可信方。

## 测试

```bash
node --test tests/key.test.ts
```

向量位于 `tests/vectors/key.json`：

- **AES-KW**：RFC 3394 全部 6 条官方向量（4.1–4.6），wrap 与 unwrap 双向验证；
- **HKDF**：RFC 5869 TC1 与 TC3（TC2 未收录，见 README 末尾说明）；
- **PBKDF2**：PBKDF2-HMAC-SHA256 参考向量，并与 `node:crypto` 交叉比对；
- **SM3**：GM/T 0004。

另有：KWP 任意长度 round-trip、篡改后 unwrap 必须失败、HKDF/PBKDF2 与 `node:crypto` 一致性、生成密钥长度与随机性、3DES 奇校验、KCV 确定性与三种算法互不相同、分散的确定性与输入敏感性、**分散输出绝不回显主密钥**、缺参与非法 hex 报错。

## 安全注意事项

- 密钥、主密钥、KEK **绝不**写入日志、错误信息或输出。错误响应只含错误码与描述。
- `diversify` 与 `kcv` 的返回只包含派生结果与元信息，**不包含**输入的主密钥。
- `unwrap` 校验失败一律返回 `INTEGRITY_CHECK_FAILED`，**不会**返回可能已被破坏的密钥。
- 缺失的密码参数（如 `hash`、`iterations`）会显式报错，不会由实现猜测默认值（PBKDF2 的 `iterations` 默认 100000 属文档化的接口默认，非密码参数猜测）。
- 随机数一律来自 `node:crypto` 的 `randomBytes`（CSPRNG）。

## 限制

- 未提供 `3DES-KW` 的 CLI 入口（`des3KeyWrap` 是简化实现：3DES-CBC + 外部 IV，无完整性校验，不适合作为安全封装，故未暴露）。
- 未提供 SM2-KDF（GM/T 0003 基于 SM3 的 KDF）。
- 未提供 RSA/EC 密钥对的生成（见 `sc-signature`）。
- HKDF 仅收录 RFC 5869 TC1 与 TC3：TC2 的期望值未能可靠核对，故不收录，避免写入未经证实的数据。
