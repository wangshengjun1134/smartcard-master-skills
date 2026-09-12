# sc-digest

密码学摘要（Hash）计算技能。纯 TypeScript，零第三方依赖：MD5 / SHA-1 / SHA-2 / SHA-3 使用 `node:crypto`，国密 SM3 为自实现。

## 运行

要求 Node.js >= 22.18（原生 TypeScript 类型剥离，无需编译）。

```bash
node scripts/digest.ts --input '{"operation":"hash","algorithm":"SHA-256","data":"616263"}'
node scripts/digest.ts --input-file ./in.json
echo '{"operation":"hash","algorithm":"SM3","data":"616263"}' | node scripts/digest.ts
```

退出码：`ok:true` → 0；`ok:false` → 1。stdout 只输出一份 JSON。

## 参数

| 字段 | 类型 | 必填 | 说明 |
|---|---|---|---|
| operation | string | 是 | `hash` / `list` |
| algorithm | string | hash 时必填 | 见下「算法」表 |
| data | string | hash 时必填 | 待摘要数据 |
| encoding | string | 否 | `data` 的解码方式：`hex`（默认）/ `utf8` / `ascii` / `base64` |

`encoding` 只影响**输入**如何被解码，**输出永远是 HEX 大写**。

## 算法

| 算法 | 输出长度（字节） | 实现来源 |
|---|---|---|
| `MD5` | 16 | node:crypto（遗留） |
| `SHA-1` | 20 | node:crypto（遗留） |
| `SHA-224` / `SHA-256` / `SHA-384` / `SHA-512` | 28 / 32 / 48 / 64 | node:crypto |
| `SHA-512/224` / `SHA-512/256` | 28 / 32 | node:crypto（NIST FIPS 180-4 截断变体） |
| `SHA3-224` / `SHA3-256` / `SHA3-384` / `SHA3-512` | 28 / 32 / 48 / 64 | node:crypto（NIST FIPS 202） |
| `SM3` | 32 | 自实现（GM/T 0004） |

## 示例

```bash
# 对 hex 数据 616263（即 "abc"）取 SHA-256
node scripts/digest.ts --input '{"operation":"hash","algorithm":"SHA-256","data":"616263"}'
# {"ok":true,"algorithm":"SHA-256","digest":"BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD","length":32}

# 直接对文本取摘要
node scripts/digest.ts --input '{"operation":"hash","algorithm":"SHA-256","data":"abc","encoding":"utf8"}'

# 国密 SM3
node scripts/digest.ts --input '{"operation":"hash","algorithm":"SM3","data":"616263"}'
# digest = 66C7F0F462EEEDD9D1F2D46BDC10E4E24167C4875CF2F7A2297DA02B8F4BA8E0

# 列出支持的算法
node scripts/digest.ts --input '{"operation":"list"}'
```

## 测试

```bash
node --test tests/digest.test.ts
```

测试向量位于 `tests/vectors/digest.json`，覆盖全部 13 个算法的 `abc` 与空串两个用例：

- NIST FIPS 180-4 示例（SHA-1/SHA-2 系列）
- NIST FIPS 202 示例（SHA-3 系列）
- GM/T 0004 示例（SM3）

## 安全注意事项

- 摘要不是 MAC：不具备密钥，无法提供消息认证。需要认证请用 `sc-mac`。
- MD5 与 SHA-1 存在已知碰撞攻击，仅用于兼容存量系统，**不得**用于新设计的完整性/签名场景。
- 缺失 `algorithm` 会报 `MISSING_PARAMETER`，实现**不会**默认选择某个算法。

## 限制

- 不支持 HMAC（见 `sc-mac`）、不支持带密钥的 KDF（见 `sc-key`）。
- 不支持流式/分块增量输入；大文件请自行分块后拼接（注意这不等价于流式哈希的语义）。
- 不支持 SHAKE / cSHAKE 等可扩展输出函数（XOF）。
