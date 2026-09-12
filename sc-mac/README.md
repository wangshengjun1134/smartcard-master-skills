# sc-mac

MAC（消息认证码）计算与校验技能。纯 TypeScript，零第三方依赖，仅使用 `node:` 内置模块与自实现的国密算法。

## 运行

要求 Node.js >= 22.18（使用原生 TypeScript 类型剥离，无需编译）。

```bash
# 方式一：--input 传 JSON
node scripts/mac.ts --input '{"operation":"mac","algorithm":"HMAC-SHA256","key":"0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B","data":"4869205468657265"}'

# 方式二：stdin
echo '{"operation":"mac","algorithm":"AES-CMAC","key":"2B7E151628AED2A6ABF7158809CF4F3C","data":""}' | node scripts/mac.ts

# 方式三：文件
node scripts/mac.ts --input-file ./in.json
```

退出码：`ok:true` → 0；`ok:false` → 1。stdout 只会输出一份 JSON。

## 参数

| 字段 | 类型 | 必填 | 说明 |
|---|---|---|---|
| operation | string | 是 | `mac` / `verify` |
| algorithm | string | 是 | 见下「算法」表 |
| key | hex | 是 | AES 16/24/32 字节；3DES 16/24 字节；SM4 16 字节 |
| data | hex | 是 | 消息，允许空串 |
| cipher | string | 否 | ISO9797 系列使用的块密码：`AES`/`3DES`/`SM4`，默认 `3DES` |
| iv | hex | 否 | CBC-MAC 初始向量，默认全 0 |
| mac_length | integer | 否 | 截断长度（字节），取最左若干字节 |
| expected | hex | 否 | `verify` 时必填 |

## 算法

| 算法 | 底层 | 说明 |
|---|---|---|
| `HMAC-MD5` / `HMAC-SHA1` / `HMAC-SHA224` / `HMAC-SHA256` / `HMAC-SHA384` / `HMAC-SHA512` | node:crypto `createHmac` | RFC 2104 |
| `HMAC-SM3` | 自实现 SM3 | 国密 HMAC |
| `AES-CMAC` | node:crypto AES-ECB | RFC 4493 / NIST SP 800-38B |
| `3DES-CMAC` | node:crypto 3DES-ECB | 同上，8 字节块 |
| `3DES-MAC` | 补零 CBC-MAC | 智能卡/EMV 常用，等价于 ISO9797 Method 1 |
| `ISO9797-1-M1-MAC` | 补 `0x00` 后 CBC-MAC | 若已是块长倍数则不补 |
| `ISO9797-1-M2-MAC` | 追加 `0x80` 再补 `0x00` | 总是至少追加一字节 |
| `ISO9797-1-M3-MAC` | M1 结果异或长度块后再加密 | 见下方说明 |
| `SM4-MAC` | 自实现 SM4 + CBC-MAC | 国密 |

### ISO9797-1 Method 3 的定义

ISO/IEC 9797-1 Algorithm 3 在不同实现中细节有差异。本技能采用的定义是：

1. 按 Method 1（补 `0x00`）计算 CBC-MAC，得到 `MAC1`；
2. 构造一个块长大小的补充块，其中低 8 字节为**原始消息比特长度**的 64 位大端表示，其余补 `0x00`；
3. `MAC = E_K(MAC1 XOR 补充块)`，使用原始密钥 `K`。

与其它实现的互操作性请以本定义为准，跨系统对接前建议先用已知向量比对。

### 关于 IV 默认为全 0

加密操作中缺失 IV 必须报错，但 **CBC-MAC 的初始向量标准定义就是全 0**，因此这里允许省略 `iv` 并默认全 0。这是 MAC 与加密的语义差异，不是疏漏。

### MAC 截断 ≠ 摘要截断

`mac_length` 是对 MAC 结果取**最左**若干字节（如 EMV 常用的 8 字节 MAC、银联常见的 4 字节）。这与把摘要截断是不同概念，请勿混用。

## 测试

```bash
node --test tests/mac.test.ts
```

测试包含三部分：

1. **官方 KAT 向量** —— RFC 4231（HMAC）、RFC 4493（AES-CMAC）、GM/T 0004（SM3）、GM/T 0002（SM4）；
2. **与 `node:crypto` 的独立交叉验证** —— 测试内另写一份基于 `createCipheriv` 的 CBC-MAC 参考实现，比对结果；
3. **错误处理** —— 非法 hex、未知算法、错误密钥长度等。

## 安全注意事项

- 密钥仅存在于内存中，**不会**被写入日志、错误信息或输出。任何错误响应都不包含密钥内容。
- 缺失的密码参数（如算法、密钥）一律显式报错，**不会**由实现猜测默认值。
- 未提供的密钥长度不会自动补齐或截断。
- 3DES 与 MD5/SHA-1 属于遗留算法，仅用于兼容存量系统；新系统请优先选择 `HMAC-SHA256` / `AES-CMAC`。

## 限制

- 不支持 `ISO9797-1` Algorithm 4/5/6（基于哈希或专用 MAC 构造）。
- 不支持 GMAC / Poly1305 等 AEAD 类 MAC。
- SM4 为自实现（Node.js 不提供），已通过 GM/T 0002 官方向量验证。
