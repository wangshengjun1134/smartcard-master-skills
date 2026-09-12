# sc-random

密码学安全随机数、Nonce、卡片挑战数与 UUID 生成技能。纯 TypeScript，零第三方依赖。

## 运行

要求 Node.js >= 22.18（原生 TypeScript 类型剥离，无需编译）。

```bash
node scripts/random.ts --input '{"operation":"generate","length":16,"count":2}'
node scripts/random.ts --input '{"operation":"challenge"}'      # 8 字节卡片挑战数
node scripts/random.ts --input '{"operation":"nonce","format":"base64"}'
node scripts/random.ts --input '{"operation":"uuid"}'
```

## 参数

| 字段 | 类型 | 必填 | 说明 |
|---|---|---|---|
| operation | string | 是 | `generate` / `nonce` / `challenge` / `uuid` |
| length | 整数 | 否 | 每个值的字节数。默认：`generate` 16、`nonce` 12、`challenge` 8 |
| count | 整数 | 否 | 生成个数，默认 1，上限 1024 |
| format | string | 否 | `hex`（默认）/ `base64` / `dec` / `bin` |

## 默认长度的选择

| 操作 | 默认长度 | 依据 |
|---|---|---|
| `generate` | 16 字节 | 通用随机值（128 bit） |
| `nonce` | 12 字节 | AES-GCM 推荐 nonce 长度（NIST SP 800-38D） |
| `challenge` | 8 字节 | 智能卡 EXTERNAL AUTHENTICATE 常见挑战数长度 |

如果你的智能卡/指令规范要求其它长度，显式传 `length` 即可。

## 关于随机源（重要，请如实理解）

- **本技能是 CSPRNG 接口，不是 TRNG。** 所有输出都来自 `node:crypto` 的 `randomBytes()`，它使用操作系统提供的熵源（Windows 下为 BCryptGenRandom，Linux 下为 getrandom(2)/urandom）。
- **本技能不提供 DRBG / 确定性随机。** 没有 seed 参数，也没有可复现模式。如果需要"用种子复现随机序列"的能力，那属于 DRBG（如 HMAC-DRBG）范畴，本技能**未实现**。
- 代码中**从未**使用 `Math.random()`——它不是密码学安全的随机数。

> 如果你需要在智能卡测试里复现某次随机数，请在业务层自行记录并重放，不要指望本技能提供可复现输出。

## 测试

```bash
node --test tests/random.test.ts
```

覆盖：输出长度与格式、各操作默认长度、`count` 生成多个且互不重复、四种 format 渲染、UUID v4 格式（版本号 `4`、变体位 `8/9/a/b`）、`length`/`count` 上限校验、未知操作与非法 format 报错、4096 次单字节抽样的分布健全性检查。

## 安全注意事项

- 密钥、IV/nonce、挑战数**必须**用 CSPRNG 生成，绝不可用 `Math.random()` 或时间戳。
- `hex` 输出为大写，长度固定为 `length * 2` 个字符（保留前导零），便于直接拼接进 APDU。
- 单次请求最多 `1024 × 65536` 字节，避免误用导致内存压力。

## 限制

- 不提供 DRBG（HMAC-DRBG / CTR-DRBG）。
- 不提供真随机数（TRNG）接口或直接访问硬件熵源。
- 不提供随机整数区间（如"1~100 的随机数"）——如需请取足够字节后自行取模（注意处理模偏差）。
