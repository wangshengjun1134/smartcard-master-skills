# sc-bitfield

位/字节字段操作技能。纯 TypeScript，零第三方依赖。

## 运行

要求 Node.js >= 22.18（原生 TypeScript 类型剥离，无需编译）。

```bash
node scripts/bitfield.ts --input '{"operation":"get","data":"A5","bit_offset":0,"bit_length":4}'
node scripts/bitfield.ts --input-file ./in.json
echo '{...}' | node scripts/bitfield.ts
```

## 参数

| 字段 | 类型 | 必填 | 说明 |
|---|---|---|---|
| operation | string | 是 | `get`/`set`/`extract`/`insert`/`mask`/`shift`/`count`/`reverse`/`msb`/`lsb` |
| data | hex | 是 | 输入字节 |
| bit_offset | 整数 | get/set 系列 | 起始位索引（从 0 开始） |
| bit_length | 整数 | get/set 系列 | 字段位宽 |
| value | 整数/字符串 | set/insert | 待写入的值（整数、十进制字符串或 hex 字符串） |
| direction | string | shift | `left`（默认）/ `right` |
| shift | 整数 | shift | 位移位数 |
| mask | hex | mask（可选） | 直接应用该掩码，而不生成 |
| bit_order | string | 否 | `msb`（默认）/ `lsb` |

## 位序约定（重要）

- **`msb`（默认）**：bit 0 = 第 0 字节的**最高**有效位。这是智能卡 / EMV 数据对象的惯例。
- **`lsb`**：bit 0 = 第 0 字节的**最低**有效位，即 bit *i* 的权重为 2^i。

示例（`data = A5` = `1010 0101`）：

| 操作 | msb | lsb |
|---|---|---|
| `get` offset 0 len 4 | `0A`（高 4 位） | `05`（低 4 位） |
| `get` offset 0 len 8 | `A5` | `A5` |
| `set` offset 0 len 4 = 0x0F | `F5` | `AF` |

## 操作说明

| 操作 | 说明 |
|---|---|
| `get` / `extract` | 读取字段，返回 `value`（十进制字符串）、`bits`、`hex`（大端定长字节，保留前导零） |
| `set` / `insert` | 写入字段，**只修改寻址到的位**，其余位保持不变 |
| `mask` | 给了 `mask` 则按位与；否则按 `bit_length` 生成高位对齐的掩码 |
| `shift` | 整体位移，空出的位补 0 |
| `count` | 统计置位位数（population count） |
| `reverse` | 反转整个比特串（bit 0 变最后一位） |
| `msb` / `lsb` | 取最高/最低有效**位**（`bit`）与该**字节**（`byte`） |

## 示例

```bash
# 取 0x1234 的第 4..11 位（跨字节） -> 0x23
node scripts/bitfield.ts --input '{"operation":"get","data":"1234","bit_offset":4,"bit_length":8}'

# 把 0xA5 的高 4 位改成 0x5，低 4 位不变 -> 55
node scripts/bitfield.ts --input '{"operation":"set","data":"A5","bit_offset":0,"bit_length":4,"value":5}'

# 统计 0xA5 中 1 的个数 -> 4
node scripts/bitfield.ts --input '{"operation":"count","data":"A5"}'

# 反转比特串：0x01 -> 0x80
node scripts/bitfield.ts --input '{"operation":"reverse","data":"01"}'
```

## 测试

```bash
node --test tests/bitfield.test.ts
```

覆盖：两种位序、跨字节字段、`set` 不破坏无关位、值超长报错、popcount、`reverse` 可逆性、`shift` 补零、掩码生成与应用、msb/lsb、越界 `OUT_OF_RANGE`、缺参与非法 hex 报错。

## 错误处理

| 错误码 | 触发条件 |
|---|---|
| `OUT_OF_RANGE` | `bit_offset + bit_length` 超出数据总位数（**不会**静默截断） |
| `INVALID_PARAMETER` | 值为负、超出位宽容纳范围、`direction`/`bit_order` 非法、掩码长度不匹配 |
| `MISSING_PARAMETER` | 缺少 `bit_offset`/`bit_length`/`value`/`shift` |
| `INVALID_HEX` | `data` 不是合法偶数长 hex |

## 限制

- 单次操作的位宽受 `Number`/`BigInt` 限制，实际上限很大（内部用 `BigInt`），但 `bit_length` 超过约 2^20 时性能会明显下降（逐位循环）。
- 未提供 `concat` / `split` 操作；拼接请直接用 hex 字符串处理。
