# sc-encoding 开发者文档

智能卡工具链的编码 / 数据表示转换技能。零运行时依赖，使用 Node 22 原生 TS 类型剥离运行。

## 安装与运行

```bash
# 直接运行（Node 绝对路径见规范）
node scripts/encoding.ts --input '{"operation":"convert","data":"68656C6C6F","from":"hex","to":"utf8"}'

# 从文件读取
node scripts/encoding.ts --input-file ./req.json

# 从管道读取
echo '{"operation":"decode","data":"aGVsbG8=","encoding":"base64"}' | node scripts/encoding.ts
```

- 成功输出：`{"ok":true,"from":"...","to":"...","result":"...","bytes":N}`，退出码 0
- 失败输出：`{"ok":false,"error":{"code":"...","message":"..."}}`，退出码 1，不抛未捕获异常
- **stdout 仅含 JSON**，无任何日志

## 参数表

| 字段 | 类型 | 必填 | 说明 |
|---|---|---|---|
| operation | string | 是 | `encode` / `decode` / `convert` |
| data | string | 是 | 输入值（语义随 operation 而定，永远是字符串） |
| from | string | convert | 源表示 |
| to | string | convert | 目标表示 |
| encoding | string | encode/decode | encode 的目标表示 / decode 的源表示 |
| length | integer | 否 | `integer` 定长输出字节数；`bcd` 定长字节数 |
| endian | string | 否 | `integer` 字节序，`big`(默认) / `little` |
| bcd_padding | string | 否 | 奇数位 BCD 填充侧，`right`(默认) / `left` |

## 支持的表示（算法清单）

- `hex`：大写十六进制，偶数长度；奇数长度或非 hex 字符 → `INVALID_HEX`
- `ascii`：仅 0x00–0x7F；越界 → `INVALID_INPUT`
- `utf8` / `utf-8`：UTF-8 文本，`TextDecoder({fatal:true})` 保证往返无损
- `latin1`：0x00–0xFF（JS 单字节字符）
- `base64`：标准 base64，带 `=` 填充；非法字符/非法填充 → `INVALID_BASE64`
- `base64url`：`-`、`_` 且无填充
- `bcd`（8421 BCD）：每字节两个十进制数字
- `bcd-tbcd`（压缩 BCD / TBCD）：低 4 位在前、高 4 位在后；`*`=0A `#`=0B `a`–`c`=0C–0E，0F 填充；双向可逆
- `integer`：无符号大整数（BigInt），大端；不指定 `length` 时取最小字节数，值为 0 输出 `00`，指定 `length` 时保留前导零
- `binary`：0/1 字符串，长度须为 8 的倍数

## 语义约定（关键）

- `convert`：显式 `from` → `to`，不做任何隐式推断；缺 `from`/`to` → `MISSING_PARAMETER`
- `decode`：源表示 `encoding` → 底层字节，结果以 `hex` 字符串返回
- `encode`：源是 `hex` 字节串，结果以 `encoding` 表示返回
- 所有二进制一律 **HEX（大写）**
- **前导零字节必须保留**：`integer` 值 1、`length=4` 得到 `00000001`，绝不为 `01`
- **数值与其字节串是不同语义**：`integer` 经 BigInt 处理；`hex` 仅为字节串

## BCD / TBCD 填充约定（取舍说明）

- BCD 奇数位数字串：默认 `bcd_padding=right`（**右靠**，即在左侧补 0，把数值右对齐）。
  例：`"123"` → 左补 0 → `"0123"` → 字节 `01 23` → hex `0123`。
  设 `left` 时右侧补 0：`"123"` → `"1230"` → `1230`。
- BCD 解码每字节固定输出两个数字；因此奇数位编码后再解码会多出一个前导 `0`（右靠时），这是表示本身的固有限制，已在测试与本文中说明。偶数位字符串可无损往返。
- TBCD（如电话号码）：每字节存放两个数字，**低 nibble 在前、高 nibble 在后**；奇数个数字时，最末数字放入低 nibble、高 nibble 填 `0xF`（填充）。例如 `"123"` → `21 F3`。解码遇高 nibble=0xF 即停止，保证双向可逆。

## 示例命令

```bash
# hex -> utf8
node scripts/encoding.ts --input '{"operation":"convert","data":"68656C6C6F","from":"hex","to":"utf8"}'
# 4 字节定长整数，保留前导零
node scripts/encoding.ts --input '{"operation":"convert","data":"1","from":"integer","to":"hex","length":4}'
# TBCD 电话号码
node scripts/encoding.ts --input '{"operation":"decode","data":"123","encoding":"bcd-tbcd"}'
```

## 测试向量来源

`tests/vectors/encoding.json` 为本项目自构的真实向量，覆盖各表示正例、前导零、定长、字节序、填充约定，以及 `INVALID_HEX`/`INVALID_BASE64`/`INVALID_BCD`/`INVALID_INPUT`/`MISSING_PARAMETER`/`UNSUPPORTED_PARAMETER` 反例。运行：

```bash
node --test
```

## 安全注意事项

- 本技能为非密码学纯编码转换，不处理密钥。
- 任何错误信息的 `message` 均不包含敏感输入内容；失败仅以结构化 `error.code` 暴露原因。

## 已知限制

- `integer` 仅支持无符号整数（BigInt），不支持负数与浮点。
- BCD 奇数位字符串无法与偶数位字符串在解码端区分，往返会补前导 0（见上）。
- `base64`/`base64url` 未校验填充位必须为 0（与多数宽松解码器一致）。
