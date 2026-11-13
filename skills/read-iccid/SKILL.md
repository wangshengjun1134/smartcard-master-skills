# read-iccid

读取 SIM 卡的 ICCID（集成电路卡标识符）。

## Description

该 Skill 通过三步 APDU 指令读取 SIM 卡的 ICCID：

1. **SELECT MF** - 选择主文件 (3F00)
2. **SELECT EF_ICCID** - 选择 ICCID 文件 (2FE2)
3. **READ BINARY** - 读取 10 字节 ICCID 数据

最后解析 BCD 编码的 ICCID 并返回结果。

## Input Schema

```json
{
  "type": "object",
  "properties": {
    "readerId": {
      "type": "string",
      "description": "读卡器标识"
    }
  },
  "required": ["readerId"]
}
```

## Output Schema

```json
{
  "type": "object",
  "properties": {
    "iccid": {
      "type": "string",
      "description": "ICCID 字符串（19-20 位数字）"
    }
  }
}
```

## Usage

### Agent Runtime 调用

```json
// 初始化
{"jsonrpc": "2.0", "id": "1", "method": "skill.init", "params": {"skillId": "read.iccid", "input": {"readerId": "reader-01"}}}

// 启动
{"jsonrpc": "2.0", "id": "2", "method": "skill.start", "params": {"sessionId": "<session-id>"}}

// 处理 Action 结果（需要多轮）
{"jsonrpc": "2.0", "id": "3", "method": "skill.handleActionResult", "params": {"sessionId": "<session-id>", "result": {...}}}
```

### CLI 直接调用

```bash
uv run --package read-iccid-skill read-iccid-skill --direct --input '{"readerId": "reader-01"}'
```

## APDU 指令详解

| 步骤 | APDU | 说明 |
|------|------|------|
| SELECT MF | `00A40000023F00` | 选择主文件 3F00 |
| SELECT EF_ICCID | `00A40000022FE2` | 选择 ICCID 文件 2FE2 |
| READ BINARY | `00B000000A` | 读取 10 字节数据 |

## ICCID 结构

| 位置 | 长度 | 说明 |
|------|------|------|
| 0-1 | 2 | 固定前缀 89（电信行业） |
| 2-3 | 2 | 国家代码（86 = 中国） |
| 4-5 | 2 | 运营商代码 |
| 6-9 | 4 | 个人化数据 |
| 最后 | 1 | Luhn 校验位 |

## BCD 编码规则

- 每个字节包含两个数字
- **低 4 位在前，高 4 位在后**
- 例如：`0x89` → `"98"`
- `0x0F` 表示填充位

## Examples

### 示例 1：标准 ICCID 读取

**输入：**
```json
{"readerId": "reader-01"}
```

**输出：**
```json
{"iccid": "89860012345678901234"}
```

### 示例 2：带填充位的 ICCID

**原始数据（hex）：**
```
98 68 10 32 54 76 98 10 32 F3
```

**解析结果：**
```
898601234567890123
```

## Error Codes

| 错误码 | 说明 |
|--------|------|
| `APDU_ERROR` | APDU 执行失败 |
| `APDU_STATUS_ERROR` | 卡片返回错误状态字 |
| `UNKNOWN_STATE` | 状态机进入未知状态 |

## Requirements

- 需要读卡器支持
- 需要 SIM 卡已插入

## Version

1.0.0
