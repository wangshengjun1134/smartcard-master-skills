---
name: read-iccid
description: >
  读取 SIM 卡的 ICCID（集成电路卡标识符）。
  当用户需要获取 SIM 卡号、识别运营商或验证卡片信息时使用。
  通过标准 APDU 指令与卡片通信，解析 BCD 编码的 ICCID 数据。
  不适用于 USIM 应用选择或联系人读取。
---

# 读取 ICCID

读取 SIM 卡的 ICCID（Integrated Circuit Card Identifier）。

## 适用场景

- 获取 SIM 卡唯一标识符
- 识别卡片所属运营商
- 验证 SIM 卡是否可正常通信
- 批量读取多张卡片的 ICCID

## 不适用场景

- 读取 USIM 应用数据（如 5G 密钥）
- 读取联系人或短信
- 修改 SIM 卡内容
- 需要 PIN 验证的操作

## 输入要求

| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| readerId | string | 是 | 读卡器标识 |

## 工作流程

### 步骤 1：选择主文件 (MF)

发送 APDU 指令选择主文件：

```
APDU: 00 A4 00 00 02 3F00
含义: SELECT MF (Master File)
期望: SW = 9000
```

### 步骤 2：选择 ICCID 文件 (EF_ICCID)

发送 APDU 指令选择 ICCID 文件：

```
APDU: 00 A4 00 00 02 2FE2
含义: SELECT EF_ICCID (Elementary File)
期望: SW = 9000
```

### 步骤 3：读取数据

发送 READ BINARY 指令读取 10 字节数据：

```
APDU: 00 B0 00 00 0A
含义: READ BINARY, 偏移 0, 长度 10
期望: SW = 9000, 数据 = 10 字节 BCD 编码
```

### 步骤 4：解析 ICCID

将 BCD 编码转换为数字字符串：

- 每个字节包含两个数字（低 4 位在前，高 4 位在后）
- `0x89` → `"98"`
- `0x0F` 表示填充位，解析结束

## 输出规范

返回 JSON 格式：

```json
{
  "iccid": "89860012345678901234"
}
```

| 字段 | 类型 | 说明 |
|------|------|------|
| iccid | string | 19-20 位数字字符串 |

## 异常处理

| 情况 | 处理方式 |
|------|----------|
| 卡片未插入 | 返回错误，提示用户插入卡片 |
| APDU 执行失败 | 返回 APDU_ERROR，包含详细错误信息 |
| 卡片返回错误状态 | 返回 APDU_STATUS_ERROR，包含 SW 状态字 |
| 数据解析失败 | 返回 PARSE_ERROR，包含原始数据 |

## 参考资源

- [APDU 指令参考](./references/apdu-reference.md)
- [ICCID 格式说明](./references/iccid-format.md)
- [执行流程示例](./examples/read-flow.md)
- [测试用例](./tests/test_cases.md)

## 版本

1.0.0
