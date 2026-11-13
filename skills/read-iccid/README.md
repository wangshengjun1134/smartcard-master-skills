# read-iccid-skill

读取 SIM 卡 ICCID 的 SmartCard Skill。

## 功能

- 通过标准 APDU 指令读取 SIM 卡的 ICCID
- 支持 BCD 编码解析
- 完整的多步状态机实现

## 安装

```bash
uv sync --package read-iccid-skill
```

## 使用

### 作为 Skill 运行

```bash
uv run --package read-iccid-skill read-iccid-skill
```

### 直接模式

```bash
uv run --package read-iccid-skill read-iccid-skill --direct --input '{"readerId": "reader-01"}'
```

## 测试

```bash
uv run pytest tests/test_read_iccid.py -v
```

## 协议

遵循 SmartCard Skill SDK 的 stdin/stdout JSON-RPC 协议。

## 许可证

MIT
