# sc-tlv 开发者文档

智能卡 / EMV 场景的 TLV 编解码与查询技能。零运行时依赖，使用 Node 22 原生 TS 类型剥离运行。

## 安装与运行

```bash
node scripts/tlv.ts --input '{"operation":"parse","data":"6F0A8408A000000003000000"}'
node scripts/tlv.ts --input-file ./req.json
echo '{"operation":"parse","data":"..."}' | node scripts/tlv.ts
```

- 成功：`{"ok":true,...}`；失败：`{"ok":false,"error":{"code":"...","message":"..."}}`，退出码 1
- **stdout 仅含 JSON**，无日志

## 操作与参数

| 操作 | 必填字段 | 说明 |
|---|---|---|
| parse | data, format? | 解析为树；`pretty` 附加 tag 名称与文本树 |
| encode | items | 由节点数组编码为 HEX |
| find | data, tag | 查找首个匹配 tag；未找到 `found:false`（仍 `ok:true`） |
| set | data, tag, value | 替换首个匹配值（变原地为基本元素），未找到则追加到根 |
| delete | data, tag | 删除首个匹配 tag |
| flatten | data | 展开为叶子节点扁平列表（含 path） |

公共参数：`format`(`ber`/`simple`/`raw`，默认 `ber`)、`preserve_order`(默认 true)、`tag_bytes`/`length_bytes`(RAW 格式用)。

## 算法 / 格式说明

### BER-TLV（默认）
- **Tag**：首字节低 5 位（0x1F）全 1 表示多字节 tag，继续读取直到高 bit 为 0 的字节。
- **构造位**：tag 首字节 bit5（0x20）置位 → constructed，其 value 递归解析为子 TLV。
- **Length**：
  - 短形式：`0x00`–`0x7F` 表示长度本身；
  - 长形式：`0x80 | N`（N∈1..4）后跟 N 字节大端长度；
  - `0x80`（不定长）→ `UNSUPPORTED_LENGTH_FORM`；`0xFF`（保留）→ `MALFORMED_TLV`；N>4 → `MALFORMED_TLV`。

### SIMPLE-TLV
- Tag 1 字节，Length 1 字节（0–255）；构造位同样取首字节 0x20。Length > 255 编码时报 `INVALID_INPUT`。

### RAW-TLV
- Tag / Length 字节数由 `tag_bytes` / `length_bytes`（默认 1）指定，Length 为大端整数。超出表示范围时报 `INVALID_INPUT`。

## 关键设计取舍

- **fail-closed**：截断数据、声明的 length 超出剩余字节、非法 length 编码、尾部多余字节、奇数长度 hex → 一律 `MALFORMED_TLV`（或对应错误码），绝不静默截断或返回部分结果。
- **不定长 `0x80` 不支持**：智能卡场景几乎不用不定长，统一返回 `UNSUPPORTED_LENGTH_FORM`，避免与值 `0x80` 混淆。
- **Tag 字典只是元数据**：`algorithms/tags.ts` 仅含常见 EMV tag 名称（如 `9F02` = Amount, Authorised），仅在 `pretty` 输出时给节点附加 `name`，**解析器逻辑完全不依赖它**。
- **set 语义**：命中时替换为首层基本元素（constructed 位置保留），未命中时追加到根末尾；`preserve_order` 默认 true，保证原始顺序不被打乱。
- **flatten** 仅列出非构造（叶子）节点，每个带完整 `path`（祖先 tag 以 `/` 连接）。

## 示例命令

```bash
# 解析并美化
node scripts/tlv.ts --input '{"operation":"parse","data":"6F15A5138408A0000000030000009F0206000000001000","pretty":true}'
# 编码嵌套
node scripts/tlv.ts --input '{"operation":"encode","items":[{"tag":"6F","children":[{"tag":"84","value":"A000000003000000"}]}]}'
# 查找
node scripts/tlv.ts --input '{"operation":"find","data":"6F15A5138408A0000000030000009F0206000000001000","tag":"9F02"}'
```

## 测试向量来源

`tests/vectors/tlv.json` 为自构真实向量，覆盖：单层 / 嵌套 constructed / 多字节 tag（9F02）/ 长形式长度（0x8180=128）/ SIMPLE / RAW / find 命中与未命中 / set 替换与追加 / delete / flatten / 各类畸形反例（0xFF、0x80 不定长、N>4、截断、尾部多余、非法 hex）。运行：

```bash
node --test
```

## 安全注意事项

- 本技能为非密码学纯数据解析，不处理密钥/敏感值。
- 错误信息仅含结构化 `error.code` 与简短说明，不回显输入中的数据内容。

## 已知限制

- RAW 与 SIMPLE 的 length 上限受 `length_bytes` / 1 字节约束；超大长度需相应配置。
- `set` 会把命中节点固化为基本元素（不保留其原有子节点结构）。
- 字典仅覆盖常见 EMV tag，未知 tag 在 pretty 模式下不显示名称。
