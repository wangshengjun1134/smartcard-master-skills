# sc-padding

分组密码 / MAC 的填充、去填充与校验技能。纯 TypeScript，零第三方依赖。

## 运行

要求 Node.js >= 22.18（原生 TypeScript 类型剥离，无需编译）。

```bash
node scripts/padding.ts --input '{"operation":"pad","algorithm":"PKCS7","data":"0011223344","block_size":16}'
node scripts/padding.ts --input-file ./in.json
echo '{"operation":"validate","algorithm":"PKCS7","data":"...","block_size":16}' | node scripts/padding.ts
```

退出码：`ok:true` → 0；`ok:false` → 1。stdout 只输出一份 JSON。

## 参数

| 字段 | 类型 | 必填 | 说明 |
|---|---|---|---|
| operation | string | 是 | `pad` / `unpad` / `validate` |
| algorithm | string | 是 | 见下「填充方案」表，大小写不敏感 |
| data | hex | 是 | 输入字节 |
| block_size | 整数 | 是 | 块大小（字节），1–255 |

## 填充方案

| 方案 | 填充规则 | 能否无歧义还原长度 |
|---|---|---|
| `ISO7816-4` | 追加 `0x80`，再补 `0x00` 至块长倍数 | 能 |
| `ISO9797-1-M1` | 仅补 `0x00` 至块长倍数（已是倍数则不补） | **不能** |
| `ISO9797-1-M2` | 追加 `0x80` 再补 `0x00`（字节层面同 ISO7816-4） | 能 |
| `PKCS7` | 补 N 个字节，每个字节值 = N；已是倍数则**再补一整块** | 能 |
| `ANSI-X9.23` | 补 `0x00`，最后一个字节 = 填充长度 | 能 |
| `ZERO` | 仅补 `0x00` | **不能**（有歧义） |

### 关于 ISO7816-4 与 ISO9797-1-M2

两者在字节层面产生**完全相同**的输出。它们被保留为两个独立条目，是为了让调用方能够表达规范来源上的意图（智能卡块填充 vs. MAC 填充方法 2），而不是因为实现不同。互操作上二者可以互换。

### 关于 ZERO 与 ISO9797-1-M1 的歧义

`ZERO` 和 `ISO9797-1-M1` 都不记录原始数据长度，因此**无法区分真实数据尾部的零字节与填充字节**。

- `ISO9797-1-M1` 的 `unpad` 直接返回块对齐后的数据（不裁剪），因为它没有足够信息；
- `ZERO` 的 `unpad` 会裁掉所有尾部 `0x00`，这会**误删**原始数据末尾的零字节。

需要精确还原长度时，请使用 `PKCS7`、`ANSI-X9.23` 或 `ISO7816-4`。

### 示例

```bash
# 输入已是块长倍数时，PKCS7 仍会补出一整块（16 字节 0x10）
node scripts/padding.ts --input '{"operation":"pad","algorithm":"PKCS7","data":"00112233445566778899AABBCCDDEEFF","block_size":16}'
# -> 00112233445566778899AABBCCDDEEFF10101010101010101010101010101010

# ISO 7816-4
node scripts/padding.ts --input '{"operation":"pad","algorithm":"ISO7816-4","data":"0011223344","block_size":8}'
# -> 0011223344800000
```

## 测试

```bash
node --test tests/padding.test.ts
```

覆盖：各方案填充/去填充、块对齐时的 PKCS7 补整块、ANSI-X9.23 长度字节、M1 已对齐不补、round-trip、非法 padding 的 fail-closed 行为、`validate` 对畸形输入返回 `false` 而不抛错、`block_size` 必填与范围校验、未知方案与非法 hex 报错、`ZERO` 的歧义行为。

## 安全注意事项

- **去填充必须 fail-closed**：任何非法填充（长度 0、长度超过块长、PKCS7 字节值不一致、ISO7816-4 找不到 `0x80` 分界、数据非块长倍数）都会返回 `INVALID_PADDING`，**绝不**返回可能已被破坏的数据。
- 这一点对避免 padding oracle 至关重要：调用方不应把 `INVALID_PADDING` 与其它错误（如 `INVALID_HEX`）区分暴露给不可信方，也不应让两者的响应时间产生可观测差异。
- 本技能只做填充，不做加解密（见 `sc-encryption`）或 MAC（见 `sc-mac`）。

## 限制

- 不支持 ISO/IEC 9797-1 填充方法 3 及其之后的变体（其长度块构造属于 MAC 算法的一部分，见 `sc-mac` 的 ISO9797-1-M3）。
- 不支持 bit-level 填充（如 SHA-3 的 pad10*1）。
