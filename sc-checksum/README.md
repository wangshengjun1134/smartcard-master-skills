# sc-checksum

非密码学校验值计算与校验技能。纯 TypeScript，零第三方依赖，全部算法直接实现。

## 运行

要求 Node.js >= 22.18（原生 TypeScript 类型剥离，无需编译）。

```bash
node scripts/checksum.ts --input '{"operation":"compute","algorithm":"CRC-32","data":"313233343536373839"}'
node scripts/checksum.ts --input-file ./in.json
echo '{"operation":"compute","algorithm":"CRC-8","data":"00FF10"}' | node scripts/checksum.ts
```

退出码：`ok:true` → 0；`ok:false` → 1。stdout 只输出一份 JSON。

## 参数

| 字段 | 类型 | 必填 | 说明 |
|---|---|---|---|
| operation | string | 是 | `compute`（别名 `checksum`）/ `verify`（别名 `validate`） |
| algorithm | string | 是 | 见下「算法」表 |
| data | hex | 是 | 输入字节 |
| checksum | hex | verify 时必填 | 期望的校验值 |
| init | 整数 | 否 | 覆盖初始值 |
| xorout | 整数 | 否 | 覆盖结果异或值 |
| poly | 整数 | 否 | 覆盖多项式（仅 CRC） |
| endian | string | 否 | `big`（默认）/ `little`，多字节输出的字节序 |

## 算法

### CRC 系列

表驱动实现，参数化为 width / poly / init / refin / refout / xorout。

| 算法 | 宽度 | 多项式（反射形式） | 初始值 | 结果异或 | check 值* |
|---|---|---|---|---|---|
| `CRC-8` | 8 | 0x07 | 0x00 | 0x00 | `F4` |
| `CRC-8/MAXIM` | 8 | 0x8C（正向 0x31） | 0x00 | 0x00 | `A1` |
| `CRC-16/CCITT-FALSE` | 16 | 0x1021 | 0xFFFF | 0x0000 | `29B1` |
| `CRC-16/IBM` | 16 | 0xA001（正向 0x8005） | 0x0000 | 0x0000 | `BB3D` |
| `CRC-16/XMODEM` | 16 | 0x1021 | 0x0000 | 0x0000 | `31C3` |
| `CRC-32` | 32 | 0xEDB88320 | 0xFFFFFFFF | 0xFFFFFFFF | `CBF43926` |
| `CRC-32C` | 32 | 0x82F63B78 | 0xFFFFFFFF | 0xFFFFFFFF | `E3069283` |

\* check 值为输入 `"123456789"`（hex `313233343536373839`）的标准结果，来自 CRC catalogue 的通行定义。

> **注意**：`CRC_ALGORITHMS` 表中存的多项式是**反射形式**（refin=true 时需用反射多项式）。例如 `CRC-8/MAXIM` 正向多项式是 0x31，反射后为 0x8C，表中存 0x8C。修改参数时请保持一致。

### 非 CRC 校验

这些算法在不同标准里定义不一致，本技能采用的定义如下，均有测试覆盖：

| 算法 | 定义 | `123456789` 的结果 |
|---|---|---|
| `XOR` | 所有字节按位异或，单字节 | `31` |
| `LRC` | **字节和的二进制补码**：`(0x100 - (sum & 0xff)) & 0xff`，即 ISO 1155 LRC-8，满足 `sum(data) + LRC ≡ 0 (mod 256)` | `23` |
| `SUM-8` | 所有字节之和 mod 2⁸ | `DD` |
| `SUM-16` | 所有字节之和 mod 2¹⁶（字节序由 `endian` 决定） | `01DD` |

> **ISO/IEC 7816-3 T=1 用户请注意**：T=1 协议中的 "LRC" 字节实际是**所有字节的异或**，在本技能中对应 `XOR` 算法，不是 `LRC`。

## 测试

```bash
node --test tests/checksum.test.ts
```

测试向量位于 `tests/vectors/checksum.json`，包含全部 11 个算法的标准 check 值。另有针对已修复缺陷的回归测试：

- CRC-32 结果不得被截断为 0（`1 << 32` 在 JS 中溢出为 1 的经典陷阱）；
- `CRC-8/MAXIM` 必须使用反射多项式 0x8C；
- `LRC` 与 `XOR` 不得退化为同一实现。

## 安全注意事项

**校验值不是 MAC。** CRC、LRC、XOR、SUM 都只能检测随机误码，**完全无法**防御蓄意篡改——攻击者可以轻易构造碰撞。任何安全相关的完整性校验请使用 `sc-mac`。

## 限制

- 未覆盖全部 CRC catalogue 变体；可通过 `poly`/`init`/`xorout` 覆盖参数来自定义。
- 不支持按字节反射输入输出的混合模式（`refin≠refout`）以外的自定义位序组合。
- 不支持 Fletcher / Adler 校验和。
