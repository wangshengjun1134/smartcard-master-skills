# sc-signature

数字签名与验签技能。纯 TypeScript，零第三方依赖：RSA / RSA-PSS / ECDSA / EdDSA 使用 `node:crypto`，国密 SM2 与 SM3 为自实现（已通过 GM/T 0003 官方向量验证）。

## 运行

要求 Node.js >= 22.18（原生 TypeScript 类型剥离，无需编译）。

```bash
node scripts/signature.ts --input '{"operation":"generate","algorithm":"SM2"}'
node scripts/signature.ts --input-file ./req.json
echo '{"operation":"verify",...}' | node scripts/signature.ts
```

退出码：`ok:true` → 0；`ok:false` → 1。stdout 只输出一份 JSON。

## 参数

| 字段 | 类型 | 必填 | 说明 |
|---|---|---|---|
| operation | string | 是 | `sign` / `verify` / `generate` |
| algorithm | string | 是 | `RSA`、`RSA-PSS`、`ECDSA`、`SM2`、`EdDSA`（大小写不敏感） |
| data | hex | sign/verify | 待签消息 |
| private_key | PEM | sign | PEM 私钥 |
| public_key | PEM | verify | PEM 公钥 |
| signature | hex | verify | 待验签名 |
| hash | string | RSA/ECDSA 必填 | `SHA-224`/`SHA-256`/`SHA-384`/`SHA-512`/`SM3` |
| curve | string | 否 | ECDSA：`P-256`/`P-384`/`P-521`/`secp256k1`；EdDSA：`Ed25519`/`Ed448` |
| salt_length | 整数 | 否 | RSA-PSS 盐长，默认取摘要长度 |
| signature_encoding | string | 否 | `der`（默认）或 `raw`（r‖s），ECDSA/SM2 适用 |
| sm2_id | string | 否 | SM2 用户标识，默认 `1234567812345678` |

## 算法说明

| 算法 | 实现来源 | 说明 |
|---|---|---|
| `RSA` | node:crypto | PKCS#1 v1.5 |
| `RSA-PSS` | node:crypto | 概率签名，需 `hash`，可选 `salt_length` |
| `ECDSA` | node:crypto | 支持 P-256/384/521、secp256k1 |
| `SM2` | 自实现 | GM/T 0003，含 ZA 计算与 sm2p256v1 曲线运算 |
| `EdDSA` | node:crypto | Ed25519 / Ed448 |

### 签名编码 ≠ 密钥编码

`signature_encoding` 只影响签名的序列化格式：

- `der`：ASN.1 `SEQUENCE { INTEGER r, INTEGER s }`，SM2/ECDSA 默认。
- `raw`：r 与 s 各按曲线字节数定长拼接（SM2 为 64 字节）。

它与密钥的 PEM/DER 编码是**两回事**，二者互不影响。

### SM2 要点

- SM2 固定使用 SM3 摘要，传入其它 `hash` 会报 `INVALID_PARAMETER`。
- `sm2_id` 参与 ZA（`SM3(ENTL‖ID‖a‖b‖xG‖yG‖xA‖yA)`）计算，**改变 ID 会得到完全不同的签名**。跨系统对接时双方必须使用相同 ID，默认 `1234567812345678`。
- `sm2_id` 支持 `hex:` 前缀传入原始字节，如 `hex:01020304`。

## 测试

```bash
node --test tests/signature.test.ts
```

测试覆盖：

1. **SM3 / SM2 官方向量**（`tests/vectors/sm2.json`，GM/T 0003.5-2012 附录示例）：公钥坐标、ZA、固定 k 下的 r/s、验签通过、篡改消息与篡改 s 均被拒绝；
2. **各算法 round-trip**：SM2（DER + raw）、ECDSA P-256（DER + raw）、RSA 与 RSA-PSS、Ed25519；
3. **参数校验**：RSA/ECDSA 缺 `hash` 必须报错（不允许默认推断）、EdDSA 不接受 `hash`、SM2 不接受非 SM3、未知操作/算法报错；
4. **sm2_id 语义**：不同 ID 签名互不可验。

## 安全注意事项

- 私钥只在内存中存在，**不会**写入日志、错误信息或任何输出。
- `verify` 失败返回 `ok:false` + `SIGNATURE_INVALID`，这是正常的校验结果，不是内部错误；内部异常为 `INTERNAL_ERROR`。
- 缺失的密码参数一律显式报错，**不会**由实现猜测（例如不会默认 SHA-256）。
- SM2 签名使用 `crypto.randomBytes` 生成随机 k，`k` 不可通过外部参数指定（固定 k 仅用于内部测试向量验证）。

## 限制

- 不做证书链/PKI 校验（X.509 解析属更高层能力）。
- 不支持密钥格式的相互转换（PEM↔DER↔JWK）。
- SM2 加密/解密（GM/T 0003 第 4 部分）不在本技能范围内。
