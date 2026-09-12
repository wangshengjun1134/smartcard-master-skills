# sc-encryption 开发文档

对称加密/解密工具，面向智能卡密码学工作流。零运行时依赖，仅使用 Node 内置模块与纯 TS 自实现的 SM4。

## 安装与运行

```bash
# 使用规范指定的 Node 绝对路径
NODE="C:/Users/DELL/.workbuddy/binaries/node/versions/22.22.2-2/node.exe"
$NODE scripts/encrypt.ts --input '{"operation":"encrypt","algorithm":"AES-128","mode":"CBC","key":"...","iv":"...","data":"..."}'
$NODE scripts/encrypt.ts --input-file ./in.json      # 从文件读取 JSON
echo '{"operation":"..."}' | $NODE scripts/encrypt.ts  # 从 stdin 读取
```

Node 22.22.2 原生支持 TS 类型剥离，无需 tsc/tsx。stdout 只输出一份 JSON，无日志。
成功：`{ "ok": true, ... }`（退出码 0）；失败：`{ "ok": false, "error": { "code": "...", "message": "..." } }`（退出码 1）。

## 参数表

| 字段 | 类型 | 必填 | 说明 |
|---|---|---|---|
| operation | string | 是 | `encrypt` / `decrypt` |
| algorithm | string | 是 | `AES-128`/`AES-192`/`AES-256`/`3DES`/`3DES-2KEY`/`SM4` |
| mode | string | 是 | `ECB`/`CBC`/`CTR`/`GCM` |
| key | hex | 是 | 密钥。AES-128=16B, AES-192=24B, AES-256=32B, 3DES=24B, 3DES-2KEY=16B(扩展为 K1‖K2‖K1), SM4=16B |
| data | hex | 是 | 明文(encrypt)/密文(decrypt) |
| iv | hex | CBC/CTR | 初始向量/计数器块，长度=块长(16 或 8) |
| nonce | hex | GCM | 随机数，默认长度 12 |
| aad | hex | GCM 可选 | 附加认证数据 |
| tag | hex | GCM 解密 | 认证标签 |
| tag_length | int | GCM 加密可选 | 标签长度 4..16，默认 16 |
| padding | string | ECB/CBC 可选 | `none`/`pkcs7`/`iso7816-4`/`iso9797-1-m1`/`iso9797-1-m2`，默认 `pkcs7` |

## 算法与模式支持矩阵

| 算法 | ECB | CBC | CTR | GCM |
|---|---|---|---|---|
| AES-128/192/256 | ✅ | ✅ | ✅ | ✅ |
| 3DES / 3DES-2KEY | ✅ | ✅ | ❌ UNSUPPORTED_MODE | ❌ UNSUPPORTED_MODE |
| SM4 | ✅ | ✅ | ✅ | ❌ UNSUPPORTED_MODE（未实现） |

- **3DES-CTR/GCM 不支持**：`node:crypto` 提供的可用 des cipher 仅有 `des-ede3`、`des-ede3-cbc`、`des-ede3-ecb`（及 cfb/ofb），无 `des-ede3-ctr`，故 3DES 仅支持 ECB/CBC。
- **SM4-GCM 未实现**：SM4 为纯 TS 自实现（GM/T 0002），已实现 ECB/CBC/CTR；GCM 作为 AEAD 未实现，返回 `UNSUPPORTED_MODE`。
- **CTR/GCM 不接受 padding**：传入 `padding` 字段一律报 `INVALID_PARAMETER`（流/AEAD 模式无需分组填充）。

## 测试向量来源

- AES（ECB/CBC/CTR）：FIPS-197 Appendix C.3 官方已知应答向量；AES-GCM 采用 RFC 5116 Test Case 1。
- 3DES：等密钥（K1=K2=K3）退化为单 DES，借用经典 DES 向量（key `133457799BBCDFF1...`，明文 `0123456789ABCDEF` → `85E813540F0AB405`）验证 ECB/CBC 与 2KEY 密钥扩展。
- SM4：GM/T 0002 官方向量（key/明文 `0123456789abcdeffedcba9876543210` → `681EDF34D206965E86B3E94F536E4246`）。
- 数据均存放在 `tests/vectors/kat.json`，由 `tests/encrypt.test.ts` 读取。

## 安全注意事项

- **ECB 风险**：ECB 不提供语义安全，不作为默认推荐；优先使用 CBC/CTR/GCM。README 与 SKILL.md 均标注。
- **缺失参数禁止默认**：IV/nonce 缺失必须报错，**绝不**默认全 0。
- **密钥安全**：密钥绝不打印、写入日志或回显；错误消息不含密钥内容。
- **padding 失败即拒绝（fail-closed）**：非法 padding（长度 0、>块长、字节值不合法、ISO 7816-4 找不到 0x80 分界等）返回 `ok:false`+`INVALID_PADDING`，绝不静默输出错误明文。
- **GCM 认证顺序**：先校验 tag 再返回明文；tag 校验失败返回 `AUTHENTICATION_FAILED`，不泄露明文。
- **ISO 9797-1-M1 局限**：仅补 0x00 且无法可靠去除，解密只能返回填充后的块（块对齐时方可无损往返）；M2 与 ISO 7816-4 字节层面等价，区别仅在规范来源。

## 已知限制

- 3DES 不支持 CTR/GCM；SM4 不支持 GCM。
- `node --test tests/` 在本 Node 22.22.2 下会把目录误当作模块路径，请改用 `node --test`（自动发现 `tests/`）或 `node --test tests/*.test.ts`。

## 示例命令

```bash
# AES-128-CBC 加密（默认 pkcs7 填充）
$NODE scripts/encrypt.ts --input '{"operation":"encrypt","algorithm":"AES-128","mode":"CBC","key":"2b7e151628aed2a6abf7158809cf4f3c","iv":"000102030405060708090a0b0c0d0e0f","data":"4142434445464748494a4b4c4d4e4f"}'

# SM4-ECB 官方向量
$NODE scripts/encrypt.ts --input '{"operation":"encrypt","algorithm":"SM4","mode":"ECB","padding":"none","key":"0123456789abcdeffedcba9876543210","data":"0123456789abcdeffedcba9876543210"}'

# AES-128-GCM 加密
$NODE scripts/encrypt.ts --input '{"operation":"encrypt","algorithm":"AES-128","mode":"GCM","key":"feffe9928665731c6d6a8f9467308308","nonce":"cafebabefacedbaddecaf888","aad":"feedfacedeadbeeffeedfacedeadbeefabaddad2","data":"d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39"}'
```
