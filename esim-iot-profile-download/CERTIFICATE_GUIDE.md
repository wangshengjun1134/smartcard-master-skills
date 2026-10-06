# eSIM IoT Profile Download Skill - 证书和 Profile 配置指南

## 概述

本 Skill 支持两种方式指定证书和 Profile 文件：
1. **资源目录方式**（推荐）：通过 `resources_dir` 参数指定目录，自动发现证书和 Profile 文件
2. **直接传入方式**：通过输入参数直接传入证书和 Profile 数据（适合动态场景）

---

## 方式一：资源目录方式（推荐）

### 目录结构

```
resources_dir/
├── certs/                          # 证书和密钥目录
│   ├── SK_S_SM_DP_TLS_NIST.pem     # DPauth 私钥 (PEM 格式)
│   ├── CERT_S_SM_DP_TLS_NIST.der   # DPauth 证书 (DER 格式)
│   ├── SK_S_SM_DPpb_ECDSA_NIST.pem # DP Profile Binding 私钥 (PEM 格式)
│   ├── CERT_S_SM_DPpb_ECDSA_NIST.der # DP Profile Binding 证书 (DER 格式)
│   └── CERT_CI_ECDSA_NIST.pem      # CI 根证书 (PEM 格式)
└── profiles/                       # Profile 文件目录
    ├── PROFILE_OPERATIONAL1.HEX    # 默认 UPP 文件 (十六进制文本)
    ├── PROFILE_OPERATIONAL1.bin    # 或二进制格式
    └── PROFILE_OPERATIONAL1_8929901012345678905.HEX  # 按 ICCID 匹配
```

### 证书文件说明

| 文件 | 格式 | 说明 | 必需 |
|------|------|------|------|
| `SK_S_SM_DP_TLS_*.pem` | PEM | DPauth 私钥，用于 InitiateAuthentication 签名 | ✅ |
| `CERT_S_SM_DP_TLS_*.der` | DER | DPauth 证书，包含公钥和身份信息 | ✅ |
| `SK_S_SM_DPpb_*.pem` | PEM | DP Profile Binding 私钥，用于 BPP 签名 | ✅ |
| `CERT_S_SM_DPpb_*.der` | DER | DP Profile Binding 证书，用于 BPP 验证 | ✅ |
| `CERT_CI_*.pem` | PEM | CI 根证书，信任根，用于验证证书链 | ✅ |

### Profile 文件说明

| 文件 | 格式 | 说明 | 必需 |
|------|------|------|------|
| `PROFILE_OPERATIONAL1.HEX` | 十六进制文本 | UPP (User Profile Package)，每行一个 Profile | 条件 |
| `PROFILE_OPERATIONAL1.bin` | 二进制 | UPP 二进制文件 | 条件 |
| `*<ICCID>.*` | 任意 | 按 ICCID 匹配的 Profile 文件（优先级最高） | 可选 |

**匹配优先级：**
1. `profiles/*<ICCID>*.*` （按 ICCID 匹配）
2. `profiles/PROFILE_OPERATIONAL1.HEX` （默认十六进制文件）
3. `profiles/PROFILE_OPERATIONAL1.bin` （默认二进制文件）

### 输入参数示例

```json
{
  "operation": "install_and_enable",
  "mode": "direct",
  "eid": "89049032123451234512345678901235",
  "smdp_address": "testsmdpplus1.example.com",
  "matching_id": "04386-AGYFT-A74Y8-3F815",
  "iccid": "8929901012345678905",
  "profile_id": "A0000005591010FFFFFFFF8900001000",
  "resources_dir": "/home/user/smartcard-resources",
  "profile_name": "Operational Profile 1",
  "spn": "Test SP",
  "profile_class": 2,
  "rounds": 1
}
```

---

## 方式二：直接传入方式

### 适用场景
- 证书和 Profile 数据动态生成
- 不想使用文件系统
- 需要嵌入式部署

### 输入参数示例

```json
{
  "operation": "install_and_enable",
  "mode": "direct",
  "eid": "89049032123451234512345678901235",
  "smdp_address": "testsmdpplus1.example.com",
  "matching_id": "04386-AGYFT-A74Y8-3F815",
  "iccid": "8929901012345678905",
  "profile_id": "A0000005591010FFFFFFFF8900001000",
  
  "dp_auth_key_pem": "LS0tLS1CRUdJTiBQUklWQVRFIEtFWS0tLS0tXG4...",
  "dp_auth_cert_der": "MIIBkTCB+wIJALRiMLAh...",
  "dp_pb_key_pem": "LS0tLS1CRUdJTiBQUklWQVRFIEtFWS0tLS0tXG4...",
  "dp_pb_cert_der": "MIIBkTCB+wIJALRiMLAh...",
  "ci_cert_pem": "LS0tLS1CRUdJTiDRVGlGSUNBVEUtLS0tLQo...",
  
  "upp_payload": "A0000005591010FFFFFFFF8900001000...",
  
  "profile_name": "Operational Profile 1",
  "spn": "Test SP",
  "profile_class": 2,
  "rounds": 1
}
```

### 参数说明

| 参数 | 类型 | 说明 |
|------|------|------|
| `dp_auth_key_pem` | string | DPauth 私钥 (PEM 格式字符串) |
| `dp_auth_cert_der` | string | DPauth 证书 (Base64 编码的 DER) |
| `dp_pb_key_pem` | string | DP Profile Binding 私钥 (PEM 格式字符串) |
| `dp_pb_cert_der` | string | DP Profile Binding 证书 (Base64 编码的 DER) |
| `ci_cert_pem` | string | CI 根证书 (PEM 格式字符串) |
| `upp_payload` | string | UPP Profile Payload (十六进制字符串或 Base64) |

---

## 证书生成示例

### 使用 OpenSSL 生成测试证书

```bash
# 1. 生成 DPauth 私钥 (ECDSA P-256)
openssl ecparam -genkey -name prime256v1 -out SK_S_SM_DP_TLS_NIST.pem

# 2. 生成 DPauth 证书 (自签名，有效期 365 天)
openssl req -new -x509 -key SK_S_SM_DP_TLS_NIST.pem \
    -out CERT_S_SM_DP_TLS_NIST.der \
    -days 365 \
    -subj "/CN=SM-DP+ Auth/O=Test/C=CN" \
    -set_serial 1001 \
    -outform DER

# 3. 生成 DP Profile Binding 私钥
openssl ecparam -genkey -name prime256v1 -out SK_S_SM_DPpb_ECDSA_NIST.pem

# 4. 生成 DP Profile Binding 证书
openssl req -new -x509 -key SK_S_SM_DPpb_ECDSA_NIST.pem \
    -out CERT_S_SM_DPpb_ECDSA_NIST.der \
    -days 365 \
    -subj "/CN=SM-DP+ Profile Binding/O=Test/C=CN" \
    -set_serial 1002 \
    -outform DER

# 5. 生成 CI 根证书 (PEM 格式)
openssl ecparam -genkey -name prime256v1 -out SK_CI_ECDSA_NIST.pem
openssl req -new -x509 -key SK_CI_ECDSA_NIST.pem \
    -out CERT_CI_ECDSA_NIST.pem \
    -days 3650 \
    -subj "/CN=CI Root/O=Test/C=CN" \
    -set_serial 1
```

---

## Profile 文件 (UPP) 格式

### UPP 文件内容

UPP (User Profile Package) 是加密的 Profile 数据，通常由 SM-DP+ 服务器生成。

**十六进制文本格式示例** (`PROFILE_OPERATIONAL1.HEX`):
```
A0000005591010FFFFFFFF8900001000
0102030405060708090A0B0C0D0E0F10
1112131415161718191A1B1C1D1E1F20
...
```

**二进制格式示例** (`PROFILE_OPERATIONAL1.bin`):
```
[二进制数据]
```

---

## 完整配置示例

### 示例 1：使用资源目录

```bash
# 1. 创建资源目录
mkdir -p /home/user/smartcard-resources/{certs,profiles}

# 2. 复制证书
cp /path/to/certs/* /home/user/smartcard-resources/certs/

# 3. 复制 Profile 文件
cp /path/to/profiles/* /home/user/smartcard-resources/profiles/

# 4. 运行 Skill
python3 main.py --input '{
  "operation": "install_and_enable",
  "mode": "direct",
  "eid": "89049032123451234512345678901235",
  "smdp_address": "testsmdpplus1.example.com",
  "matching_id": "04386-AGYFT-A74Y8-3F815",
  "iccid": "8929901012345678905",
  "profile_id": "A0000005591010FFFFFFFF8900001000",
  "resources_dir": "/home/user/smartcard-resources"
}'
```

### 示例 2：使用输入参数

```bash
python3 main.py --input '{
  "operation": "install_and_enable",
  "mode": "direct",
  "eid": "89049032123451234512345678901235",
  "smdp_address": "testsmdpplus1.example.com",
  "matching_id": "04386-AGYFT-A74Y8-3F815",
  "iccid": "8929901012345678905",
  "profile_id": "A0000005591010FFFFFFFF8900001000",
  "dp_auth_key_pem": "LS0tLS1CRUdJTiBQUklWQVRFIEtFWS0tLS0t...",
  "dp_auth_cert_der": "MIIBkTCB+wIJALRiMLAh...",
  "dp_pb_key_pem": "LS0tLS1CRUdJTiBQUklWQVRFIEtFWS0tLS0t...",
  "dp_pb_cert_der": "MIIBkTCB+wIJALRiMLAh...",
  "ci_cert_pem": "LS0tLS1CRUdJTiDRVGlGSUNBVEUtLS0tLQo...",
  "upp_payload": "A0000005591010FFFFFFFF8900001000..."
}'
```

---

## 常见问题

### Q: 证书文件格式不对怎么办？

**A**: 检查证书格式：
- 私钥必须是 PEM 格式（`-----BEGIN PRIVATE KEY-----` 开头）
- 证书必须是 DER 格式（二进制）或 PEM 格式（`-----BEGIN CERTIFICATE-----` 开头）
- 使用 `openssl x509 -in cert.der -inform DER -text -noout` 验证证书

### Q: Profile 文件加载失败？

**A**: 检查：
1. 文件是否在 `resources/profiles/` 目录下
2. 文件名是否包含 ICCID 或为 `PROFILE_OPERATIONAL1.HEX/.bin`
3. HEX 文件是否为纯十六进制文本（无 `0x` 前缀）
4. 使用 `xxd` 或 `hexdump` 验证二进制文件内容

### Q: 如何验证证书链？

**A**: 使用 OpenSSL：
```bash
openssl verify -CAfile CERT_CI_ECDSA_NIST.pem CERT_S_SM_DP_TLS_NIST.der
openssl verify -CAfile CERT_CI_ECDSA_NIST.pem CERT_S_SM_DPpb_ECDSA_NIST.der
```

### Q: 支持国密 SM2 证书吗？

**A**: 当前版本仅支持 ECDSA P-256。国密 SM2 支持计划中。

---

## 参考

- [SGP.22 v2.0](https://www.gsma.com/solutions/iot/resources/gsma-sgp-22-euicc-remote-manager-requirements-and-technical-specifications/) - eUICC Remote Manager 规范
- [SGP.33 v1.0](https://www.gsma.com/solutions/iot/resources/gsma-sgp-33-iot-euicc-technical-specification/) - IoT eUICC 规范
- [OpenSSL 文档](https://www.openssl.org/docs/) - 证书生成和验证工具
