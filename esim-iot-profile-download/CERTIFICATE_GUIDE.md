# eSIM IoT Profile Download Skill - 证书和 Profile 配置指南

## 概述

本 Skill 通过 `resources_dir` 指定证书与 Profile 目录（默认 `SKILL_PACKAGE_PATH/resources`），
按约定文件名自动发现；**不支持**在输入参数里直接传证书/Profile 数据。

---

## 证书与 Profile 目录

### 目录结构

```
resources_dir/
├── certs/                                  # 证书和密钥目录
│   ├── SK_S_SM_DPauth_ECDSA_NIST.pem       # DPauth 私钥 (PEM)
│   ├── CERT_S_SM_DPauth_ECDSA_NIST.der     # DPauth 证书 (DER)
│   ├── SK_S_SM_DPpb_ECDSA_NIST.pem         # DP Profile Binding 私钥 (PEM)
│   ├── CERT_S_SM_DPpb_ECDSA_NIST.der       # DP Profile Binding 证书 (DER)
│   ├── CERT_CI_ECDSA_NIST.pem              # CI 根证书 (PEM)
│   └── SK_EIM_ECDSA_NIST.pem / CERT_EIM_ECDSA_NIST.der   # eIM（indirect 模式必需）
└── profiles/                               # Profile 文件目录
    ├── PROFILE_OPERATIONAL1_<ICCID>.HEX    # 按 ICCID 匹配（优先）
    ├── PROFILE_OPERATIONAL1.HEX            # 默认 UPP 文件（十六进制文本）
    ├── PROFILE_OPERATIONAL1.bin            # 或二进制格式
    └── icon1.png                           # StoreMetadata(93/94) 需要
```

### 证书文件说明

| 文件 | 格式 | 说明 | 必需 |
|------|------|------|------|
| `SK_S_SM_DPauth_ECDSA_NIST.pem` | PEM | DPauth 私钥，用于 InitiateAuthentication 签名 | ✅ |
| `CERT_S_SM_DPauth_ECDSA_NIST.der` | DER | DPauth 证书，包含公钥和身份信息 | ✅ |
| `SK_S_SM_DPpb_ECDSA_NIST.pem` | PEM | DP Profile Binding 私钥，用于 BPP 签名 | ✅ |
| `CERT_S_SM_DPpb_ECDSA_NIST.der` | DER | DP Profile Binding 证书，用于 BPP 验证 | ✅ |
| `CERT_CI_ECDSA_NIST.pem` | PEM | CI 根证书，信任根，用于验证证书链 | ✅ |
| `SK_EIM_ECDSA_NIST.pem` / `CERT_EIM_ECDSA_NIST.der` | PEM / DER | eIM 私钥与证书（BF57/BF51 签名与验证） | indirect 模式 ✅ |

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

## 方式二：外部注入（可选覆盖包内默认）

适合证书轮换、多租户或不希望密钥随技能包发布的场景。**每一项都可单独注入，未注入的仍取包内默认**；
值支持 **PEM 文本**或 **base64 编码的 DER**。

```json
{
  "operation": "install_and_enable",
  "mode": "indirect",
  "eid": "89049032123451234512345678901235",
  "smdp_address": "testsmdpplus1.example.com",
  "matching_id": "04386-AGYFT-A74Y8-3F815",
  "iccid": "8929901012345678905",
  "profile_id": "A0000005591010FFFFFFFF8900001000",
  "eim_id": "testeim1",

  "dp_auth_key": "-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----\n",
  "dp_auth_cert": "MIIBkTCB+wIJALRiMLAh...",
  "dp_pb_key": "-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----\n",
  "dp_pb_cert": "MIIBkTCB+wIJALRiMLAh...",
  "ci_cert": "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----\n",
  "eim_key": "-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----\n",
  "eim_cert": "MIIBkTCB+wIJALRiMLAh...",

  "upp_payload": "A040800102810103821447534D41..."
}
```

| 参数 | 说明 |
|------|------|
| `dp_auth_key` / `dp_auth_cert` | DPauth 私钥 / 证书（InitiateAuthentication 签名） |
| `dp_pb_key` / `dp_pb_cert` | DP Profile Binding 私钥 / 证书（BPP 签名） |
| `ci_cert` | CI 根证书 |
| `eim_key` / `eim_cert` | eIM 私钥 / 证书（indirect 模式必需） |
| `upp_payload` | UPP 载荷（十六进制文本或 base64），覆盖 `profiles/` 下按 ICCID 匹配的文件 |

来源优先级：输入注入 > `resources_dir` 包内文件；本次执行用到的注入项会以 `INFO` 输出事件上报
（`使用外部注入的材料: ...`）。

---

## 证书生成示例

### 使用 OpenSSL 生成测试证书

```bash
# 1. 生成 DPauth 私钥 (ECDSA P-256)
openssl ecparam -genkey -name prime256v1 -out SK_S_SM_DPauth_ECDSA_NIST.pem

# 2. 生成 DPauth 证书 (自签名，有效期 365 天)
openssl req -new -x509 -key SK_S_SM_DPauth_ECDSA_NIST.pem \
    -out CERT_S_SM_DPauth_ECDSA_NIST.der \
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

### 方式 1：通过 Runtime / Agent（推荐）

技能包注册后（见 SKILL.md「注册与开关」），由 agent 在对话中调用
`smartcard_execute_skill`（`skillId = esim.iot-profile-download`），或直接调用
`POST /smartcard/skills/esim.iot-profile-download/execute`，`input` 见 SKILL.md「输入参数」。

### 方式 2：本地真卡调试（测试脚本扮演 Runtime）

```bash
pip install -r tests/requirements.txt          # pyscard
python3 tests/end_to_end_test.py --input tests/input-example.json --mode indirect
```

该脚本复用技能的执行器，用 pyscard 执行 Action 并把 `action_result` 回灌，
因此与 Runtime 下的行为一致（可换成 `--mode direct` 只做安装）。

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
openssl verify -CAfile CERT_CI_ECDSA_NIST.pem CERT_S_SM_DPauth_ECDSA_NIST.der
openssl verify -CAfile CERT_CI_ECDSA_NIST.pem CERT_S_SM_DPpb_ECDSA_NIST.der
```

### Q: 支持国密 SM2 证书吗？

**A**: 当前版本仅支持 ECDSA P-256。国密 SM2 支持计划中。

---

## 参考

- [SGP.22 v2.0](https://www.gsma.com/solutions/iot/resources/gsma-sgp-22-euicc-remote-manager-requirements-and-technical-specifications/) - eUICC Remote Manager 规范
- [SGP.33 v1.0](https://www.gsma.com/solutions/iot/resources/gsma-sgp-33-iot-euicc-technical-specification/) - IoT eUICC 规范
- [OpenSSL 文档](https://www.openssl.org/docs/) - 证书生成和验证工具
