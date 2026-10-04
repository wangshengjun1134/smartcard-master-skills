# eSIM IoT Profile Download Skill

IoT eSIM Profile 下载和启用 Skill（本地 SM-DP+ 实现）

## 概述

基于 SGP.33 4.2.21.2.1 TC_eUICC_ES10b_EnableProfile_Case3 规范实现 IoT 卡的 eSIM Profile 安装和启用功能。**完整内嵌本地 SM-DP+ 实现**，无需远程调用。

## 核心特性

### 本地 SM-DP+ 实现
- **InitiateAuthentication** - 初始化认证（生成 serverSigned1 + 签名）
- **AuthenticateClient** - 客户端认证（验证 eUICC 响应）
- **GetBoundProfilePackage** - 生成 BPP（ECKA 密钥协商 + AES 加密 + 签名）
- **ProfilePackageStore** - Profile Package 内存存储
- **BppGenerator** - BPP 生成器（支持分段传输）

### 双模式支持
- **Direct 模式**：直接与本地 SM-DP+ 交互
- **Indirect 模式**：通过 eIM 平台间接启用

### 完整业务流程
1. 初始化 → Cleanup → Profile 安装（BF20→BF2E→BF38→BF21→BF36）→ eIM Enable（BF57→BF51）→ 验证 → Final Cleanup

## 安装

```bash
pip install -r requirements.txt
```

## 使用

### 输入参数

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
  "tac": "00000000",
  "rounds": 1,
  "resources_dir": "/path/to/resources"
}
```

### 输出结果

```json
{
  "ok": true,
  "profile_state": "enabled",
  "isdp_aid": "A0000005591010FFFFFFFF8900001000",
  "rounds_completed": 1
}
```

## 项目结构

```
esim-iot-profile-download/
├── src/                     # 核心模块
│   ├── __init__.py
│   ├── utils.py             # 工具函数
│   ├── pki_manager.py       # PKI 证书/密钥管理
│   ├── crypto_provider.py   # 密码学操作（ECDSA/AES-GCM/ECKA）
│   ├── asn1_codec.py        # ASN.1 DER 编解码（BF38/BF21/BF36）
│   ├── profile_package_store.py  # Profile Package 存储
│   ├── bpp_generator.py     # BPP 生成器
│   ├── smdp_plus.py         # 本地 SM-DP+ 实现
│   ├── state_machine.py     # 下载会话状态机
│   ├── apdu_builder.py      # APDU 命令构建器
│   └── profile_download.py  # Profile 下载业务流程
├── main.py                  # Skill IPC 入口
├── skill.json               # Skill 元数据
├── requirements.txt         # Python 依赖
├── resources/               # 资源文件
│   └── certs/               # PKI 证书和密钥
├── tests/                   # 测试
│   ├── test_profile_download.py
│   └── input-example.json
├── SKILL.md                 # Skill 规范文档
└── README.md                # 本文件
```

## 技术栈

- **Python 3.10+**
- **cryptography** - 密码学操作（ECDSA P-256、AES-GCM、ECKA）
- **pyasn1** - ASN.1 DER 编解码
- **pydantic** - 数据验证

## 本地 SM-DP+ 实现详解

### InitiateAuthentication 流程

```python
# 1. 验证 Profile Package 存在
template = packages.require_by_matching_id(matching_id)

# 2. 解析 EuiccInfo1，验证 CI PK ID
euicc_info = decode_euicc_info1(euicc_info1)
ci_pk_id = get_subject_key_identifier(trusted_root)

# 3. 生成 transactionId 和 serverChallenge
transaction_id = uuid.uuid4().hex
server_challenge = os.urandom(16)

# 4. 编码 serverSigned1 并签名
server_signed1_der = encode_server_signed1(...)
server_signature1 = sign_ecdsa_p256(server_signed1_der, dp_auth_identity.private_key)

# 5. 返回认证响应
return {
    'transaction_id': transaction_id,
    'server_challenge': server_challenge,
    'server_signed1': server_signed1_der,
    'server_signature1': server_signature1,
    'euicc_ci_pk_id': ci_pk_id,
    'server_certificate': cert_der,
}
```

### GetBoundProfilePackage 流程

```python
# 1. 解析 PrepareDownloadResponse，获取 eUICC OTPK
parsed = decode_prepare_download_response(prepare_download_response)
euicc_otpk = parsed['euicc_otpk']

# 2. ECKA 密钥协商
shared_secret = ecdh_key_agreement(profile_binding_identity.private_key, euicc_otpk)

# 3. 派生加密密钥
enc_key = derive_keys_x963(shared_secret, shared_info, key_length=16)

# 4. 加密 UPP Payload
encrypted_payload = aes_gcm_encrypt(enc_key, payload)

# 5. 编码 BPP 并签名
bpp_der = encode_bpp(...)
signature = sign_ecdsa_p256(bpp_der, profile_binding_identity.private_key)

# 6. 编码为 BF36 格式
bf36 = encode_bf36(bpp_der, signature, certificate)

# 7. 分段
segments = segment_bpp(bf36, max_segment_size=255)
```

## 开发

### 运行测试

```bash
python3 -m unittest tests.test_profile_download -v
```

### 添加新功能

1. 在 `src/` 下实现新模块
2. 在 `src/profile_download.py` 中添加步骤
3. 在 `tests/` 中添加测试

## 证书和 Profile 配置

详见 [CERTIFICATE_GUIDE.md](CERTIFICATE_GUIDE.md)

### 快速开始

**方式一：资源目录（推荐）**
```bash
mkdir -p resources/{certs,profiles}
cp /path/to/certs/* resources/certs/
cp /path/to/profiles/* resources/profiles/
```

**方式二：直接传入**
```json
{
  "dp_auth_key_pem": "...",
  "dp_auth_cert_der": "...",
  "upp_payload": "..."
}
```

## 参考规范

- **SGP.33**: IoT eSIM 远程配置规范
  - 4.2.21.2.1 TC_eUICC_ES10b_EnableProfile_Case3
- **GlobalPlatform**: eUICC 技术规范
- **SGP.22**: SM-DP+ 和 eUICC 接口

## 许可证

私有 - 内部使用
