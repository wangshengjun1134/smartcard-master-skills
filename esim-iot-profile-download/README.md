# eSIM IoT Profile Download Skill

IoT eSIM Profile 下载与启用 Skill（内嵌本地 SM-DP+ 实现）。

- **skillId**: `esim.iot-profile-download`（见 `skill.json`）
- **Runtime**: python 3.10+
- 详细规范见 [SKILL.md](SKILL.md)，证书说明见 [CERTIFICATE_GUIDE.md](CERTIFICATE_GUIDE.md)

## 概述

基于 SGP.33 4.2.21.2.1 `TC_eUICC_ES10b_EnableProfile_Case3`，实现 IoT eSIM Profile 的安装与启用，
业务逻辑对齐 Java 参考脚本 `IOT_PERF_TEST_Install_Enable_Profile`（`ScriptTaskProcesser`）。
**SM-DP+ 功能完全内嵌**，无远程 HTTP 调用。

## 核心特性

### 本地 SM-DP+
- **InitiateAuthentication**：解析 EuiccInfo1、校验 CI PK ID、生成 serverSigned1（DPauth 签名）
- **AuthenticateClient**：校验 eUICC 响应、编码 smdpSigned2（DP Profile Binding 签名）
- **GetBoundProfilePackage**：ECKA/ECDH + X9.63 KDF + SCP03t 保护，按 ASN.1 对象边界生成 BPP 分块
  （块号在每个 StoreData 对象内从 0 重启，末块 `P1=0x91`）

### 双模式
- **direct**：仅安装，不做 eIM 启用
- **indirect**：安装后通过 eIM（AddInitialEim BF57 + LoadEuiccPackage Enable PSMO BF51）启用

### 完整流程
初始化/准备 → Cleanup(BF34/BF28/BF30) → 安装(BF20→BF2E→BF38→BF21→BF36) → PostInstall 冷复位
→ eIM 启用(BF57→BF51→校验) → PostEnable 冷复位 → GetProfilesInfo(BF2D) 校验 → FinalCleanup

### 执行模型（对齐 Skill Runtime 规范）
- 流程由**语义 Step** 驱动，每个 Step 产出 0..N 个 **Action** 交给 Runtime 执行：
  `APDU` / `RESET_CARD` / `WAIT`（Skill 不直接操作读卡器）
- 传输层 61XX/91XX 由 Skill 自动跟进：`61XX` → `GET RESPONSE`、`91XX` → `FETCH`
- 结果不硬编码：`execution_finished.data.profile_state` 来自 `GetProfilesInfo` 的 `9F70`

## 安装

```bash
# 用 Runtime 实际使用的 python 解释器（ProcessPythonHost 用 `python`）
pip install -r requirements.txt
```

运行环境要求（`python` 命令、依赖、`SKILL_PACKAGE_PATH`）见 [SKILL.md](SKILL.md#运行环境)。

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
  "eim_initial_counter": 1,
  "eim_enable_counter": 2,
  "tac": "00000000",
  "rounds": 1,
  "resources_dir": "/path/to/resources"
}
```

字段完整说明见 [SKILL.md](SKILL.md#输入参数)。

### 输出结果（`execution_finished.data`）

```json
{
  "iccid": "8929901012345678905",
  "profile_id": "A0000005591010FFFFFFFF8900001000",
  "eid": "89049032123451234512345678901235",
  "mode": "indirect",
  "rounds_completed": 1,
  "profile_state": "ENABLED",
  "verified": true,
  "isdp_aid": "A0000005591010FFFFFFFF8900001400",
  "enable_result": 0
}
```

`profile_state` / `verified` 为**实际观测值**：若流程跑完但卡片 `9F70` 仍为 0（DISABLED），
则返回 `SUCCESS` + `verified: false` + `WARN` 输出（详见 SKILL.md「已知卡片行为」）。

## 项目结构

```
esim-iot-profile-download/
├── SKILL.md                     # 技能文档（含 IPC 契约 / 参数 / 阶段说明）
├── skill.json                   # Runtime 元数据
├── main.py                      # IPC 入口 + 执行器（Action 批次 / 传输层跟进）
├── requirements.txt             # 运行依赖（cryptography / pyasn1）
├── src/
│   ├── skill_actions.py         # Action 模型（APDU / RESET_CARD / WAIT → IPC JSON）
│   ├── apdu_builder.py          # APDU 命令构建器
│   ├── profile_download.py      # 流程（语义 Step 状态机）
│   ├── asn1_codec.py            # ASN.1 DER 编解码（BF38/BF21/BF20/BF2E）
│   ├── sgp32_codec.py           # SGP.32 eIM 编解码（BF57/BF51/PSMO）
│   ├── bpp_codec.py             # BF36 BPP 编码（SCP03t 保护 + StoreData 分块）
│   ├── scp03t.py                # SCP03t（ECKA / X9.63 KDF / AES-CMAC）
│   ├── smdp_plus.py             # 本地 SM-DP+
│   ├── local_eim.py             # 本地 eIM 平台模拟
│   ├── state_machine.py         # 下载会话状态机（SM-DP+ 侧）
│   ├── crypto_provider.py       # 密码学操作
│   ├── pki_manager.py           # 证书/私钥加载
│   ├── profile_package_store.py # Profile Package 存储
│   └── utils.py                 # 工具函数（hex/BCD/SW/TLV）
├── resources/
│   ├── certs/                   # DPauth / DPpb / CI / EIM 证书与私钥
│   └── profiles/                # UPP Profile 模板 + icon1.png（StoreMetadata 93/94）
└── tests/
    ├── test_profile_download.py # 工具函数单元测试
    ├── test_ipc_contract.py     # IPC 契约 + eIM 报文回归（离线，无需读卡器）
    ├── end_to_end_test.py       # 真卡端到端（复用执行器 + pyscard sink）
    ├── test_card_connection.py  # 真卡 APDU/Cleanup/下载+eIM 调试脚本
    ├── quick_test.py            # 读卡器连通性快速检查
    └── requirements.txt         # 测试依赖（pyscard）
```

## 技术栈

- **Python 3.10+**
- **cryptography**：ECDSA P-256、AES-CMAC/CBC、ECKA（ECDH + X9.63 KDF）
- **pyasn1**：部分 ASN.1 编解码

## 开发

### 运行测试

```bash
# 离线测试（无需读卡器）
python3 -m unittest discover -s tests -p "test_*.py" -v

# 真卡端到端（需读卡器 + 可测试 eUICC）
pip install -r tests/requirements.txt
python3 tests/end_to_end_test.py --input tests/input-example-resources.json
```

### 添加新功能

1. 在 `src/` 下实现协议逻辑
2. 在 `src/profile_download.py` 的 `Step` 枚举与 `_dispatch()` 中登记新步骤（返回 Action 列表）
3. 在 `tests/test_ipc_contract.py` 添加报文/契约回归测试

## 证书和 Profile 配置

证书与 Profile 统一从 `resources_dir`（默认 `SKILL_PACKAGE_PATH/resources`）加载：

```bash
cp /path/to/certs/*    resources/certs/
cp /path/to/profiles/* resources/profiles/
```

文件清单与来源见 [CERTIFICATE_GUIDE.md](CERTIFICATE_GUIDE.md)。

## 参考规范

- **SGP.33**：IoT eSIM 远程配置（4.2.21.2.1 `TC_eUICC_ES10b_EnableProfile_Case3`）
- **SGP.22 / SGP.32**：SM-DP+ / eIM 接口与 eUICC Package
- 内部：《SmartCard Multi Language Skills Guide》《SmartCard Agent Skills Dev v1.1》

## 许可证

私有 - 内部使用
