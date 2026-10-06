---
name: esim-iot-profile-download
description: IoT eSIM Profile 下载与启用（内嵌本地 SM-DP+，直接模式 + eIM 间接启用，SGP.33）。
---

# eSIM IoT Profile Download Skill

通过 SmartCard Skill Runtime 执行 IoT eSIM Profile 的安装与启用，**完整内嵌本地 SM-DP+**
（无需远程 HTTP 调用）。业务逻辑对齐 Java 参考脚本
`IOT_PERF_TEST_Install_Enable_Profile`（`ScriptTaskProcesser`），对应 SGP.33
4.2.21.2.1 `TC_eUICC_ES10b_EnableProfile_Case3`。

## 运行环境

- Python 3.10+，依赖见 `requirements.txt`（`cryptography`、`pyasn1`）
- Runtime 通过 `ProcessPythonHost` 以 **`python`**（不是 `python3`）启动入口文件，
  **不会自动安装依赖**，也不使用技能包内的虚拟环境。请确保该解释器具备上述依赖：
  ```bash
  pip install -r requirements.txt     # 用 Runtime 实际使用的 python 执行
  ```
- 证书/Profile 资源目录：默认取环境变量 `SKILL_PACKAGE_PATH` 下的 `resources/`
  （可用输入参数 `resources_dir` 覆盖），内含：
  - `certs/SK_S_SM_DPauth_ECDSA_NIST.pem`、`certs/CERT_S_SM_DPauth_ECDSA_NIST.der`
  - `certs/SK_S_SM_DPpb_ECDSA_NIST.pem`、`certs/CERT_S_SM_DPpb_ECDSA_NIST.der`
  - `certs/CERT_CI_ECDSA_NIST.pem`
  - `certs/SK_EIM_ECDSA_NIST.pem`、`certs/CERT_EIM_ECDSA_NIST.der`（间接模式必需）
  - `profiles/PROFILE_OPERATIONAL1_<ICCID>.HEX`（UPP）
  - `profiles/icon1.png`（Profile 图标；StoreMetadata(BF25) 的 93/94 字段需要，本测试卡会校验）
- 技能包**不要打包** `venv/`、`__pycache__/`、`tests/card_run_*.log`（仅本地开发/测试产物）

## IPC 契约

| 方向 | 消息 |
| --- | --- |
| Runtime → Skill | `start` / `action_result` / `stop` |
| Skill → Runtime | `skill_action` / `output` / `execution_finished` |

- `action_result.response = { sw: number, data: number[] }`；`RESET_CARD` 结果带 `atr`
- `execution_finished.error` 为字符串；日志写 stderr，stdout 只输出 JSON
- Skill **不直接操作读卡器**，所有卡片操作以 Action 交给 Runtime：
  - `APDU`（`apdu.cla/ins/p1/p2[/data][/le]`；`sensitive` 标记需脱敏的密文块）
  - `RESET_CARD`（冷复位，等价 Java `ApduUtil.coldReset`）
  - `WAIT`（复位后等卡片上电稳定）
- T=0 大响应（`61XX`）与 eUICC 异步响应（`91XX`）由本 Skill 在传输层自动跟进：
  `61XX` → `GET RESPONSE`，`91XX` → `FETCH`，数据自动拼接后再交给流程

## 输入参数

| 字段 | 类型 | 必填 | 说明 |
| --- | --- | --- | --- |
| operation | string | 是 | 固定 `install_and_enable` |
| mode | string | 否 | `direct` / `indirect`（默认 `indirect`） |
| eid | string | 是 | eUICC EID（32 位数字） |
| smdp_address | string | 是 | SM-DP+ 地址 |
| matching_id | string | 是 | Matching ID（5-32 字符） |
| iccid | string | 是 | Profile ICCID（10-20 位数字） |
| profile_id | string | 是 | Profile AID（ISD-P AID） |
| eim_id | string | 条件 | eIM 平台 ID（`indirect` 模式必填） |
| eim_initial_counter | number | 否 | AddInitialEim 的 counter（默认 1） |
| eim_enable_counter | number | 否 | enable PSMO 的 counter（默认 2） |
| tac | hex | 否 | TAC 字节（默认 `00000000`） |
| profile_name | string | 否 | Profile 名称（默认 `IoT Profile`） |
| spn | string | 否 | Service Provider Name |
| profile_class | number | 否 | Profile 类别（默认 2） |
| icon_type | number | 否 | 图标类型（1=PNG, 2=JPG, 0=无；默认按 `profiles/icon1.*` 自动识别） |
| rounds | number | 否 | 循环轮次（默认 1，性能测试用） |
| resources_dir | string | 否 | 证书/Profile 资源目录（默认 `SKILL_PACKAGE_PATH/resources`） |

## 输出

`execution_finished.data` 为**实际观测**到的执行结果（不做硬编码判断）：

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

- `profile_state`：来自 `GetProfilesInfo(BF2D)` 的 `profileState(9F70)`，取值 `ENABLED` / `DISABLED` / `UNKNOWN`
- `verified`：是否最终确认为 `ENABLED`
- `warnings` / `enable_result_note`：容错项说明（例如 eIM enable 返回空响应）
- 状态判读**必须以 `9F70` 为准**，不能仅凭“流程无报错”判定启用成功

## 本地 SM-DP+ 功能

- **InitiateAuthentication**：解析 EuiccInfo1 校验 CI PK ID，生成 transactionId + serverSigned1
  （DPauth 私钥签名）与 serverChallenge
- **AuthenticateClient**：校验 eUICC 的 AuthenticateServerResponse，编码 smdpSigned2
  （DP Profile Binding 私钥签名）
- **GetBoundProfilePackage**：解析 PrepareDownloadResponse 的 eUICC OTPK，ECKA/ECDH 协商 →
  X9.63 KDF → SCP03t 保护 → 生成 BPP，并按 ASN.1 层次边界分块

## 执行阶段（语义 Step）

| 阶段 | 步骤 |
| --- | --- |
| 初始化与准备 | COLDRESET → SELECT MF → TERMINAL CAPABILITY → TERMINAL PROFILE → STATUS + MANAGE_CHANNEL → SELECT ISD-R |
| Cleanup | EuiccMemoryReset(BF34) → 91XX/REFRESH 处理 → ListNotification(BF28) → RemoveNotification(BF30) |
| Profile 安装 | GetEuiccInfo1(BF20) → GetEuiccChallenge(BF2E) → AuthenticateServer(BF38) → PrepareDownload(BF21) → LoadProfilePackage(BF36)（按 ASN.1 对象切分，块号每对象从 0 起） |
| PostInstall | COLDRESET → IC1/IC2 → 打开通道 → SELECT ISD-R |
| eIM 启用（indirect） | AddInitialEim(BF57) → LoadEuiccPackage Enable PSMO(BF51) → 校验 enableResult → PostEnable COLDRESET → IC1/IC2 → SELECT ISD-R → GetProfilesInfo(BF2D) → 校验 profileState |
| FinalCleanup | EuiccMemoryReset → ListNotification → RemoveNotification |
| 轮次 | `rounds > 1` 时回到安装阶段继续下一轮 |

`direct` 模式跳过 eIM 阶段（BF57/BF51），FinalCleanup 前仅校验 `profileState`。

## 关键约束

- 响应 SW 处理：正常 `9000`；`91XX` 用 `FETCH`；`61XX` 用 `GET RESPONSE`（传输层自动跟进）
- BPP（BF36）必须按 ASN.1 层次边界切成 StoreData 对象；BF38/BF21/BF57/BF51 按 255 字节分块
  （块号从 0 起，末块 `P1=0x91`）
- StoreMetadata 的 ICCID 使用**半字节交换 BCD**，并按 Java 参考脚本带上 `iconType/icon`（93/94）；
  eIM enable PSMO 的 ICCID 对齐 Java 参考脚本的**非交换 BCD**（`ScriptTaskProcesser.digitsToBcd`）
- BF38/BF21/BF57 的编码细节（IMPLICIT 上下文标签、`5F37` 签名、eIM 证书承载方式）以 Java 参考
  实测报文为准，见 `src/asn1_codec.py`、`src/sgp32_codec.py`
- 关键步骤失败立即 FAILED；非关键容错项记入 `warnings` 并继续

## 已知卡片行为（测试卡实测，与 Java 参考一致）

`LoadEuiccPackage(enable PSMO)` 在本测试卡上返回**空响应 + SW=9000**，随后 `GetProfilesInfo`
的 `profileState` 仍为 `DISABLED`；Java 参考脚本对此同样容错（只打印 WARNING 后继续）。
因此本 Skill 在流程执行成功但状态未达 `ENABLED` 时返回 `SUCCESS` + `verified: false` + `WARN` 输出，
由调用方据此判定（而不是假装启用成功）。

## 目录结构

```
esim-iot-profile-download/
├── SKILL.md                  # 本文档
├── skill.json                # Runtime 元数据（skillId=esim.iot-profile-download）
├── main.py                   # 入口：IPC 协议 + 执行器（Action 批次 / 传输层跟进）
├── requirements.txt          # 运行依赖
├── resources/                # 证书与 Profile 资源
├── src/                      # 协议逻辑（ASN.1 / SCP03t / SM-DP+ / eIM / 流程）
└── tests/                    # 离线测试 + 真卡连线测试
```
