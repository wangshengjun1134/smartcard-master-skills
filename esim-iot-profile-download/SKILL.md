# eSIM IoT Profile Download Skill

## 业务概述

实现 IoT 卡的 Profile 安装和启用流程，遵循 SGP.33 4.2.21.2.1 TC_eUICC_ES10b_EnableProfile_Case3 规范。**完整内嵌本地 SM-DP+ 实现**，无需远程 HTTP 调用。

**核心流程：**
1. 冷启动和初始化（IC1/IC2）
2. 准备阶段（Cleanup）
3. Profile 安装（本地 SM-DP+ 下载链）
4. eIM Enable（间接模式启用 Profile）
5. 验证和 Cleanup

## 本地 SM-DP+ 功能

### InitiateAuthentication
- 验证 Profile Package 存在
- 解析 EuiccInfo1，验证 CI PK ID
- 生成 transactionId 和 serverChallenge
- 编码 serverSigned1 并用 DPauth 私钥签名
- 返回认证响应（serverSigned1 + signature + certificate）

### AuthenticateClient
- 验证 eUICC AuthenticateServerResponse
- 验证 transactionId/EID/challenge 匹配
- 编码 smdpSigned2 并用 DP Profile Binding 私钥签名
- 返回认证响应（smdpSigned2 + signature + certificate）

### GetBoundProfilePackage
- 解析 PrepareDownloadResponse，获取 eUICC OTPK
- ECKA 密钥协商（ECDH）
- 派生加密密钥（X9.63 KDF）
- 加密 UPP Payload（AES-GCM）
- 编码 BPP 并签名
- 分段传输（255 字节/段）

## 操作模式

- **direct**: 直接模式下载（本地 SM-DP+ 直接交互）
- **indirect**: 间接模式（通过 eIM 平台）

## 输入参数

| 字段 | 类型 | 必填 | 说明 |
|------|------|------|------|
| operation | string | yes | `install_and_enable` |
| mode | string | no | `direct` / `indirect`（默认 indirect） |
| eid | string | yes | eUICC EID（32 位数字） |
| smdp_address | string | yes | SM-DP+ 地址 |
| matching_id | string | yes | Matching ID（5-32 字符） |
| iccid | string | yes | Profile ICCID（10-20 位数字） |
| profile_id | string | yes | Profile AID（ISD-P AID，32 位十六进制） |
| eim_id | string | 条件 | eIM 平台 ID（indirect 模式必填） |
| tac | hex | no | TAC 字节（默认 00000000） |
| profile_name | string | no | Profile 名称 |
| spn | string | no | Service Provider Name |
| profile_class | number | no | Profile 类别（默认 2） |
| rounds | number | no | 执行轮次（默认 1） |
| resources_dir | string | 条件 | 证书资源目录路径 |

## 输出

```json
{
  "ok": true,
  "profile_state": "ENABLED",
  "isdp_aid": "A0000005591010FFFFFFFF8900001000",
  "rounds_completed": 1
}
```

## 执行阶段

### 阶段 1: 初始化和准备
- 冷启动 + RESET
- IC1: SELECT MF + TERMINAL CAPABILITY
- IC2: TERMINAL PROFILE + STATUS + 打开逻辑通道
- SELECT ISD-R
- Cleanup（MemoryReset + ListNotification + RemoveNotification）

### 阶段 2: Profile 安装（本地 SM-DP+ 下载链）
- IC1/IC2 重新初始化
- GetEuiccInfo1 (BF20)
- GetEuiccChallenge (BF2E)
- AuthenticateServer (BF38) - **本地 SM-DP+ InitiateAuthentication**
- PrepareDownload (BF21) - **本地 SM-DP+ AuthenticateClient**
- LoadProfilePackage (BF36 分段) - **本地 SM-DP+ GetBoundProfilePackage**
- 验证 ProfileInstallationResult (BF37)

### 阶段 3: eIM Enable（间接模式）
- AddInitialEim (BF57)
- LoadEuiccPackage Enable PSMO (BF51)
- 验证 EnableResult

### 阶段 4: 验证
- COLDRESET + 重新 IC1/IC2
- GetProfilesInfo (BF2D)
- 验证 Profile 状态 = ENABLED

### 阶段 5: Final Cleanup
- EuiccMemoryReset
- ListNotification + RemoveNotification

## 规则

- 所有 APDU 响应 SW 码接受: 9000, 91XX, 61XX
- 91XX 响应需要 FETCH 获取完整数据
- 61XX 响应需要 STATUS 命令获取响应长度
- Profile 安装支持分段传输（BF36，255 字节/段）
- eIM Enable 使用 Enable PSMO（无 rollbackFlag）
- 支持多轮次循环测试（性能测试）
- 错误处理：关键步骤失败立即终止，非关键步骤警告继续

## 技术实现

- 语言: Python 3.10+
- ASN.1 编解码: pyasn1
- 密码学: cryptography (ECDSA P-256, AES-GCM, ECKA)
- 状态机: DownloadSession (INITIATED → CLIENT_AUTHENTICATED → DELIVERED)
- **本地 SM-DP+**: 完整实现 InitiateAuthentication / AuthenticateClient / GetBoundProfilePackage
