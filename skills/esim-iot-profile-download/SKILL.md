---
name: esim-iot-profile-download
description: >
  IoT eSIM Profile 下载与启用（内嵌本地 SM-DP+，直接模式 + eIM 间接启用，SGP.33）。
  当用户需要安装 eSIM Profile 到 IoT 设备、测试 eSIM 卡片功能时使用。
  通过 APDU 指令与 eUICC 通信，完成 Profile 的下载、安装和启用。
  不适用于传统 SIM 卡操作或普通手机 eSIM 管理。
---

# eSIM IoT Profile Download

通过 SmartCard Skill Runtime 执行 IoT eSIM Profile 的安装与启用。

## 适用场景

- IoT 设备 eSIM Profile 批量写入
- eSIM 卡片功能测试
- SGP.33 协议验证
- 本地 SM-DP+ 环境搭建

## 不适用场景

- 传统 SIM 卡操作
- 普通手机 eSIM 管理
- 需要远程 SM-DP+ 服务器的场景

## 核心流程

### 阶段 1：初始化与准备

1. **COLDRESET** - 冷复位卡片
2. **SELECT MF** - 选择主文件
3. **TERMINAL CAPABILITY** - 设置终端能力
4. **TERMINAL PROFILE** - 设置终端配置
5. **STATUS + MANAGE_CHANNEL** - 获取状态并管理通道
6. **SELECT ISD-R** - 选择 ISD-R（Issuer Security Domain）

### 阶段 2：下载前清理

> **重要**：在下载前必须清理 eUICC，否则之前失败的下载可能导致后续操作失败。

1. **EuiccMemoryReset (BF34)** - 重置 eUICC 内存，清除之前的下载状态
2. **FETCH REFRESH** - 处理 91XX 异步响应（如果需要）
3. **ListNotification (BF28)** - 列出待处理的通知
4. **RemoveNotification (BF30)** - 删除所有待处理的通知

### 阶段 3：Profile 安装

1. **GetEuiccInfo1 (BF20)** - 获取 eUICC 信息
2. **GetEuiccChallenge (BF2E)** - 获取 eUICC 挑战值
3. **AuthenticateServer (BF38)** - 服务器认证（SM-DP+ 认证）
4. **PrepareDownload (BF21)** - 准备下载
5. **LoadProfilePackage (BF36)** - 加载 Profile 包

### 阶段 4：后安装处理

1. **COLDRESET** - 冷复位
2. **IC1/IC2** - 初始化通道
3. **SELECT ISD-R** - 重新选择 ISD-R
4. **GetProfilesInfo (BF2D)** - 获取 Profile 信息
5. **校验 profileState** - 验证 Profile 状态

### 阶段 5：eIM 启用（间接模式）

1. **AddInitialEim (BF57)** - 添加初始 eIM
2. **LoadEuiccPackage Enable PSMO (BF51)** - 启用 PSMO
3. **校验 enableResult** - 验证启用结果
4. **PostEnable COLDRESET** - 启用后冷复位
5. **SELECT ISD-R** - 重新选择 ISD-R
6. **GetProfilesInfo (BF2D)** - 获取 Profile 信息
7. **校验 profileState** - 验证 Profile 状态

## 输入参数

| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| operation | string | 是 | 固定 `install_and_enable` |
| mode | string | 否 | `direct` / `indirect`（默认 `indirect`） |
| eid | string | 是 | eUICC EID（32 位数字） |
| smdp_address | string | 是 | SM-DP+ 地址 |
| matching_id | string | 是 | Matching ID（5-32 字符） |
| iccid | string | 是 | Profile ICCID（10-20 位数字） |
| profile_id | string | 是 | Profile AID（ISD-P AID） |
| eim_id | string | 条件 | eIM 平台 ID（`indirect` 模式必填） |
| profile_name | string | 否 | Profile 名称（默认 `IoT Profile`） |
| spn | string | 否 | Service Provider Name |

## 输出

```json
{
  "iccid": "8929901012345678905",
  "profile_id": "A0000005591010FFFFFFFF8900001000",
  "eid": "89049032123451234512345678901235",
  "mode": "indirect",
  "profile_state": "ENABLED",
  "verified": true,
  "isdp_aid": "A0000005591010FFFFFFFF8900001400"
}
```

## 关键 APDU 指令

| 指令 | CLA INS P1 P2 | 说明 |
|------|---------------|------|
| EuiccMemoryReset | 80 E2 91 00 | 重置 eUICC 内存（清理） |
| ListNotification | 80 E2 91 00 | 列出待处理通知（清理） |
| RemoveNotification | 80 E2 91 00 | 删除通知（清理） |
| FETCH | 80 12 00 00 | 处理 91XX 异步响应 |
| GetEuiccInfo1 | 80 BF 20 00 | 获取 eUICC 信息 |
| GetEuiccChallenge | 80 BF 2E 00 | 获取挑战值 |
| AuthenticateServer | 80 BF 38 00 | 服务器认证 |
| PrepareDownload | 80 BF 21 00 | 准备下载 |
| LoadProfilePackage | 80 BF 36 00 | 加载 Profile 包 |
| GetProfilesInfo | 80 BF 2D 00 | 获取 Profile 信息 |
| AddInitialEim | 80 BF 57 00 | 添加初始 eIM |
| EnablePSMO | 80 BF 51 00 | 启用 PSMO |

## 异常处理

| 情况 | 处理方式 |
|------|----------|
| 卡片未插入 | 返回错误，提示用户插入卡片 |
| APDU 执行失败 | 返回 APDU_ERROR，包含详细错误信息 |
| Profile 状态异常 | 返回 PROFILE_STATE_ERROR，包含当前状态 |
| 认证失败 | 返回 AUTH_ERROR，包含错误详情 |

## 参考资源

- [SGP.33 规范](https://www.gsma.com/solutions-and-impact/technologies/esim/wp-content/uploads/2020/06/SGP.33-v1.0.pdf)
- [APDU 指令参考](./references/apdu-reference.md)

## 版本

1.0.0
