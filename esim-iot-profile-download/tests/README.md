# eSIM IoT Profile Download - 测试指南

## 概述

本目录包含与智能卡读卡器交互的测试脚本，用于验证 Skill 的端到端功能。

## 前置条件

### 1. 安装依赖

```bash
# 安装 Python 依赖
pip install -r requirements.txt

# 或者单独安装 pyscard
pip install pyscard
```

### 2. 确保 PC/SC 服务运行

```bash
# 检查 pcscd 状态
systemctl status pcscd

# 如果未运行，启动它
sudo systemctl start pcscd
sudo systemctl enable pcscd
```

### 3. 连接读卡器和智能卡

- 确保 PC/SC 读卡器已连接
- 确保 eUICC 智能卡已插入读卡器

## 测试脚本

### 1. 快速测试 (`quick_test.py`)

最简单的读卡器连接测试，验证基本功能。

```bash
# 列出读卡器并连接第一个
python3 quick_test.py

# 连接指定读卡器
python3 quick_test.py --reader "SCM Microsystems"
```

**输出示例：**
```
==================================================
Smart Card Reader Quick Test
==================================================

✓ Found 1 reader(s):
  [0] SCM Microsystems Inc. SCR 3310 00 00

Connecting to: SCM Microsystems Inc. SCR 3310 00 00
✓ Connected!
  Reader: SCM Microsystems Inc. SCR 3310 00 00
  ATR: 3B7F96000080318065B0830300900090C1

Testing SELECT MF (00 A4 00 04 02 3F 00 00)...
  Response: 61109000 SW=9000
  ✓ SELECT MF successful

✓ Quick test completed
```

### 2. 完整测试 (`test_card_connection.py`)

功能完整的测试工具，支持多种测试模式。

```bash
# 列出所有读卡器
python3 test_card_connection.py --list-readers

# 连接并显示 ATR
python3 test_card_connection.py --connect

# 发送原始 APDU
python3 test_card_connection.py --apdu "00A40004023F0000"

# 测试 IC1/IC2 初始化序列
python3 test_card_connection.py --test-ic-sequence

# 测试 eUICC 信息读取
python3 test_card_connection.py --test-euicc-info --channel 1

# 交互式 APDU 发送
python3 test_card_connection.py --interactive

# 调试模式
python3 test_card_connection.py --debug --connect
```

### 3. 端到端测试 (`end_to_end_test.py`)

完整的 Profile 下载测试，连接读卡器 + 本地 SM-DP+。

```bash
# 使用默认配置运行
python3 end_to_end_test.py

# 指定读卡器
python3 end_to_end_test.py --reader "SCM Microsystems"

# 使用配置文件
python3 end_to_end_test.py --input input-example-resources.json

# 调试模式
python3 end_to_end_test.py --debug
```

## 测试流程

### 基本连接测试

```
1. 列出读卡器
2. 连接读卡器
3. 读取 ATR
4. 发送 SELECT MF
5. 验证响应
```

### IC1/IC2 初始化测试

```
1. SELECT MF
2. TERMINAL CAPABILITY
3. TERMINAL PROFILE
4. STATUS
5. MANAGE_CHANNEL OPEN
6. SELECT ISD-R
```

### eUICC 信息读取测试

```
1. GetEuiccInfo1 (BF20)
2. GetEuiccChallenge (BF2E)
3. 验证响应
```

### 端到端 Profile 下载测试

```
1. 初始化本地 SM-DP+
2. 加载证书和 Profile
3. 连接读卡器
4. 执行完整下载流程:
   - IC1/IC2 初始化
   - Cleanup
   - GetEuiccInfo1
   - GetEuiccChallenge
   - AuthenticateServer (BF38)
   - PrepareDownload (BF21)
   - LoadProfilePackage (BF36)
   - 验证
   - Final Cleanup
```

## 配置文件

### input-example.json

基本配置示例（需要手动提供证书数据）。

### input-example-resources.json

资源目录配置示例（自动从 resources 目录加载证书和 Profile）。

```json
{
  "operation": "install_and_enable",
  "mode": "direct",
  "eid": "89049032123451234512345678901235",
  "smdp_address": "testsmdpplus1.example.com",
  "matching_id": "04386-AGYFT-A74Y8-3F815",
  "iccid": "8929901012345678905",
  "profile_id": "A0000005591010FFFFFFFF8900001000",
  "resources_dir": "/path/to/resources"
}
```

## 常见问题

### Q: 找不到读卡器？

**A:** 检查以下几点：
1. 读卡器是否已连接：`lsusb`
2. pcscd 是否运行：`systemctl status pcscd`
3. 是否有权限访问：`sudo usermod -aG scard $USER`（需要重新登录）

### Q: 连接被拒绝？

**A:** 检查：
1. 是否有其他程序占用了读卡器
2. 智能卡是否正确插入
3. 尝试重新插拔智能卡

### Q: APDU 返回错误 SW？

**A:** 常见 SW 码：
- `9000`: 成功
- `6A86`: 参数错误（尝试不同的 P1/P2）
- `6982`: 安全状态不满足
- `6985`: 条件不满足
- `6F00`: 内部错误

### Q: 如何调试？

**A:** 使用 `--debug` 参数启用详细日志：
```bash
python3 test_card_connection.py --debug --connect
```

## 模块说明

### card_reader.py

读卡器连接模块，封装了 pyscard 的功能：
- `CardReader`: 读卡器连接类
- `list_readers()`: 列出所有读卡器
- `transmit()`: 发送 APDU
- 上下文管理器支持

### test_card_connection.py

完整测试工具，支持：
- 列出读卡器
- 连接测试
- APDU 发送
- IC1/IC2 序列测试
- eUICC 信息读取
- 交互式模式

### quick_test.py

快速测试脚本，用于：
- 验证读卡器连接
- 基本 APDU 测试
- 故障排查

### end_to_end_test.py

端到端测试，集成：
- 本地 SM-DP+
- 读卡器连接
- 完整 Profile 下载流程

## 参考

- [pyscard 文档](https://pyscard.sourceforge.net/)
- [CERTIFICATE_GUIDE.md](../CERTIFICATE_GUIDE.md)
- [README.md](../README.md)
