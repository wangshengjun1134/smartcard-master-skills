# eSIM IoT Profile Download - 测试指南

本目录是技能的测试/调试工具集。**技能完整说明见 `../SKILL.md`**，这里只讲怎么跑。

## 前置条件

### 1. 技能自带环境（uv 优先）

```bash
bash ../scripts/setup-env.sh                 # 创建 <技能包>/.venv（uv venv + uv pip install）
uv pip install --python ../.venv/bin/python -r requirements.txt   # 测试依赖（pyscard）
```

也可以让 agent 通过 IPC 触发运行时环境安装：`{"operation": "setup_env"}`。

### 2. PC/SC 服务与读卡器

```bash
systemctl status pcscd        # 未运行则: sudo systemctl start pcscd
lsusb                         # 确认读卡器已连接，且已插入 eUICC 卡片
```

下述命令都假设用技能自带环境执行（`.venv/bin/python`，或先 `source ../.venv/bin/activate`）。

## 离线测试（无需读卡器）

```bash
.venv/bin/python -m unittest discover -s tests -p "test_*.py"    # 共 46 项
```

| 文件 | 覆盖内容 |
|---|---|
| `test_profile_download.py` | 工具函数单元测试（hex/BCD/SW/分块） |
| `test_ipc_contract.py` | IPC 契约（消息/字段/RESET_CARD/61XX·91XX 跟进）+ eIM 报文与 Java 参考逐字节回归 + 环境自检 |
| `test_resource_injection.py` | 证书/密钥/UPP 外部注入（PEM/base64、优先级、缺文件报错） |

## 真卡测试

### 端到端（推荐：复用技能执行器，测试脚本扮演 Runtime）

```bash
.venv/bin/python end_to_end_test.py                                   # 默认 input-example.json
.venv/bin/python end_to_end_test.py --input input-example.json --mode indirect
.venv/bin/python end_to_end_test.py --reader "Identiv SCR35xx" --mode direct
```

它把技能产出的 Action（APDU / RESET_CARD / WAIT）交给 pyscard 执行、把 `action_result` 回灌，
因此与 Runtime 下行为一致。结束打印 `Status` 与 `data`（`iccid`/`isdp_aid`/`profile_state`/`verified`/`warnings`）。

### 底层 APDU 调试（`test_card_connection.py`，逐字节对齐 Java 参考报文）

```bash
.venv/bin/python test_card_connection.py --list-readers
.venv/bin/python test_card_connection.py --connect                 # 连接并显示 ATR
.venv/bin/python test_card_connection.py --test-ic-sequence        # IC1/IC2 初始化序列
.venv/bin/python test_card_connection.py --test-euicc-info         # BF20/BF2E 读取
.venv/bin/python test_card_connection.py --test-cleanup            # EuiccMemoryReset + 通知清理
.venv/bin/python test_card_connection.py --test-profile-download   # 手工完整下载链（含 eIM 激活）
.venv/bin/python test_card_connection.py --apdu "00A40004023F0000" --channel 0
.venv/bin/python test_card_connection.py --interactive             # 交互式发 APDU
.venv/bin/python test_card_connection.py --debug --connect         # 详细日志
```

> `--test-profile-download` 是手工逐步发报文的历史对照工具（用于与 Java 日志逐字节比对）；
> 常规验证请用上面的 `end_to_end_test.py`。

## 输入样例

`input-example.json` 是唯一的输入样例（`mode` 可用 `--mode` 覆盖 direct/indirect）；
证书/Profile 默认取包内 `resources/`，也可用输入参数外部注入（见 `../CERTIFICATE_GUIDE.md`）。

## 常见问题

- **找不到读卡器**：`lsusb` 看设备、`systemctl status pcscd`、必要时 `sudo usermod -aG scard $USER` 后重新登录
- **连接被拒**：确认没有其他程序占用读卡器、卡片插到位（可重新插拔）
- **APDU 返回错误 SW**：`9000` 成功；`6A86` 参数错；`6982` 安全状态不满足；`6985` 条件不满足；`6F00` 内部错误
- **技能进程起不来**：Runtime 固定调 `python`（本机若无该命令，需 `python-is-python3` 或设 `QWEN_SMARTCARD_PYTHON`）

## 模块

| 文件 | 说明 |
|---|---|
| `card_reader.py` | pyscard 封装（连接/ATR/APDU、61XX GET RESPONSE、91XX FETCH、MANAGE_CHANNEL 特例） |
| `end_to_end_test.py` | 端到端真卡测试（复用技能执行器） |
| `test_card_connection.py` | 底层 APDU/IC1·IC2/Cleanup/手工下载链调试工具 |
| `input-example.json` | 输入样例 |
| `requirements.txt` | 测试依赖（pyscard） |
