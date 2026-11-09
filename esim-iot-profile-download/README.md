# eSIM IoT Profile Download Skill

通过 SmartCard Skill Runtime 执行 IoT eSIM Profile 的安装与启用（内嵌本地 SM-DP+，无远程 HTTP 调用）。

- **skillId**: `esim.iot-profile-download`（见 `skill.json`）；**Runtime**: python 3.10+
- **完整文档以 [SKILL.md](SKILL.md) 为准**（Agent 调用方式 / IPC 契约 / 输入参数 / 输出 / 执行阶段 / 运行环境）；
  本文件只做快速上手

## 快速上手

```bash
# 1) 安装技能自带运行环境（uv 优先；也可由 agent 调 {"operation":"setup_env"} 触发）
bash scripts/setup-env.sh

# 2) 通过 Runtime / agent 执行（详见 SKILL.md「在对话中调用」）
#    a. smartcard_connect            连接读卡器
#    b. smartcard_execute_skill      skillId=esim.iot-profile-download，input 见 SKILL.md「输入参数」
#    判读: execution_finished.data 的 profile_state(9F70) / verified / warnings
```

本地真卡调试（不需要 Runtime，测试脚本扮演 Runtime）：

```bash
uv pip install --python .venv/bin/python -r tests/requirements.txt     # 测试依赖（pyscard）
.venv/bin/python tests/end_to_end_test.py --input tests/input-example.json --mode indirect
```

## 测试

```bash
.venv/bin/python -m unittest discover -s tests -p "test_*.py"    # 离线 46 项，无需读卡器
```

真卡脚本与调试工具见 [tests/README.md](tests/README.md)。

## 目录结构

```
esim-iot-profile-download/
├── SKILL.md                     # 技能完整文档（agent 使用方式 / IPC / 参数 / 输出 / 环境）
├── skill.json                   # Runtime 元数据（skillId=esim.iot-profile-download）
├── main.py                      # 入口：IPC 协议 + 执行器（Action 批次 / 传输层跟进 / 环境自检）
├── requirements.txt             # 运行依赖（cryptography / pyasn1）
├── scripts/setup-env.sh         # 生成技能自带环境（uv 优先）
├── resources/                   # 证书与 Profile（包内默认，可被输入参数注入覆盖）
├── src/                         # 协议实现（ASN.1 / SCP03t / SM-DP+ / eIM / 流程）
└── tests/                       # 离线测试 + 真卡测试（见 tests/README.md）
```

## 证书与 Profile

默认取包内 `resources/`（`certs/` + `profiles/`），每一项都可用输入参数外部注入覆盖；
文件清单、注入示例、openssl 生成/验证命令见 [CERTIFICATE_GUIDE.md](CERTIFICATE_GUIDE.md)。

## 参考规范

- **SGP.33**：IoT eSIM 远程配置（4.2.21.2.1 `TC_eUICC_ES10b_EnableProfile_Case3`）
- **SGP.22 / SGP.32**：SM-DP+ / eIM 接口与 eUICC Package
- 内部：《SmartCard Agent Skills Dev v1.1》《SmartCard Skill Package Structure》

## 许可证

私有 - 内部使用
