# SmartCard Master Skills

SmartCard Agent Skills 框架 - 基于 Python 的智能卡操作技能集合。

## 项目概述

本项目是一个基于 uv workspace 的 Python 项目，实现了 SmartCard Agent Skills 框架，提供了一套完整的智能卡操作技能。每个 Skill 都是独立的 Python 包，通过 stdin/stdout JSON-RPC 协议与 Agent Runtime 通信。

## 项目结构

```
smartcard-master-skills/
├── packages/                    # 核心包
│   ├── skill-sdk/              # SmartCard Skill SDK
│   └── card-reader/            # 读卡器连接模块
├── skills/                      # Skill 实现
│   ├── read-iccid/             # 读取 ICCID Skill
│   └── esim-iot-profile-download/  # eSIM Profile 下载 Skill
├── tests/                       # 测试用例
├── docs/                        # 文档
├── pyproject.toml              # 项目配置
└── README.md                   # 本文件
```

## 核心组件

### 1. SmartCard Skill SDK (`packages/skill-sdk`)

提供 Skill 开发的基础框架：

- **协议模型** (`protocol.py`): Action, ActionResult, SkillResult 等核心数据结构
- **会话管理** (`session_store.py`): SkillSession, SessionStore
- **抽象基类** (`base.py`): Skill, SkillContext, OutputCollector
- **简单 APDU 基类** (`simple_apdu.py`): SimpleApduSkill

### 2. Card Reader (`packages/card-reader`)

读卡器连接和 APDU 通信模块：

- 支持 T=0/T=1 协议自动选择
- 处理 61XX (GET RESPONSE) 和 91XX (FETCH) 响应
- 上下文管理器支持
- 完整的错误处理

### 3. Read ICCID Skill (`skills/read-iccid`)

读取 SIM 卡 ICCID 的 Skill：

- 三步 APDU 流程：SELECT MF → SELECT EF_ICCID → READ BINARY
- BCD 编码解析
- 完整的文档结构 (SKILL.md, references/, examples/)

### 4. eSIM IoT Profile Download Skill (`skills/esim-iot-profile-download`)

IoT eSIM Profile 下载与启用 Skill（SGP.33 协议）：

- 完整状态机（22+ 状态）
- 下载前清理流程（EuiccMemoryReset, ListNotification, RemoveNotification）
- Profile 安装流程（AuthenticateServer, PrepareDownload, LoadProfilePackage）
- eIM 启用流程（AddInitialEim, EnablePSMO）
- ASN.1 编解码支持
- 资源管理（证书、Profile 包）

## 快速开始

### 环境要求

- Python >= 3.11
- uv (Python 包管理器)

### 安装

```bash
# 克隆项目
git clone https://github.com/wangshengjun1134/smartcard-master-skills.git
cd smartcard-master-skills

# 安装依赖
uv sync
```

### 运行测试

```bash
# 运行所有测试
uv run pytest -v

# 运行特定测试
uv run pytest tests/test_read_iccid.py -v
uv run pytest tests/test_esim_iot_profile_download.py -v

# 运行真实卡片测试（需要读卡器）
uv run pytest tests/test_card_reader.py -v
uv run pytest tests/test_esim_real_card.py -v
```

## Skill 开发指南

### 创建新 Skill

1. 在 `skills/` 目录下创建新目录
2. 创建 `pyproject.toml` 配置
3. 实现 Skill 类（继承 `Skill` 或 `SimpleApduSkill`）
4. 创建 `SKILL.md` 文档
5. 编写测试用例

### Skill 通信协议

Skill 通过 stdin/stdout 与 Agent Runtime 通信，使用 JSON-RPC 2.0 协议：

```json
// 初始化
{"jsonrpc": "2.0", "id": "1", "method": "skill.init", "params": {...}}

// 启动
{"jsonrpc": "2.0", "id": "2", "method": "skill.start", "params": {"sessionId": "..."}}

// 处理 Action 结果
{"jsonrpc": "2.0", "id": "3", "method": "skill.handleActionResult", "params": {...}}
```

### Skill 状态

- `INITIALIZED`: 初始化完成
- `CONTINUE`: 需要执行下一个 Action
- `SUCCESS`: 执行成功
- `FAILED`: 执行失败
- `NEED_INPUT`: 需要用户输入

## 文档

- [Skill 设计文档](docs/skill-design.md) - 整体架构设计
- [实施计划](docs/implementation-plan.md) - 实施任务分解
- [Read ICCID SKILL.md](skills/read-iccid/SKILL.md) - ICCID 读取技能文档
- [eSIM Profile Download SKILL.md](skills/esim-iot-profile-download/SKILL.md) - eSIM 下载技能文档

## 测试覆盖

- ✅ 协议模型测试
- ✅ 会话管理测试
- ✅ APDU 生成测试
- ✅ ASN.1 编解码测试
- ✅ 状态机测试
- ✅ 完整流程测试
- ✅ stdin/stdout 协议测试
- ✅ 真实卡片测试

## 技术栈

- **Python 3.11+**
- **uv** - 包管理和 workspace 管理
- **pydantic** - 数据验证
- **pyasn1** - ASN.1 编解码
- **pyscard** - 智能卡通信
- **pytest** - 测试框架
- **cryptography** - 密码学操作

## 许可证

MIT

## 贡献

欢迎提交 Issue 和 Pull Request！

## 联系方式

- GitHub: [wangshengjun1134](https://github.com/wangshengjun1134)
