# SmartCard Agent Skills 设计文档

**版本：** v2.0  
**项目：** smartcard-master-skills  
**语言：** Python  
**依赖管理：** uv Workspaces

---

## 1. 文档目的

本文档定义 smartcard-master-skills 项目的整体设计，包括：

- 多 Skill 集合的项目组织方式；
- 基于 uv Workspaces 的模块依赖管理；
- Skill 与 Agent Runtime 之间的标准 stdin/stdout 协议；
- 多交互 Skill 的会话与本地状态管理；
- APDU 类 Skill 与 Agent、读卡器、UI 之间的接口约定；
- Agent LLM 首次参数收集与执行期免 LLM 的运行模型；
- 特殊指令直接调用 Skill 的直执行模式；
- 安全、脱敏、错误处理、测试与开发检查清单。

---

## 2. 背景与目标

smartcard-master-skills 是一个多 Skill 集合项目，每个 Skill 表示一项完整的 SmartCard 操作能力，例如：

- `scp02.open`
- `scp02.close`
- `read.iccid`
- `read.imsi`
- `pin.verify`
- `profile.load`
- `profile.install`

Skill 作者负责协议逻辑与状态机；Runtime 负责进程管理、读卡器访问、APDU 执行、UI 事件、会话文件和 Agent 交互。

### 2.1 设计目标

- 使用 Python 实现所有 Skill 与 SDK。
- 使用 uv Workspaces 管理多模块及模块间依赖，统一 `uv.lock`。
- 每个 Skill 是独立模块，可单独安装、运行、测试。
- Skill 通过 stdin/stdout 与 Agent Runtime 交互，遵循统一协议。
- 支持多种 Skill 形态：
  - 提示词型；
  - 单次交互型（例如算法 Skill）；
  - 多次交互型（例如打开 SCP 通道）；
  - APDU 交互型。
- 多交互 Skill 自行维护状态，使用运行时本地会话文件，不提交 Git。
- `sessionId` 由 Skill 在初始化时生成，后续所有响应和请求必须携带。
- APDU 类 Skill 不直接访问读卡器，只向 Runtime 返回可解析的 Action。
- Agent LLM 只在首次收集参数或特殊 `NEED_INPUT` 场景参与；正常执行过程不经过 LLM。
- 支持特殊指令直接调用 Skill，绕过 Agent LLM 推理。
- 过程输出与执行结果分离，敏感信息必须脱敏。
- 支持多会话并发识别与隔离。

### 2.2 非目标

- 本文档不定义具体读卡器厂商驱动实现。
- 本文档不定义 Agent UI 的具体前端实现。
- 默认不保证执行中断后从任意 Action 中间恢复；只支持会话级继续和消息边界恢复。
- 不将运行时会话文件纳入版本管理。

---

## 3. 核心术语

| 术语 | 说明 |
|------|------|
| Skill | 一个完整 SmartCard 操作能力，如 `scp02.open` |
| SkillId | 全局唯一 Skill 标识，建议使用点分层级 |
| Skill Runtime / Runtime | 执行 Skill、调用读卡器、转发 UI 事件的宿主 |
| SkillSession | 一次 Skill 会话的动态状态 |
| sessionId | Skill 初始化时生成的会话标识 |
| Action | Skill 请求 Runtime 执行的操作，如 APDU、复位、连接读卡器 |
| ActionResult | Runtime 执行 Action 后返回给 Skill 的事实 |
| SkillResult | Skill 本轮控制流结果，表示继续、成功、失败、取消或需要输入 |
| Output | 执行过程中的展示信息，与 SkillResult 控制流分离 |
| Manifest | Skill 元数据、输入 Schema、能力声明 |
| Direct Mode | 通过特殊指令或 CLI 绕过 Agent LLM 直接执行 Skill |

---

## 4. 总体架构

```
+---------------------+
|      Agent UI       |
+----------+----------+
           |
           v
+---------------------+       stdin/stdout NDJSON       +----------------------+
|   Agent Runtime     | <==============================> |   Skill Process      |
|                     |                                  |  Python Skill 模块   |
| - Skill Manager     |                                  |  - Skill 实现        |
| - Protocol Adapter  |                                  |  - 状态机            |
| - Action Executor   |                                  |  - Session 管理      |
| - Reader Bridge     |                                  |  - Manifest          |
| - Session Store     |                                  +----------------------+
| - UI Event Stream   |
| - Direct Router     |
+----------+----------+
           |
           v
+---------------------+
|   SmartCard Reader  |
+---------------------+
```

### 4.1 职责边界

**Skill 负责：**

- 协议逻辑；
- 状态机；
- APDU 构造；
- 响应解析；
- 密码学计算；
- 会话状态维护；
- 声明下一步 Action；
- 输出可展示信息。

**Runtime 负责：**

- 启动、停止 Skill 进程；
- stdin/stdout 协议收发；
- 执行 Action；
- 连接、断开、复位读卡器；
- 发送 APDU；
- UI 事件展示；
- 会话文件目录与权限基础保障；
- 直执行命令路由；
- 必要时调用 Agent LLM 进行 `NEED_INPUT` 提示。

**Skill 不应：**

- 直接访问读卡器；
- 直接操作 UI；
- 输出密钥明文；
- 输出过程日志到 stdout（应使用 stderr）。

---

## 5. 项目结构与 uv Workspaces

### 5.1 推荐目录结构

```
smartcard-master-skills/
├── pyproject.toml                 # 根 workspace 配置
├── uv.lock                        # 全局统一锁文件
├── .gitignore
├── docs/
│   └── skill-design.md
├── packages/
│   └── skill-sdk/                 # 公共 SDK
│       ├── pyproject.toml
│       └── src/smartcard_skill_sdk/
│           ├── protocol.py
│           ├── models.py
│           ├── session_store.py
│           ├── base.py
│           └── simple_apdu.py
├── skills/
│   ├── scp02/
│   │   ├── pyproject.toml
│   │   ├── skill.toml             # Manifest，可选
│   │   ├── src/scp02_skill/
│   │   │   ├── __init__.py
│   │   │   ├── main.py
│   │   │   ├── skill.py
│   │   │   ├── state.py
│   │   │   └── crypto.py
│   │   └── .sessions/             # 运行时生成，不提交 Git
│   │       ├── session-<uuid>.json
│   │       └── ...
│   └── read-iccid/
│       ├── pyproject.toml
│       └── src/read_iccid_skill/
└── tests/
```

### 5.2 根 pyproject.toml

```toml
[tool.uv.workspace]
members = ["packages/*", "skills/*"]
```

所有成员共享根目录 `uv.lock`，确保依赖版本一致。

### 5.3 Skill 模块 pyproject.toml 示例

```toml
[project]
name = "scp02-skill"
version = "0.1.0"
requires-python = ">=3.11"
dependencies = [
    "smartcard-skill-sdk",
]

[project.scripts]
scp02-skill = "scp02_skill.main:main"

[project.entry-points."smartcard.skills"]
"scp02.open" = "scp02_skill.main:main"

[tool.uv.sources]
smartcard-skill-sdk = { workspace = true }
```

### 5.4 日常操作

```bash
# 安装整个 workspace 依赖
uv sync

# 在指定 Skill 环境中运行
uv run --package scp02-skill python -m scp02_skill

# 更新全局锁文件
uv lock

# 运行测试
uv run pytest
```

---

## 6. Skill 形态与实现模型

### 6.1 Skill 分类

| 类型 | 示例 | 是否需要读卡器 | 说明 |
|------|------|----------------|------|
| 提示词型 | 参数解释、操作建议 | 否 | 直接返回文本或结构化输出 |
| 单次算法型 | 密钥派生、数据编码 | 否 | 一次请求返回 SUCCESS |
| 单次 APDU 型 | `read.iccid` | 是 | 构造 APDU，等待结果，解析返回 |
| 多次交互型 | `scp02.open` | 是 | 显式状态机，多轮 Action/ActionResult |
| 复杂协议型 | SCP80、Profile Download | 是 | 多状态、密码学、条件分支 |

### 6.2 推荐 Python 接口

SDK 提供抽象基类：

```python
class Skill:
    def init(self, ctx: SkillContext, params: dict) -> InitResult: ...
    def start(self, ctx: SkillContext, session: SkillSession) -> SkillResult: ...
    def handle_action_result(
        self, ctx: SkillContext, result: ActionResult, session: SkillSession
    ) -> SkillResult: ...
    def provide_input(
        self, ctx: SkillContext, input_data: dict, session: SkillSession
    ) -> SkillResult: ...
    def cancel(self, ctx: SkillContext, session: SkillSession) -> SkillResult: ...
```

### 6.3 简单 APDU Skill

单条 APDU 的 Skill 可继承 `SimpleApduSkill`：

```
build APDU -> APDU Action -> APDU Result -> parse -> SUCCESS
```

### 6.4 复杂 Skill

SCP02、SCP80、Secure Messaging、Profile Download 等应直接实现完整 Skill，使用语义状态机：

```python
class Scp02State(Enum):
    START = "START"
    WAIT_RESET = "WAIT_RESET"
    WAIT_INITIALIZE_UPDATE = "WAIT_INITIALIZE_UPDATE"
    WAIT_EXTERNAL_AUTHENTICATE = "WAIT_EXTERNAL_AUTHENTICATE"
    ESTABLISHED = "ESTABLISHED"
    FAILED = "FAILED"
```

**禁止使用 `step = 1` 这类无语义状态。**

---

## 7. Skill Manifest 与输入契约

每个 Skill 必须提供 Manifest，供 Agent LLM 首次收集参数、UI 展示、直执行路由和校验使用。

### 7.1 Manifest 示例

```json
{
  "skillId": "scp02.open",
  "version": "1.0.0",
  "description": "打开 SCP02 安全通道",
  "protocolVersion": "1.0",
  "modes": ["interactive", "direct"],
  "requiresReader": true,
  "supportsSession": true,
  "sessionTtlSeconds": 3600,
  "inputSchema": {
    "type": "object",
    "properties": {
      "readerId": { "type": "string" },
      "keyVersion": { "type": "integer" },
      "keysetId": { "type": "string" }
    },
    "required": ["readerId"]
  },
  "outputSchema": {
    "type": "object",
    "properties": {
      "securityLevel": { "type": "string" },
      "keyVersion": { "type": "integer" }
    }
  }
}
```

### 7.2 输入参数原则

- Agent LLM 第一次根据 `inputSchema` 收集执行参数。
- Runtime 对输入做 Schema 校验。
- 正常执行过程中不再调用 LLM。
- 仅当 Skill 返回 `NEED_INPUT` 时，Runtime 才可调用 Agent LLM 或 UI 提示用户补充信息。
- 直执行模式必须使用结构化输入；若缺少参数，返回 `INPUT_REQUIRED` 或由 CLI 交互补全。

---

## 8. stdin/stdout 协议

### 8.1 传输约定

- 使用 UTF-8 编码；
- 使用 NDJSON，即每行一个 JSON 对象；
- stdout 只允许输出协议消息；
- stderr 用于日志、调试和错误堆栈；
- Skill 进程不得向 stdout 打印普通日志；
- 协议基于 JSON-RPC 2.0 的子集，支持双向请求与通知。

### 8.2 消息类型

**Runtime → Skill：**

- `skill.init`
- `skill.start`
- `skill.handleActionResult`
- `skill.provideInput`
- `skill.cancel`
- `skill.shutdown`

**Skill → Runtime：**

- `skill.output` — 通知，可选，用于流式输出
- `skill.error` — 通知，可选，用于严重错误

Skill 对 Runtime 请求的响应必须包含 `sessionId`。

### 8.3 初始化

**Runtime 请求：**

```json
{
  "jsonrpc": "2.0",
  "id": "req-1",
  "method": "skill.init",
  "params": {
    "protocolVersion": "1.0",
    "skillId": "scp02.open",
    "input": {
      "readerId": "reader-01",
      "keyVersion": 1
    },
    "context": {
      "traceId": "trace-001",
      "mode": "interactive"
    }
  }
}
```

**Skill 响应：**

```json
{
  "jsonrpc": "2.0",
  "id": "req-1",
  "result": {
    "sessionId": "5f1c2d7e-8a9b-4c3d-9e0f-123456789abc",
    "manifest": {
      "skillId": "scp02.open",
      "version": "1.0.0",
      "requiresReader": true,
      "supportsSession": true
    },
    "status": "INITIALIZED"
  }
}
```

`sessionId` 由 Skill 在 `skill.init` 时生成。之后所有响应和后续请求必须携带该 `sessionId`。

### 8.4 启动执行

```json
{
  "jsonrpc": "2.0",
  "id": "req-2",
  "method": "skill.start",
  "params": {
    "sessionId": "5f1c2d7e-8a9b-4c3d-9e0f-123456789abc",
    "skillId": "scp02.open",
    "input": {
      "readerId": "reader-01",
      "keyVersion": 1
    }
  }
}
```

**Skill 返回：**

```json
{
  "jsonrpc": "2.0",
  "id": "req-2",
  "result": {
    "sessionId": "5f1c2d7e-8a9b-4c3d-9e0f-123456789abc",
    "status": "CONTINUE",
    "nextAction": {
      "actionId": "scp02.reset-card",
      "type": "RESET_CARD",
      "name": "复位卡片",
      "description": "执行 SCP02 前复位卡片",
      "sensitive": false,
      "payload": {}
    },
    "outputs": [
      {
        "type": "info",
        "message": "开始执行 SCP02"
      }
    ]
  }
}
```

### 8.5 Action 结果回传

```json
{
  "jsonrpc": "2.0",
  "id": "req-3",
  "method": "skill.handleActionResult",
  "params": {
    "sessionId": "5f1c2d7e-8a9b-4c3d-9e0f-123456789abc",
    "actionId": "scp02.initialize-update",
    "result": {
      "type": "APDU_RESULT",
      "status": "OK",
      "data": {
        "response": "0000000000000000000000000000000000000000000000000000000000000000",
        "sw": "9000"
      },
      "elapsedMs": 32
    }
  }
}
```

Skill 根据结果更新 Session，返回下一个 SkillResult。

### 8.6 需要用户输入

**Skill 返回：**

```json
{
  "jsonrpc": "2.0",
  "id": "req-4",
  "result": {
    "sessionId": "5f1c2d7e-8a9b-4c3d-9e0f-123456789abc",
    "status": "NEED_INPUT",
    "inputRequest": {
      "requestId": "input-1",
      "prompt": "请输入 PIN",
      "inputSchema": {
        "type": "object",
        "properties": {
          "pin": { "type": "string", "sensitive": true }
        },
        "required": ["pin"]
      }
    }
  }
}
```

**Runtime 通过 UI 或 Agent LLM 收集后回传：**

```json
{
  "jsonrpc": "2.0",
  "id": "req-5",
  "method": "skill.provideInput",
  "params": {
    "sessionId": "5f1c2d7e-8a9b-4c3d-9e0f-123456789abc",
    "requestId": "input-1",
    "input": {
      "pin": "1234"
    }
  }
}
```

### 8.7 流式输出

Skill 可发送通知：

```json
{
  "jsonrpc": "2.0",
  "method": "skill.output",
  "params": {
    "sessionId": "5f1c2d7e-8a9b-4c3d-9e0f-123456789abc",
    "output": {
      "type": "stream",
      "message": "正在计算 Session Key...\n"
    }
  }
}
```

---

## 9. SkillResult、Action、ActionResult、Output

### 9.1 SkillResult

SkillResult 只表达控制流。

```json
{
  "sessionId": "...",
  "status": "CONTINUE | SUCCESS | FAILED | CANCELLED | NEED_INPUT",
  "nextAction": {},
  "inputRequest": {},
  "outputs": [],
  "data": {},
  "error": {}
}
```

**约束：**

- `CONTINUE` 必须包含 `nextAction`；
- `SUCCESS` 可包含最终 `data`；
- `FAILED` 必须包含 `error`；
- `CANCELLED` 表示执行取消；
- `NEED_INPUT` 必须包含 `inputRequest`；
- 过程日志不放入 `data`，放入 `outputs` 或 `skill.output`。

### 9.2 Action

Action 是 Skill 请求 Runtime 执行的操作。

**支持类型：**

- `APDU`
- `RESET_CARD`
- `CONNECT_READER`
- `DISCONNECT_READER`
- `WAIT`
- `DELAY`
- `CUSTOM`

**Action 通用结构：**

```json
{
  "actionId": "scp02.initialize-update",
  "type": "APDU",
  "name": "Initialize Update",
  "description": "获取 Sequence Counter、Card Challenge 等数据",
  "sensitive": false,
  "timeoutMs": 5000,
  "payload": {}
}
```

Action 的 `name`、`description`、`actionId` 可直接用于 Agent UI 和执行 Trace。

### 9.3 ActionResult

ActionResult 是 Runtime 执行 Action 后返回的事实。

```json
{
  "actionId": "scp02.initialize-update",
  "type": "APDU_RESULT",
  "status": "OK | ERROR | TIMEOUT | CANCELLED",
  "data": {},
  "error": null,
  "elapsedMs": 32
}
```

Skill 必须根据 ActionResult 更新 Session，并决定下一步。

### 9.4 Output

Output 与 Result 完全分离。

```python
ctx.output.info("开始执行 SCP02")
ctx.output.text("发送 Initialize Update")
ctx.output.data(parsed_data)
ctx.output.stream("正在计算 Session Key...\n")
```

Output 通过 EventStream 到达 Agent UI，不参与控制流。

**原则：**

- Session → 给 Skill 后续逻辑
- Output → 给 Agent / UI

---

## 10. 多会话与本地状态管理

### 10.1 会话目录

多交互 Skill 使用本地文件维护会话状态。目录位于 Skill 模块下，仅运行时生成，不提交 Git。

```
skills/scp02/
├── src/
└── .sessions/
    ├── session-5f1c2d7e.json
    └── session-9a8b7c6d.json
```

`.gitignore` 必须包含：

```gitignore
skills/**/.sessions/
**/.sessions/
```

### 10.2 会话文件结构

```json
{
  "schemaVersion": 1,
  "sessionId": "5f1c2d7e-8a9b-4c3d-9e0f-123456789abc",
  "skillId": "scp02.open",
  "createdAt": "2026-01-01T10:00:00Z",
  "updatedAt": "2026-01-01T10:01:00Z",
  "status": "WAITING_ACTION",
  "state": "WAIT_INITIALIZE_UPDATE",
  "data": {
    "hostChallenge": "...",
    "sequenceCounter": "...",
    "sessionKeysRef": "secure-ref-001"
  },
  "lastActionId": "scp02.initialize-update",
  "ttlSeconds": 3600
}
```

### 10.3 会话规则

- `sessionId` 由 Skill 在 `skill.init` 时生成，建议使用 UUIDv4 或 ULID。
- 每个响应报文和后续请求报文必须携带 `sessionId`。
- 一个 Skill 进程默认处理一个会话；如需多会话，可通过多次 `skill.init` 创建，或用多个进程隔离。
- Session 只保存本次执行所需的动态状态。
- Skill 对象不得把 Session 保存为实例字段；Session 必须作为参数传递。
- 会话文件写入使用临时文件 + 原子重命名。
- 会话目录权限建议 `0700`，文件权限 `0600`。
- 会话文件应设置 TTL，过期可清理。
- 敏感密钥不得以明文长期落盘。生产环境应使用安全引用、OS Keyring 或加密会话存储；无法安全存储时应拒绝持久化敏感字段。
- 默认不支持从任意 Action 中间恢复；进程重启后只允许在消息边界按 `sessionId` 加载会话继续。

### 10.4 会话状态建议

- `CREATED`
- `RUNNING`
- `WAITING_ACTION`
- `WAITING_INPUT`
- `SUCCESS`
- `FAILED`
- `CANCELLED`
- `EXPIRED`

---

## 11. APDU 类 Skill 与读卡器接口

### 11.1 基本原则

APDU 类 Skill 不直接操作读卡器。读卡器由 Agent Runtime 执行。

**Skill 返回 APDU Action：**

```json
{
  "actionId": "read.iccid.select-mf",
  "type": "APDU",
  "name": "选择 MF",
  "description": "选择主文件",
  "sensitive": false,
  "timeoutMs": 3000,
  "payload": {
    "apdu": "00A40000023F00",
    "expectedStatus": ["9000"],
    "display": {
      "title": "选择 MF",
      "showApdu": true
    }
  }
}
```

**Runtime 执行后返回：**

```json
{
  "actionId": "read.iccid.select-mf",
  "type": "APDU_RESULT",
  "status": "OK",
  "data": {
    "response": "",
    "sw": "9000"
  },
  "elapsedMs": 12
}
```

### 11.2 UI 可解析要求

Action 必须包含：

- `actionId`：稳定标识；
- `type`：Action 类型；
- `name`：UI 展示名称；
- `description`：UI 说明；
- `sensitive`：是否敏感；
- `payload`：执行参数。

UI 可显示 APDU 名称、状态、耗时、结果摘要。若 `sensitive=true`，UI 不得展示原始数据或密钥。

### 11.3 执行期免 LLM

**执行流程：**

```
Agent LLM 首次收集参数
        |
        v
Runtime 校验 inputSchema
        |
        v
Skill.start()
        |
        v
Action <-> ActionResult 循环，由 Runtime 自动执行
        |
        v
SUCCESS / FAILED / CANCELLED
```

正常 APDU 循环不经过 LLM。只有 Skill 返回 `NEED_INPUT` 时，才允许 Runtime 请求 Agent LLM 或 UI 提示用户补充信息。

---

## 12. 直接执行模式

### 12.1 目标

用户可以通过特殊指令直接调用 Skill，绕过 Agent LLM 推理。

### 12.2 Agent 特殊指令

建议语法：

```
@skill scp02.open {"readerId":"reader-01","keyVersion":1}
```

或：

```
/skill run scp02.open --input '{"readerId":"reader-01","keyVersion":1}'
```

Runtime 的 Direct Router 解析后：

1. 查找 Skill Manifest；
2. 校验输入；
3. 启动 Skill；
4. 自动执行 Action/ActionResult 循环；
5. 将 Output 和最终结果返回 UI。

### 12.3 CLI 直执行

```bash
uv run --package scp02-skill scp02-skill \
  --direct \
  --input '{"readerId":"reader-01","keyVersion":1}'
```

或：

```bash
scp02-skill --direct --input @params.json
```

### 12.4 直执行模式下的输入

- 必须提供结构化输入；
- 输入不符合 Schema 时返回 `INPUT_REQUIRED` 或 `INVALID_INPUT`；
- 若 Skill 返回 `NEED_INPUT`：
  - `--interactive` 模式下可由 CLI 提示用户输入；
  - 非交互模式直接失败并返回所需输入 Schema。
- 直执行仍然通过 Runtime 执行 APDU，不允许 Skill 直接访问读卡器。

---

## 13. 安全与脱敏

### 13.1 禁止输出

**不得输出：**

- ENC KEY
- MAC KEY
- KEK
- SESSION ENC KEY
- SESSION MAC KEY
- PIN 明文
- 完整密钥材料

**可以输出：**

- `keyVersion`
- `securityLevel`
- `algorithm`
- 状态摘要
- 脱敏后的 APDU 结果

### 13.2 日志与 Trace

- stderr 日志必须脱敏；
- `sensitive=true` 的 Action 和结果不得记录原始 payload；
- Output 中的敏感字段必须由 SDK 脱敏器处理；
- 会话文件中的敏感字段使用安全引用或加密存储；
- 异常堆栈不得包含密钥和 PIN。

### 13.3 会话安全

- `sessionId` 使用不可预测随机值；
- 会话文件权限最小化；
- 会话 TTL 到期清理；
- 多会话并发时使用文件锁或原子写入，避免竞态；
- 不允许跨 Skill 复用 `sessionId`。

---

## 14. 错误处理、超时与取消

### 14.1 错误结构

```json
{
  "code": "APDU_STATUS_ERROR",
  "message": "卡片返回非预期状态字",
  "retryable": false,
  "details": {
    "sw": "6A82"
  }
}
```

### 14.2 常见错误码

- `INVALID_INPUT`
- `INPUT_REQUIRED`
- `UNSUPPORTED_ACTION`
- `READER_NOT_FOUND`
- `READER_BUSY`
- `APDU_TIMEOUT`
- `APDU_STATUS_ERROR`
- `SESSION_NOT_FOUND`
- `SESSION_EXPIRED`
- `PROTOCOL_ERROR`
- `INTERNAL_ERROR`
- `CANCELLED`

### 14.3 超时

- Action 可携带 `timeoutMs`；
- Runtime 超时后返回 `TIMEOUT` ActionResult；
- Skill 决定失败、重试或返回 `FAILED`；
- 进程级超时由 Runtime 管理。

### 14.4 取消

Runtime 可发送：

```json
{
  "jsonrpc": "2.0",
  "id": "req-cancel",
  "method": "skill.cancel",
  "params": {
    "sessionId": "..."
  }
}
```

Skill 应清理临时状态并返回 `CANCELLED`。取消后再次执行应创建新会话，而不是复用失败会话。

---

## 15. 推荐 Skill 模板

```python
from smartcard_skill_sdk import Skill, SkillContext, SkillSession, SkillResult
from smartcard_skill_sdk.actions import ResetCardAction, ApduAction
from smartcard_skill_sdk.results import ActionResult, ResetCardResult, ApduActionResult


class XxxSkill(Skill):
    def init(self, ctx: SkillContext, params: dict):
        session = ctx.sessions.create(params)
        return ctx.init_result(session_id=session.session_id)

    def start(self, ctx: SkillContext, session: SkillSession) -> SkillResult:
        ctx.output.info("开始执行 XxxSkill")
        session.state = "WAIT_RESET"
        return SkillResult.continue_with(
            ResetCardAction.create(
                action_id="xxx.reset-card",
                name="复位卡片",
                description="执行前复位卡片",
            )
        )

    def handle_action_result(
        self,
        ctx: SkillContext,
        result: ActionResult,
        session: SkillSession,
    ) -> SkillResult:
        if isinstance(result, ResetCardResult):
            session.state = "WAIT_APDU"
            return SkillResult.continue_with(
                ApduAction.builder()
                .action_id("xxx.select")
                .name("选择应用")
                .description("发送 SELECT APDU")
                .apdu("00A4040000")
                .sensitive(False)
                .build()
            )

        if isinstance(result, ApduActionResult):
            if result.sw != "9000":
                return SkillResult.failed(
                    code="APDU_STATUS_ERROR",
                    message=f"非预期状态字: {result.sw}",
                )
            session.state = "SUCCESS"
            return SkillResult.success(data={"status": "ok"})

        return SkillResult.failed(
            code="UNSUPPORTED_ACTION_RESULT",
            message="未知 ActionResult",
        )
```

---

## 16. 测试与可观测性

### 16.1 测试类型

**协议一致性测试：**

- `init` 是否生成 `sessionId`；
- 后续请求是否携带 `sessionId`；
- `CONTINUE` 是否包含 `nextAction`；
- `NEED_INPUT` 是否包含 `inputRequest`；
- stdout 是否只有协议消息。

**会话测试：**

- 多会话隔离；
- 会话文件原子写入；
- TTL 清理；
- 敏感字段不落明文。

**Action 测试：**

- APDU Action/Result 编解码；
- 超时、取消、异常状态字。

**直执行测试：**

- 特殊指令路由；
- Schema 校验；
- 非交互模式 `NEED_INPUT` 失败。

**脱敏测试：**

- 密钥、PIN 不出现在 Output、日志、Trace、会话文件中。

### 16.2 可观测性

- 每条请求携带 `traceId`；
- 每个 Action 携带 `actionId`；
- Runtime 记录 Action 耗时、状态；
- Skill 通过 Output 提供业务过程信息；
- 日志与 Trace 默认脱敏。

---

## 17. 开发完成检查清单

- [ ] SkillId 明确且全局唯一
- [ ] Manifest 完整，inputSchema 可校验
- [ ] Session 为本次执行独立实例
- [ ] sessionId 在 init 时生成
- [ ] 所有响应和后续请求均携带 sessionId
- [ ] State 语义明确，不使用无意义 step 整数
- [ ] 不直接操作 Reader
- [ ] Action 类型明确，包含 actionId/name/description/sensitive
- [ ] ActionResult 正确处理
- [ ] SkillResult 只负责控制流
- [ ] Output 与 Result 分离
- [ ] 正常执行过程不调用 Agent LLM
- [ ] NEED_INPUT 场景定义清晰
- [ ] 敏感信息脱敏
- [ ] 会话文件不提交 Git
- [ ] 会话文件权限与 TTL 已处理
- [ ] 成功/失败/取消边界明确
- [ ] 简单 Skill 使用 SimpleApduSkill
- [ ] 复杂协议使用显式状态机
- [ ] 支持直执行模式或明确不支持原因
- [ ] 协议、会话、脱敏测试通过

---

## 18. 示例：scp02.open 执行流程

```
Agent LLM 收集 readerId、keyVersion
        |
        v
Runtime 启动 scp02 Skill 进程
        |
        v
skill.init -> 生成 sessionId
        |
        v
skill.start -> CONTINUE: RESET_CARD
        |
        v
Runtime 执行复位 -> skill.handleActionResult
        |
        v
CONTINUE: APDU Initialize Update
        |
        v
Runtime 发送 APDU -> 返回 APDU_RESULT
        |
        v
Skill 解析 Card Challenge、Sequence Counter，更新 Session
        |
        v
CONTINUE: APDU External Authenticate
        |
        v
Runtime 发送 APDU -> 返回 APDU_RESULT
        |
        v
Skill 计算 Session Keys，建立安全通道
        |
        v
SUCCESS(data: securityLevel, keyVersion)
```

整个执行循环中，除首次参数收集和可能的 `NEED_INPUT` 外，不经过 Agent LLM。

---

## 19. 版本与兼容性

- 协议版本字段：`protocolVersion`，当前为 `1.0`。
- Skill Manifest 必须声明协议版本。
- Runtime 与 Skill 在 `skill.init` 阶段协商版本。
- 不兼容时返回 `PROTOCOL_VERSION_UNSUPPORTED`。
- 新增 Action 类型必须保证旧 Runtime 可识别并返回 `UNSUPPORTED_ACTION`，或通过能力声明提前禁用。

---

## 20. 结论

本设计将 smartcard-master-skills 定义为基于 Python 和 uv Workspaces 的多 Skill 集合。每个 Skill 是独立模块，通过标准 stdin/stdout 协议与 Agent Runtime 交互；APDU 和读卡器操作由 Runtime 执行；多交互 Skill 使用本地 `.sessions` 文件维护会话，`sessionId` 在初始化时生成并贯穿全部报文；过程输出与控制流结果分离；Agent LLM 仅用于首次参数收集和特殊补充输入；同时支持特殊指令直执行 Skill，满足免 LLM 推理的直接调用需求。
