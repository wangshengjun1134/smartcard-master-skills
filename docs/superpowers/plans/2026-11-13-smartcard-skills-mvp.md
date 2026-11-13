# SmartCard Skills MVP 实施计划

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 实现最小可运行的 SmartCard Skill 端到端流程，验证 SDK 设计和协议规范。

**Architecture:** 自底向上分层推进：先搭建 uv workspace 基础设施，再实现 SDK 核心（protocol、session、base），然后实现一个简单 APDU Skill（read-iccid）跑通完整流程。

**Tech Stack:** Python 3.11+, uv workspaces, pydantic 2.x, pytest

**Spec:** `docs/skill-design.md` v2.0

## Global Constraints

- Python >= 3.11
- uv workspace 管理多模块，统一 `uv.lock`
- 每个 Skill 独立模块，可单独安装、运行、测试
- Skill 通过 stdin/stdout 与 Runtime 交互，NDJSON 格式
- sessionId 由 Skill 在 init 时生成，后续所有报文必须携带
- APDU Skill 不直接访问读卡器，只返回 Action
- 敏感信息（密钥、PIN）不得出现在 stdout 或日志
- 会话文件存放于 `.sessions/`，不提交 Git

## Review Focus

1. **协议消息完整性**：init/start/handleActionResult 流程中 sessionId 是否正确传递
2. **会话原子写入**：并发写入时会话文件是否损坏
3. **脱敏边界**：sensitive=true 的 Action 是否泄露密钥材料
4. **状态机语义**：Skill 状态是否使用有意义的枚举值而非 step 整数
5. **直执行兼容**：CLI 模式下输入缺失时是否返回 INPUT_REQUIRED

---

## 文件结构

```
smartcard-master-skills/
├── pyproject.toml                    # 根 workspace 配置
├── .gitignore                        # Git 忽略规则
├── packages/
│   └── skill-sdk/
│       ├── pyproject.toml            # SDK 包配置
│       └── src/smartcard_skill_sdk/
│           ├── __init__.py           # SDK 导出
│           ├── protocol.py           # 协议模型（Action, ActionResult, SkillResult）
│           ├── session_store.py      # 会话管理（SkillSession, SessionStore）
│           ├── base.py               # 抽象基类（Skill, SkillContext）
│           └── simple_apdu.py        # 简单 APDU Skill 基类
├── skills/
│   └── read-iccid/
│       ├── pyproject.toml            # Skill 包配置
│       └── src/read_iccid_skill/
│           ├── __init__.py
│           ├── skill.py              # ReadIccidSkill 实现
│           └── main.py               # stdin/stdout 入口
└── tests/
    ├── test_protocol.py              # 协议测试
    ├── test_session.py               # 会话测试
    └── test_read_iccid.py            # Skill 测试
```

---

## Task 1: 项目基础设施搭建

**Files:**
- Create: `pyproject.toml`
- Create: `.gitignore`
- Create: 目录结构 `packages/`, `skills/`, `tests/`

**Interfaces:**
- Produces: uv workspace 可执行 `uv sync`

- [ ] **Step 1: 创建根 pyproject.toml**

```toml
[project]
name = "smartcard-master-skills"
version = "0.1.0"
requires-python = ">=3.11"

[tool.uv.workspace]
members = ["packages/*", "skills/*"]

[tool.pytest.ini_options]
testpaths = ["tests"]
```

- [ ] **Step 2: 创建 .gitignore**

```gitignore
# Python
__pycache__/
*.py[cod]
.venv/

# uv
uv.lock

# 会话文件
skills/**/.sessions/
**/.sessions/

# IDE
.vscode/
.idea/
```

- [ ] **Step 3: 创建目录结构**

```bash
mkdir -p packages/skill-sdk/src/smartcard_skill_sdk
mkdir -p skills/read-iccid/src/read_iccid_skill
mkdir -p tests
```

- [ ] **Step 4: 验证 workspace 配置**

Run: `uv sync`
Expected: 无报错，生成 `uv.lock`

- [ ] **Step 5: Commit**

```bash
git add pyproject.toml .gitignore
git commit -m "chore: init uv workspace"
```

---

## Task 2: SDK 协议模型（protocol.py）

**Files:**
- Create: `packages/skill-sdk/pyproject.toml`
- Create: `packages/skill-sdk/src/smartcard_skill_sdk/protocol.py`
- Test: `tests/test_protocol.py`

**Interfaces:**
- Consumes: 无
- Produces: `SkillStatus`, `ActionType`, `ActionResultStatus`, `Action`, `ActionResult`, `Output`, `InputRequest`, `Error`, `SkillResult`, `JsonRpcRequest`, `JsonRpcResponse`

- [ ] **Step 1: 创建 SDK pyproject.toml**

```toml
[project]
name = "smartcard-skill-sdk"
version = "0.1.0"
requires-python = ">=3.11"
dependencies = ["pydantic>=2.0"]

[build-system]
requires = ["hatchling"]
build-backend = "hatchling.build"

[tool.hatch.build.targets.wheel]
packages = ["src/smartcard_skill_sdk"]
```

- [ ] **Step 2: 编写协议模型测试**

```python
# tests/test_protocol.py
import pytest
from smartcard_skill_sdk.protocol import (
    SkillStatus, ActionType, Action, ActionResult, SkillResult
)

def test_skill_status_enum():
    assert SkillStatus.CONTINUE == "CONTINUE"
    assert SkillStatus.SUCCESS == "SUCCESS"

def test_action_type_enum():
    assert ActionType.APDU == "APDU"
    assert ActionType.RESET_CARD == "RESET_CARD"

def test_action_model():
    action = Action(
        action_id="test.apdu",
        type=ActionType.APDU,
        name="测试 APDU",
        description="发送测试 APDU",
        sensitive=False,
        payload={"apdu": "00A40000"}
    )
    assert action.action_id == "test.apdu"
    assert action.type == ActionType.APDU

def test_skill_result_continue():
    action = Action(
        action_id="test.apdu",
        type=ActionType.APDU,
        name="测试",
        description="测试"
    )
    result = SkillResult.continue_with("session-123", action)
    assert result.session_id == "session-123"
    assert result.status == SkillStatus.CONTINUE
    assert result.next_action == action

def test_skill_result_success():
    result = SkillResult.success("session-123", {"data": "value"})
    assert result.status == SkillStatus.SUCCESS
    assert result.data == {"data": "value"}

def test_skill_result_failed():
    result = SkillResult.failed("session-123", "ERROR_CODE", "错误信息")
    assert result.status == SkillStatus.FAILED
    assert result.error.code == "ERROR_CODE"
```

- [ ] **Step 3: 运行测试验证失败**

Run: `uv run pytest tests/test_protocol.py -v`
Expected: FAIL - "No module named 'smartcard_skill_sdk'"

- [ ] **Step 4: 实现 protocol.py**

```python
# packages/skill-sdk/src/smartcard_skill_sdk/protocol.py
from enum import Enum
from pydantic import BaseModel
from typing import Any


class SkillStatus(str, Enum):
    INITIALIZED = "INITIALIZED"
    CONTINUE = "CONTINUE"
    SUCCESS = "SUCCESS"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"
    NEED_INPUT = "NEED_INPUT"


class ActionType(str, Enum):
    APDU = "APDU"
    RESET_CARD = "RESET_CARD"
    CONNECT_READER = "CONNECT_READER"
    DISCONNECT_READER = "DISCONNECT_READER"
    WAIT = "WAIT"
    DELAY = "DELAY"
    CUSTOM = "CUSTOM"


class ActionResultStatus(str, Enum):
    OK = "OK"
    ERROR = "ERROR"
    TIMEOUT = "TIMEOUT"
    CANCELLED = "CANCELLED"


class Action(BaseModel):
    action_id: str
    type: ActionType
    name: str
    description: str
    sensitive: bool = False
    timeout_ms: int = 5000
    payload: dict[str, Any] = {}


class ActionResult(BaseModel):
    action_id: str
    type: str
    status: ActionResultStatus
    data: dict[str, Any] = {}
    error: dict[str, Any] | None = None
    elapsed_ms: int = 0


class Output(BaseModel):
    type: str
    message: str = ""
    data: dict[str, Any] | None = None


class InputRequest(BaseModel):
    request_id: str
    prompt: str
    input_schema: dict[str, Any]


class Error(BaseModel):
    code: str
    message: str
    retryable: bool = False
    details: dict[str, Any] | None = None


class SkillResult(BaseModel):
    session_id: str
    status: SkillStatus
    next_action: Action | None = None
    input_request: InputRequest | None = None
    outputs: list[Output] = []
    data: dict[str, Any] = {}
    error: Error | None = None

    @classmethod
    def continue_with(cls, session_id: str, action: Action) -> "SkillResult":
        return cls(session_id=session_id, status=SkillStatus.CONTINUE, next_action=action)

    @classmethod
    def success(cls, session_id: str, data: dict[str, Any] | None = None) -> "SkillResult":
        return cls(session_id=session_id, status=SkillStatus.SUCCESS, data=data or {})

    @classmethod
    def failed(cls, session_id: str, code: str, message: str) -> "SkillResult":
        return cls(
            session_id=session_id,
            status=SkillStatus.FAILED,
            error=Error(code=code, message=message)
        )

    @classmethod
    def need_input(cls, session_id: str, request: InputRequest) -> "SkillResult":
        return cls(session_id=session_id, status=SkillStatus.NEED_INPUT, input_request=request)


class JsonRpcRequest(BaseModel):
    jsonrpc: str = "2.0"
    id: str | int
    method: str
    params: dict[str, Any] = {}


class JsonRpcResponse(BaseModel):
    jsonrpc: str = "2.0"
    id: str | int
    result: dict[str, Any] | None = None
    error: dict[str, Any] | None = None
```

- [ ] **Step 5: 运行测试验证通过**

Run: `uv run pytest tests/test_protocol.py -v`
Expected: 6 passed

- [ ] **Step 6: Commit**

```bash
git add packages/skill-sdk/pyproject.toml packages/skill-sdk/src/smartcard_skill_sdk/protocol.py tests/test_protocol.py
git commit -m "feat: add SDK protocol models"
```

---

## Task 3: 会话管理（session_store.py）

**Files:**
- Create: `packages/skill-sdk/src/smartcard_skill_sdk/session_store.py`
- Test: `tests/test_session.py`

**Interfaces:**
- Consumes: 无
- Produces: `SkillSession`, `SessionStore`

- [ ] **Step 1: 编写会话管理测试**

```python
# tests/test_session.py
import pytest
import tempfile
import os
from pathlib import Path
from smartcard_skill_sdk.session_store import SkillSession, SessionStore

def test_skill_session_auto_generates_id():
    session = SkillSession(skill_id="test.skill")
    assert session.session_id != ""
    assert len(session.session_id) == 36  # UUID format

def test_skill_session_auto_sets_timestamps():
    session = SkillSession(skill_id="test.skill")
    assert session.created_at != ""
    assert session.updated_at != ""
    assert session.created_at.endswith("Z")

def test_session_store_creates_directory():
    with tempfile.TemporaryDirectory() as tmpdir:
        store = SessionStore(tmpdir)
        assert Path(tmpdir).exists()

def test_session_store_save_and_load():
    with tempfile.TemporaryDirectory() as tmpdir:
        store = SessionStore(tmpdir)
        session = SkillSession(skill_id="test.skill", state="RUNNING")
        store.save(session, "test.skill")
        
        loaded = store.load(session.session_id)
        assert loaded is not None
        assert loaded.session_id == session.session_id
        assert loaded.state == "RUNNING"

def test_session_store_delete():
    with tempfile.TemporaryDirectory() as tmpdir:
        store = SessionStore(tmpdir)
        session = SkillSession(skill_id="test.skill")
        store.save(session, "test.skill")
        
        store.delete(session.session_id)
        loaded = store.load(session.session_id)
        assert loaded is None

def test_session_file_permissions():
    with tempfile.TemporaryDirectory() as tmpdir:
        store = SessionStore(tmpdir)
        session = SkillSession(skill_id="test.skill")
        store.save(session, "test.skill")
        
        file_path = Path(tmpdir) / f"session-{session.session_id[:8]}.json"
        stat = os.stat(file_path)
        assert oct(stat.st_mode)[-3:] == "600"
```

- [ ] **Step 2: 运行测试验证失败**

Run: `uv run pytest tests/test_session.py -v`
Expected: FAIL - "No module named 'smartcard_skill_sdk.session_store'"

- [ ] **Step 3: 实现 session_store.py**

```python
# packages/skill-sdk/src/smartcard_skill_sdk/session_store.py
import json
import os
import tempfile
from datetime import datetime
from pathlib import Path
from typing import Any
import uuid


class SkillSession:
    def __init__(
        self,
        skill_id: str,
        session_id: str = "",
        state: str = "",
        data: dict[str, Any] | None = None,
        ttl_seconds: int = 3600
    ):
        self.schema_version = 1
        self.session_id = session_id or str(uuid.uuid4())
        self.skill_id = skill_id
        self.created_at = datetime.utcnow().isoformat() + "Z"
        self.updated_at = self.created_at
        self.status = "CREATED"
        self.state = state or ""
        self.data = data or {}
        self.last_action_id = ""
        self.ttl_seconds = ttl_seconds

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "session_id": self.session_id,
            "skill_id": self.skill_id,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "status": self.status,
            "state": self.state,
            "data": self.data,
            "last_action_id": self.last_action_id,
            "ttl_seconds": self.ttl_seconds
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "SkillSession":
        session = cls(
            skill_id=data["skill_id"],
            session_id=data["session_id"],
            state=data.get("state", ""),
            data=data.get("data", {}),
            ttl_seconds=data.get("ttl_seconds", 3600)
        )
        session.created_at = data.get("created_at", session.created_at)
        session.updated_at = data.get("updated_at", session.updated_at)
        session.status = data.get("status", "CREATED")
        session.last_action_id = data.get("last_action_id", "")
        return session


class SessionStore:
    def __init__(self, base_dir: str):
        self.base_dir = Path(base_dir)
        self.base_dir.mkdir(parents=True, exist_ok=True, mode=0o700)

    def save(self, session: SkillSession, skill_id: str) -> None:
        session.updated_at = datetime.utcnow().isoformat() + "Z"
        file_path = self.base_dir / f"session-{session.session_id[:8]}.json"
        
        with tempfile.NamedTemporaryFile(
            mode='w', dir=self.base_dir, delete=False, suffix='.tmp'
        ) as f:
            json.dump(session.to_dict(), f, indent=2)
            temp_path = f.name
        
        os.chmod(temp_path, 0o600)
        os.replace(temp_path, file_path)

    def load(self, session_id: str) -> SkillSession | None:
        file_path = self.base_dir / f"session-{session_id[:8]}.json"
        if not file_path.exists():
            return None
        with open(file_path) as f:
            data = json.load(f)
        return SkillSession.from_dict(data)

    def delete(self, session_id: str) -> None:
        file_path = self.base_dir / f"session-{session_id[:8]}.json"
        if file_path.exists():
            file_path.unlink()
```

- [ ] **Step 4: 运行测试验证通过**

Run: `uv run pytest tests/test_session.py -v`
Expected: 5 passed

- [ ] **Step 5: Commit**

```bash
git add packages/skill-sdk/src/smartcard_skill_sdk/session_store.py tests/test_session.py
git commit -m "feat: add session management"
```

---

## Task 4: 抽象基类（base.py）

**Files:**
- Create: `packages/skill-sdk/src/smartcard_skill_sdk/base.py`
- Test: `tests/test_base.py`

**Interfaces:**
- Consumes: `SkillSession`, `SessionStore`, `Output`, `SkillResult`, `ActionResult`
- Produces: `Skill`, `SkillContext`, `OutputCollector`

- [ ] **Step 1: 编写基类测试**

```python
# tests/test_base.py
import pytest
import tempfile
from smartcard_skill_sdk.base import Skill, SkillContext, OutputCollector
from smartcard_skill_sdk.session_store import SessionStore, SkillSession
from smartcard_skill_sdk.protocol import SkillResult, ActionResult, ActionResultStatus, Action, ActionType

class ConcreteSkill(Skill):
    def init(self, ctx, params):
        session = ctx.sessions.create(params, ctx.skill_id)
        return {"sessionId": session.session_id, "status": "INITIALIZED"}
    
    def start(self, ctx, session):
        ctx.output.info("开始执行")
        return SkillResult.success(session.session_id, {"status": "ok"})
    
    def handle_action_result(self, ctx, result, session):
        return SkillResult.success(session.session_id)

def test_output_collector_info():
    collector = OutputCollector()
    collector.info("测试信息")
    outputs = collector.collect()
    assert len(outputs) == 1
    assert outputs[0].type == "info"
    assert outputs[0].message == "测试信息"

def test_output_collector_collect_clears():
    collector = OutputCollector()
    collector.info("第一条")
    collector.collect()
    outputs = collector.collect()
    assert len(outputs) == 0

def test_skill_context_creation():
    with tempfile.TemporaryDirectory() as tmpdir:
        store = SessionStore(tmpdir)
        ctx = SkillContext(skill_id="test.skill", sessions=store, output=OutputCollector())
        assert ctx.skill_id == "test.skill"

def test_concrete_skill_init():
    with tempfile.TemporaryDirectory() as tmpdir:
        store = SessionStore(tmpdir)
        ctx = SkillContext(skill_id="test.skill", sessions=store, output=OutputCollector())
        skill = ConcreteSkill()
        result = skill.init(ctx, {})
        assert "sessionId" in result
        assert result["status"] == "INITIALIZED"

def test_concrete_skill_start():
    with tempfile.TemporaryDirectory() as tmpdir:
        store = SessionStore(tmpdir)
        ctx = SkillContext(skill_id="test.skill", sessions=store, output=OutputCollector())
        skill = ConcreteSkill()
        session = SkillSession(skill_id="test.skill")
        result = skill.start(ctx, session)
        assert result.status == SkillStatus.SUCCESS
        outputs = ctx.output.collect()
        assert len(outputs) == 1
```

- [ ] **Step 2: 运行测试验证失败**

Run: `uv run pytest tests/test_base.py -v`
Expected: FAIL - "No module named 'smartcard_skill_sdk.base'"

- [ ] **Step 3: 实现 base.py**

```python
# packages/skill-sdk/src/smartcard_skill_sdk/base.py
from abc import ABC, abstractmethod
from dataclasses import dataclass
from .protocol import Output, SkillResult, ActionResult
from .session_store import SessionStore, SkillSession


class OutputCollector:
    def __init__(self):
        self.outputs: list[Output] = []

    def info(self, message: str) -> None:
        self.outputs.append(Output(type="info", message=message))

    def text(self, message: str) -> None:
        self.outputs.append(Output(type="text", message=message))

    def stream(self, message: str) -> None:
        self.outputs.append(Output(type="stream", message=message))

    def data(self, data: dict) -> None:
        self.outputs.append(Output(type="data", data=data))

    def collect(self) -> list[Output]:
        outputs = self.outputs.copy()
        self.outputs.clear()
        return outputs


@dataclass
class SkillContext:
    skill_id: str
    sessions: SessionStore
    output: OutputCollector


class Skill(ABC):
    @abstractmethod
    def init(self, ctx: SkillContext, params: dict) -> dict:
        pass

    @abstractmethod
    def start(self, ctx: SkillContext, session: SkillSession) -> SkillResult:
        pass

    @abstractmethod
    def handle_action_result(
        self, ctx: SkillContext, result: ActionResult, session: SkillSession
    ) -> SkillResult:
        pass

    def provide_input(
        self, ctx: SkillContext, input_data: dict, session: SkillSession
    ) -> SkillResult:
        return SkillResult.failed(session.session_id, "UNSUPPORTED", "此 Skill 不支持用户输入")

    def cancel(self, ctx: SkillContext, session: SkillSession) -> SkillResult:
        return SkillResult.failed(session.session_id, "CANCELLED", "已取消")
```

- [ ] **Step 4: 添加 create 方法到 SessionStore**

在 `session_store.py` 的 `SessionStore` 类中添加：

```python
def create(self, params: dict, skill_id: str) -> SkillSession:
    session = SkillSession(skill_id=skill_id, data={"params": params})
    self.save(session, skill_id)
    return session
```

- [ ] **Step 5: 运行测试验证通过**

Run: `uv run pytest tests/test_base.py -v`
Expected: 5 passed

- [ ] **Step 6: Commit**

```bash
git add packages/skill-sdk/src/smartcard_skill_sdk/base.py tests/test_base.py
git commit -m "feat: add skill base classes"
```

---

## Task 5: 简单 APDU Skill 基类（simple_apdu.py）

**Files:**
- Create: `packages/skill-sdk/src/smartcard_skill_sdk/simple_apdu.py`
- Test: `tests/test_simple_apdu.py`

**Interfaces:**
- Consumes: `Skill`, `SkillContext`, `SkillSession`, `SkillResult`, `Action`, `ActionType`
- Produces: `SimpleApduSkill`

- [ ] **Step 1: 编写测试**

```python
# tests/test_simple_apdu.py
import pytest
import tempfile
from smartcard_skill_sdk.simple_apdu import SimpleApduSkill
from smartcard_skill_sdk.base import SkillContext, OutputCollector
from smartcard_skill_sdk.session_store import SessionStore, SkillSession
from smartcard_skill_sdk.protocol import ActionResult, ActionResultStatus, ActionType

class TestApduSkill(SimpleApduSkill):
    def build_apdu(self, ctx, params):
        return "00A40000023F00"
    
    def parse_response(self, response, sw):
        if sw != "9000":
            raise ValueError(f"APDU error: {sw}")
        return {"data": response[:10]}
    
    def get_manifest(self):
        return {"skillId": "test.apdu", "name": "Test", "description": "Test APDU"}

def test_simple_apdu_skill_build_apdu():
    with tempfile.TemporaryDirectory() as tmpdir:
        store = SessionStore(tmpdir)
        ctx = SkillContext(skill_id="test.apdu", sessions=store, output=OutputCollector())
        skill = TestApduSkill()
        apdu = skill.build_apdu(ctx, {})
        assert apdu == "00A40000023F00"

def test_simple_apdu_skill_start():
    with tempfile.TemporaryDirectory() as tmpdir:
        store = SessionStore(tmpdir)
        ctx = SkillContext(skill_id="test.apdu", sessions=store, output=OutputCollector())
        skill = TestApduSkill()
        session = SkillSession(skill_id="test.apdu", data={"params": {}})
        result = skill.start(ctx, session)
        assert result.status.value == "CONTINUE"
        assert result.next_action.type == ActionType.APDU
        assert result.next_action.payload["apdu"] == "00A40000023F00"

def test_simple_apdu_skill_handle_result_success():
    with tempfile.TemporaryDirectory() as tmpdir:
        store = SessionStore(tmpdir)
        ctx = SkillContext(skill_id="test.apdu", sessions=store, output=OutputCollector())
        skill = TestApduSkill()
        session = SkillSession(skill_id="test.apdu")
        
        action_result = ActionResult(
            action_id="test.apdu.execute",
            type="APDU_RESULT",
            status=ActionResultStatus.OK,
            data={"response": "9801234567890", "sw": "9000"}
        )
        result = skill.handle_action_result(ctx, action_result, session)
        assert result.status.value == "SUCCESS"
        assert "data" in result.data

def test_simple_apdu_skill_handle_result_error():
    with tempfile.TemporaryDirectory() as tmpdir:
        store = SessionStore(tmpdir)
        ctx = SkillContext(skill_id="test.apdu", sessions=store, output=OutputCollector())
        skill = TestApduSkill()
        session = SkillSession(skill_id="test.apdu")
        
        action_result = ActionResult(
            action_id="test.apdu.execute",
            type="APDU_RESULT",
            status=ActionResultStatus.ERROR,
            data={}
        )
        result = skill.handle_action_result(ctx, action_result, session)
        assert result.status.value == "FAILED"
```

- [ ] **Step 2: 运行测试验证失败**

Run: `uv run pytest tests/test_simple_apdu.py -v`
Expected: FAIL - "No module named 'smartcard_skill_sdk.simple_apdu'"

- [ ] **Step 3: 实现 simple_apdu.py**

```python
# packages/skill-sdk/src/smartcard_skill_sdk/simple_apdu.py
from abc import abstractmethod
from .base import Skill, SkillContext, SkillSession
from .protocol import SkillResult, ActionResult, Action, ActionType
from .session_store import SkillSession


class SimpleApduSkill(Skill):
    @abstractmethod
    def build_apdu(self, ctx: SkillContext, params: dict) -> str:
        pass

    @abstractmethod
    def parse_response(self, response: str, sw: str) -> dict:
        pass

    def get_manifest(self) -> dict:
        return {
            "skillId": self.__class__.__name__,
            "name": "APDU Skill",
            "description": "Simple APDU Skill",
            "version": "1.0.0",
            "requiresReader": True,
            "supportsSession": True
        }

    def init(self, ctx: SkillContext, params: dict) -> dict:
        session = ctx.sessions.create(params, ctx.skill_id)
        return {
            "sessionId": session.session_id,
            "manifest": self.get_manifest(),
            "status": "INITIALIZED"
        }

    def start(self, ctx: SkillContext, session: SkillSession) -> SkillResult:
        ctx.output.info(f"开始执行 {ctx.skill_id}")
        params = session.data.get("params", {})
        apdu = self.build_apdu(ctx, params)
        
        manifest = self.get_manifest()
        action = Action(
            action_id=f"{ctx.skill_id}.execute",
            type=ActionType.APDU,
            name=manifest.get("name", "APDU"),
            description=manifest.get("description", "执行 APDU"),
            sensitive=False,
            payload={"apdu": apdu, "expectedStatus": ["9000"]}
        )
        return SkillResult.continue_with(session.session_id, action)

    def handle_action_result(
        self, ctx: SkillContext, result: ActionResult, session: SkillSession
    ) -> SkillResult:
        if result.status.value != "OK":
            return SkillResult.failed(
                session.session_id,
                "APDU_ERROR",
                f"APDU 执行失败: {result.status}"
            )
        
        data = result.data
        try:
            parsed = self.parse_response(data.get("response", ""), data.get("sw", ""))
            return SkillResult.success(session.session_id, parsed)
        except Exception as e:
            return SkillResult.failed(session.session_id, "PARSE_ERROR", str(e))
```

- [ ] **Step 4: 运行测试验证通过**

Run: `uv run pytest tests/test_simple_apdu.py -v`
Expected: 4 passed

- [ ] **Step 5: Commit**

```bash
git add packages/skill-sdk/src/smartcard_skill_sdk/simple_apdu.py tests/test_simple_apdu.py
git commit -m "feat: add simple APDU skill base class"
```

---

## Task 6: SDK 导出（__init__.py）

**Files:**
- Create: `packages/skill-sdk/src/smartcard_skill_sdk/__init__.py`

**Interfaces:**
- Consumes: 所有 SDK 模块
- Produces: 统一的 SDK 导入接口

- [ ] **Step 1: 实现 __init__.py**

```python
# packages/skill-sdk/src/smartcard_skill_sdk/__init__.py
from .protocol import (
    SkillStatus, ActionType, ActionResultStatus,
    Action, ActionResult, Output, InputRequest, Error, SkillResult,
    JsonRpcRequest, JsonRpcResponse
)
from .session_store import SkillSession, SessionStore
from .base import Skill, SkillContext, OutputCollector
from .simple_apdu import SimpleApduSkill

__all__ = [
    "SkillStatus", "ActionType", "ActionResultStatus",
    "Action", "ActionResult", "Output", "InputRequest", "Error", "SkillResult",
    "JsonRpcRequest", "JsonRpcResponse",
    "SkillSession", "SessionStore",
    "Skill", "SkillContext", "OutputCollector",
    "SimpleApduSkill"
]
```

- [ ] **Step 2: 验证导入**

Run: `uv run python -c "from smartcard_skill_sdk import Skill, SkillResult, Action; print('OK')"`
Expected: OK

- [ ] **Step 3: Commit**

```bash
git add packages/skill-sdk/src/smartcard_skill_sdk/__init__.py
git commit -m "feat: add SDK exports"
```

---

## Task 7: read-iccid Skill 实现

**Files:**
- Create: `skills/read-iccid/pyproject.toml`
- Create: `skills/read-iccid/src/read_iccid_skill/__init__.py`
- Create: `skills/read-iccid/src/read_iccid_skill/skill.py`
- Create: `skills/read-iccid/src/read_iccid_skill/main.py`
- Test: `tests/test_read_iccid.py`

**Interfaces:**
- Consumes: `SimpleApduSkill`, `SkillContext`
- Produces: `ReadIccidSkill`, CLI 入口 `main.py`

- [ ] **Step 1: 创建 read-iccid pyproject.toml**

```toml
[project]
name = "read-iccid-skill"
version = "0.1.0"
requires-python = ">=3.11"
dependencies = ["smartcard-skill-sdk"]

[project.scripts]
read-iccid-skill = "read_iccid_skill.main:main"

[project.entry-points."smartcard.skills"]
"read.iccid" = "read_iccid_skill.main:main"

[tool.uv.sources]
smartcard-skill-sdk = { workspace = true }

[build-system]
requires = ["hatchling"]
build-backend = "hatchling.build"

[tool.hatch.build.targets.wheel]
packages = ["src/read_iccid_skill"]
```

- [ ] **Step 2: 编写 Skill 测试**

```python
# tests/test_read_iccid.py
import pytest
import tempfile
from read_iccid_skill.skill import ReadIccidSkill
from smartcard_skill_sdk.base import SkillContext, OutputCollector
from smartcard_skill_sdk.session_store import SessionStore, SkillSession

def test_read_iccid_build_apdu():
    with tempfile.TemporaryDirectory() as tmpdir:
        store = SessionStore(tmpdir)
        ctx = SkillContext(skill_id="read.iccid", sessions=store, output=OutputCollector())
        skill = ReadIccidSkill()
        apdu = skill.build_apdu(ctx, {})
        assert apdu == "00A40000023F00"

def test_read_iccid_parse_response():
    skill = ReadIccidSkill()
    result = skill.parse_response("98012345678901234567890", "9000")
    assert "iccid" in result
    assert result["iccid"] == "98012345678901234567"

def test_read_iccid_manifest():
    skill = ReadIccidSkill()
    manifest = skill.get_manifest()
    assert manifest["skillId"] == "read.iccid"
    assert "ICCID" in manifest["description"]
```

- [ ] **Step 3: 运行测试验证失败**

Run: `uv run pytest tests/test_read_iccid.py -v`
Expected: FAIL - "No module named 'read_iccid_skill'"

- [ ] **Step 4: 实现 ReadIccidSkill**

```python
# skills/read-iccid/src/read_iccid_skill/__init__.py
__version__ = "0.1.0"
```

```python
# skills/read-iccid/src/read_iccid_skill/skill.py
from smartcard_skill_sdk import SimpleApduSkill, SkillContext


class ReadIccidSkill(SimpleApduSkill):
    def build_apdu(self, ctx: SkillContext, params: dict) -> str:
        # SELECT MF (3F00)
        return "00A40000023F00"

    def parse_response(self, response: str, sw: str) -> dict:
        if sw != "9000":
            raise ValueError(f"APDU error: {sw}")
        # 简化示例：返回前 20 字符作为 ICCID
        return {"iccid": response[:20] if response else ""}

    def get_manifest(self) -> dict:
        return {
            "skillId": "read.iccid",
            "name": "读取 ICCID",
            "description": "读取 SIM 卡的 ICCID",
            "version": "1.0.0",
            "requiresReader": True,
            "supportsSession": True
        }
```

- [ ] **Step 5: 实现 main.py**

```python
# skills/read-iccid/src/read_iccid_skill/main.py
import sys
import json
from smartcard_skill_sdk import SkillContext, SessionStore, OutputCollector
from .skill import ReadIccidSkill


def main():
    skill = ReadIccidSkill()
    store = SessionStore("./.sessions")
    ctx = SkillContext(skill_id="read.iccid", sessions=store, output=OutputCollector())

    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        
        try:
            request = json.loads(line)
        except json.JSONDecodeError:
            continue

        method = request.get("method")
        request_id = request.get("id")
        params = request.get("params", {})

        if method == "skill.init":
            result = skill.init(ctx, params.get("input", {}))
            response = {"jsonrpc": "2.0", "id": request_id, "result": result}
            print(json.dumps(response), flush=True)

        elif method == "skill.start":
            session_id = params["sessionId"]
            session = store.load(session_id)
            if not session:
                response = {
                    "jsonrpc": "2.0",
                    "id": request_id,
                    "error": {"code": "SESSION_NOT_FOUND", "message": "会话不存在"}
                }
            else:
                result = skill.start(ctx, session)
                response = {"jsonrpc": "2.0", "id": request_id, "result": result.model_dump()}
            print(json.dumps(response), flush=True)

        elif method == "skill.handleActionResult":
            session_id = params["sessionId"]
            session = store.load(session_id)
            if not session:
                response = {
                    "jsonrpc": "2.0",
                    "id": request_id,
                    "error": {"code": "SESSION_NOT_FOUND", "message": "会话不存在"}
                }
            else:
                from smartcard_skill_sdk import ActionResult
                action_result = ActionResult(**params["result"])
                result = skill.handle_action_result(ctx, action_result, session)
                response = {"jsonrpc": "2.0", "id": request_id, "result": result.model_dump()}
            print(json.dumps(response), flush=True)


if __name__ == "__main__":
    main()
```

- [ ] **Step 6: 运行测试验证通过**

Run: `uv run pytest tests/test_read_iccid.py -v`
Expected: 3 passed

- [ ] **Step 7: Commit**

```bash
git add skills/read-iccid/ tests/test_read_iccid.py
git commit -m "feat: add read-iccid skill"
```

---

## Task 8: 端到端集成测试

**Files:**
- Test: `tests/test_integration.py`

**Interfaces:**
- Consumes: `ReadIccidSkill`, SDK 所有模块
- Produces: 完整流程验证

- [ ] **Step 1: 编写集成测试**

```python
# tests/test_integration.py
import pytest
import json
import tempfile
from smartcard_skill_sdk import (
    SkillContext, SessionStore, OutputCollector,
    SkillResult, ActionResult, ActionResultStatus
)
from read_iccid_skill.skill import ReadIccidSkill


def test_full_flow():
    """测试完整的 init -> start -> handleActionResult 流程"""
    with tempfile.TemporaryDirectory() as tmpdir:
        store = SessionStore(tmpdir)
        ctx = SkillContext(skill_id="read.iccid", sessions=store, output=OutputCollector())
        skill = ReadIccidSkill()

        # 1. Init
        init_result = skill.init(ctx, {})
        assert "sessionId" in init_result
        session_id = init_result["sessionId"]

        # 2. Load session
        session = store.load(session_id)
        assert session is not None

        # 3. Start
        start_result = skill.start(ctx, session)
        assert start_result.status.value == "CONTINUE"
        assert start_result.next_action is not None
        assert start_result.next_action.type.value == "APDU"

        # 4. Handle Action Result
        action_result = ActionResult(
            action_id=start_result.next_action.action_id,
            type="APDU_RESULT",
            status=ActionResultStatus.OK,
            data={"response": "98012345678901234567890", "sw": "9000"}
        )
        final_result = skill.handle_action_result(ctx, action_result, session)
        assert final_result.status.value == "SUCCESS"
        assert "iccid" in final_result.data


def test_session_id_consistency():
    """验证 sessionId 在整个流程中保持一致"""
    with tempfile.TemporaryDirectory() as tmpdir:
        store = SessionStore(tmpdir)
        ctx = SkillContext(skill_id="read.iccid", sessions=store, output=OutputCollector())
        skill = ReadIccidSkill()

        init_result = skill.init(ctx, {})
        session_id = init_result["sessionId"]

        session = store.load(session_id)
        start_result = skill.start(ctx, session)
        assert start_result.session_id == session_id

        action_result = ActionResult(
            action_id=start_result.next_action.action_id,
            type="APDU_RESULT",
            status=ActionResultStatus.OK,
            data={"response": "test", "sw": "9000"}
        )
        final_result = skill.handle_action_result(ctx, action_result, session)
        assert final_result.session_id == session_id


def test_output_collection():
    """验证 Output 正确收集"""
    with tempfile.TemporaryDirectory() as tmpdir:
        store = SessionStore(tmpdir)
        ctx = SkillContext(skill_id="read.iccid", sessions=store, output=OutputCollector())
        skill = ReadIccidSkill()

        session = store.create({}, "read.iccid")
        skill.start(ctx, session)
        
        outputs = ctx.output.collect()
        assert len(outputs) > 0
        assert any("开始执行" in o.message for o in outputs)
```

- [ ] **Step 2: 运行集成测试**

Run: `uv run pytest tests/test_integration.py -v`
Expected: 3 passed

- [ ] **Step 3: 运行所有测试**

Run: `uv run pytest -v`
Expected: All tests passed

- [ ] **Step 4: Final Commit**

```bash
git add tests/test_integration.py
git commit -m "test: add integration tests"
```

---

## 验收标准

- [ ] `uv sync` 成功安装所有依赖
- [ ] `uv run pytest` 所有测试通过（至少 20 个测试）
- [ ] `python -c "from smartcard_skill_sdk import Skill"` 导入成功
- [ ] read-iccid Skill 可响应 `skill.init` 和 `skill.start`
- [ ] sessionId 在 init 时生成并贯穿所有响应
- [ ] 会话文件正确写入 `.sessions/` 目录
- [ ] 敏感信息未出现在 stdout
