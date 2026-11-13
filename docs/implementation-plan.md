# SmartCard Agent Skills 实施计划

**基于：** skill-design.md v2.0  
**粒度：** 2-5 分钟原子任务  
**日期：** 2026-11-13

---

## 总体策略

采用 **自底向上、分层推进** 的实施策略：

1. **Phase 1 - 基础设施**：项目骨架、uv workspace、基础配置
2. **Phase 2 - SDK 核心**：协议模型、会话管理、抽象基类
3. **Phase 3 - 示例 Skill**：简单 APDU Skill（read-iccid）
4. **Phase 4 - 复杂 Skill**：多交互 Skill（scp02.open）
5. **Phase 5 - 测试与文档**：协议测试、脱敏测试、端到端测试

---

## Phase 1 - 项目基础设施（预计 15 分钟）

### 1.1 创建根目录配置文件

**任务 1.1.1** 创建 `pyproject.toml`（根 workspace 配置）
- **文件：** `pyproject.toml`
- **内容：**
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
- **依赖：** 无
- **验证：** `uv sync` 成功

**任务 1.1.2** 创建 `.gitignore`
- **文件：** `.gitignore`
- **内容：**
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
- **依赖：** 无
- **验证：** `git status` 不显示 `__pycache__` 等

**任务 1.1.3** 创建目录结构
- **操作：** 创建以下空目录
  ```
  packages/
  packages/skill-sdk/
  packages/skill-sdk/src/smartcard_skill_sdk/
  skills/
  skills/scp02/
  skills/scp02/src/scp02_skill/
  skills/read-iccid/
  skills/read-iccid/src/read_iccid_skill/
  tests/
  docs/
  ```
- **依赖：** 无
- **验证：** `tree` 命令显示正确结构

---

## Phase 2 - SDK 核心模块（预计 60 分钟）

### 2.1 SDK 项目配置

**任务 2.1.1** 创建 SDK `pyproject.toml`
- **文件：** `packages/skill-sdk/pyproject.toml`
- **内容：**
  ```toml
  [project]
  name = "smartcard-skill-sdk"
  version = "0.1.0"
  requires-python = ">=3.11"
  dependencies = [
      "pydantic>=2.0",
      "jsonschema>=4.0",
  ]

  [build-system]
  requires = ["hatchling"]
  build-backend = "hatchling.build"

  [tool.hatch.build.targets.wheel]
  packages = ["src/smartcard_skill_sdk"]
  ```
- **依赖：** 1.1.1
- **验证：** `uv sync --package smartcard-skill-sdk` 成功

### 2.2 协议模型（protocol.py）

**任务 2.2.1** 定义消息类型枚举
- **文件：** `packages/skill-sdk/src/smartcard_skill_sdk/protocol.py`
- **内容：**
  ```python
  from enum import Enum

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
  ```
- **依赖：** 2.1.1
- **验证：** `python -c "from smartcard_skill_sdk.protocol import SkillStatus"` 成功

**任务 2.2.2** 定义请求/响应数据模型
- **文件：** `packages/skill-sdk/src/smartcard_skill_sdk/protocol.py`（追加）
- **内容：**
  ```python
  from pydantic import BaseModel
  from typing import Any

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
      type: str  # info, text, stream, data
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
  ```
- **依赖：** 2.2.1
- **验证：** `python -c "from smartcard_skill_sdk.protocol import Action, ActionResult"` 成功

**任务 2.2.3** 定义 SkillResult 模型
- **文件：** `packages/skill-sdk/src/smartcard_skill_sdk/protocol.py`（追加）
- **内容：**
  ```python
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
      def success(cls, session_id: str, data: dict = {}) -> "SkillResult":
          return cls(session_id=session_id, status=SkillStatus.SUCCESS, data=data)

      @classmethod
      def failed(cls, session_id: str, code: str, message: str) -> "SkillResult":
          return cls(session_id=session_id, status=SkillStatus.FAILED, error=Error(code=code, message=message))

      @classmethod
      def need_input(cls, session_id: str, request: InputRequest) -> "SkillResult":
          return cls(session_id=session_id, status=SkillStatus.NEED_INPUT, input_request=request)
  ```
- **依赖：** 2.2.2
- **验证：** `python -c "from smartcard_skill_sdk.protocol import SkillResult; print(SkillResult.success('test', {}))"`

**任务 2.2.4** 定义 JSON-RPC 消息结构
- **文件：** `packages/skill-sdk/src/smartcard_skill_sdk/protocol.py`（追加）
- **内容：**
  ```python
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
- **依赖：** 2.2.3
- **验证：** 单元测试覆盖序列化/反序列化

### 2.3 会话管理（session_store.py）

**任务 2.3.1** 定义 SkillSession 模型
- **文件：** `packages/skill-sdk/src/smartcard_skill_sdk/session_store.py`
- **内容：**
  ```python
  from pydantic import BaseModel
  from datetime import datetime
  from typing import Any
  import uuid

  class SkillSession(BaseModel):
      schema_version: int = 1
      session_id: str = ""
      skill_id: str = ""
      created_at: str = ""
      updated_at: str = ""
      status: str = "CREATED"
      state: str = ""
      data: dict[str, Any] = {}
      last_action_id: str = ""
      ttl_seconds: int = 3600

      def __init__(self, **data):
          super().__init__(**data)
          if not self.session_id:
              self.session_id = str(uuid.uuid4())
          if not self.created_at:
              self.created_at = datetime.utcnow().isoformat() + "Z"
          self.updated_at = self.created_at
  ```
- **依赖：** 2.1.1
- **验证：** `python -c "from smartcard_skill_sdk.session_store import SkillSession; s = SkillSession(); print(s.session_id)"`

**任务 2.3.2** 实现 SessionStore 类
- **文件：** `packages/skill-sdk/src/smartcard_skill_sdk/session_store.py`（追加）
- **内容：**
  ```python
  import json
  import os
  from pathlib import Path
  import tempfile

  class SessionStore:
      def __init__(self, base_dir: str):
          self.base_dir = Path(base_dir)
          self.base_dir.mkdir(parents=True, exist_ok=True, mode=0o700)

      def save(self, session: SkillSession) -> None:
          session.updated_at = datetime.utcnow().isoformat() + "Z"
          file_path = self.base_dir / f"session-{session.session_id[:8]}.json"
          with tempfile.NamedTemporaryFile(mode='w', dir=self.base_dir, delete=False) as f:
              json.dump(session.model_dump(), f, indent=2)
              temp_path = f.name
          os.chmod(temp_path, 0o600)
          os.replace(temp_path, file_path)

      def load(self, session_id: str) -> SkillSession | None:
          file_path = self.base_dir / f"session-{session_id[:8]}.json"
          if not file_path.exists():
              return None
          with open(file_path) as f:
              data = json.load(f)
          return SkillSession(**data)

      def delete(self, session_id: str) -> None:
          file_path = self.base_dir / f"session-{session_id[:8]}.json"
          if file_path.exists():
              file_path.unlink()
  ```
- **依赖：** 2.3.1
- **验证：** 创建、读取、删除会话文件，验证权限和原子写入

**任务 2.3.3** 实现 TTL 清理功能
- **文件：** `packages/skill-sdk/src/smartcard_skill_sdk/session_store.py`（追加）
- **内容：**
  ```python
  from datetime import datetime, timezone

  def cleanup_expired(self) -> int:
      now = datetime.now(timezone.utc)
      removed = 0
      for file_path in self.base_dir.glob("session-*.json"):
          try:
              with open(file_path) as f:
                  data = json.load(f)
              session = SkillSession(**data)
              created = datetime.fromisoformat(session.created_at.replace("Z", "+00:00"))
              if (now - created).total_seconds() > session.ttl_seconds:
                  file_path.unlink()
                  removed += 1
          except Exception:
              continue
      return removed
  ```
- **依赖：** 2.3.2
- **验证：** 创建过期会话，调用清理，验证文件被删除

### 2.4 抽象基类（base.py）

**任务 2.4.1** 定义 SkillContext
- **文件：** `packages/skill-sdk/src/smartcard_skill_sdk/base.py`
- **内容：**
  ```python
  from dataclasses import dataclass
  from .session_store import SessionStore, SkillSession
  from .protocol import Output

  @dataclass
  class SkillContext:
      skill_id: str
      sessions: SessionStore
      output: "OutputCollector"

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
  ```
- **依赖：** 2.2.2, 2.3.1
- **验证：** `python -c "from smartcard_skill_sdk.base import SkillContext, OutputCollector"`

**任务 2.4.2** 定义 Skill 抽象基类
- **文件：** `packages/skill-sdk/src/smartcard_skill_sdk/base.py`（追加）
- **内容：**
  ```python
  from abc import ABC, abstractmethod
  from .protocol import SkillResult, ActionResult

  class Skill(ABC):
      @abstractmethod
      def init(self, ctx: SkillContext, params: dict) -> dict:
          """初始化 Skill，返回 manifest 和 sessionId"""
          pass

      @abstractmethod
      def start(self, ctx: SkillContext, session: SkillSession) -> SkillResult:
          """启动执行，返回第一个 SkillResult"""
          pass

      @abstractmethod
      def handle_action_result(
          self, ctx: SkillContext, result: ActionResult, session: SkillSession
      ) -> SkillResult:
          """处理 Action 结果，返回下一个 SkillResult"""
          pass

      def provide_input(
          self, ctx: SkillContext, input_data: dict, session: SkillSession
      ) -> SkillResult:
          """处理用户输入（可选实现）"""
          return SkillResult.failed(session.session_id, "UNSUPPORTED", "此 Skill 不支持用户输入")

      def cancel(self, ctx: SkillContext, session: SkillSession) -> SkillResult:
          """取消执行（可选实现）"""
          return SkillResult.cancelled(session.session_id)
  ```
- **依赖：** 2.4.1
- **验证：** 子类化并实现所有抽象方法

### 2.5 简单 APDU Skill 基类（simple_apdu.py）

**任务 2.5.1** 实现 SimpleApduSkill
- **文件：** `packages/skill-sdk/src/smartcard_skill_sdk/simple_apdu.py`
- **内容：**
  ```python
  from .base import Skill, SkillContext, SkillSession, OutputCollector
  from .protocol import SkillResult, ActionResult, Action, ActionType
  from abc import abstractmethod

  class SimpleApduSkill(Skill):
      """单条 APDU 的 Skill 基类"""

      @abstractmethod
      def build_apdu(self, ctx: SkillContext, params: dict) -> str:
          """构造 APDU 字符串"""
          pass

      @abstractmethod
      def parse_response(self, response: str, sw: str) -> dict:
          """解析响应，返回结果数据"""
          pass

      def init(self, ctx: SkillContext, params: dict) -> dict:
          session = ctx.sessions.create(params)
          return {
              "sessionId": session.session_id,
              "manifest": self.get_manifest(),
              "status": "INITIALIZED"
          }

      def start(self, ctx: SkillContext, session: SkillSession) -> SkillResult:
          ctx.output.info(f"开始执行 {ctx.skill_id}")
          apdu = self.build_apdu(ctx, session.data.get("params", {}))
          action = Action(
              action_id=f"{ctx.skill_id}.execute",
              type=ActionType.APDU,
              name=self.get_manifest()["name"],
              description=self.get_manifest()["description"],
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
          parsed = self.parse_response(data.get("response", ""), data.get("sw", ""))
          return SkillResult.success(session.session_id, parsed)

      def get_manifest(self) -> dict:
          return {
              "skillId": self.__class__.__name__,
              "name": "APDU Skill",
              "description": "Simple APDU Skill",
              "version": "1.0.0",
              "requiresReader": True,
              "supportsSession": True
          }
  ```
- **依赖：** 2.4.2
- **验证：** 子类化并实现 build_apdu/parse_response

### 2.6 SDK 导出

**任务 2.6.1** 创建 `__init__.py`
- **文件：** `packages/skill-sdk/src/smartcard_skill_sdk/__init__.py`
- **内容：**
  ```python
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
- **依赖：** 2.2, 2.3, 2.4, 2.5
- **验证：** `python -c "from smartcard_skill_sdk import Skill, SkillResult, Action"` 成功

---

## Phase 3 - 示例 Skill：read-iccid（预计 30 分钟）

### 3.1 Skill 项目配置

**任务 3.1.1** 创建 `pyproject.toml`
- **文件：** `skills/read-iccid/pyproject.toml`
- **内容：**
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
- **依赖：** 2.1.1
- **验证：** `uv sync --package read-iccid-skill` 成功

### 3.2 Skill 实现

**任务 3.2.1** 创建 `__init__.py`
- **文件：** `skills/read-iccid/src/read_iccid_skill/__init__.py`
- **内容：** 空文件或版本声明
- **依赖：** 3.1.1
- **验证：** 导入成功

**任务 3.2.2** 实现 ReadIccidSkill
- **文件：** `skills/read-iccid/src/read_iccid_skill/skill.py`
- **内容：**
  ```python
  from smartcard_skill_sdk import SimpleApduSkill, SkillContext

  class ReadIccidSkill(SimpleApduSkill):
      def build_apdu(self, ctx: SkillContext, params: dict) -> str:
          # SELECT MF -> SELECT ICCID AID
          return "00A40000023F00"  # 简化示例

      def parse_response(self, response: str, sw: str) -> dict:
          if sw != "9000":
              raise ValueError(f"APDU error: {sw}")
          # 解析 ICCID（简化）
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
- **依赖：** 2.5, 3.1.1
- **验证：** 实例化并调用 build_apdu

**任务 3.2.3** 实现 main.py
- **文件：** `skills/read-iccid/src/read_iccid_skill/main.py`
- **内容：**
  ```python
  import sys
  import json
  from smartcard_skill_sdk import SkillContext, SessionStore, OutputCollector
  from .skill import ReadIccidSkill

  def main():
      skill = ReadIccidSkill()
      store = SessionStore("./.sessions")
      ctx = SkillContext(skill_id="read.iccid", sessions=store, output=OutputCollector())

      # 读取 stdin
      for line in sys.stdin:
          request = json.loads(line.strip())
          method = request.get("method")

          if method == "skill.init":
              result = skill.init(ctx, request["params"].get("input", {}))
              print(json.dumps({"jsonrpc": "2.0", "id": request["id"], "result": result}))
              sys.stdout.flush()

          elif method == "skill.start":
              session_id = request["params"]["sessionId"]
              session = store.load(session_id)
              result = skill.start(ctx, session)
              print(json.dumps({"jsonrpc": "2.0", "id": request["id"], "result": result.model_dump()}))
              sys.stdout.flush()

          elif method == "skill.handleActionResult":
              # 处理 Action 结果
              pass

  if __name__ == "__main__":
      main()
  ```
- **依赖：** 3.2.2
- **验证：** `python -m read_iccid_skill` 启动并等待 stdin

### 3.3 Skill 测试

**任务 3.3.1** 编写单元测试
- **文件：** `tests/test_read_iccid.py`
- **内容：**
  ```python
  import pytest
  from read_iccid_skill.skill import ReadIccidSkill
  from smartcard_skill_sdk import SkillContext, SessionStore, OutputCollector

  def test_build_apdu():
      skill = ReadIccidSkill()
      store = SessionStore("/tmp/test-sessions")
      ctx = SkillContext(skill_id="read.iccid", sessions=store, output=OutputCollector())
      apdu = skill.build_apdu(ctx, {})
      assert apdu == "00A40000023F00"

  def test_parse_response():
      skill = ReadIccidSkill()
      result = skill.parse_response("98012345678901234567890", "9000")
      assert "iccid" in result
  ```
- **依赖：** 3.2.2
- **验证：** `uv run pytest tests/test_read_iccid.py -v` 通过

---

## Phase 4 - 复杂 Skill：scp02.open（预计 90 分钟）

### 4.1 Skill 项目配置

**任务 4.1.1** 创建 `pyproject.toml`
- **文件：** `skills/scp02/pyproject.toml`
- **内容：** 类似 3.1.1，替换名称为 `scp02-skill`
- **依赖：** 2.1.1
- **验证：** `uv sync --package scp02-skill` 成功

### 4.2 状态机定义

**任务 4.2.1** 定义 Scp02State 枚举
- **文件：** `skills/scp02/src/scp02_skill/state.py`
- **内容：**
  ```python
  from enum import Enum

  class Scp02State(str, Enum):
      START = "START"
      WAIT_RESET = "WAIT_RESET"
      WAIT_INITIALIZE_UPDATE = "WAIT_INITIALIZE_UPDATE"
      WAIT_EXTERNAL_AUTHENTICATE = "WAIT_EXTERNAL_AUTHENTICATE"
      ESTABLISHED = "ESTABLISHED"
      FAILED = "FAILED"
  ```
- **依赖：** 4.1.1
- **验证：** 导入成功

### 4.3 密码学模块

**任务 4.3.1** 实现 Session Keys 计算
- **文件：** `skills/scp02/src/scp02_skill/crypto.py`
- **内容：**
  ```python
  from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
  from cryptography.hazmat.backends import default_backend
  import os

  def calculate_session_keys(enc_key: bytes, mac_key: bytes, sequence_counter: bytes) -> dict:
      """计算 SCP02 Session Keys"""
      # 简化示例，实际需按 GP 规范实现
      return {
          "session_enc_key": derive_key(enc_key, sequence_counter, "enc"),
          "session_mac_key": derive_key(mac_key, sequence_counter, "mac"),
      }

  def derive_key(master_key: bytes, counter: bytes, key_type: str) -> bytes:
      """密钥派生（简化）"""
      # 实际应使用 3DES
      return master_key  # 占位
  ```
- **依赖：** 4.1.1, 需添加 `cryptography` 依赖
- **验证：** 单元测试验证密钥派生

### 4.4 Skill 实现

**任务 4.4.1** 实现 Scp02Skill
- **文件：** `skills/scp02/src/scp02_skill/skill.py`
- **内容：** 完整状态机实现（参考设计文档 15. 推荐 Skill 模板）
- **依赖：** 4.2.1, 4.3.1
- **验证：** 状态转换测试

**任务 4.4.2** 实现 main.py
- **文件：** `skills/scp02/src/scp02_skill/main.py`
- **内容：** 类似 3.2.3，适配 SCP02 多轮交互
- **依赖：** 4.4.1
- **验证：** 端到端执行流程测试

### 4.5 Skill 测试

**任务 4.5.1** 编写状态机测试
- **文件：** `tests/test_scp02.py`
- **内容：** 测试所有状态转换、错误处理、取消逻辑
- **依赖：** 4.4.1
- **验证：** `uv run pytest tests/test_scp02.py -v` 通过

---

## Phase 5 - 测试与文档（预计 30 分钟）

### 5.1 协议测试

**任务 5.1.1** 编写协议一致性测试
- **文件：** `tests/test_protocol.py`
- **内容：** 测试所有消息类型的序列化/反序列化
- **依赖：** 2.2
- **验证：** 测试通过

### 5.2 会话测试

**任务 5.2.1** 编写会话管理测试
- **文件：** `tests/test_session.py`
- **内容：** 测试创建、读取、更新、删除、TTL 清理
- **依赖：** 2.3
- **验证：** 测试通过

### 5.3 脱敏测试

**任务 5.3.1** 编写脱敏测试
- **文件：** `tests/test_security.py`
- **内容：** 验证密钥、PIN 不出现在输出中
- **依赖：** 2.4
- **验证：** 测试通过

---

## 依赖关系图

```
Phase 1 (基础设施)
    │
    ├── 1.1.1 ──────┬─────────────────┐
    │               │                 │
    ▼               ▼                 ▼
Phase 2.1 (SDK 配置)              Phase 3.1, 4.1 (Skill 配置)
    │
    ├── 2.2 (协议模型) ────┬──────────────────────┐
    │                      │                      │
    ▼                      ▼                      ▼
2.3 (会话管理)       2.4 (抽象基类)         5.1 (协议测试)
    │                      │
    ▼                      ▼
2.5 (简单 APDU)      2.6 (SDK 导出)
    │                      │
    └──────────┬───────────┘
               │
               ▼
          Phase 3.2 (read-iccid 实现)
               │
               ▼
          Phase 4.2-4.5 (scp02 实现)
               │
               ▼
          Phase 5.2-5.3 (会话、脱敏测试)
```

---

## 执行建议

1. **严格顺序执行**：每个任务依赖前序任务，不可跳过
2. **每任务验证**：完成每个任务后立即执行验证步骤
3. **增量提交**：每完成一个 Phase，执行 `git commit`
4. **遇到问题回退**：如果验证失败，修复后再继续下一个任务

---

## 验收标准

- [ ] `uv sync` 成功安装所有依赖
- [ ] `uv run pytest` 所有测试通过
- [ ] `python -c "from smartcard_skill_sdk import Skill"` 导入成功
- [ ] read-iccid Skill 可启动并响应 `skill.init`
- [ ] scp02 Skill 可完成完整状态机流程
- [ ] 会话文件正确写入 `.sessions/` 目录
- [ ] 敏感信息未出现在 stdout 或日志中
