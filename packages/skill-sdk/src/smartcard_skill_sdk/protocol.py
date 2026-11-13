from enum import Enum
from pydantic import BaseModel, ConfigDict
from typing import Any


def to_camel(s: str) -> str:
    """将 snake_case 转换为 camelCase"""
    parts = s.split("_")
    return parts[0] + "".join(word.capitalize() for word in parts[1:])


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
    model_config = ConfigDict(alias_generator=to_camel, populate_by_name=True)
    
    action_id: str
    type: ActionType
    name: str
    description: str
    sensitive: bool = False
    timeout_ms: int = 5000
    payload: dict[str, Any] = {}


class ActionResult(BaseModel):
    model_config = ConfigDict(alias_generator=to_camel, populate_by_name=True)
    
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
    model_config = ConfigDict(alias_generator=to_camel, populate_by_name=True)
    
    request_id: str
    prompt: str
    input_schema: dict[str, Any]


class Error(BaseModel):
    code: str
    message: str
    retryable: bool = False
    details: dict[str, Any] | None = None


class SkillResult(BaseModel):
    model_config = ConfigDict(alias_generator=to_camel, populate_by_name=True)
    
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
