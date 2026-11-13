from abc import ABC, abstractmethod
from dataclasses import dataclass
from .protocol import Output, SkillResult, ActionResult, SkillStatus
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
