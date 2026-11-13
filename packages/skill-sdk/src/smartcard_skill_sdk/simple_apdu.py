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
