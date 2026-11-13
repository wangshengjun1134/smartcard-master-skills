import pytest
import tempfile
from smartcard_skill_sdk.base import Skill, SkillContext, OutputCollector
from smartcard_skill_sdk.session_store import SessionStore, SkillSession
from smartcard_skill_sdk.protocol import SkillResult, ActionResult, ActionResultStatus, Action, ActionType, SkillStatus

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
