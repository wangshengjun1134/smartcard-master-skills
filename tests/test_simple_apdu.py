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
