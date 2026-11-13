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
