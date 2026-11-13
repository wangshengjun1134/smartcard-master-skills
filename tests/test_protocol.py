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
