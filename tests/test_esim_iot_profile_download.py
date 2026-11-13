"""eSIM IoT Profile Download Skill 测试"""

import pytest
import tempfile
from esim_iot_profile_download.skill import EsimIotProfileDownloadSkill
from esim_iot_profile_download.state_machine import EsimState
from esim_iot_profile_download.apdu_builder import ApduBuilder, ResponseParser
from smartcard_skill_sdk.base import SkillContext, OutputCollector
from smartcard_skill_sdk.session_store import SessionStore, SkillSession
from smartcard_skill_sdk.protocol import ActionResult, ActionResultStatus, ActionType


def test_skill_manifest():
    """测试 Skill Manifest"""
    skill = EsimIotProfileDownloadSkill()
    manifest = skill.get_manifest()
    
    assert manifest["skillId"] == "esim.iot-profile-download"
    assert manifest["requiresReader"] == True


def test_skill_init():
    """测试 Skill 初始化"""
    with tempfile.TemporaryDirectory() as tmpdir:
        store = SessionStore(tmpdir)
        ctx = SkillContext(skill_id="esim.iot-profile-download", sessions=store, output=OutputCollector())
        skill = EsimIotProfileDownloadSkill()
        
        params = {
            "operation": "install_and_enable",
            "eid": "89049032123451234512345678901235",
            "smdp_address": "test.example.com",
            "matching_id": "ABC12345",
            "iccid": "8929901012345678905",
            "profile_id": "A0000005591010FFFFFFFF8900001000",
            "mode": "indirect"
        }
        
        result = skill.init(ctx, params)
        
        assert "sessionId" in result
        assert result["status"] == "INITIALIZED"


def test_skill_start():
    """测试 Skill 启动（第一步应该是冷复位）"""
    with tempfile.TemporaryDirectory() as tmpdir:
        store = SessionStore(tmpdir)
        ctx = SkillContext(skill_id="esim.iot-profile-download", sessions=store, output=OutputCollector())
        skill = EsimIotProfileDownloadSkill()
        
        session = store.create({
            "operation": "install_and_enable",
            "eid": "89049032123451234512345678901235",
            "mode": "indirect"
        }, "esim.iot-profile-download")
        
        result = skill.start(ctx, session)
        
        assert result.status.value == "CONTINUE"
        assert result.next_action.type == ActionType.RESET_CARD
        assert session.data["state"] == EsimState.WAIT_RESET


def test_state_transitions():
    """测试状态转换"""
    with tempfile.TemporaryDirectory() as tmpdir:
        store = SessionStore(tmpdir)
        ctx = SkillContext(skill_id="esim.iot-profile-download", sessions=store, output=OutputCollector())
        skill = EsimIotProfileDownloadSkill()
        
        session = store.create({"mode": "indirect"}, "esim.iot-profile-download")
        
        # 启动 -> 冷复位
        result = skill.start(ctx, session)
        assert session.data["state"] == EsimState.WAIT_RESET
        
        # 冷复位完成 -> SELECT MF
        reset_result = ActionResult(
            action_id="esim.reset-card",
            type="RESET_CARD_RESULT",
            status=ActionResultStatus.OK,
            data={"atr": "3B9F96801FC38031E073FE21135780290000"}
        )
        result = skill.handle_action_result(ctx, reset_result, session)
        assert session.data["state"] == EsimState.WAIT_SELECT_MF
        assert result.next_action.payload["apdu"] == "00A40004023F00"


def test_apdu_builder_select_mf():
    """测试 SELECT MF APDU"""
    apdu = ApduBuilder.select_mf()
    assert apdu == "00A40004023F00"


def test_apdu_builder_get_euicc_info():
    """测试 GetEuiccInfo1 APDU"""
    apdu = ApduBuilder.get_euicc_info1()
    assert apdu == "80E2910003BF2000"


def test_apdu_builder_get_profiles_info():
    """测试 GetProfilesInfo APDU"""
    apdu = ApduBuilder.get_profiles_info()
    assert apdu == "80E2910003BF2D00"


def test_apdu_builder_euicc_memory_reset():
    """测试 EuiccMemoryReset APDU"""
    apdu = ApduBuilder.euicc_memory_reset()
    # 80 E2 91 00 07 BF3404820205E0 00
    assert apdu.startswith("80E29100")
    assert "BF34" in apdu


def test_apdu_builder_list_notification():
    """测试 ListNotification APDU"""
    apdu = ApduBuilder.list_notification()
    # 80 E2 91 00 03 BF2800 00
    assert apdu.startswith("80E29100")
    assert "BF28" in apdu


def test_apdu_builder_remove_notification():
    """测试 RemoveNotification APDU"""
    apdu = ApduBuilder.remove_notification("0001")
    # 80 E2 91 00 07 BF300480020001 00
    assert apdu.startswith("80E29100")
    assert "BF30" in apdu
    assert "0001" in apdu


def test_apdu_builder_fetch():
    """测试 FETCH APDU"""
    apdu = ApduBuilder.fetch(16)
    # 80 12 00 00 10
    assert apdu == "8012000010"


def test_response_parser_sw_9000():
    """测试 SW 9000 解析"""
    result = ResponseParser.parse_sw("9000")
    assert result["status"] == "OK"


def test_response_parser_sw_61xx():
    """测试 SW 61XX 解析（更多数据）"""
    result = ResponseParser.parse_sw("6110")
    assert result["status"] == "MORE_DATA"
    assert result["length"] == 16


def test_response_parser_sw_91xx():
    """测试 SW 91XX 解析（FETCH 需要）"""
    result = ResponseParser.parse_sw("9120")
    assert result["status"] == "FETCH_REQUIRED"
    assert result["length"] == 32


def test_response_parser_sw_error():
    """测试错误 SW 解析"""
    result = ResponseParser.parse_sw("6A82")
    assert result["status"] == "ERROR"
    assert "文件未找到" in result["message"]
