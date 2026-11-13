import pytest
import tempfile
from read_iccid_skill.skill import ReadIccidSkill, ReadIccidState
from smartcard_skill_sdk.base import SkillContext, OutputCollector
from smartcard_skill_sdk.session_store import SessionStore, SkillSession
from smartcard_skill_sdk.protocol import ActionResult, ActionResultStatus, ActionType

def test_read_iccid_initial_state():
    """测试初始状态"""
    with tempfile.TemporaryDirectory() as tmpdir:
        store = SessionStore(tmpdir)
        ctx = SkillContext(skill_id="read.iccid", sessions=store, output=OutputCollector())
        skill = ReadIccidSkill()
        
        session = store.create({}, "read.iccid")
        result = skill.start(ctx, session)
        
        assert result.status.value == "CONTINUE"
        assert result.next_action.action_id == "read.iccid.select-mf"
        assert result.next_action.payload["apdu"] == "00A40000023F00"
        assert session.data["state"] == ReadIccidState.WAIT_SELECT_MF

def test_read_iccid_after_select_mf():
    """测试 SELECT MF 成功后的状态转换"""
    with tempfile.TemporaryDirectory() as tmpdir:
        store = SessionStore(tmpdir)
        ctx = SkillContext(skill_id="read.iccid", sessions=store, output=OutputCollector())
        skill = ReadIccidSkill()
        
        session = store.create({}, "read.iccid")
        session.data["state"] = ReadIccidState.WAIT_SELECT_MF
        
        # 模拟 SELECT MF 成功
        action_result = ActionResult(
            action_id="read.iccid.select-mf",
            type="APDU_RESULT",
            status=ActionResultStatus.OK,
            data={"response": "", "sw": "9000"}
        )
        
        result = skill.handle_action_result(ctx, action_result, session)
        
        assert result.status.value == "CONTINUE"
        assert result.next_action.action_id == "read.iccid.select-iccid"
        assert result.next_action.payload["apdu"] == "00A40000022FE2"
        assert session.data["state"] == ReadIccidState.WAIT_SELECT_ICCID

def test_read_iccid_after_select_iccid():
    """测试 SELECT EF_ICCID 成功后的状态转换"""
    with tempfile.TemporaryDirectory() as tmpdir:
        store = SessionStore(tmpdir)
        ctx = SkillContext(skill_id="read.iccid", sessions=store, output=OutputCollector())
        skill = ReadIccidSkill()
        
        session = store.create({}, "read.iccid")
        session.data["state"] = ReadIccidState.WAIT_SELECT_ICCID
        
        # 模拟 SELECT EF_ICCID 成功
        action_result = ActionResult(
            action_id="read.iccid.select-iccid",
            type="APDU_RESULT",
            status=ActionResultStatus.OK,
            data={"response": "", "sw": "9000"}
        )
        
        result = skill.handle_action_result(ctx, action_result, session)
        
        assert result.status.value == "CONTINUE"
        assert result.next_action.action_id == "read.iccid.read-binary"
        assert result.next_action.payload["apdu"] == "00B000000A"
        assert session.data["state"] == ReadIccidState.WAIT_READ_BINARY

def test_read_iccid_complete():
    """测试完整流程：读取 ICCID 数据并解析"""
    with tempfile.TemporaryDirectory() as tmpdir:
        store = SessionStore(tmpdir)
        ctx = SkillContext(skill_id="read.iccid", sessions=store, output=OutputCollector())
        skill = ReadIccidSkill()
        
        session = store.create({}, "read.iccid")
        session.data["state"] = ReadIccidState.WAIT_READ_BINARY
        
        # 模拟 READ BINARY 成功
        # ICCID: 8986001234567890123 (BCD 编码)
        # Hex: 98 68 10 32 54 76 98 10 32 F3
        action_result = ActionResult(
            action_id="read.iccid.read-binary",
            type="APDU_RESULT",
            status=ActionResultStatus.OK,
            data={"response": "986810325476981032F3", "sw": "9000"}
        )
        
        result = skill.handle_action_result(ctx, action_result, session)
        
        assert result.status.value == "SUCCESS"
        assert "iccid" in result.data
        # 解析后的 ICCID 应该是数字字符串
        iccid = result.data["iccid"]
        assert iccid.isdigit()
        assert len(iccid) > 0

def test_read_iccid_parse_bcd():
    """测试 BCD 编码解析"""
    skill = ReadIccidSkill()
    
    # 测试标准 ICCID: 8986001234567890123
    # BCD 编码: 98 68 10 32 54 76 98 10 32 F3
    hex_data = "986810325476981032F3"
    iccid = skill._parse_iccid(hex_data)
    
    # 解析结果应该是数字
    assert iccid.isdigit()
    # 应该以 89 开头（电信行业标识）
    assert iccid.startswith("89")

def test_read_iccid_error_handling():
    """测试错误处理"""
    with tempfile.TemporaryDirectory() as tmpdir:
        store = SessionStore(tmpdir)
        ctx = SkillContext(skill_id="read.iccid", sessions=store, output=OutputCollector())
        skill = ReadIccidSkill()
        
        session = store.create({}, "read.iccid")
        session.data["state"] = ReadIccidState.WAIT_SELECT_MF
        
        # 模拟 APDU 执行失败
        action_result = ActionResult(
            action_id="read.iccid.select-mf",
            type="APDU_RESULT",
            status=ActionResultStatus.ERROR,
            data={}
        )
        
        result = skill.handle_action_result(ctx, action_result, session)
        
        assert result.status.value == "FAILED"
        assert session.data["state"] == ReadIccidState.FAILED

def test_read_iccid_manifest():
    """测试 Manifest"""
    skill = ReadIccidSkill()
    manifest = skill.get_manifest()
    
    assert manifest["skillId"] == "read.iccid"
    assert "ICCID" in manifest["description"]
    assert manifest["requiresReader"] == True
