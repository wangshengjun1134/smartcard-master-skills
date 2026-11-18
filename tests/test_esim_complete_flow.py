"""eSIM IoT Profile Download 完整流程测试

模拟完整的卡片交互流程，验证 APDU 生成和响应处理。
"""

import pytest
import tempfile
import os
from esim_iot_profile_download.skill import EsimIotProfileDownloadSkill
from esim_iot_profile_download.state_machine import EsimState
from esim_iot_profile_download.apdu_builder import ApduBuilder
from smartcard_skill_sdk.base import SkillContext, OutputCollector
from smartcard_skill_sdk.session_store import SessionStore, SkillSession
from smartcard_skill_sdk.protocol import ActionResult, ActionResultStatus, ActionType


class MockCardResponses:
    """模拟卡片响应数据"""
    
    # ATR (复位响应)
    ATR = "3B9F96801FC38031E073FE21135780290000"
    
    # SELECT MF 响应 (SW=9000)
    SELECT_MF_RESPONSE = {"response": "", "sw": "9000"}
    
    # TERMINAL CAPABILITY 响应
    TERMINAL_CAPABILITY_RESPONSE = {"response": "", "sw": "9000"}
    
    # TERMINAL PROFILE 响应
    TERMINAL_PROFILE_RESPONSE = {"response": "", "sw": "9000"}
    
    # STATUS 响应 (简化)
    STATUS_RESPONSE = {"response": "0000000000000000", "sw": "9000"}
    
    # MANAGE CHANNEL 响应 (打开通道 1)
    MANAGE_CHANNEL_RESPONSE = {"response": "01", "sw": "9000"}
    
    # SELECT ISD-R 响应
    SELECT_ISDR_RESPONSE = {"response": "", "sw": "9000"}
    
    # GetEuiccInfo1 响应 (BF20)
    # 包含 SVN、verificationCiPkIds、signingCiPkIds
    GET_EUICC_INFO_RESPONSE = {
        "response": "BF20208203322E30890A040801020304050607080A04080102030405060709",
        "sw": "9000"
    }
    
    # GetEuiccChallenge 响应 (BF2E)
    # 包含 16 字节挑战值
    GET_EUICC_CHALLENGE_RESPONSE = {
        "response": "BF2E138010" + "0102030405060708090A0B0C0D0E0F10",
        "sw": "9000"
    }
    
    # AuthenticateServer 响应 (BF38)
    # 简化版本，实际应包含 serverSigned2 等
    AUTHENTICATE_SERVER_RESPONSE = {
        "response": "BF3800",  # 空响应占位
        "sw": "9000"
    }
    
    # PrepareDownload 响应 (BF21)
    # transactionId + 65 字节 euiccOtpk（P-256 生成元）
    _GX = "6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296"
    _GY = "4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5"
    PREPARE_DOWNLOAD_RESPONSE = {
        "response": "BF215BA05930558010" + "0102030405060708090A0B0C0D0E0F10"
                    + "5F4941" + "04" + _GX + _GY,
        "sw": "9000"
    }
    
    # LoadProfilePackage 响应
    LOAD_PROFILE_PACKAGE_RESPONSE = {"response": "", "sw": "9000"}
    
    # GetProfilesInfo 响应 (BF2D)
    # 包含 profileState (9F70)
    GET_PROFILES_INFO_RESPONSE_ENABLED = {
        "response": "BF2D0A9F700101",  # profileState = ENABLED (1)
        "sw": "9000"
    }
    
    GET_PROFILES_INFO_RESPONSE_DISABLED = {
        "response": "BF2D0A9F700100",  # profileState = DISABLED (0)
        "sw": "9000"
    }
    
    # AddInitialEim 响应（addInitialEimOk = A0）
    ADD_INITIAL_EIM_RESPONSE = {"response": "BF5704A0020500", "sw": "9000"}

    # LoadEuiccPackage 响应（enableResult [3] = 0）
    ENABLE_PSMO_RESPONSE = {
        "response": "BF515DA05B301680087465737465696D318101028302020C30038301005F3740" + "00" * 64,
        "sw": "9000"
    }


def drain_pending_apdus(skill, ctx, store, session, action_id: str = "esim.continue"):
    """把分块 APDU 剩余的块用空 9000 响应逐块推进，直到状态发生变化"""
    result = None
    initial_state = session.data.get("state")
    for _ in range(64):
        if session.data.get("state") != initial_state:
            break
        result = skill.handle_action_result(ctx, ActionResult(
            action_id=action_id,
            type="APDU_RESULT",
            status=ActionResultStatus.OK,
            data={"response": "", "sw": "9000"}
        ), session)
        store.save(session, "esim.iot-profile-download")
    return result


@pytest.fixture
def test_env():
    tmpdir = tempfile.mkdtemp()
    store = SessionStore(tmpdir)
    ctx = SkillContext(
        skill_id="esim.iot-profile-download",
        sessions=store,
        output=OutputCollector()
    )
    skill = EsimIotProfileDownloadSkill()
    
    yield skill, ctx, store
    
    # 清理
    import shutil
    shutil.rmtree(tmpdir, ignore_errors=True)


def test_complete_flow_direct_mode(test_env):
    """测试直接模式的完整流程"""
    skill, ctx, store = test_env
    
    # 初始化参数
    params = {
        "operation": "install_and_enable",
        "mode": "direct",  # 直接模式
        "eid": "89049032123451234512345678901235",
        "smdp_address": "test.example.com",
        "matching_id": "ABC12345",
        "iccid": "8929901012345678905",
        "profile_id": "A0000005591010FFFFFFFF8900001000",
        "tac": "00000000"
    }
    
    # 1. 初始化
    init_result = skill.init(ctx, params)
    assert "sessionId" in init_result
    session_id = init_result["sessionId"]
    
    # 2. 加载会话
    session = store.load(session_id)
    assert session is not None
    
    # 3. 启动 -> 冷复位
    result = skill.start(ctx, session)
    assert result.status.value == "CONTINUE"
    assert result.next_action.type == ActionType.RESET_CARD
    assert session.data["state"] == EsimState.WAIT_RESET
    
    # 4. 冷复位完成 -> SELECT MF
    reset_result = ActionResult(
        action_id="esim.reset-card",
        type="RESET_CARD_RESULT",
        status=ActionResultStatus.OK,
        data={"atr": MockCardResponses.ATR}
    )
    result = skill.handle_action_result(ctx, reset_result, session)
    store.save(session, "esim.iot-profile-download")  # 模拟 main.py 的保存行为
    assert session.data["state"] == EsimState.WAIT_SELECT_MF
    assert result.next_action.payload["apdu"] == ApduBuilder.select_mf()
    
    # 5. SELECT MF 完成 -> TERMINAL CAPABILITY
    mf_result = ActionResult(
        action_id="esim.select-mf",
        type="APDU_RESULT",
        status=ActionResultStatus.OK,
        data=MockCardResponses.SELECT_MF_RESPONSE
    )
    result = skill.handle_action_result(ctx, mf_result, session)
    store.save(session, "esim.iot-profile-download")
    assert session.data["state"] == EsimState.WAIT_TERMINAL_CAPABILITY
    
    # 6. TERMINAL CAPABILITY 完成 -> TERMINAL PROFILE
    tc_result = ActionResult(
        action_id="esim.terminal-capability",
        type="APDU_RESULT",
        status=ActionResultStatus.OK,
        data=MockCardResponses.TERMINAL_CAPABILITY_RESPONSE
    )
    result = skill.handle_action_result(ctx, tc_result, session)
    store.save(session, "esim.iot-profile-download")
    assert session.data["state"] == EsimState.WAIT_TERMINAL_PROFILE
    
    # 7. TERMINAL PROFILE 完成 -> STATUS
    tp_result = ActionResult(
        action_id="esim.terminal-profile",
        type="APDU_RESULT",
        status=ActionResultStatus.OK,
        data=MockCardResponses.TERMINAL_PROFILE_RESPONSE
    )
    result = skill.handle_action_result(ctx, tp_result, session)
    store.save(session, "esim.iot-profile-download")
    assert session.data["state"] == EsimState.WAIT_STATUS
    
    # 8. STATUS 完成 -> MANAGE CHANNEL
    status_result = ActionResult(
        action_id="esim.status",
        type="APDU_RESULT",
        status=ActionResultStatus.OK,
        data=MockCardResponses.STATUS_RESPONSE
    )
    result = skill.handle_action_result(ctx, status_result, session)
    store.save(session, "esim.iot-profile-download")
    assert session.data["state"] == EsimState.WAIT_MANAGE_CHANNEL
    
    # 9. MANAGE CHANNEL 完成 -> SELECT ISD-R
    mc_result = ActionResult(
        action_id="esim.manage-channel",
        type="APDU_RESULT",
        status=ActionResultStatus.OK,
        data=MockCardResponses.MANAGE_CHANNEL_RESPONSE
    )
    result = skill.handle_action_result(ctx, mc_result, session)
    store.save(session, "esim.iot-profile-download")
    assert session.data["state"] == EsimState.WAIT_SELECT_ISDR
    assert session.data["channel"] == 1
    
    # 10. SELECT ISD-R 完成 -> EUICC MEMORY RESET (清理阶段)
    isdr_result = ActionResult(
        action_id="esim.select-isdr",
        type="APDU_RESULT",
        status=ActionResultStatus.OK,
        data=MockCardResponses.SELECT_ISDR_RESPONSE
    )
    result = skill.handle_action_result(ctx, isdr_result, session)
    store.save(session, "esim.iot-profile-download")
    assert session.data["state"] == EsimState.WAIT_EUICC_MEMORY_RESET
    
    # 11. EUICC MEMORY RESET 完成 -> LIST NOTIFICATION
    reset_result = ActionResult(
        action_id="esim.euicc-memory-reset",
        type="APDU_RESULT",
        status=ActionResultStatus.OK,
        data={"response": "", "sw": "9000"}
    )
    result = skill.handle_action_result(ctx, reset_result, session)
    store.save(session, "esim.iot-profile-download")
    assert session.data["state"] == EsimState.WAIT_LIST_NOTIFICATION
    
    # 12. LIST NOTIFICATION 完成 -> REMOVE NOTIFICATION
    list_result = ActionResult(
        action_id="esim.list-notification",
        type="APDU_RESULT",
        status=ActionResultStatus.OK,
        data={"response": "", "sw": "9000"}  # 无通知
    )
    result = skill.handle_action_result(ctx, list_result, session)
    store.save(session, "esim.iot-profile-download")
    # 无通知时直接进入安装阶段，顺序与参考实现一致：先 GetEuiccChallenge(BF2E)
    assert session.data["state"] == EsimState.WAIT_GET_EUICC_CHALLENGE

    # 12. GET EUICC CHALLENGE 完成 -> GET EUICC INFO
    challenge_result = ActionResult(
        action_id="esim.get-euicc-challenge",
        type="APDU_RESULT",
        status=ActionResultStatus.OK,
        data=MockCardResponses.GET_EUICC_CHALLENGE_RESPONSE
    )
    result = skill.handle_action_result(ctx, challenge_result, session)
    store.save(session, "esim.iot-profile-download")
    assert session.data["state"] == EsimState.WAIT_GET_EUICC_INFO
    assert "challenge" in session.data

    # 13. GET EUICC INFO 完成 -> AUTHENTICATE SERVER
    euicc_info_result = ActionResult(
        action_id="esim.get-euicc-info",
        type="APDU_RESULT",
        status=ActionResultStatus.OK,
        data=MockCardResponses.GET_EUICC_INFO_RESPONSE
    )
    result = skill.handle_action_result(ctx, euicc_info_result, session)
    store.save(session, "esim.iot-profile-download")
    assert session.data["state"] == EsimState.WAIT_AUTHENTICATE_SERVER
    
    # 13. AUTHENTICATE SERVER 完成 -> PREPARE DOWNLOAD（BF38 分块，需逐块推进）
    auth_result = ActionResult(
        action_id="esim.authenticate-server",
        type="APDU_RESULT",
        status=ActionResultStatus.OK,
        data=MockCardResponses.AUTHENTICATE_SERVER_RESPONSE
    )
    result = skill.handle_action_result(ctx, auth_result, session)
    store.save(session, "esim.iot-profile-download")
    drain_pending_apdus(skill, ctx, store, session)
    assert session.data["state"] == EsimState.WAIT_PREPARE_DOWNLOAD

    # 14. PREPARE DOWNLOAD 完成 -> LOAD PROFILE PACKAGE（BF21 分块）
    pd_result = ActionResult(
        action_id="esim.prepare-download",
        type="APDU_RESULT",
        status=ActionResultStatus.OK,
        data=MockCardResponses.PREPARE_DOWNLOAD_RESPONSE
    )
    result = skill.handle_action_result(ctx, pd_result, session)
    store.save(session, "esim.iot-profile-download")
    drain_pending_apdus(skill, ctx, store, session)
    assert session.data["state"] == EsimState.WAIT_LOAD_PROFILE_PACKAGE
    
    # 15. LOAD PROFILE PACKAGE 完成 -> POST INSTALL RESET
    lpp_result = ActionResult(
        action_id="esim.load-profile-package",
        type="APDU_RESULT",
        status=ActionResultStatus.OK,
        data=MockCardResponses.LOAD_PROFILE_PACKAGE_RESPONSE
    )
    result = skill.handle_action_result(ctx, lpp_result, session)
    store.save(session, "esim.iot-profile-download")
    assert session.data["state"] == EsimState.WAIT_POST_INSTALL_RESET
    
    # 16. POST INSTALL RESET -> IC1
    post_reset_result = ActionResult(
        action_id="esim.post-install-reset",
        type="RESET_CARD_RESULT",
        status=ActionResultStatus.OK,
        data={"atr": MockCardResponses.ATR}
    )
    result = skill.handle_action_result(ctx, post_reset_result, session)
    store.save(session, "esim.iot-profile-download")
    assert session.data["state"] == EsimState.WAIT_POST_INSTALL_IC1
    
    # 17. IC1（打开通道）-> SELECT ISD-R
    ic1_result = ActionResult(
        action_id="esim.post-install-ic1",
        type="APDU_RESULT",
        status=ActionResultStatus.OK,
        data={"response": "01", "sw": "9000"}
    )
    result = skill.handle_action_result(ctx, ic1_result, session)
    store.save(session, "esim.iot-profile-download")
    assert session.data["state"] == EsimState.WAIT_POST_INSTALL_SELECT_ISDR
    
    # 19. SELECT ISD-R -> GET PROFILES INFO
    isdr2_result = ActionResult(
        action_id="esim.post-install-select-isdr",
        type="APDU_RESULT",
        status=ActionResultStatus.OK,
        data=MockCardResponses.SELECT_ISDR_RESPONSE
    )
    result = skill.handle_action_result(ctx, isdr2_result, session)
    store.save(session, "esim.iot-profile-download")
    assert session.data["state"] == EsimState.WAIT_GET_PROFILES_INFO
    
    # 20. GET PROFILES INFO -> SUCCESS (直接模式)
    profiles_result = ActionResult(
        action_id="esim.get-profiles-info",
        type="APDU_RESULT",
        status=ActionResultStatus.OK,
        data=MockCardResponses.GET_PROFILES_INFO_RESPONSE_ENABLED
    )
    result = skill.handle_action_result(ctx, profiles_result, session)
    store.save(session, "esim.iot-profile-download")
    
    assert result.status.value == "SUCCESS"
    assert result.data["profile_state"] == "ENABLED"
    assert result.data["verified"] == True


def test_complete_flow_indirect_mode(test_env):
    """测试间接模式的完整流程（包含 eIM 启用）"""
    skill, ctx, store = test_env
    
    # 初始化参数
    params = {
        "operation": "install_and_enable",
        "mode": "indirect",  # 间接模式
        "eid": "89049032123451234512345678901235",
        "smdp_address": "test.example.com",
        "matching_id": "ABC12345",
        "iccid": "8929901012345678905",
        "profile_id": "A0000005591010FFFFFFFF8900001000",
        "eim_id": "test-eim-001",
        "tac": "00000000"
    }
    
    # 初始化并启动
    init_result = skill.init(ctx, params)
    session_id = init_result["sessionId"]
    session = store.load(session_id)
    
    # 模拟已经完成了 Profile 安装，直接进入后安装阶段
    session.data["state"] = EsimState.WAIT_POST_INSTALL_RESET
    session.data["challenge"] = "0102030405060708090A0B0C0D0E0F10"
    session.data["euicc_ci_pk_id"] = "0102030405060708"
    session.data["profiles_info_response"] = MockCardResponses.GET_PROFILES_INFO_RESPONSE_DISABLED["response"]
    
    # 模拟到达 GET PROFILES INFO 状态
    session.data["state"] = EsimState.WAIT_GET_PROFILES_INFO
    
    # GET PROFILES INFO -> ENABLE PSMO（eIM 已在下载前配置）
    profiles_result = ActionResult(
        action_id="esim.get-profiles-info",
        type="APDU_RESULT",
        status=ActionResultStatus.OK,
        data=MockCardResponses.GET_PROFILES_INFO_RESPONSE_DISABLED
    )
    result = skill.handle_action_result(ctx, profiles_result, session)
    assert session.data["state"] == EsimState.WAIT_ENABLE_PSMO

    # ENABLE PSMO -> POST ENABLE RESET
    psmo_result = ActionResult(
        action_id="esim.enable-psmo",
        type="APDU_RESULT",
        status=ActionResultStatus.OK,
        data=MockCardResponses.ENABLE_PSMO_RESPONSE
    )
    result = skill.handle_action_result(ctx, psmo_result, session)
    assert session.data["state"] == EsimState.WAIT_POST_ENABLE_RESET
    
    # POST ENABLE RESET -> 重新打开逻辑通道
    post_reset_result = ActionResult(
        action_id="esim.post-enable-reset",
        type="RESET_CARD_RESULT",
        status=ActionResultStatus.OK,
        data={"atr": MockCardResponses.ATR}
    )
    result = skill.handle_action_result(ctx, post_reset_result, session)
    assert session.data["state"] == EsimState.WAIT_POST_ENABLE_IC

    # 打开通道 -> SELECT ISD-R
    ic_result = ActionResult(
        action_id="esim.post-enable-ic",
        type="APDU_RESULT",
        status=ActionResultStatus.OK,
        data={"response": "01", "sw": "9000"}
    )
    result = skill.handle_action_result(ctx, ic_result, session)
    assert session.data["state"] == EsimState.WAIT_POST_ENABLE_SELECT_ISDR
    
    # SELECT ISD-R -> VERIFY PROFILE STATE
    isdr_result = ActionResult(
        action_id="esim.post-enable-select-isdr",
        type="APDU_RESULT",
        status=ActionResultStatus.OK,
        data=MockCardResponses.SELECT_ISDR_RESPONSE
    )
    result = skill.handle_action_result(ctx, isdr_result, session)
    assert session.data["state"] == EsimState.WAIT_VERIFY_PROFILE_STATE
    
    # VERIFY PROFILE STATE -> SUCCESS
    verify_result = ActionResult(
        action_id="esim.verify-profile-state",
        type="APDU_RESULT",
        status=ActionResultStatus.OK,
        data=MockCardResponses.GET_PROFILES_INFO_RESPONSE_ENABLED
    )
    result = skill.handle_action_result(ctx, verify_result, session)
    assert result.status.value == "SUCCESS"
    assert result.data["profile_state"] == "ENABLED"


def test_apdu_generation():
    """测试 APDU 生成的正确性"""
    # SELECT MF (P2=04 返回 FCI)
    assert ApduBuilder.select_mf() == "00A40004023F00"

    # SELECT ISD-R
    isdr_apdu = ApduBuilder.select_isdr()
    assert "A0000005591010FFFFFFFF8900000100" in isdr_apdu

    # GetEuiccInfo1 (ES10 命令格式)
    assert ApduBuilder.get_euicc_info1() == "80E2910003BF2000"

    # GetEuiccChallenge (ES10 命令格式)
    assert ApduBuilder.get_euicc_challenge() == "80E2910003BF2E00"

    # GetProfilesInfo (ES10 命令格式)
    assert ApduBuilder.get_profiles_info() == "80E2910003BF2D00"

    # AddInitialEim / LoadEuiccPackage 均为 ES10 命令（INS=E2, P1=91）
    eim_apdu = ApduBuilder.add_initial_eim("BF5700")
    assert eim_apdu == "80E2910003BF5700"

    psmo_apdu = ApduBuilder.enable_psmo("BF5100")
    assert psmo_apdu == "80E2910003BF5100"


def test_error_handling(test_env):
    """测试错误处理"""
    skill, ctx, store = test_env
    
    params = {
        "operation": "install_and_enable",
        "mode": "direct",
        "eid": "89049032123451234512345678901235",
        "smdp_address": "test.example.com",
        "matching_id": "ABC12345",
        "iccid": "8929901012345678905",
        "profile_id": "A0000005591010FFFFFFFF8900001000"
    }
    
    init_result = skill.init(ctx, params)
    session_id = init_result["sessionId"]
    session = store.load(session_id)
    
    # 启动
    skill.start(ctx, session)
    
    # 模拟 APDU 执行失败
    fail_result = ActionResult(
        action_id="esim.select-mf",
        type="APDU_RESULT",
        status=ActionResultStatus.ERROR,
        data={}
    )
    result = skill.handle_action_result(ctx, fail_result, session)
    assert result.status.value == "FAILED"
    assert result.error.code == "APDU_ERROR"
    
    # 模拟卡片返回错误状态
    session.data["state"] = EsimState.WAIT_SELECT_MF
    error_sw_result = ActionResult(
        action_id="esim.select-mf",
        type="APDU_RESULT",
        status=ActionResultStatus.OK,
        data={"response": "", "sw": "6A82"}  # 文件未找到
    )
    result = skill.handle_action_result(ctx, error_sw_result, session)
    assert result.status.value == "FAILED"
    assert result.error.code == "APDU_STATUS_ERROR"
