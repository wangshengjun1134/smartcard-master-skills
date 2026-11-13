"""eSIM IoT Profile Download stdin/stdout 协议测试

通过 stdin/stdout JSON-RPC 协议完整测试 eSIM Profile 下载流程。
模拟真实的 Agent 调用方式。
"""

import pytest
import json
import tempfile
import subprocess
import sys
import os


class MockCardResponses:
    """模拟卡片响应数据"""
    
    ATR = "3B9F96801FC38031E073FE21135780290000"
    
    # 各步骤的模拟响应
    SELECT_MF = {"response": "", "sw": "9000"}
    TERMINAL_CAPABILITY = {"response": "", "sw": "9000"}
    TERMINAL_PROFILE = {"response": "", "sw": "9000"}
    STATUS = {"response": "0000000000000000", "sw": "9000"}
    MANAGE_CHANNEL = {"response": "01", "sw": "9000"}
    SELECT_ISDR = {"response": "", "sw": "9000"}
    
    # GetEuiccInfo1 响应 (BF20) - 包含 SVN 和 CI PK IDs
    GET_EUICC_INFO = {
        "response": "BF20208203322E30890A040801020304050607080A04080102030405060709",
        "sw": "9000"
    }
    
    # GetEuiccChallenge 响应 (BF2E) - 包含 16 字节挑战值
    GET_EUICC_CHALLENGE = {
        "response": "BF2E138010" + "0102030405060708090A0B0C0D0E0F10",
        "sw": "9000"
    }
    
    # AuthenticateServer 响应 (BF38)
    AUTHENTICATE_SERVER = {
        "response": "BF3800",
        "sw": "9000"
    }
    
    # PrepareDownload 响应 (BF21) - 包含 transactionId 和 euiccOtpk
    PREPARE_DOWNLOAD = {
        "response": "BF2130A0148010" + "0102030405060708090A0B0C0D0E0F10" + "5F4910" + "1112131415161718191A1B1C1D1E1F20",
        "sw": "9000"
    }
    
    LOAD_PROFILE_PACKAGE = {"response": "", "sw": "9000"}
    
    # GetProfilesInfo 响应 (BF2D) - profileState = ENABLED
    GET_PROFILES_INFO_ENABLED = {
        "response": "BF2D0A9F700101",
        "sw": "9000"
    }
    
    ADD_INITIAL_EIM = {"response": "", "sw": "9000"}
    ENABLE_PSMO = {"response": "", "sw": "9000"}


def send_request(proc, request):
    """发送 JSON-RPC 请求并读取响应"""
    proc.stdin.write(json.dumps(request) + "\n")
    proc.stdin.flush()
    response_line = proc.stdout.readline()
    if not response_line:
        stderr = proc.stderr.read()
        raise AssertionError(f"No response received. STDERR: {stderr}")
    return json.loads(response_line)


def test_stdin_stdout_direct_mode():
    """测试直接模式的完整流程（通过 stdin/stdout）"""
    project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    
    with tempfile.TemporaryDirectory() as session_dir:
        env = {**os.environ, "PYTHONPATH": project_root, "SKILL_SESSION_DIR": session_dir}
        
        proc = subprocess.Popen(
            [sys.executable, "-m", "esim_iot_profile_download.main"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            cwd=project_root,
            env=env
        )
        
        try:
            # 1. skill.init
            init_response = send_request(proc, {
                "jsonrpc": "2.0",
                "id": "req-1",
                "method": "skill.init",
                "params": {
                    "protocolVersion": "1.0",
                    "skillId": "esim.iot-profile-download",
                    "input": {
                        "operation": "install_and_enable",
                        "mode": "direct",
                        "eid": "89049032123451234512345678901235",
                        "smdp_address": "test.example.com",
                        "matching_id": "ABC12345",
                        "iccid": "8929901012345678905",
                        "profile_id": "A0000005591010FFFFFFFF8900001000",
                        "tac": "00000000"
                    },
                    "context": {"traceId": "trace-001", "mode": "interactive"}
                }
            })
            
            assert init_response["jsonrpc"] == "2.0"
            assert init_response["id"] == "req-1"
            assert "result" in init_response
            assert "sessionId" in init_response["result"]
            session_id = init_response["result"]["sessionId"]
            
            # 2. skill.start -> 应该返回 RESET_CARD Action
            start_response = send_request(proc, {
                "jsonrpc": "2.0",
                "id": "req-2",
                "method": "skill.start",
                "params": {
                    "sessionId": session_id,
                    "skillId": "esim.iot-profile-download",
                    "input": {}
                }
            })
            
            assert start_response["result"]["status"] == "CONTINUE"
            assert start_response["result"]["nextAction"]["type"] == "RESET_CARD"
            
            # 3. handleActionResult (RESET) -> SELECT MF
            reset_response = send_request(proc, {
                "jsonrpc": "2.0",
                "id": "req-3",
                "method": "skill.handleActionResult",
                "params": {
                    "sessionId": session_id,
                    "actionId": "esim.reset-card",
                    "result": {
                        "actionId": "esim.reset-card",
                        "type": "RESET_CARD_RESULT",
                        "status": "OK",
                        "data": {"atr": MockCardResponses.ATR},
                        "elapsedMs": 100
                    }
                }
            })
            
            assert reset_response["result"]["status"] == "CONTINUE"
            assert reset_response["result"]["nextAction"]["type"] == "APDU"
            assert reset_response["result"]["nextAction"]["payload"]["apdu"] == "00A40000023F00"
            
            # 4. handleActionResult (SELECT MF) -> TERMINAL CAPABILITY
            mf_response = send_request(proc, {
                "jsonrpc": "2.0",
                "id": "req-4",
                "method": "skill.handleActionResult",
                "params": {
                    "sessionId": session_id,
                    "actionId": "esim.select-mf",
                    "result": {
                        "actionId": "esim.select-mf",
                        "type": "APDU_RESULT",
                        "status": "OK",
                        "data": MockCardResponses.SELECT_MF,
                        "elapsedMs": 10
                    }
                }
            })
            
            assert mf_response["result"]["status"] == "CONTINUE"
            assert mf_response["result"]["nextAction"]["name"] == "设置终端能力"
            
            # 5. handleActionResult (TERMINAL CAPABILITY) -> TERMINAL PROFILE
            tc_response = send_request(proc, {
                "jsonrpc": "2.0",
                "id": "req-5",
                "method": "skill.handleActionResult",
                "params": {
                    "sessionId": session_id,
                    "actionId": "esim.terminal-capability",
                    "result": {
                        "actionId": "esim.terminal-capability",
                        "type": "APDU_RESULT",
                        "status": "OK",
                        "data": MockCardResponses.TERMINAL_CAPABILITY,
                        "elapsedMs": 10
                    }
                }
            })
            
            assert tc_response["result"]["status"] == "CONTINUE"
            
            # 6. handleActionResult (TERMINAL PROFILE) -> STATUS
            tp_response = send_request(proc, {
                "jsonrpc": "2.0",
                "id": "req-6",
                "method": "skill.handleActionResult",
                "params": {
                    "sessionId": session_id,
                    "actionId": "esim.terminal-profile",
                    "result": {
                        "actionId": "esim.terminal-profile",
                        "type": "APDU_RESULT",
                        "status": "OK",
                        "data": MockCardResponses.TERMINAL_PROFILE,
                        "elapsedMs": 10
                    }
                }
            })
            
            assert tp_response["result"]["status"] == "CONTINUE"
            
            # 7. handleActionResult (STATUS) -> MANAGE CHANNEL
            status_response = send_request(proc, {
                "jsonrpc": "2.0",
                "id": "req-7",
                "method": "skill.handleActionResult",
                "params": {
                    "sessionId": session_id,
                    "actionId": "esim.status",
                    "result": {
                        "actionId": "esim.status",
                        "type": "APDU_RESULT",
                        "status": "OK",
                        "data": MockCardResponses.STATUS,
                        "elapsedMs": 10
                    }
                }
            })
            
            assert status_response["result"]["status"] == "CONTINUE"
            
            # 8. handleActionResult (MANAGE CHANNEL) -> SELECT ISD-R
            mc_response = send_request(proc, {
                "jsonrpc": "2.0",
                "id": "req-8",
                "method": "skill.handleActionResult",
                "params": {
                    "sessionId": session_id,
                    "actionId": "esim.manage-channel",
                    "result": {
                        "actionId": "esim.manage-channel",
                        "type": "APDU_RESULT",
                        "status": "OK",
                        "data": MockCardResponses.MANAGE_CHANNEL,
                        "elapsedMs": 10
                    }
                }
            })
            
            assert mc_response["result"]["status"] == "CONTINUE"
            assert "ISD-R" in mc_response["result"]["nextAction"]["name"]
            
            # 9. handleActionResult (SELECT ISD-R) -> GET EUICC INFO
            isdr_response = send_request(proc, {
                "jsonrpc": "2.0",
                "id": "req-9",
                "method": "skill.handleActionResult",
                "params": {
                    "sessionId": session_id,
                    "actionId": "esim.select-isdr",
                    "result": {
                        "actionId": "esim.select-isdr",
                        "type": "APDU_RESULT",
                        "status": "OK",
                        "data": MockCardResponses.SELECT_ISDR,
                        "elapsedMs": 10
                    }
                }
            })
            
            assert isdr_response["result"]["status"] == "CONTINUE"
            assert "eUICC" in isdr_response["result"]["nextAction"]["name"]
            
            # 10. handleActionResult (GET EUICC INFO) -> GET EUICC CHALLENGE
            euicc_info_response = send_request(proc, {
                "jsonrpc": "2.0",
                "id": "req-10",
                "method": "skill.handleActionResult",
                "params": {
                    "sessionId": session_id,
                    "actionId": "esim.get-euicc-info",
                    "result": {
                        "actionId": "esim.get-euicc-info",
                        "type": "APDU_RESULT",
                        "status": "OK",
                        "data": MockCardResponses.GET_EUICC_INFO,
                        "elapsedMs": 50
                    }
                }
            })
            
            assert euicc_info_response["result"]["status"] == "CONTINUE"
            assert "挑战" in euicc_info_response["result"]["nextAction"]["name"]
            
            # 11. handleActionResult (GET EUICC CHALLENGE) -> AUTHENTICATE SERVER
            challenge_response = send_request(proc, {
                "jsonrpc": "2.0",
                "id": "req-11",
                "method": "skill.handleActionResult",
                "params": {
                    "sessionId": session_id,
                    "actionId": "esim.get-euicc-challenge",
                    "result": {
                        "actionId": "esim.get-euicc-challenge",
                        "type": "APDU_RESULT",
                        "status": "OK",
                        "data": MockCardResponses.GET_EUICC_CHALLENGE,
                        "elapsedMs": 20
                    }
                }
            })
            
            assert challenge_response["result"]["status"] == "CONTINUE"
            assert "认证" in challenge_response["result"]["nextAction"]["name"]
            
            # 12. handleActionResult (AUTHENTICATE SERVER) -> PREPARE DOWNLOAD
            auth_response = send_request(proc, {
                "jsonrpc": "2.0",
                "id": "req-12",
                "method": "skill.handleActionResult",
                "params": {
                    "sessionId": session_id,
                    "actionId": "esim.authenticate-server",
                    "result": {
                        "actionId": "esim.authenticate-server",
                        "type": "APDU_RESULT",
                        "status": "OK",
                        "data": MockCardResponses.AUTHENTICATE_SERVER,
                        "elapsedMs": 100
                    }
                }
            })
            
            assert auth_response["result"]["status"] == "CONTINUE"
            assert "下载" in auth_response["result"]["nextAction"]["name"]
            
            # 13. handleActionResult (PREPARE DOWNLOAD) -> LOAD PROFILE PACKAGE
            pd_response = send_request(proc, {
                "jsonrpc": "2.0",
                "id": "req-13",
                "method": "skill.handleActionResult",
                "params": {
                    "sessionId": session_id,
                    "actionId": "esim.prepare-download",
                    "result": {
                        "actionId": "esim.prepare-download",
                        "type": "APDU_RESULT",
                        "status": "OK",
                        "data": MockCardResponses.PREPARE_DOWNLOAD,
                        "elapsedMs": 50
                    }
                }
            })
            
            assert pd_response["result"]["status"] == "CONTINUE"
            assert "Profile" in pd_response["result"]["nextAction"]["name"]
            
            # 14. handleActionResult (LOAD PROFILE PACKAGE) -> POST INSTALL RESET
            lpp_response = send_request(proc, {
                "jsonrpc": "2.0",
                "id": "req-14",
                "method": "skill.handleActionResult",
                "params": {
                    "sessionId": session_id,
                    "actionId": "esim.load-profile-package",
                    "result": {
                        "actionId": "esim.load-profile-package",
                        "type": "APDU_RESULT",
                        "status": "OK",
                        "data": MockCardResponses.LOAD_PROFILE_PACKAGE,
                        "elapsedMs": 500
                    }
                }
            })
            
            assert lpp_response["result"]["status"] == "CONTINUE"
            assert lpp_response["result"]["nextAction"]["type"] == "RESET_CARD"
            
            # 15. handleActionResult (POST INSTALL RESET) -> IC1
            post_reset_response = send_request(proc, {
                "jsonrpc": "2.0",
                "id": "req-15",
                "method": "skill.handleActionResult",
                "params": {
                    "sessionId": session_id,
                    "actionId": "esim.post-install-reset",
                    "result": {
                        "actionId": "esim.post-install-reset",
                        "type": "RESET_CARD_RESULT",
                        "status": "OK",
                        "data": {"atr": MockCardResponses.ATR},
                        "elapsedMs": 100
                    }
                }
            })
            
            assert post_reset_response["result"]["status"] == "CONTINUE"
            assert "通道 1" in post_reset_response["result"]["nextAction"]["name"]
            
            # 16. handleActionResult (IC1) -> IC2
            ic1_response = send_request(proc, {
                "jsonrpc": "2.0",
                "id": "req-16",
                "method": "skill.handleActionResult",
                "params": {
                    "sessionId": session_id,
                    "actionId": "esim.post-install-ic1",
                    "result": {
                        "actionId": "esim.post-install-ic1",
                        "type": "APDU_RESULT",
                        "status": "OK",
                        "data": {"response": "01", "sw": "9000"},
                        "elapsedMs": 10
                    }
                }
            })
            
            assert ic1_response["result"]["status"] == "CONTINUE"
            assert "通道 2" in ic1_response["result"]["nextAction"]["name"]
            
            # 17. handleActionResult (IC2) -> SELECT ISD-R
            ic2_response = send_request(proc, {
                "jsonrpc": "2.0",
                "id": "req-17",
                "method": "skill.handleActionResult",
                "params": {
                    "sessionId": session_id,
                    "actionId": "esim.post-install-ic2",
                    "result": {
                        "actionId": "esim.post-install-ic2",
                        "type": "APDU_RESULT",
                        "status": "OK",
                        "data": {"response": "02", "sw": "9000"},
                        "elapsedMs": 10
                    }
                }
            })
            
            assert ic2_response["result"]["status"] == "CONTINUE"
            
            # 18. handleActionResult (SELECT ISD-R) -> GET PROFILES INFO
            isdr2_response = send_request(proc, {
                "jsonrpc": "2.0",
                "id": "req-18",
                "method": "skill.handleActionResult",
                "params": {
                    "sessionId": session_id,
                    "actionId": "esim.post-install-select-isdr",
                    "result": {
                        "actionId": "esim.post-install-select-isdr",
                        "type": "APDU_RESULT",
                        "status": "OK",
                        "data": MockCardResponses.SELECT_ISDR,
                        "elapsedMs": 10
                    }
                }
            })
            
            assert isdr2_response["result"]["status"] == "CONTINUE"
            assert "Profile" in isdr2_response["result"]["nextAction"]["name"]
            
            # 19. handleActionResult (GET PROFILES INFO) -> SUCCESS (直接模式)
            profiles_response = send_request(proc, {
                "jsonrpc": "2.0",
                "id": "req-19",
                "method": "skill.handleActionResult",
                "params": {
                    "sessionId": session_id,
                    "actionId": "esim.get-profiles-info",
                    "result": {
                        "actionId": "esim.get-profiles-info",
                        "type": "APDU_RESULT",
                        "status": "OK",
                        "data": MockCardResponses.GET_PROFILES_INFO_ENABLED,
                        "elapsedMs": 20
                    }
                }
            })
            
            # 最终结果应该是 SUCCESS
            assert profiles_response["result"]["status"] == "SUCCESS"
            assert profiles_response["result"]["data"]["profile_state"] == "ENABLED"
            assert profiles_response["result"]["data"]["verified"] == True
            assert profiles_response["result"]["data"]["iccid"] == "8929901012345678905"
            
        finally:
            proc.terminate()
            proc.wait(timeout=5)
