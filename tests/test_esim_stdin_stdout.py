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
        "response": "BF384EA04C30038001015F3740" + "11" * 64 + "30003000",
        "sw": "9000"
    }
    
    # PrepareDownload 响应 (BF21) - transactionId + 65 字节 euiccOtpk（P-256 生成元）
    _GX = "6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296"
    _GY = "4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5"
    PREPARE_DOWNLOAD = {
        "response": "BF215BA05930558010" + "0102030405060708090A0B0C0D0E0F10"
                    + "5F4941" + "04" + _GX + _GY,
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


def drain_chunked(proc, session_id, response, block_data=None):
    """分块 APDU（BF38/BF21/BF36 等）逐块推进，直到不再是“续”动作

    block_data: 每块回传的数据；非最后一块会被 Skill 忽略，最后一块才会被解析。
    """
    seq = 1000
    data = block_data if block_data is not None else {"response": "", "sw": "9000"}
    while True:
        next_action = response["result"].get("nextAction") or {}
        if "续" not in next_action.get("name", ""):
            return response
        seq += 1
        action_id = next_action["actionId"]
        response = send_request(proc, {
            "jsonrpc": "2.0",
            "id": f"req-drain-{seq}",
            "method": "skill.handleActionResult",
            "params": {
                "sessionId": session_id,
                "actionId": action_id,
                "result": {
                    "actionId": action_id,
                    "type": "APDU_RESULT",
                    "status": "OK",
                    "data": data,
                    "elapsedMs": 10
                }
            }
        })


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
            assert reset_response["result"]["nextAction"]["payload"]["apdu"] == "00A40004023F00"
            
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

            # 9. handleActionResult (SELECT ISD-R) -> EUICC MEMORY RESET (清理阶段)
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
            assert "内存" in isdr_response["result"]["nextAction"]["name"] or "reset" in isdr_response["result"]["nextAction"]["name"].lower()

            # 10. handleActionResult (EUICC MEMORY RESET) -> LIST NOTIFICATION
            reset_response = send_request(proc, {
                "jsonrpc": "2.0",
                "id": "req-10",
                "method": "skill.handleActionResult",
                "params": {
                    "sessionId": session_id,
                    "actionId": "esim.euicc-memory-reset",
                    "result": {
                        "actionId": "esim.euicc-memory-reset",
                        "type": "APDU_RESULT",
                        "status": "OK",
                        "data": {"response": "", "sw": "9000"},
                        "elapsedMs": 50
                    }
                }
            })

            assert reset_response["result"]["status"] == "CONTINUE"
            assert "通知" in reset_response["result"]["nextAction"]["name"] or "notification" in reset_response["result"]["nextAction"]["name"].lower()

            # 11. handleActionResult (LIST NOTIFICATION) -> GET EUICC INFO (无通知时)
            list_response = send_request(proc, {
                "jsonrpc": "2.0",
                "id": "req-11",
                "method": "skill.handleActionResult",
                "params": {
                    "sessionId": session_id,
                    "actionId": "esim.list-notification",
                    "result": {
                        "actionId": "esim.list-notification",
                        "type": "APDU_RESULT",
                        "status": "OK",
                        "data": {"response": "", "sw": "9000"},
                        "elapsedMs": 20
                    }
                }
            })

            assert list_response["result"]["status"] == "CONTINUE"
            assert "挑战" in list_response["result"]["nextAction"]["name"]

            # 12. handleActionResult (GET EUICC CHALLENGE) -> GET EUICC INFO
            challenge_response = send_request(proc, {
                "jsonrpc": "2.0",
                "id": "req-12",
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
            assert "eUICC" in challenge_response["result"]["nextAction"]["name"]

            # 13. handleActionResult (GET EUICC INFO) -> AUTHENTICATE SERVER
            euicc_info_response = send_request(proc, {
                "jsonrpc": "2.0",
                "id": "req-13",
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
            assert "认证" in euicc_info_response["result"]["nextAction"]["name"]
            
            # 14. handleActionResult (AUTHENTICATE SERVER) -> PREPARE DOWNLOAD
            auth_response = send_request(proc, {
                "jsonrpc": "2.0",
                "id": "req-14",
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

            # BF38 分块下发，逐块推进直到进入 PrepareDownload
            auth_response = drain_chunked(
                proc, session_id, auth_response, MockCardResponses.AUTHENTICATE_SERVER
            )
            assert auth_response["result"]["status"] == "CONTINUE"
            assert "下载" in auth_response["result"]["nextAction"]["name"]
            
            # 15. handleActionResult (PREPARE DOWNLOAD) -> LOAD PROFILE PACKAGE
            pd_response = send_request(proc, {
                "jsonrpc": "2.0",
                "id": "req-15",
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
            
            # BF21 分块下发，逐块推进直到进入 LoadProfilePackage
            pd_response = drain_chunked(
                proc, session_id, pd_response, MockCardResponses.PREPARE_DOWNLOAD
            )
            assert pd_response["result"]["status"] == "CONTINUE"
            assert "Profile" in pd_response["result"]["nextAction"]["name"]
            
            # 16. handleActionResult (LOAD PROFILE PACKAGE) -> POST INSTALL RESET
            lpp_response = send_request(proc, {
                "jsonrpc": "2.0",
                "id": "req-16",
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
            
            # BF36 分块下发，逐块推进直到进入后安装冷复位
            lpp_response = drain_chunked(proc, session_id, lpp_response)
            assert lpp_response["result"]["status"] == "CONTINUE"
            assert lpp_response["result"]["nextAction"]["type"] == "RESET_CARD"
            
            # 17. handleActionResult (POST INSTALL RESET) -> IC1
            post_reset_response = send_request(proc, {
                "jsonrpc": "2.0",
                "id": "req-17",
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
            assert "通道" in post_reset_response["result"]["nextAction"]["name"]

            # 18. handleActionResult (IC1 打开通道) -> SELECT ISD-R
            ic1_response = send_request(proc, {
                "jsonrpc": "2.0",
                "id": "req-18",
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
            assert "ISD-R" in ic1_response["result"]["nextAction"]["name"]

            # 19. handleActionResult (SELECT ISD-R) -> GET PROFILES INFO
            ic2_response = send_request(proc, {
                "jsonrpc": "2.0",
                "id": "req-19",
                "method": "skill.handleActionResult",
                "params": {
                    "sessionId": session_id,
                    "actionId": "esim.post-install-select-isdr",
                    "result": {
                        "actionId": "esim.post-install-select-isdr",
                        "type": "APDU_RESULT",
                        "status": "OK",
                        "data": {"response": "02", "sw": "9000"},
                        "elapsedMs": 10
                    }
                }
            })
            
            assert ic2_response["result"]["status"] == "CONTINUE"
            assert "Profile" in ic2_response["result"]["nextAction"]["name"]

            # 20. handleActionResult (GET PROFILES INFO) -> SUCCESS (直接模式)
            isdr2_response = send_request(proc, {
                "jsonrpc": "2.0",
                "id": "req-20",
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

            assert isdr2_response["result"]["status"] == "SUCCESS"
            assert isdr2_response["result"]["data"]["profile_state"] == "ENABLED"
            assert isdr2_response["result"]["data"]["verified"] is True
            assert isdr2_response["result"]["data"]["iccid"] == "8929901012345678905"
            
        finally:
            proc.terminate()
            proc.wait(timeout=5)
