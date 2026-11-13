import pytest
import json
import tempfile
import subprocess
import sys
import os
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


def test_stdin_stdout_protocol():
    """测试通过 stdin/stdout JSON-RPC 协议调用 Skill"""
    # 获取项目根目录
    project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

    # 创建临时会话目录
    with tempfile.TemporaryDirectory() as session_dir:
        # 启动 Skill 进程
        env = {**os.environ, "PYTHONPATH": project_root, "SKILL_SESSION_DIR": session_dir}
        proc = subprocess.Popen(
            [sys.executable, "-m", "read_iccid_skill.main"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            cwd=project_root,
            env=env
        )

        try:
            # 发送 skill.init 请求
            init_request = {
                "jsonrpc": "2.0",
                "id": "req-1",
                "method": "skill.init",
                "params": {
                    "protocolVersion": "1.0",
                    "skillId": "read.iccid",
                    "input": {},
                    "context": {"traceId": "trace-001", "mode": "interactive"}
                }
            }
            proc.stdin.write(json.dumps(init_request) + "\n")
            proc.stdin.flush()
            
            # 读取 init 响应
            init_response_line = proc.stdout.readline()
            init_response = json.loads(init_response_line)
            
            assert init_response["jsonrpc"] == "2.0"
            assert init_response["id"] == "req-1"
            assert "result" in init_response
            assert "sessionId" in init_response["result"]
            session_id = init_response["result"]["sessionId"]
            
            # 发送 skill.start 请求
            start_request = {
                "jsonrpc": "2.0",
                "id": "req-2",
                "method": "skill.start",
                "params": {
                    "sessionId": session_id,
                    "skillId": "read.iccid",
                    "input": {}
                }
            }
            proc.stdin.write(json.dumps(start_request) + "\n")
            proc.stdin.flush()
            
            # 读取 start 响应
            start_response_line = proc.stdout.readline()
            start_response = json.loads(start_response_line)
            
            assert start_response["jsonrpc"] == "2.0"
            assert start_response["id"] == "req-2"
            assert start_response["result"]["status"] == "CONTINUE"
            assert start_response["result"]["nextAction"]["type"] == "APDU"
            assert start_response["result"]["nextAction"]["payload"]["apdu"] == "00A40000023F00"
            
            # 发送 skill.handleActionResult 请求
            action_result_request = {
                "jsonrpc": "2.0",
                "id": "req-3",
                "method": "skill.handleActionResult",
                "params": {
                    "sessionId": session_id,
                    "actionId": "read.iccid.execute",
                    "result": {
                        "actionId": "read.iccid.execute",
                        "type": "APDU_RESULT",
                        "status": "OK",
                        "data": {
                            "response": "98012345678901234567890",
                            "sw": "9000"
                        },
                        "elapsedMs": 10
                    }
                }
            }
            proc.stdin.write(json.dumps(action_result_request) + "\n")
            proc.stdin.flush()
            
            # 读取最终响应
            final_response_line = proc.stdout.readline()
            if not final_response_line:
                stderr_output = proc.stderr.read()
                raise AssertionError(f"No response received. STDERR: {stderr_output}")
            final_response = json.loads(final_response_line)
            
            assert final_response["jsonrpc"] == "2.0"
            assert final_response["id"] == "req-3"
            assert final_response["result"]["status"] == "SUCCESS"
            assert "iccid" in final_response["result"]["data"]
            assert final_response["result"]["data"]["iccid"] == "98012345678901234567"
            
        finally:
            proc.terminate()
            proc.wait(timeout=5)
