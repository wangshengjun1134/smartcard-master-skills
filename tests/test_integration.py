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
from read_iccid_skill.skill import ReadIccidSkill, ReadIccidState


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

        # 3. Start - 应该返回 SELECT MF 的 Action
        start_result = skill.start(ctx, session)
        assert start_result.status.value == "CONTINUE"
        assert start_result.next_action is not None
        assert start_result.next_action.type.value == "APDU"
        assert start_result.next_action.action_id == "read.iccid.select-mf"
        assert start_result.next_action.payload["apdu"] == "00A40000023F00"

        # 4. Handle SELECT MF result - 应该返回 SELECT ICCID 的 Action
        mf_result = ActionResult(
            action_id="read.iccid.select-mf",
            type="APDU_RESULT",
            status=ActionResultStatus.OK,
            data={"response": "", "sw": "9000"}
        )
        iccid_action = skill.handle_action_result(ctx, mf_result, session)
        assert iccid_action.status.value == "CONTINUE"
        assert iccid_action.next_action.action_id == "read.iccid.select-iccid"
        assert iccid_action.next_action.payload["apdu"] == "00A40000022FE2"

        # 5. Handle SELECT ICCID result - 应该返回 READ BINARY 的 Action
        iccid_result = ActionResult(
            action_id="read.iccid.select-iccid",
            type="APDU_RESULT",
            status=ActionResultStatus.OK,
            data={"response": "", "sw": "9000"}
        )
        read_action = skill.handle_action_result(ctx, iccid_result, session)
        assert read_action.status.value == "CONTINUE"
        assert read_action.next_action.action_id == "read.iccid.read-binary"
        assert read_action.next_action.payload["apdu"] == "00B000000A"

        # 6. Handle READ BINARY result - 应该返回 SUCCESS 和解析后的 ICCID
        read_result = ActionResult(
            action_id="read.iccid.read-binary",
            type="APDU_RESULT",
            status=ActionResultStatus.OK,
            data={"response": "986810325476981032F3", "sw": "9000"}
        )
        final_result = skill.handle_action_result(ctx, read_result, session)
        assert final_result.status.value == "SUCCESS"
        assert "iccid" in final_result.data
        assert final_result.data["iccid"].startswith("89")


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

        # 模拟完整流程
        mf_result = ActionResult(
            action_id="read.iccid.select-mf",
            type="APDU_RESULT",
            status=ActionResultStatus.OK,
            data={"response": "", "sw": "9000"}
        )
        iccid_action = skill.handle_action_result(ctx, mf_result, session)
        assert iccid_action.session_id == session_id

        iccid_result = ActionResult(
            action_id="read.iccid.select-iccid",
            type="APDU_RESULT",
            status=ActionResultStatus.OK,
            data={"response": "", "sw": "9000"}
        )
        read_action = skill.handle_action_result(ctx, iccid_result, session)
        assert read_action.session_id == session_id

        read_result = ActionResult(
            action_id="read.iccid.read-binary",
            type="APDU_RESULT",
            status=ActionResultStatus.OK,
            data={"response": "986810325476981032F3", "sw": "9000"}
        )
        final_result = skill.handle_action_result(ctx, read_result, session)
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
        assert any("开始读取 ICCID" in o.message for o in outputs)
        assert any("步骤 1/3" in o.message for o in outputs)


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
            
            # 读取 start 响应 - 应该返回 SELECT MF
            start_response_line = proc.stdout.readline()
            start_response = json.loads(start_response_line)
            
            assert start_response["jsonrpc"] == "2.0"
            assert start_response["id"] == "req-2"
            assert start_response["result"]["status"] == "CONTINUE"
            assert start_response["result"]["nextAction"]["type"] == "APDU"
            assert start_response["result"]["nextAction"]["actionId"] == "read.iccid.select-mf"
            assert start_response["result"]["nextAction"]["payload"]["apdu"] == "00A40000023F00"
            
            # 发送 SELECT MF 的 ActionResult
            mf_result_request = {
                "jsonrpc": "2.0",
                "id": "req-3",
                "method": "skill.handleActionResult",
                "params": {
                    "sessionId": session_id,
                    "actionId": "read.iccid.select-mf",
                    "result": {
                        "actionId": "read.iccid.select-mf",
                        "type": "APDU_RESULT",
                        "status": "OK",
                        "data": {"response": "", "sw": "9000"},
                        "elapsedMs": 10
                    }
                }
            }
            proc.stdin.write(json.dumps(mf_result_request) + "\n")
            proc.stdin.flush()
            
            # 读取响应 - 应该返回 SELECT ICCID
            mf_response_line = proc.stdout.readline()
            mf_response = json.loads(mf_response_line)
            
            assert mf_response["result"]["status"] == "CONTINUE"
            assert mf_response["result"]["nextAction"]["actionId"] == "read.iccid.select-iccid"
            assert mf_response["result"]["nextAction"]["payload"]["apdu"] == "00A40000022FE2"
            
            # 发送 SELECT ICCID 的 ActionResult
            iccid_result_request = {
                "jsonrpc": "2.0",
                "id": "req-4",
                "method": "skill.handleActionResult",
                "params": {
                    "sessionId": session_id,
                    "actionId": "read.iccid.select-iccid",
                    "result": {
                        "actionId": "read.iccid.select-iccid",
                        "type": "APDU_RESULT",
                        "status": "OK",
                        "data": {"response": "", "sw": "9000"},
                        "elapsedMs": 10
                    }
                }
            }
            proc.stdin.write(json.dumps(iccid_result_request) + "\n")
            proc.stdin.flush()
            
            # 读取响应 - 应该返回 READ BINARY
            iccid_response_line = proc.stdout.readline()
            iccid_response = json.loads(iccid_response_line)
            
            assert iccid_response["result"]["status"] == "CONTINUE"
            assert iccid_response["result"]["nextAction"]["actionId"] == "read.iccid.read-binary"
            assert iccid_response["result"]["nextAction"]["payload"]["apdu"] == "00B000000A"
            
            # 发送 READ BINARY 的 ActionResult
            read_result_request = {
                "jsonrpc": "2.0",
                "id": "req-5",
                "method": "skill.handleActionResult",
                "params": {
                    "sessionId": session_id,
                    "actionId": "read.iccid.read-binary",
                    "result": {
                        "actionId": "read.iccid.read-binary",
                        "type": "APDU_RESULT",
                        "status": "OK",
                        "data": {"response": "986810325476981032F3", "sw": "9000"},
                        "elapsedMs": 10
                    }
                }
            }
            proc.stdin.write(json.dumps(read_result_request) + "\n")
            proc.stdin.flush()
            
            # 读取最终响应 - 应该返回 SUCCESS 和 ICCID
            final_response_line = proc.stdout.readline()
            if not final_response_line:
                stderr_output = proc.stderr.read()
                raise AssertionError(f"No response received. STDERR: {stderr_output}")
            final_response = json.loads(final_response_line)
            
            assert final_response["jsonrpc"] == "2.0"
            assert final_response["id"] == "req-5"
            assert final_response["result"]["status"] == "SUCCESS"
            assert "iccid" in final_response["result"]["data"]
            assert final_response["result"]["data"]["iccid"].startswith("89")
            
        finally:
            proc.terminate()
            proc.wait(timeout=5)
