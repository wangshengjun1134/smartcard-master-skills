"""eSIM IoT Profile Download Skill 连卡测试

通过 stdin/stdout JSON-RPC 协议测试 eSIM Profile 下载流程。
使用真实读卡器和卡片执行完整的 Skill 测试。

测试流程：
1. 启动 Skill 进程
2. 通过 stdin 发送 JSON-RPC 请求
3. 从 stdout 读取 Skill 响应
4. 根据 Skill 返回的 Action 执行真实卡片操作
5. 将卡片响应通过 handleActionResult 返回给 Skill
6. 重复直到 Skill 返回 SUCCESS 或 FAILED

注意：
- 61XX (GET RESPONSE) 和 91XX (FETCH) 响应由 Skill 处理
- 测试代码只负责透传卡片响应给 Skill
"""

import pytest
import json
import subprocess
import sys
import os
import time
from typing import Optional, Dict, Any

# 添加 card_reader 模块路径
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'packages', 'card-reader', 'src'))

from card_reader import CardReader, CardReaderError


def parse_apdu(apdu: str) -> str:
    """解析 APDU 指令，返回可读格式"""
    if len(apdu) < 10:
        return apdu
    
    cla = int(apdu[0:2], 16)
    ins = int(apdu[2:4], 16)
    p1 = int(apdu[4:6], 16)
    p2 = int(apdu[6:8], 16)
    
    # 判断通道号
    if cla < 0x80:
        channel = cla
        cla_desc = f"通道{channel}"
    else:
        channel = cla - 0x80
        cla_desc = f"0x80+通道{channel}"
    
    # 判断指令类型
    ins_names = {
        0xA4: "SELECT",
        0xC0: "GET RESPONSE",
        0x70: "MANAGE CHANNEL",
        0xE2: "ES10命令",
        0xBF: "BF指令",
        0xAA: "TERMINAL CAPABILITY",
        0x10: "TERMINAL PROFILE",
        0xF2: "STATUS",
        0x12: "FETCH",
    }
    ins_name = ins_names.get(ins, f"未知({ins:02X})")
    
    # 对于 ES10 和 BF 指令，进一步解析
    sub_cmd = ""
    if ins == 0xE2 and len(apdu) >= 12:
        # ES10 命令，数据部分以 BF XX 开头
        data_start = 10
        if len(apdu) > data_start:
            tag = apdu[data_start:data_start+4]
            sub_cmd = f" [{tag}]"
    elif ins == 0xBF and len(apdu) >= 10:
        # BF 指令，P1 表示子命令
        bf_cmds = {
            0x21: "PrepareDownload",
            0x36: "LoadProfilePackage",
            0x38: "AuthenticateServer",
            0x57: "AddInitialEim",
            0x51: "EnablePSMO",
        }
        sub_cmd = f" [{bf_cmds.get(p1, f'BF_{p1:02X}')}]"
    
    return f"{cla_desc} {ins_name}{sub_cmd}"


class RealCardExecutor:
    """真实卡片执行器 - 处理 Skill 返回的 Action 并执行真实卡片操作
    
    注意：61XX 和 91XX 响应由 Skill 处理，测试代码只负责透传卡片响应。
    """
    
    def __init__(self):
        self.reader = CardReader()
        self.connected = False
        
    def connect(self) -> str:
        """连接读卡器"""
        atr = self.reader.connect()
        self.connected = True
        return atr
    
    def disconnect(self):
        """断开读卡器"""
        if self.connected:
            self.reader.disconnect()
            self.connected = False
    
    def execute_action(self, action: Dict[str, Any]) -> Dict[str, Any]:
        """执行 Skill 返回的 Action
        
        Args:
            action: Skill 返回的 Action 对象
            
        Returns:
            ActionResult 对象
        """
        action_type = action.get("type", "")
        action_id = action.get("actionId", "")
        payload = action.get("payload", {})
        
        if action_type == "RESET_CARD":
            return self._execute_reset(action_id)
        elif action_type == "APDU":
            return self._execute_apdu(action_id, payload)
        elif action_type == "CONNECT_READER":
            return self._execute_connect(action_id)
        elif action_type == "DISCONNECT_READER":
            return self._execute_disconnect(action_id)
        else:
            return {
                "actionId": action_id,
                "type": f"{action_type}_RESULT",
                "status": "ERROR",
                "error": {"code": "UNSUPPORTED_ACTION", "message": f"不支持的 Action 类型: {action_type}"},
                "elapsedMs": 0
            }
    
    def _execute_reset(self, action_id: str) -> Dict[str, Any]:
        """执行卡片复位"""
        start_time = time.time()
        try:
            # 断开并重新连接以执行复位
            if self.connected:
                self.reader.disconnect()
                self.connected = False
            
            atr = self.reader.connect()
            self.connected = True
            
            elapsed = int((time.time() - start_time) * 1000)
            return {
                "actionId": action_id,
                "type": "RESET_CARD_RESULT",
                "status": "OK",
                "data": {"atr": atr},
                "elapsedMs": elapsed
            }
        except CardReaderError as e:
            elapsed = int((time.time() - start_time) * 1000)
            return {
                "actionId": action_id,
                "type": "RESET_CARD_RESULT",
                "status": "ERROR",
                "error": {"code": "READER_ERROR", "message": str(e)},
                "elapsedMs": elapsed
            }
    
    def _execute_apdu(self, action_id: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        """执行 APDU 命令
        
        注意：只发送 APDU 并返回原始响应，不处理 61XX/91XX。
        Skill 会根据响应决定下一步操作（如发送 GET RESPONSE 或 FETCH）。
        """
        start_time = time.time()
        apdu = payload.get("apdu", "")
        
        try:
            # 发送 APDU
            response, sw1, sw2 = self.reader.send_apdu(apdu)
            
            elapsed = int((time.time() - start_time) * 1000)
            return {
                "actionId": action_id,
                "type": "APDU_RESULT",
                "status": "OK",
                "data": {
                    "response": response,
                    "sw": f"{sw1:02X}{sw2:02X}"
                },
                "elapsedMs": elapsed
            }
        except CardReaderError as e:
            elapsed = int((time.time() - start_time) * 1000)
            return {
                "actionId": action_id,
                "type": "APDU_RESULT",
                "status": "ERROR",
                "error": {"code": "APDU_ERROR", "message": str(e)},
                "elapsedMs": elapsed
            }
    
    def _execute_connect(self, action_id: str) -> Dict[str, Any]:
        """执行连接读卡器"""
        start_time = time.time()
        try:
            if not self.connected:
                self.reader.connect()
                self.connected = True
            
            elapsed = int((time.time() - start_time) * 1000)
            return {
                "actionId": action_id,
                "type": "CONNECT_READER_RESULT",
                "status": "OK",
                "data": {},
                "elapsedMs": elapsed
            }
        except CardReaderError as e:
            elapsed = int((time.time() - start_time) * 1000)
            return {
                "actionId": action_id,
                "type": "CONNECT_READER_RESULT",
                "status": "ERROR",
                "error": {"code": "READER_ERROR", "message": str(e)},
                "elapsedMs": elapsed
            }
    
    def _execute_disconnect(self, action_id: str) -> Dict[str, Any]:
        """执行断开读卡器"""
        start_time = time.time()
        try:
            if self.connected:
                self.reader.disconnect()
                self.connected = False
            
            elapsed = int((time.time() - start_time) * 1000)
            return {
                "actionId": action_id,
                "type": "DISCONNECT_READER_RESULT",
                "status": "OK",
                "data": {},
                "elapsedMs": elapsed
            }
        except CardReaderError as e:
            elapsed = int((time.time() - start_time) * 1000)
            return {
                "actionId": action_id,
                "type": "DISCONNECT_READER_RESULT",
                "status": "ERROR",
                "error": {"code": "READER_ERROR", "message": str(e)},
                "elapsedMs": elapsed
            }


def send_request(proc: subprocess.Popen, request: Dict[str, Any], timeout: int = 30) -> Dict[str, Any]:
    """发送 JSON-RPC 请求并读取响应
    
    Args:
        proc: Skill 进程
        request: JSON-RPC 请求
        timeout: 超时时间（秒）
        
    Returns:
        JSON-RPC 响应
    """
    proc.stdin.write(json.dumps(request) + "\n")
    proc.stdin.flush()
    
    start = time.time()
    while time.time() - start < timeout:
        response_line = proc.stdout.readline()
        if response_line:
            return json.loads(response_line)
        time.sleep(0.1)
    
    stderr = proc.stderr.read()
    raise AssertionError(f"Timeout waiting for response. STDERR: {stderr}")


def run_skill_with_real_card(
    skill_input: Dict[str, Any],
    max_steps: int = 500,
    verbose: bool = True
) -> Dict[str, Any]:
    """使用真实卡片运行 Skill
    
    Args:
        skill_input: Skill 输入参数
        max_steps: 最大执行步骤数
        verbose: 是否输出详细信息
        
    Returns:
        最终 Skill 结果
    """
    project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    executor = RealCardExecutor()
    
    # 启动 Skill 进程
    if verbose:
        print("=== 启动 Skill 进程 ===")
    
    proc = subprocess.Popen(
        [sys.executable, "-m", "esim_iot_profile_download.main"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        cwd=project_root,
        env={**os.environ, "PYTHONPATH": project_root}
    )
    
    try:
        # 1. skill.init
        if verbose:
            print("\n[1] skill.init")
        
        init_response = send_request(proc, {
            "jsonrpc": "2.0",
            "id": "req-init",
            "method": "skill.init",
            "params": {
                "protocolVersion": "1.0",
                "skillId": "esim.iot-profile-download",
                "input": skill_input,
                "context": {"traceId": "trace-001", "mode": "interactive"}
            }
        })
        
        if verbose:
            print(f"    Status: {init_response['result']['status']}")
        
        session_id = init_response["result"]["sessionId"]
        
        # 2. skill.start
        if verbose:
            print("\n[2] skill.start")
        
        start_response = send_request(proc, {
            "jsonrpc": "2.0",
            "id": "req-start",
            "method": "skill.start",
            "params": {
                "sessionId": session_id,
                "skillId": "esim.iot-profile-download",
                "input": {}
            }
        })
        
        if verbose:
            print(f"    Status: {start_response['result']['status']}")
        
        current_response = start_response
        step = 3
        
        # 3. 循环执行 Action
        while step <= max_steps:
            status = current_response["result"]["status"]
            
            # 检查是否结束
            if status in ["SUCCESS", "FAILED", "CANCELLED"]:
                if verbose:
                    print(f"\n=== Skill 执行完成: {status} ===")
                    error = current_response["result"].get("error")
                    if error:
                        print(f"errorCode: {error.get('code')}")
                        print(f"errorMessage: {error.get('message')}")
                    if "data" in current_response["result"]:
                        print(f"Data: {json.dumps(current_response['result']['data'], indent=2, ensure_ascii=False)}")
                return current_response["result"]
            
            # 获取下一个 Action
            next_action = current_response["result"].get("nextAction")
            if not next_action:
                if verbose:
                    print(f"\n=== 没有更多 Action，状态: {status} ===")
                return current_response["result"]
            
            action_type = next_action.get("type", "")
            action_id = next_action.get("actionId", "")
            action_name = next_action.get("name", "")
            
            if verbose:
                print(f"\n[{step}] 执行 Action: {action_name} ({action_id})")
                if "payload" in next_action:
                    apdu = next_action["payload"].get("apdu", "")
                    if apdu:
                        # 解析并打印 APDU 指令
                        apdu_desc = parse_apdu(apdu)
                        print(f"     APDU: {apdu}")
                        print(f"     解析: {apdu_desc}")
            
            # 执行 Action
            result = executor.execute_action(next_action)
            
            if verbose:
                print(f"     结果: {result['status']}")
                if result["status"] == "OK":
                    if "response" in result.get("data", {}):
                        resp = result["data"]["response"]
                        print(f"     响应: {resp[:60]}..." if len(resp) > 60 else f"     响应: {resp}")
                        if len(resp) > 60 and resp.startswith("BF37"):
                            print(f"     ProfileInstallationResult: {resp}")
                    if "sw" in result.get("data", {}):
                        print(f"     SW: {result['data']['sw']}")
            
            # 发送 handleActionResult
            response = send_request(proc, {
                "jsonrpc": "2.0",
                "id": f"req-{step}",
                "method": "skill.handleActionResult",
                "params": {
                    "sessionId": session_id,
                    "actionId": action_id,
                    "result": result
                }
            })
            
            current_response = response
            step += 1
        
        # 超过最大步骤数
        if verbose:
            print(f"\n=== 超过最大步骤数 ({max_steps})，停止执行 ===")
        
        return current_response["result"]
        
    finally:
        proc.terminate()
        proc.wait(timeout=5)
        executor.disconnect()


# ========== pytest 测试用例 ==========

def is_reader_available() -> bool:
    """检查是否有可用的读卡器"""
    try:
        reader = CardReader()
        readers = reader.list_readers()
        return len(readers) > 0
    except Exception:
        return False


pytestmark = pytest.mark.skipif(
    not is_reader_available(),
    reason="No card reader available"
)


class TestEsimSkillWithRealCard:
    """eSIM Skill 真实卡片测试"""
    
    def test_skill_init_and_start(self):
        """测试 Skill 初始化和启动"""
        result = run_skill_with_real_card(
            skill_input={
                "operation": "install_and_enable",
                "mode": "direct",
                "eid": "89049032123451234512345678901235",
                "smdp_address": "test.example.com",
                "matching_id": "ABC12345",
                "iccid": "8929901012345678905F",
                "profile_id": "A0000005591010FFFFFFFF8900001000",
                "tac": "00000000"
            },
            max_steps=5,  # 只执行前几步
            verbose=True
        )
        
        # 应该能正常初始化并启动
        assert result["status"] in ["CONTINUE", "SUCCESS", "FAILED"]
    
    def test_full_flow_until_success_or_fail(self):
        """测试完整流程直到成功或失败"""
        result = run_skill_with_real_card(
            skill_input={
                "operation": "install_and_enable",
                "mode": "direct",
                "eid": "89049032123451234512345678901235",
                "smdp_address": "testsmdpplus1.example.com",
                "matching_id": "ABC12345",
                "iccid": "8929901012345678905F",
                "profile_id": "A0000005591010FFFFFFFF8900001000",
                "tac": "00000000"
            },
            max_steps=80,
            verbose=True
        )

        # 流程应该能正常结束
        assert result["status"] in ["SUCCESS", "FAILED"]

    def test_indirect_mode_install_and_enable(self):
        """间接模式：AddInitialEim → 下载 → LoadEuiccPackage(enable)"""
        result = run_skill_with_real_card(
            skill_input={
                "operation": "install_and_enable",
                "mode": "indirect",
                "eid": "89049032123451234512345678901235",
                "smdp_address": "testsmdpplus1.example.com",
                "matching_id": "ABC12345",
                "iccid": "8929901012345678905F",
                "profile_id": "A0000005591010FFFFFFFF8900001000",
                "eim_id": "testeim1",
                "eim_fqdn": "eimfqdn.example.com",
                "eim_id_type": 3,
                "tac": "00000000"
            },
            max_steps=120,
            verbose=True
        )

        assert result["status"] in ["SUCCESS", "FAILED"]


if __name__ == "__main__":
    # 直接运行时执行完整测试
    print("=== eSIM IoT Profile Download Skill 连卡测试 ===\n")

    result = run_skill_with_real_card(
        skill_input={
            "operation": "install_and_enable",
            "mode": "direct",
            "eid": "89049032123451234512345678901235",
            "smdp_address": "test.example.com",
            "matching_id": "ABC12345",
            "iccid": "8929901012345678905F",
            "profile_id": "A0000005591010FFFFFFFF8900001000",
            "tac": "00000000"
        },
        max_steps=500,
        verbose=True
    )

    print(f"\n最终状态: {result['status']}")
