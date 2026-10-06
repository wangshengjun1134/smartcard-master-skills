#!/usr/bin/env python3
"""IPC 契约 / 编解码回归测试（离线，无需读卡器）

覆盖：
  1. Skill ↔ Runtime IPC 契约：消息类型、动作字段、RESET_CARD/WAIT、61XX/91XX 跟进、
     execution_finished.error 为字符串（对齐 ipc-protocol.ts）
  2. eIM 报文回归：BF57 / BF51 与 Java 参考脚本实测报文一致
  3. 真卡响应解析回归：ListNotification 序号、GetProfilesInfo 的 profileState

运行：
    cd <skill 根目录> && python3 -m unittest tests.test_ipc_contract -v
"""

import json
import os
import subprocess
import sys
import time
import unittest

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, 'tests'))

from src.local_eim import LocalEim
from src.pki_manager import PkiIdentity, load_private_key_from_pem, load_certificate_from_der
from src.profile_download import ProfileDownloadFlow, Step
from src.sgp32_codec import (decode_euicc_package_request, verify_euicc_package,
                             verify_add_initial_eim_ok, verify_enable_result_ok, Sgp32CodecError)
from src.utils import digits_to_bcd

MAIN = os.path.join(ROOT, 'main.py')
RESOURCES = os.path.join(ROOT, 'resources')
SKILL_ID = 'esim.iot-profile-download'

EIM_ID = 'testeim1'
EID = '89049032123451234512345678901235'
ICCID = '8929901012345678905'

# Java 参考脚本 IOT_PERF_TEST_Install_Enable_Profile 实测报文（日志 261005006398-111）
JAVA_BF57_PREFIX = "BF57820185A08201813082017D80087465737465696D31830101A582016C30820168"
JAVA_BF51_PREFIX = ("BF5174302F80087465737465696D315A1089049032123451234512345678901235"
                    "810102A00EA30C5A0A8929901012345678905F5F3740")
# 真卡响应（同一日志）
CARD_BF2D_DISABLED = ("BF2D5CA05AE3585A0A989209012143658709F54F10A0000005591010FFFFFFFF8900001400"
                      "9F70010091095350204E616D652031921A4F7065726174696F6E616C2050726F66696C65204E616D65"
                      "20319501029F7B01009F2601009F670100")
CARD_BF28_ONE_NOTIFICATION = ("BF2882018CA0820188BF2F2E80010F810207800C1974657374736D6470706C7573312E"
                             "6578616D706C652E636F6D5A0A989209012143658709F5")

ACTION_TYPES = {"APDU", "RESET_CARD", "CONNECT_READER", "DISCONNECT_READER", "WAIT"}


def _load_eim_identity() -> PkiIdentity:
    certs = os.path.join(RESOURCES, 'certs')
    key = load_private_key_from_pem(open(os.path.join(certs, 'SK_EIM_ECDSA_NIST.pem'), 'rb').read())
    cert = load_certificate_from_der(open(os.path.join(certs, 'CERT_EIM_ECDSA_NIST.der'), 'rb').read())
    return PkiIdentity(key, [cert])


def _input(**overrides) -> dict:
    data = {
        "operation": "install_and_enable",
        "mode": "indirect",
        "eid": EID,
        "smdp_address": "testsmdpplus1.example.com",
        "matching_id": "04386-AGYFT-A74Y8-3F815",
        "iccid": ICCID,
        "profile_id": "A0000005591010FFFFFFFF8900001000",
        "eim_id": EIM_ID,
        "resources_dir": RESOURCES,
    }
    data.update(overrides)
    return data


class FakeRuntime:
    """假 Runtime：驱动 main.py 子进程，按脚本回 action_result。"""

    def __init__(self, responder, max_actions=300, force_failure=False):
        self.responder = responder
        self.max_actions = max_actions
        self.force_failure = force_failure
        self.actions = []
        self.outputs = []
        self.finished = None
        self.raw_lines = []

    def run(self, input_data):
        process = subprocess.Popen(
            [sys.executable, MAIN], cwd=ROOT, text=True,
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        start = {
            "type": "start", "executionId": "exec-test", "skillId": SKILL_ID,
            "input": input_data,
            "cardSession": {"readerId": "fake-reader", "atr": "3B00", "connected": True},
        }
        try:
            process.stdin.write(json.dumps(start) + "\n")
            process.stdin.flush()
            while len(self.actions) < self.max_actions:
                line = process.stdout.readline()
                if not line:
                    break
                self.raw_lines.append(line)
                msg = json.loads(line)      # stdout 必须是纯 JSON
                msg_type = msg.get("type")

                if msg_type == "skill_action":
                    action = msg["action"]
                    self.actions.append(action)
                    sw, data, extra = self.responder(action)
                    result = {
                        "type": "action_result", "executionId": "exec-test",
                        "actionId": action["id"], "actionType": action["type"],
                        "success": not self.force_failure,
                        "response": {"sw": sw, "data": list(data)},
                    }
                    if self.force_failure:
                        result["error"] = "reader is not connected"
                    result.update(extra)
                    process.stdin.write(json.dumps(result) + "\n")
                    process.stdin.flush()
                elif msg_type == "output":
                    self.outputs.append(msg)
                elif msg_type == "execution_finished":
                    self.finished = msg
                    break
        finally:
            try:
                process.stdin.close()
            except Exception:
                pass
            try:
                process.wait(timeout=15)
            except subprocess.TimeoutExpired:
                process.kill()
            for stream in (process.stdout, process.stderr):
                try:
                    stream.close()
                except Exception:
                    pass
        return self


def ok_responder():
    """全部回 9000 空响应的最小假卡。"""
    def respond(action):
        return 0x9000, b"", {}
    return respond


def follow_up_responder():
    """首次 APDU 先回 61XX，再首次回 91XX，验证传输层自动跟进。"""
    state = {"sent_61": False, "sent_91": False}

    def respond(action):
        if action["type"] != "APDU":
            return 0x9000, b"", {}
        ins = action["apdu"]["ins"]
        if ins == 0xC0:                      # GET RESPONSE
            return 0x9000, bytes.fromhex("A50102"), {}
        if ins == 0x12:                      # FETCH
            return 0x9000, bytes.fromhex("D00102"), {}
        if not state["sent_61"]:
            state["sent_61"] = True
            return 0x6128, bytes.fromhex("0102"), {}
        if not state["sent_91"]:
            state["sent_91"] = True
            return 0x9110, bytes.fromhex("0304"), {}
        return 0x9000, b"", {}
    return respond


SYSTEM_PYTHON = "/usr/bin/python3"      # 缺 pyasn1，用于验证「缺依赖」路径


def _drive_start(input_data, interpreter=None, env_overrides=None, timeout=60):
    """启动 main.py 子进程，喂一条 start，收集输出直到 execution_finished。"""
    env = dict(os.environ)
    env.update(env_overrides or {})
    env.pop("ESIM_SKILL_AUTO_INSTALL", None)
    env.pop("ESIM_SKILL_VENV_ACTIVE", None)
    process = subprocess.Popen(
        [interpreter or sys.executable, MAIN], cwd=ROOT, env=env, text=True,
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    outputs = []
    finished = None
    try:
        process.stdin.write(json.dumps({
            "type": "start", "executionId": "exec-env", "skillId": SKILL_ID,
            "input": input_data, "cardSession": {"readerId": None, "atr": None, "connected": False},
        }) + "\n")
        process.stdin.flush()
        deadline = time.time() + timeout
        while time.time() < deadline:
            line = process.stdout.readline()
            if not line:
                break
            msg = json.loads(line)
            if msg.get("type") == "output":
                outputs.append(msg)
            elif msg.get("type") == "execution_finished":
                finished = msg
                break
    finally:
        try:
            process.stdin.close()
        except Exception:
            pass
        try:
            process.wait(timeout=15)
        except subprocess.TimeoutExpired:
            process.kill()
        for stream in (process.stdout, process.stderr):
            try:
                stream.close()
            except Exception:
                pass
    return finished, outputs


class TestIpcContract(unittest.TestCase):
    """Skill ↔ Runtime IPC 契约（ipc-protocol.ts）"""

    def test_action_message_schema_and_reset_card(self):
        runtime = FakeRuntime(ok_responder()).run(_input())

        self.assertTrue(runtime.actions, "Skill 未发出任何 Action")
        # 所有 Action 必须符合协议 schema
        ids = []
        for action in runtime.actions:
            self.assertIn(action["type"], ACTION_TYPES)
            self.assertIsInstance(action["id"], str)
            self.assertTrue(action["id"], "action.id 不能为空")
            ids.append(action["id"])
            if action["type"] == "APDU":
                apdu = action["apdu"]
                for field in ("cla", "ins", "p1", "p2"):
                    self.assertIsInstance(apdu[field], int)
                if "data" in apdu:
                    self.assertTrue(all(isinstance(b, int) for b in apdu["data"]))
        # Action id 唯一（语义化前缀 + 序号）
        self.assertEqual(len(ids), len(set(ids)), f"action id 重复: {ids}")

        # 冷复位必须是 RESET_CARD（不能是占位 APDU），并跟一个 WAIT
        self.assertEqual(runtime.actions[0]["type"], "RESET_CARD")
        self.assertEqual(runtime.actions[1]["type"], "WAIT")
        self.assertIn("milliseconds", runtime.actions[1])
        # 语义化 id 前缀（step 标签 + 序号）
        self.assertTrue(runtime.actions[0]["id"].startswith("card.cold-start"),
                        runtime.actions[0]["id"])

    def test_transport_follow_ups_for_61xx_and_91xx(self):
        runtime = FakeRuntime(follow_up_responder()).run(_input())

        apdus = [a for a in runtime.actions if a["type"] == "APDU"]
        get_response = [a for a in apdus if a["apdu"]["ins"] == 0xC0]
        fetches = [a for a in apdus if a["apdu"]["ins"] == 0x12]

        self.assertTrue(get_response, "61XX 未触发 GET RESPONSE")
        self.assertEqual(get_response[0]["apdu"]["le"], 0x28)
        self.assertTrue(fetches, "91XX 未触发 FETCH")
        self.assertEqual(fetches[0]["apdu"]["le"], 0x10)
        # FETCH 使用逻辑通道 CLA（0x80 | channel）
        self.assertTrue(fetches[0]["apdu"]["cla"] & 0x80, hex(fetches[0]["apdu"]["cla"]))
        # 失败/完成上报：error 必须是字符串
        self.assertIsNotNone(runtime.finished)
        if runtime.finished["status"] != "SUCCESS":
            self.assertIsInstance(runtime.finished.get("error"), str)

    def test_action_failure_reports_string_error(self):
        runtime = FakeRuntime(ok_responder(), force_failure=True).run(_input())
        self.assertIsNotNone(runtime.finished)
        self.assertEqual(runtime.finished["status"], "FAILED")
        self.assertIsInstance(runtime.finished["error"], str)
        self.assertIn("ACTION_FAILED", runtime.finished["error"])

    def test_invalid_input_is_rejected(self):
        runtime = FakeRuntime(ok_responder()).run(_input(eid="123"))
        self.assertIsNotNone(runtime.finished)
        self.assertEqual(runtime.finished["status"], "FAILED")
        self.assertIsInstance(runtime.finished["error"], str)
        self.assertIn("INVALID_INPUT", runtime.finished["error"])


class TestEimEncodingRegression(unittest.TestCase):
    """eIM 报文与 Java 参考脚本实测报文一致"""

    def _flow(self) -> ProfileDownloadFlow:
        return ProfileDownloadFlow(
            eid=EID, smdp_address="testsmdpplus1.example.com",
            matching_id="04386-AGYFT-A74Y8-3F815", iccid=ICCID,
            profile_id="A0000005591010FFFFFFFF8900001000",
            smdp_plus=None, mode="indirect", eim_id=EIM_ID,
            eim_identity=_load_eim_identity(),
        )

    def test_bf57_matches_java_reference(self):
        flow = self._flow()
        actions = flow.execute_step(Step.ADD_INITIAL_EIM)
        self.assertTrue(actions)
        payload = b"".join(action.data for action in actions)
        # 分块规则：非末块 P1=0x11，末块 P1=0x91，块号从 0
        for index, action in enumerate(actions):
            self.assertEqual(action.ins, 0xE2)
            self.assertEqual(action.p1, 0x91 if index == len(actions) - 1 else 0x11)
            self.assertEqual(action.p2, index)
        self.assertEqual(payload.hex().upper()[:len(JAVA_BF57_PREFIX)], JAVA_BF57_PREFIX)
        self.assertEqual(len(payload), 394)
        # AddInitialEimResponse(alreadyExists) 容错
        self.assertFalse(verify_add_initial_eim_ok(bytes.fromhex("BF5703810102"), True))

    def test_bf51_matches_java_reference(self):
        flow = self._flow()
        actions = flow.execute_step(Step.LOAD_EUICC_PACKAGE_ENABLE)
        self.assertEqual(len(actions), 1)
        payload = actions[0].data
        self.assertEqual(payload.hex().upper()[:len(JAVA_BF51_PREFIX)], JAVA_BF51_PREFIX)
        signed, signature = decode_euicc_package_request(payload)
        self.assertTrue(verify_euicc_package(signed, signature, _load_eim_identity().certificate))

    def test_verify_enable_result(self):
        with self.assertRaises(Sgp32CodecError):
            verify_enable_result_ok(b"")           # 空响应（本卡实测）由调用方容错
        with self.assertRaises(Sgp32CodecError):
            verify_enable_result_ok(bytes.fromhex("00"))


class TestCardResponseParsing(unittest.TestCase):
    """真卡响应解析回归（报文取自 Java 参考日志）"""

    def test_notification_sequences_accepts_one_byte_seq(self):
        sequences = ProfileDownloadFlow._notification_sequences(
            bytes.fromhex(CARD_BF28_ONE_NOTIFICATION))
        self.assertEqual(sequences, [b"\x00\x0f"])   # seq=15，补齐 2 字节
        self.assertEqual(ProfileDownloadFlow._notification_sequences(
            bytes.fromhex("BF280381017F")), [])       # 空列表/错误响应
        self.assertEqual(ProfileDownloadFlow._notification_sequences(None), [])

    def test_profile_state_disabled_from_real_card(self):
        state, aid = ProfileDownloadFlow._parse_profile_state(
            bytes.fromhex(CARD_BF2D_DISABLED))
        self.assertEqual(state, 0)
        self.assertEqual(aid, "A0000005591010FFFFFFFF8900001400")

    def test_profile_state_enabled(self):
        enabled = CARD_BF2D_DISABLED.replace("9F700100", "9F700101")
        state, _ = ProfileDownloadFlow._parse_profile_state(bytes.fromhex(enabled))
        self.assertEqual(state, 1)


class TestFlowSemantics(unittest.TestCase):
    """批次语义 / Step 枚举"""

    def test_multi_action_batch_advances_once(self):
        flow = ProfileDownloadFlow(
            eid=EID, smdp_address="a", matching_id="matching", iccid=ICCID,
            profile_id="A0000005591010FFFFFFFF8900001000", smdp_plus=None,
            mode="direct",
        )
        first = flow.execute_step(Step.COLD_START)
        self.assertEqual([type(a).__name__ for a in first], ["ResetCardAction", "WaitAction"])
        self.assertEqual(flow.get_current_step(), int(Step.PREP_SELECT_MF))
        # PREP_STATUS_CHANNEL 是一个多动作批次
        flow.next_step(Step.PREP_STATUS_CHANNEL)
        batch = flow.execute_step(Step.PREP_STATUS_CHANNEL)
        self.assertEqual(len(batch), 2)
        self.assertEqual(flow.get_current_step(), int(Step.PREP_SELECT_ISDR))
        # 通道号来自 MANAGE_CHANNEL 响应
        isdr = flow.execute_step(Step.PREP_SELECT_ISDR, apdu_response=b"\x03", sw="9000")
        self.assertEqual(len(isdr), 1)
        self.assertEqual(flow.logical_channel, 3)
        self.assertEqual(isdr[0].cla, 3)

    def test_direct_mode_skips_eim_steps(self):
        flow = ProfileDownloadFlow(
            eid=EID, smdp_address="a", matching_id="matching", iccid=ICCID,
            profile_id="A0000005591010FFFFFFFF8900001000", smdp_plus=None,
            mode="direct",
        )
        self.assertEqual(flow.execute_step(Step.ADD_INITIAL_EIM), [])
        self.assertEqual(flow.get_current_step(), int(Step.POST_ENABLE_RESET))

    def test_indirect_mode_requires_eim_identity(self):
        with self.assertRaises(Exception):
            ProfileDownloadFlow(
                eid=EID, smdp_address="a", matching_id="matching", iccid=ICCID,
                profile_id="A0000005591010FFFFFFFF8900001000", smdp_plus=None,
                mode="indirect", eim_id=EIM_ID,
            )


class TestRuntimeEnvironmentBootstrap(unittest.TestCase):
    """技能自带运行环境自检（Runtime 不管理依赖，入口需自行切换到自带环境）"""

    def setUp(self):
        import main as skill_main
        self.skill_main = skill_main

    def test_venv_candidates_order_and_override(self):
        package_dir = "/tmp/skill-pkg"
        candidates = self.skill_main.venv_python_candidates(package_dir)
        self.assertEqual(candidates[:2], [
            "/tmp/skill-pkg/.venv/bin/python",
            "/tmp/skill-pkg/.venv/Scripts/python.exe",
        ])
        self.assertIn("/tmp/skill-pkg/venv/bin/python", candidates)
        # ESIM_SKILL_VENV 覆盖优先
        os.environ["ESIM_SKILL_VENV"] = "/opt/esim-env"
        try:
            overridden = self.skill_main.venv_python_candidates(package_dir)
            self.assertEqual(overridden[0], "/opt/esim-env/bin/python")
        finally:
            del os.environ["ESIM_SKILL_VENV"]

    def test_current_interpreter_has_dependencies(self):
        # 测试进程（venv）应具备运行依赖
        self.assertTrue(self.skill_main.current_interpreter_has_dependencies())

    def test_missing_env_reports_env_not_ready(self):
        """缺依赖且无自带环境 → 业务操作返回 FAILED ENV_NOT_READY（不再以退出码 3 静默退出）"""
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            finished, outputs = _drive_start(
                {"operation": "install_and_enable", "eid": "89049032123451234512345678901235",
                 "smdp_address": "a", "matching_id": "matching", "iccid": "8929901012345678905",
                 "profile_id": "A0000005591010FFFFFFFF8900001000"},
                interpreter=SYSTEM_PYTHON,
                env_overrides={"SKILL_PACKAGE_PATH": tmp,
                               "ESIM_SKILL_VENV": os.path.join(tmp, "nope")},
            )
        self.assertIsNotNone(finished)
        self.assertEqual(finished["status"], "FAILED")
        self.assertIn("ENV_NOT_READY", finished["error"])
        self.assertIn("setup_env", finished["error"])

    def test_setup_env_available_without_dependencies(self):
        """缺依赖时仍能执行 setup_env（只用标准库路径），安装方式走 uv"""
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            stub_bin = os.path.join(tmp, "bin")
            os.makedirs(stub_bin)
            real_python = sys.executable          # 具备依赖的解释器（模拟 uv 装出来的环境）
            uv_stub = os.path.join(stub_bin, "uv")
            # 伪 uv：venv → 造出一个可用的解释器 shim（转发到测试解释器，即"已装好依赖"的环境）；
            #          pip → 直接成功。用于离线验证 setup_env 的 uv 分支与依赖校验逻辑。
            with open(uv_stub, "w") as fh:
                fh.write("#!/bin/sh\n"
                         "case \"$1\" in\n"
                         "  venv)\n"
                         "    dir=\"$2\"; mkdir -p \"$dir/bin\"\n"
                         "    printf 'home = /usr\ninclude-system-site-packages = false\n' > \"$dir/pyvenv.cfg\"\n"
                         "    printf '#!/bin/sh\\nexec " + real_python + " \"$@\"\\n' > \"$dir/bin/python\"\n"
                         "    chmod +x \"$dir/bin/python\" ;;\n"
                         "  pip) exit 0 ;;\n"
                         "esac\n"
                         "exit 0\n")
            os.chmod(uv_stub, 0o755)

            package_dir = os.path.join(tmp, "pkg")
            os.makedirs(package_dir)
            with open(os.path.join(package_dir, "requirements.txt"), "w") as fh:
                fh.write("cryptography\npyasn1\n")

            finished, outputs = _drive_start(
                {"operation": "setup_env"},
                interpreter=SYSTEM_PYTHON,
                env_overrides={"SKILL_PACKAGE_PATH": package_dir,
                               "ESIM_SKILL_VENV": os.path.join(tmp, "nope"),
                               "PATH": stub_bin + os.pathsep + os.environ.get("PATH", "")},
            )

        self.assertIsNotNone(finished)
        self.assertEqual(finished["status"], "SUCCESS", finished.get("error"))
        data = finished.get("data") or {}
        self.assertEqual(data.get("method"), "uv")
        self.assertEqual(data.get("status"), "installed")
        self.assertTrue(str(data.get("env_path", "")).endswith(os.path.join("pkg", ".venv")))
        self.assertIn("pyasn1", data.get("dependencies") or {})

    def test_setup_env_already_satisfied(self):
        """已有环境时 setup_env 直接返回 already_satisfied（不重复安装）"""
        finished, outputs = _drive_start(
            {"operation": "setup_env"},
            env_overrides={"SKILL_PACKAGE_PATH": ROOT},
        )
        self.assertIsNotNone(finished)
        self.assertEqual(finished["status"], "SUCCESS", finished.get("error"))
        self.assertEqual((finished.get("data") or {}).get("status"), "already_satisfied")

    def test_switches_to_package_venv_when_current_lacks_deps(self):
        """当前解释器缺依赖、自带环境可用 → os.execv 切换到自带环境解释器"""
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            venv_bin = os.path.join(tmp, ".venv", "bin")
            os.makedirs(venv_bin)
            fake_python = os.path.join(venv_bin, "python")
            with open(fake_python, "w") as fh:
                fh.write("#!/bin/sh\nexit 0\n")   # 依赖探测（import ...）视为成功
            os.chmod(fake_python, 0o755)

            script = (
                "import main, os;"
                "record = [];"
                "main.current_interpreter_has_dependencies = lambda: False;"
                "main.interpreter_has_dependencies = lambda exe, timeout=30: os.path.exists(exe);"
                "main.os.execv = lambda exe, argv: record.append((exe, argv));"
                "main.bootstrap_runtime_environment();"
                "print(record[0][0]);"
                "print(record[0][1][1]);"
                "print(os.environ.get('ESIM_SKILL_VENV_ACTIVE'))"
            )
            env = dict(os.environ)
            env["SKILL_PACKAGE_PATH"] = tmp
            env.pop("ESIM_SKILL_VENV_ACTIVE", None)
            completed = subprocess.run(
                [sys.executable, "-c", script], cwd=ROOT, env=env, text=True,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            lines = completed.stdout.strip().splitlines()
            self.assertEqual(lines[0], fake_python)
            self.assertTrue(lines[1].endswith("main.py"))
            self.assertEqual(lines[2], "1")     # 防重入标记


if __name__ == '__main__':
    unittest.main()
