#!/usr/bin/env python3
"""eSIM IoT Profile Download Skill - 入口（Python Skill）

与 SmartCard Skill Runtime 通过 JSON Lines IPC 通信：

  Runtime → Skill: start / action_result / stop
  Skill → Runtime: skill_action / output / execution_finished

协议字段严格对齐 `packages/core/src/smartcard/runtime/ipc-protocol.ts`：
  * action_result.response = { sw: number, data: number[] }；RESET_CARD 结果带 atr
  * execution_finished.error 为字符串；日志一律写 stderr（stdout 只输出 JSON）
  * Skill 不直接操作读卡器：所有卡片操作都以 Action（APDU / RESET_CARD / WAIT）交给 Runtime
"""

import json
import os
import sys
import logging
from typing import Any, Dict, List, Optional

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from src.apdu_builder import ApduCommand
from src.profile_download import ProfileDownloadFlow, ProfileDownloadError
from src.smdp_plus import LocalSmdpPlus
from src.pki_manager import PkiIdentity, load_private_key_from_pem, load_certificate_from_der
from src.profile_package_store import ProfilePackageStore, ProfilePackageTemplate
from src.skill_actions import to_ipc
from src.utils import validate_eid, validate_iccid, validate_matching_id

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    stream=sys.stderr,
)
logger = logging.getLogger(__name__)

REQUIRED_MODULES = ("cryptography", "pyasn1")

# 单条 APDU 的 61XX/91XX 自动跟进次数上限（防死循环）
MAX_TRANSPORT_FOLLOW_UPS = 16
# 连续「无动作步骤」上限（verify/round-check 等空批次）
MAX_EMPTY_STEPS = 64


# ------------------------------------------------------------------ IPC

def send_message(msg: Dict[str, Any]):
    sys.stdout.write(json.dumps(msg) + "\n")
    sys.stdout.flush()


def read_message() -> Optional[Dict[str, Any]]:
    line = sys.stdin.readline()
    return json.loads(line) if line else None


def send_output(execution_id: str, level: str, message: str, data: Optional[Dict] = None):
    msg = {"type": "output", "executionId": execution_id, "level": level, "message": message}
    if data:
        msg["data"] = data
    send_message(msg)


def send_action(execution_id: str, action) -> None:
    send_message({"type": "skill_action", "executionId": execution_id, "action": to_ipc(action)})


def send_finished(execution_id: str, status: str, data: Optional[Dict] = None,
                  error: Optional[str] = None):
    """status ∈ SUCCESS | FAILED | CANCELLED；error 按协议为字符串。"""
    msg: Dict[str, Any] = {"type": "execution_finished", "executionId": execution_id, "status": status}
    if data:
        msg["data"] = data
    if error:
        msg["error"] = error
    send_message(msg)


def check_runtime_dependencies() -> Optional[str]:
    """运行前检查依赖（Runtime 不会自动安装依赖，见 Design v2.4 §9）。"""
    missing = []
    for module in REQUIRED_MODULES:
        try:
            __import__(module)
        except ImportError:
            missing.append(module)
    if missing:
        return (f"缺少 Python 依赖: {', '.join(missing)}；"
                f"请用 Runtime 使用的解释器安装：pip install -r requirements.txt")
    return None


def validate_input(input_data: Dict[str, Any]) -> Optional[str]:
    if input_data.get("operation") != "install_and_enable":
        return f"Unsupported operation: {input_data.get('operation')}"
    if not input_data.get("eid") or not validate_eid(input_data["eid"]):
        return "eid is required (32 digits)"
    if not input_data.get("smdp_address"):
        return "smdp_address is required"
    if not input_data.get("matching_id") or not validate_matching_id(input_data["matching_id"]):
        return "matching_id is required (5-32 chars)"
    if not input_data.get("iccid") or not validate_iccid(input_data["iccid"]):
        return "iccid is required (10-20 digits)"
    if not input_data.get("profile_id"):
        return "profile_id is required"
    if input_data.get("mode", "indirect") == "indirect" and not input_data.get("eim_id"):
        return "eim_id is required for indirect mode"
    return None


# ------------------------------------------------------- 资源加载

def default_resources_dir() -> str:
    """默认资源目录：Runtime 通过 SKILL_PACKAGE_PATH 告知技能包路径。"""
    package_path = os.environ.get("SKILL_PACKAGE_PATH") or os.path.dirname(os.path.abspath(__file__))
    return os.path.join(package_path, "resources")


def load_identity(key_path: str, cert_path: str) -> PkiIdentity:
    key = load_private_key_from_pem(open(key_path, 'rb').read())
    cert = load_certificate_from_der(open(cert_path, 'rb').read())
    return PkiIdentity(key, [cert])


def load_pki_from_resources(resources_dir: str) -> Dict[str, Any]:
    """加载 DPauth / DPpb / CI，以及（可选的）eIM 证书与私钥。

    目录结构：
        resources_dir/certs/
            SK_S_SM_DPauth_ECDSA_NIST.pem      CERT_S_SM_DPauth_ECDSA_NIST.der
            SK_S_SM_DPpb_ECDSA_NIST.pem        CERT_S_SM_DPpb_ECDSA_NIST.der
            CERT_CI_ECDSA_NIST.pem
            SK_EIM_ECDSA_NIST.pem              CERT_EIM_ECDSA_NIST.der   (间接模式)
    """
    from src.pki_manager import load_certificate_from_pem

    certs_dir = os.path.join(resources_dir, "certs")
    if not os.path.exists(certs_dir):
        raise FileNotFoundError(f"Certs directory not found: {certs_dir}")

    dp_auth = load_identity(
        os.path.join(certs_dir, "SK_S_SM_DPauth_ECDSA_NIST.pem"),
        os.path.join(certs_dir, "CERT_S_SM_DPauth_ECDSA_NIST.der"),
    )
    dp_pb = load_identity(
        os.path.join(certs_dir, "SK_S_SM_DPpb_ECDSA_NIST.pem"),
        os.path.join(certs_dir, "CERT_S_SM_DPpb_ECDSA_NIST.der"),
    )
    ci_cert = load_certificate_from_pem(
        open(os.path.join(certs_dir, "CERT_CI_ECDSA_NIST.pem"), 'rb').read()
    )

    eim_identity: Optional[PkiIdentity] = None
    eim_key_path = os.path.join(certs_dir, "SK_EIM_ECDSA_NIST.pem")
    eim_cert_path = os.path.join(certs_dir, "CERT_EIM_ECDSA_NIST.der")
    if os.path.exists(eim_key_path) and os.path.exists(eim_cert_path):
        eim_identity = load_identity(eim_key_path, eim_cert_path)

    return {
        "dp_auth_identity": dp_auth,
        "dp_pb_identity": dp_pb,
        "ci_cert": ci_cert,
        "eim_identity": eim_identity,
    }


def load_profile_payload(resources_dir: str, iccid: str) -> bytes:
    """加载 Profile Payload（UPP）：优先匹配 ICCID，其次默认文件名。"""
    import glob

    profiles_dir = os.path.join(resources_dir, "profiles")
    if not os.path.exists(profiles_dir):
        logger.warning(f"Profiles directory not found: {profiles_dir}, using empty payload")
        return b''

    candidates = glob.glob(os.path.join(profiles_dir, f"*{iccid}*"))
    if not candidates:
        for name in ("PROFILE_OPERATIONAL1.HEX", "PROFILE_OPERATIONAL1.bin"):
            path = os.path.join(profiles_dir, name)
            if os.path.exists(path):
                candidates = [path]
                break
    if not candidates:
        logger.warning(f"No profile payload found in {profiles_dir}, using empty payload")
        return b''

    upp_file = candidates[0]
    if upp_file.lower().endswith(".bin"):
        return open(upp_file, 'rb').read()
    text = open(upp_file, 'r').read().strip()
    return bytes.fromhex(text.replace(" ", "").replace("\n", "").replace("\r", ""))


def load_profile_icon(resources_dir: str):
    """加载 Profile 图标：返回 (icon_bytes, icon_type)。

    对齐 Java 参考脚本（ICON_TYPE_PNG=1 + icon 文件）：StoreMetadata(BF25) 的
    93/94 字段需要一并提供，本测试卡会校验 storeMetadata 内容。
    """
    profiles_dir = os.path.join(resources_dir, "profiles")
    for name, icon_type in (("icon1.png", 1), ("icon1.jpg", 2), ("icon1.jpeg", 2)):
        path = os.path.join(profiles_dir, name)
        if os.path.exists(path):
            return open(path, 'rb').read(), icon_type
    return None, 0


# ------------------------------------------------------- 执行器

class ProfileDownloadExecutor:
    """一次 Execution 的驱动：Action 批次派发 + 传输层跟进 + 流程推进。

    Session 隔离（Dev Spec v1.1 §7）：每次 `start` 都会新建执行器实例。
    输出/动作/结束三类事件通过 sink 注入：默认走 Runtime IPC，
    测试（含真卡连线）可注入自己的 sink 复用同一套循环逻辑。
    """

    def __init__(self, input_data: Dict[str, Any], resources_dir: Optional[str] = None,
                 execution_id: str = "local",
                 action_sink=None, output_sink=None, finish_sink=None):
        self.input = input_data
        self.execution_id = execution_id
        self._action_sink = action_sink or (lambda action: send_action(self.execution_id, action))
        self._output_sink = output_sink or (
            lambda level, message, data=None: send_output(self.execution_id, level, message, data))
        self._finish_sink = finish_sink or (
            lambda status, data=None, error=None: send_finished(self.execution_id, status, data, error))

        resources_dir = resources_dir or default_resources_dir()
        pki = load_pki_from_resources(resources_dir)
        icon_payload, detected_icon_type = load_profile_icon(resources_dir)
        icon_type = int(input_data.get("icon_type", detected_icon_type if icon_payload else 0))
        icon = icon_payload if icon_type > 0 else None

        packages = ProfilePackageStore()
        packages.save(ProfilePackageTemplate(
            matching_id=input_data["matching_id"],
            profile_id=input_data["profile_id"],
            profile_name=input_data.get("profile_name", "IoT Profile"),
            iccid=input_data["iccid"],
            service_provider_name=input_data.get("spn", ""),
            profile_class=input_data.get("profile_class", 2),
            payload=load_profile_payload(resources_dir, input_data["iccid"]),
            icon=icon,
            icon_type=icon_type,
        ))

        self.smdp_plus = LocalSmdpPlus(
            packages=packages,
            dp_auth_identity=pki["dp_auth_identity"],
            dp_profile_binding_identity=pki["dp_pb_identity"],
            trusted_root_certificate=pki["ci_cert"],
        )
        self.flow = ProfileDownloadFlow(
            eid=input_data["eid"],
            smdp_address=input_data["smdp_address"],
            matching_id=input_data["matching_id"],
            iccid=input_data["iccid"],
            profile_id=input_data["profile_id"],
            smdp_plus=self.smdp_plus,
            mode=input_data.get("mode", "indirect"),
            eim_id=input_data.get("eim_id"),
            eim_identity=pki["eim_identity"],
            eim_initial_counter=int(input_data.get("eim_initial_counter", 1)),
            eim_enable_counter=int(input_data.get("eim_enable_counter", 2)),
            tac=bytes.fromhex(input_data.get("tac", "00000000")),
            total_rounds=int(input_data.get("rounds", 1)),
        )

        self.pending: List[object] = []          # 当前批次未派发的 Action
        self.pending_data = bytearray()          # 当前 APDU 累积的响应数据（含 61XX/91XX）
        self.last_cla: Optional[int] = None      # 用于 61XX/91XX 的 CLA
        self.follow_ups: int = 0
        self.last_response: Optional[bytes] = None
        self.last_sw: Optional[str] = None
        self.finished_status: Optional[str] = None
        self.finished_data: Optional[Dict[str, Any]] = None
        self.finished_error: Optional[str] = None

    # ---------------------------------------------------------- 生命周期

    def start(self, execution_id: Optional[str] = None):
        if execution_id:
            self.execution_id = execution_id
        self._output("INFO",
                     f"Starting Profile Download - Mode: {self.flow.mode}, Rounds: {self.flow.total_rounds}")
        self._run_flow(None, None)

    def stop(self, reason: str = ""):
        self._output("WARN", f"Execution stopped: {reason}")
        self._finish("CANCELLED", error=f"CANCELLED: {reason}")

    def _output(self, level: str, message: str, data: Optional[Dict] = None):
        self._output_sink(level, message, data)

    def _action(self, action):
        self._action_sink(action)

    def _finish(self, status: str, data: Optional[Dict] = None, error: Optional[str] = None):
        self.finished_status, self.finished_data, self.finished_error = status, data, error
        self._finish_sink(status, data, error)

    # ---------------------------------------------------- Action 结果处理

    def handle_action_result(self, msg: Dict[str, Any]):
        action_id = msg.get("actionId") or ""
        action_type = msg.get("actionType") or ""

        if not msg.get("success", False):
            self._fail("ACTION_FAILED",
                       f"动作 {action_id} 执行失败：{msg.get('error') or 'unknown error'}")
            return

        if action_type == "APDU":
            self._handle_apdu_result(action_id, msg.get("response") or {})
        elif action_type == "RESET_CARD":
            self.flow.atr = msg.get("atr")
            self._output("INFO", f"卡片已冷复位 ATR={msg.get('atr')}")
            self._reset_transport_state()
            self._pump(b"", "9000")
        elif action_type == "WAIT":
            self._pump(self.last_response, self.last_sw)
        else:
            self._pump(self.last_response, self.last_sw)

    def _handle_apdu_result(self, action_id: str, response: Dict[str, Any]):
        data = bytes(response.get("data") or [])
        sw = int(response.get("sw") or 0)
        self.pending_data += data

        sw1, sw2 = (sw >> 8) & 0xFF, sw & 0xFF

        # T=0 大响应：61XX 需 GET RESPONSE（Runtime 只做单条 APDU 透传，不自动跟进）
        if sw1 == 0x61 and self.follow_ups < MAX_TRANSPORT_FOLLOW_UPS:
            self.follow_ups += 1
            le = sw2 or 256
            self._action(ApduCommand(cla=self.last_cla or 0x00, ins=0xC0, p1=0x00, p2=0x00, le=le,
                                     action_id=f"{action_id}.get-response",
                                     name="GET RESPONSE",
                                     description="T=0 大响应后续读取"))
            return

        # eUICC 异步响应：91XX 需 FETCH
        if sw1 == 0x91 and self.follow_ups < MAX_TRANSPORT_FOLLOW_UPS:
            self.follow_ups += 1
            le = sw2 or 256
            self._action(ApduCommand(cla=0x80 | ((self.last_cla or 0x00) & 0x0F), ins=0x12,
                                     p1=0x00, p2=0x00, le=le,
                                     action_id=f"{action_id}.fetch",
                                     name="FETCH",
                                     description="eUICC 异步响应 FETCH"))
            return

        response_bytes = bytes(self.pending_data)
        sw_str = f"{sw:04X}"
        self._reset_transport_state()
        self.last_response, self.last_sw = response_bytes, sw_str
        self._output("INFO", f"{action_id} 完成 SW={sw_str} (data={len(response_bytes)}B)")
        self._pump(response_bytes, sw_str)

    def _reset_transport_state(self):
        self.pending_data = bytearray()
        self.follow_ups = 0

    # --------------------------------------------------------- 流程推进

    def _pump(self, response: Optional[bytes], sw: Optional[str]):
        """先派发当前批次剩余 Action；批次结束后再让流程产出下一批。"""
        if self.pending:
            self._dispatch(self.pending.pop(0))
            return
        self._run_flow(response, sw)

    def _dispatch(self, action):
        self.last_cla = getattr(action, "cla", None)
        self._action(action)

    def _run_flow(self, response: Optional[bytes], sw: Optional[str]):
        try:
            for _ in range(MAX_EMPTY_STEPS):
                actions = self.flow.execute_step(self.flow.get_current_step(), response, sw)
                if self.flow.finished or self.flow.get_current_step() == -1:
                    self._finish_success()
                    return
                if actions:
                    self.pending = list(actions)
                    self._dispatch(self.pending.pop(0))
                    return
                # 空批次（校验/轮次等步骤）：沿用同一响应继续推进
                self._output("INFO", "步骤完成（无动作）")
        except ProfileDownloadError as e:
            self._fail("PROFILE_DOWNLOAD_ERROR", str(e))
            return
        except Exception as e:  # 协议/编码等未预期错误
            logger.error(f"Flow error: {e}", exc_info=True)
            self._fail("INTERNAL_ERROR", str(e))
            return
        self._fail("INTERNAL_ERROR", "流程未推进，疑似死循环（MAX_EMPTY_STEPS 超限）")

    def _finish_success(self):
        summary = self.flow.result_summary()
        if summary.get("verified"):
            self._output("INFO",
                         f"Profile 已启用：ICCID={summary['iccid']} State=ENABLED")
        else:
            self._output("WARN",
                         f"流程执行完成，但 profileState={summary.get('profile_state')}"
                         f"（未达 ENABLED）；notes="
                         f"{summary.get('warnings') or summary.get('enable_result_note')}")
        self._finish("SUCCESS", data=summary)

    def _fail(self, code: str, message: str):
        self._output("ERROR", message)
        self._finish("FAILED", error=f"{code}: {message}")


def main():
    executor: Optional[ProfileDownloadExecutor] = None

    while True:
        msg = read_message()
        if msg is None:
            break

        msg_type = msg.get("type")

        if msg_type == "start":
            execution_id = msg["executionId"]
            input_data = msg.get("input", {}) or {}

            error = check_runtime_dependencies() or validate_input(input_data)
            if error:
                send_finished(execution_id, "FAILED", error=f"INVALID_INPUT: {error}")
                continue

            try:
                executor = ProfileDownloadExecutor(input_data, input_data.get("resources_dir"),
                                                   execution_id=execution_id)
            except Exception as e:  # 资源/PKI/eIM 等初始化失败
                logger.error(f"Executor init failed: {e}", exc_info=True)
                send_finished(execution_id, "FAILED", error=f"INIT_FAILED: {e}")
                continue
            executor.start()

        elif msg_type == "action_result":
            if executor:
                executor.handle_action_result(msg)

        elif msg_type == "stop":
            if executor:
                executor.stop(msg.get("reason", ""))
            break


if __name__ == "__main__":
    main()
