#!/usr/bin/env python3
"""
eSIM IoT Profile Download Skill - 主入口

通过 JSON Lines IPC 与 SmartCard Skill Runtime 通信。
"""

import json
import sys
import os
import logging
from typing import Optional, Dict, Any, List

# 添加 src 到路径
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from src.profile_download import ProfileDownloadFlow, ProfileDownloadError
from src.smdp_plus import LocalSmdpPlus, SmdpPlusError
from src.pki_manager import PkiIdentity, load_private_key_from_pem, load_certificate_from_der
from src.profile_package_store import ProfilePackageStore, ProfilePackageTemplate
from src.utils import validate_eid, validate_iccid, validate_matching_id

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    stream=sys.stderr
)
logger = logging.getLogger(__name__)


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


def send_action(execution_id: str, action: Dict[str, Any]):
    send_message({"type": "skill_action", "executionId": execution_id, "action": action})


def send_finished(execution_id: str, status: str, data: Optional[Dict] = None, error: Optional[Dict] = None):
    msg = {"type": "execution_finished", "executionId": execution_id, "status": status}
    if data:
        msg["data"] = data
    if error:
        msg["error"] = error
    send_message(msg)


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


def build_apdu_action(apdu) -> Dict[str, Any]:
    action = {
        "id": f"apdu_{apdu.cla:02X}_{apdu.ins:02X}",
        "type": "APDU",
        "name": f"APDU CLA={apdu.cla:02X} INS={apdu.ins:02X}",
        "apdu": {"cla": apdu.cla, "ins": apdu.ins, "p1": apdu.p1, "p2": apdu.p2},
    }
    if apdu.data:
        action["apdu"]["data"] = list(apdu.data)
    if apdu.le is not None:
        action["apdu"]["le"] = apdu.le
    return action


def load_pki_from_resources(resources_dir: str) -> tuple:
    """
    从 resources 目录加载 PKI 证书和密钥
    
    目录结构:
        resources_dir/
        ├── certs/
        │   ├── SK_S_SM_DP_TLS_NIST.pem      (DPauth 私钥)
        │   ├── CERT_S_SM_DP_TLS_NIST.der    (DPauth 证书)
        │   ├── SK_S_SM_DPpb_ECDSA_NIST.pem  (DP Profile Binding 私钥)
        │   ├── CERT_S_SM_DPpb_ECDSA_NIST.der (DP Profile Binding 证书)
        │   └── CERT_CI_ECDSA_NIST.pem       (CI 根证书)
        └── profiles/
            └── PROFILE_OPERATIONAL1.HEX     (UPP Profile 文件)
    """
    import glob
    
    certs_dir = os.path.join(resources_dir, "certs")
    if not os.path.exists(certs_dir):
        raise FileNotFoundError(f"Certs directory not found: {certs_dir}")
    
    # 加载 DPauth 私钥和证书
    dp_auth_key_files = sorted(glob.glob(os.path.join(certs_dir, "SK_S_SM_DP*.pem")))
    dp_auth_cert_files = sorted(glob.glob(os.path.join(certs_dir, "CERT_S_SM_DP*.der")))
    
    if not dp_auth_key_files or not dp_auth_cert_files:
        raise FileNotFoundError(
            f"DPauth certificates not found in {certs_dir}\n"
            f"Expected: SK_S_SM_DP*.pem and CERT_S_SM_DP*.der"
        )
    
    dp_auth_key = load_private_key_from_pem(open(dp_auth_key_files[0], 'rb').read())
    dp_auth_cert = load_certificate_from_der(open(dp_auth_cert_files[0], 'rb').read())
    
    # 加载 DP Profile Binding 私钥和证书
    dp_pb_key_files = sorted(glob.glob(os.path.join(certs_dir, "SK_S_SM_DPpb*.pem")))
    dp_pb_cert_files = sorted(glob.glob(os.path.join(certs_dir, "CERT_S_SM_DPpb*.der")))
    
    if not dp_pb_key_files or not dp_pb_cert_files:
        raise FileNotFoundError(
            f"DP Profile Binding certificates not found in {certs_dir}\n"
            f"Expected: SK_S_SM_DPpb*.pem and CERT_S_SM_DPpb*.der"
        )
    
    dp_pb_key = load_private_key_from_pem(open(dp_pb_key_files[0], 'rb').read())
    dp_pb_cert = load_certificate_from_der(open(dp_pb_cert_files[0], 'rb').read())
    
    # 加载 CI 根证书
    ci_cert_files = sorted(glob.glob(os.path.join(certs_dir, "CERT_CI*.pem")))
    if not ci_cert_files:
        raise FileNotFoundError(
            f"CI root certificate not found in {certs_dir}\n"
            f"Expected: CERT_CI*.pem"
        )
    
    ci_cert = load_certificate_from_pem(open(ci_cert_files[0], 'rb').read())
    
    return (
        PkiIdentity(dp_auth_key, [dp_auth_cert]),
        PkiIdentity(dp_pb_key, [dp_pb_cert]),
        ci_cert,
    )


def load_profile_payload(resources_dir: str, iccid: str) -> bytes:
    """
    从 resources 目录加载 Profile Payload (UPP)
    
    支持格式:
        - profiles/PROFILE_OPERATIONAL1_<ICCID>.HEX  (十六进制文本文件)
        - profiles/PROFILE_OPERATIONAL1_<ICCID>.bin  (二进制文件)
        - profiles/PROFILE_OPERATIONAL1.HEX          (默认文件)
    """
    import glob
    
    profiles_dir = os.path.join(resources_dir, "profiles")
    if not os.path.exists(profiles_dir):
        # 如果没有 profiles 目录，返回空 payload
        logger.warning(f"Profiles directory not found: {profiles_dir}, using empty payload")
        return b''
    
    # 尝试按 ICCID 匹配
    iccid_pattern = os.path.join(profiles_dir, f"*{iccid}*")
    iccid_files = glob.glob(iccid_pattern)
    
    if iccid_files:
        # 优先使用匹配 ICCID 的文件
        upp_file = iccid_files[0]
    else:
        # 使用默认文件
        default_hex = os.path.join(profiles_dir, "PROFILE_OPERATIONAL1.HEX")
        default_bin = os.path.join(profiles_dir, "PROFILE_OPERATIONAL1.bin")
        
        if os.path.exists(default_hex):
            upp_file = default_hex
        elif os.path.exists(default_bin):
            upp_file = default_bin
        else:
            logger.warning(f"No profile payload found in {profiles_dir}, using empty payload")
            return b''
    
    # 加载文件
    if upp_file.endswith('.HEX') or upp_file.endswith('.hex'):
        # 十六进制文本文件
        hex_content = open(upp_file, 'r').read().strip()
        return bytes.fromhex(hex_content.replace(" ", "").replace("\n", "").replace("\r", ""))
    elif upp_file.endswith('.bin'):
        # 二进制文件
        return open(upp_file, 'rb').read()
    else:
        # 尝试作为十六进制文本读取
        try:
            hex_content = open(upp_file, 'r').read().strip()
            return bytes.fromhex(hex_content.replace(" ", "").replace("\n", "").replace("\r", ""))
        except ValueError:
            # 作为二进制文件读取
            return open(upp_file, 'rb').read()


def load_pki_from_pem_der(
    dp_auth_key_pem: bytes,
    dp_auth_cert_der: bytes,
    dp_pb_key_pem: bytes,
    dp_pb_cert_der: bytes,
    ci_cert_pem: bytes,
) -> tuple:
    """从 PEM/DER 数据加载 PKI"""
    from src.pki_manager import load_certificate_from_pem
    
    dp_auth_key = load_private_key_from_pem(dp_auth_key_pem)
    dp_auth_cert = load_certificate_from_der(dp_auth_cert_der)
    dp_pb_key = load_private_key_from_pem(dp_pb_key_pem)
    dp_pb_cert = load_certificate_from_der(dp_pb_cert_der)
    ci_cert = load_certificate_from_pem(ci_cert_pem)
    
    return (
        PkiIdentity(dp_auth_key, [dp_auth_cert]),
        PkiIdentity(dp_pb_key, [dp_pb_cert]),
        ci_cert,
    )


class ProfileDownloadExecutor:
    """Profile 下载执行器"""
    
    def __init__(self, input_data: Dict[str, Any], resources_dir: Optional[str] = None):
        self.input = input_data
        
        # 初始化 PKI
        if resources_dir:
            dp_auth_identity, dp_pb_identity, ci_cert = load_pki_from_resources(resources_dir)
        else:
            # 使用输入中的证书数据
            dp_auth_identity, dp_pb_identity, ci_cert = load_pki_from_pem_der(
                input_data.get("dp_auth_key_pem", b""),
                input_data.get("dp_auth_cert_der", b""),
                input_data.get("dp_pb_key_pem", b""),
                input_data.get("dp_pb_cert_der", b""),
                input_data.get("ci_cert_pem", b""),
            )
        
        # 加载 Profile Payload (UPP)
        if resources_dir:
            upp_payload = load_profile_payload(resources_dir, input_data["iccid"])
        else:
            # 从输入参数获取 (base64 编码或直接传入 hex)
            upp_payload = input_data.get("upp_payload", b"")
            if isinstance(upp_payload, str):
                # 如果是 hex 字符串，转换为 bytes
                upp_payload = bytes.fromhex(upp_payload.replace(" ", "").replace("\n", ""))
        
        # 初始化 Profile Package 存储
        packages = ProfilePackageStore()
        template = ProfilePackageTemplate(
            matching_id=input_data["matching_id"],
            profile_id=input_data["profile_id"],
            profile_name=input_data.get("profile_name", "IoT Profile"),
            iccid=input_data["iccid"],
            service_provider_name=input_data.get("spn", ""),
            profile_class=input_data.get("profile_class", 2),
            payload=upp_payload,
        )
        packages.save(template)
        
        # 初始化本地 SM-DP+
        self.smdp_plus = LocalSmdpPlus(
            packages=packages,
            dp_auth_identity=dp_auth_identity,
            dp_profile_binding_identity=dp_pb_identity,
            trusted_root_certificate=ci_cert,
        )
        
        # 初始化流程控制器
        self.flow = ProfileDownloadFlow(
            eid=input_data["eid"],
            smdp_address=input_data["smdp_address"],
            matching_id=input_data["matching_id"],
            iccid=input_data["iccid"],
            profile_id=input_data["profile_id"],
            smdp_plus=self.smdp_plus,
            mode=input_data.get("mode", "indirect"),
            eim_id=input_data.get("eim_id"),
            tac=bytes.fromhex(input_data.get("tac", "00000000")),
            total_rounds=input_data.get("rounds", 1),
        )
        
        self.execution_id: Optional[str] = None
        self.current_step: int = 0
    
    def start(self, execution_id: str):
        self.execution_id = execution_id
        self.current_step = 0
        
        send_output(execution_id, "INFO", f"Starting Profile Download - Mode: {self.input.get('mode', 'indirect')}, Rounds: {self.input.get('rounds', 1)}")
        self._execute_step()
    
    def handle_action_result(self, msg: Dict[str, Any]):
        action_id = msg.get("actionId", "")
        success = msg.get("success", False)
        
        if not success:
            send_output(self.execution_id, "ERROR", f"APDU failed: {action_id}")
            send_finished(self.execution_id, "FAILED", error={"code": "APDU_FAILED", "message": f"APDU {action_id} failed"})
            return
        
        # 提取 APDU 响应
        apdu_response = None
        sw = None
        if "rapdu" in msg:
            rapdu_hex = msg["rapdu"]
            if rapdu_hex:
                apdu_response = bytes.fromhex(rapdu_hex)
                sw = rapdu_hex[-4:].upper() if len(rapdu_hex) >= 4 else None
        
        send_output(self.execution_id, "INFO", f"APDU {action_id} succeeded (SW={sw})")
        self._execute_step(apdu_response, sw)
    
    def _execute_step(self, apdu_response: Optional[bytes] = None, sw: Optional[str] = None):
        try:
            apdus = self.flow.execute_step(
                self.current_step,
                apdu_response=apdu_response,
                sw=sw
            )
            
            if not apdus:
                next_step = self.flow.get_current_step()
                if next_step == -1:
                    send_output(self.execution_id, "INFO", "Profile download completed successfully")
                    send_finished(self.execution_id, "SUCCESS", data={
                        "profile_state": "enabled",
                        "rounds_completed": self.flow.current_round,
                    })
                else:
                    self.current_step = next_step
                    self._execute_step()
            else:
                for apdu in apdus:
                    action = build_apdu_action(apdu)
                    send_action(self.execution_id, action)
                    send_output(self.execution_id, "INFO", f"Sending APDU: {apdu.to_hex()}")
                self.current_step = self.flow.get_current_step()
        
        except ProfileDownloadError as e:
            send_output(self.execution_id, "ERROR", f"Profile download error: {e}")
            send_finished(self.execution_id, "FAILED", error={"code": "PROFILE_DOWNLOAD_ERROR", "message": str(e)})
        except Exception as e:
            logger.error(f"Execution error: {e}", exc_info=True)
            send_output(self.execution_id, "ERROR", f"Internal error: {e}")
            send_finished(self.execution_id, "FAILED", error={"code": "INTERNAL_ERROR", "message": str(e)})
    
    def stop(self, reason: str = ""):
        send_output(self.execution_id, "WARN", f"Execution stopped: {reason}")
        send_finished(self.execution_id, "CANCELLED", error={"code": "CANCELLED", "message": reason})


def main():
    executor: Optional[ProfileDownloadExecutor] = None
    
    while True:
        msg = read_message()
        if msg is None:
            break
        
        msg_type = msg.get("type")
        
        if msg_type == "start":
            execution_id = msg["executionId"]
            input_data = msg.get("input", {})
            
            error = validate_input(input_data)
            if error:
                send_finished(execution_id, "FAILED", error={"code": "INVALID_INPUT", "message": error})
                continue
            
            resources_dir = input_data.get("resources_dir")
            executor = ProfileDownloadExecutor(input_data, resources_dir)
            executor.start(execution_id)
        
        elif msg_type == "action_result":
            if executor:
                executor.handle_action_result(msg)
        
        elif msg_type == "stop":
            if executor:
                executor.stop(msg.get("reason", ""))
            break


if __name__ == "__main__":
    main()
