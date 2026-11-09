#!/usr/bin/env python3
"""eSIM IoT Profile Download Skill - 入口（Python Skill）

与 SmartCard Skill Runtime 通过 JSON Lines IPC 通信：

  Runtime → Skill: start / action_result / stop
  Skill → Runtime: skill_action / output / execution_finished

协议字段严格对齐 `packages/core/src/smartcard/runtime/ipc-protocol.ts`：
  * action_result.response = { sw: number, data: number[] }；RESET_CARD 结果带 atr
  * execution_finished.error 为字符串；日志一律写 stderr（stdout 只输出 JSON）
  * Skill 不直接操作读卡器：所有卡片操作都以 Action（APDU / RESET_CARD / WAIT）交给 Runtime

运行环境（技能自维护，uv 优先）：Runtime（`ProcessPythonHost`）只以 `python <entry>` 启动本文件，
不安装依赖、也不使用技能包内的虚拟环境（Design v2.4 §9：Runtime 不改执行环境）。所以：

  * 环境属于**技能自己**：`<技能包>/.venv`，由 uv（优先）或 venv+pip 创建，见 `scripts/setup-env.sh`
  * **先安装，再执行业务**：首次使用先以 `{"operation": "setup_env"}` 调用本技能（或跑 setup-env.sh），
    装好后入口会自动切换解释器（`os.execv`，stdin/stdout 保留，IPC 不受影响）
  * 未安装就执行业务 → 返回 `FAILED ENV_NOT_READY` 并提示先安装
"""

from __future__ import annotations

import base64
import binascii
import json
import importlib.util
import os
import re
import shutil
import subprocess
import sys
import logging
from typing import Any, Dict, List, Optional

PACKAGE_DIR = os.path.dirname(os.path.abspath(__file__))
REQUIRED_MODULES = ("cryptography", "pyasn1")

_VENV_ACTIVE_ENV = "ESIM_SKILL_VENV_ACTIVE"
_VENV_DIR_ENV = "ESIM_SKILL_VENV"
_AUTO_INSTALL_ENV = "ESIM_SKILL_AUTO_INSTALL"
_VENV_DIR_NAMES = (".venv", "venv")


def venv_python_candidates(package_dir: str) -> List[str]:
    """技能自带虚拟环境的解释器候选路径（支持 POSIX 与 Windows 布局）。

    `ESIM_SKILL_VENV` 指定的目录优先，其次 `<package>/.venv`、`<package>/venv`。
    """
    roots = []
    override = os.environ.get(_VENV_DIR_ENV)
    if override:
        roots.append(override)
    roots.extend(os.path.join(package_dir, name) for name in _VENV_DIR_NAMES)

    candidates = []
    for root in roots:
        candidates.append(os.path.join(root, "bin", "python"))
        candidates.append(os.path.join(root, "Scripts", "python.exe"))
    return candidates


def current_interpreter_has_dependencies() -> bool:
    """当前解释器是否具备运行依赖（只做查找，不导入）。"""
    return all(importlib.util.find_spec(module) is not None for module in REQUIRED_MODULES)


def interpreter_has_dependencies(python_exe: str, timeout: int = 30) -> bool:
    """指定解释器是否具备运行依赖（子进程探测，避免污染当前进程）。"""
    if not os.path.exists(python_exe):
        return False
    try:
        completed = subprocess.run(
            [python_exe, "-c", "import " + ", ".join(REQUIRED_MODULES)],
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            timeout=timeout, check=False,
        )
        return completed.returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


def uv_executable() -> Optional[str]:
    """返回 uv 可执行文件路径；未安装则 None。"""
    return shutil.which("uv")


def env_python(venv_dir: str) -> Optional[str]:
    """虚拟环境里的解释器路径（兼容 POSIX 与 Windows 布局）。"""
    for relative in (os.path.join("bin", "python"), os.path.join("Scripts", "python.exe")):
        candidate = os.path.join(venv_dir, relative)
        if os.path.exists(candidate):
            return candidate
    return None


def create_package_env(package_dir: str, python_spec: Optional[str] = None) -> Dict[str, Any]:
    """创建/刷新技能自带环境 `<package>/.venv` 并安装 requirements。

    **uv 优先**（`uv venv` 可自行下载所需 CPython，不依赖宿主机 Python 版本），
    未安装 uv 时回退 `python -m venv` + pip。

    返回 {"ok": bool, "method": "uv"|"venv", "python": str|None, "log": [命令行...]}
    """
    venv_dir = os.path.join(package_dir, ".venv")
    requirements = os.path.join(package_dir, "requirements.txt")
    log: List[str] = []
    uv = uv_executable()

    def run(command: List[str]) -> None:
        log.append("$ " + " ".join(str(part) for part in command))
        subprocess.run(command, check=True, stdin=subprocess.DEVNULL)

    try:
        if uv:
            try:
                run([uv, "venv", venv_dir] + (["--python", python_spec] if python_spec else []))
            except subprocess.CalledProcessError:
                log.append(f"指定解释器 {python_spec} 不可用，改用 uv 自动选择")
                run([uv, "venv", venv_dir])
            python_exe = env_python(venv_dir)
            if not python_exe:
                return {"ok": False, "method": "uv", "python": None,
                        "log": log + ["[error] 环境创建后未找到解释器"]}
            run([uv, "pip", "install", "--python", python_exe, "-r", requirements])
            return {"ok": True, "method": "uv", "python": python_exe, "log": log}

        python = shutil.which("python") or shutil.which("python3") or sys.executable
        run([python, "-m", "venv", venv_dir])
        python_exe = env_python(venv_dir)
        if not python_exe:
            return {"ok": False, "method": "venv", "python": None,
                    "log": log + ["[error] 环境创建后未找到解释器"]}
        run([python_exe, "-m", "pip", "install", "--upgrade", "pip"])
        run([python_exe, "-m", "pip", "install", "-r", requirements])
        return {"ok": True, "method": "venv", "python": python_exe, "log": log}
    except (OSError, subprocess.SubprocessError) as e:
        return {"ok": False, "method": "uv" if uv else "venv", "python": None,
                "log": log + [f"[error] {e}"]}


def dependency_versions(python_exe: str) -> Dict[str, str]:
    """读取指定解释器中运行依赖的版本（失败返回空 dict）。"""
    code = ("import importlib.metadata as m, json;"
            "print(json.dumps({n: m.version(n) for n in ('cryptography','pyasn1')}))")
    try:
        completed = subprocess.run([python_exe, "-c", code], check=True, text=True,
                                   stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                   stderr=subprocess.DEVNULL, timeout=30)
        return json.loads(completed.stdout.strip() or "{}")
    except (OSError, subprocess.SubprocessError, ValueError):
        return {}


def interpreter_python_version(python_exe: str) -> Optional[str]:
    try:
        completed = subprocess.run(
            [python_exe, "-c", "import platform;print(platform.python_version())"],
            check=True, text=True, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL, timeout=30)
        return completed.stdout.strip()
    except (OSError, subprocess.SubprocessError):
        return None


def bootstrap_runtime_environment() -> str:
    """启动期环境引导（只用标准库，缺依赖时也能启动并通过 IPC 回话）。

    1. 当前解释器已具备依赖 → "ready"
    2. 技能自带环境（`$ESIM_SKILL_VENV` → `<package>/.venv` → `<package>/venv`）具备依赖
       → `os.execv` 切换过去（保留 stdin/stdout，IPC 不受影响）
    3. `ESIM_SKILL_AUTO_INSTALL=1` → 用 uv/venv 建环境后切换
    4. 都不行 → "missing"：由 main() 回复 `ENV_NOT_READY`，请调用方先执行安装
    """
    if os.environ.get(_VENV_ACTIVE_ENV) == "1" or current_interpreter_has_dependencies():
        return "ready"

    package_dir = os.environ.get("SKILL_PACKAGE_PATH") or PACKAGE_DIR
    for candidate in venv_python_candidates(package_dir):
        if interpreter_has_dependencies(candidate):
            os.environ[_VENV_ACTIVE_ENV] = "1"
            os.execv(candidate, [candidate, os.path.abspath(__file__), *sys.argv[1:]])
            return "ready"          # execv 成功后不会执行到这里

    if os.environ.get(_AUTO_INSTALL_ENV) == "1":
        created = create_package_env(package_dir)
        python_exe = created.get("python")
        if created["ok"] and python_exe and interpreter_has_dependencies(python_exe):
            os.environ[_VENV_ACTIVE_ENV] = "1"
            os.execv(python_exe, [python_exe, os.path.abspath(__file__), *sys.argv[1:]])
            return "ready"

    return "missing"


ENV_STATUS = bootstrap_runtime_environment()

sys.path.insert(0, PACKAGE_DIR)

# 业务模块依赖第三方库：缺依赖时不阻断启动（仍能通过 IPC 回复「请先安装」/ 执行 setup_env）
try:
    from src.apdu_builder import ApduCommand
    from src.profile_download import ProfileDownloadFlow, ProfileDownloadError
    from src.smdp_plus import LocalSmdpPlus
    from src.pki_manager import (
        PkiIdentity,
        load_private_key_from_pem,
        load_private_key_from_der,
        load_certificate_from_pem,
        load_certificate_from_der,
    )
    from src.profile_package_store import ProfilePackageStore, ProfilePackageTemplate
    from src.skill_actions import to_ipc
    from src.utils import validate_eid, validate_iccid, validate_matching_id

    DEPENDENCIES_READY = True
    IMPORT_ERROR: Optional[str] = None
except ImportError as exc:      # noqa: BLE001 - 记录原因，交由 main() 通过 IPC 上报
    DEPENDENCIES_READY = False
    IMPORT_ERROR = str(exc)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    stream=sys.stderr,
)
logger = logging.getLogger(__name__)

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


def run_setup_env(execution_id: str, input_data: Dict[str, Any]) -> None:
    """operation="setup_env"：建立/刷新技能自带执行环境（供 agent 首次调用）。

    环境由技能自己维护（uv 优先，uv 可自行下载所需 CPython），不依赖宿主机 Python 版本；
    装好后 main.py 入口会自动切换到该环境（见 bootstrap_runtime_environment）。
    """
    package_dir = os.environ.get("SKILL_PACKAGE_PATH") or PACKAGE_DIR
    venv_dir = os.path.join(package_dir, ".venv")
    force = bool(input_data.get("force"))

    send_output(execution_id, "INFO", f"技能自带环境目录: {venv_dir}")

    if not force and current_interpreter_has_dependencies():
        data = {
            "status": "already_satisfied",
            "python": sys.executable,
            "python_version": interpreter_python_version(sys.executable),
            "dependencies": dependency_versions(sys.executable),
        }
        send_output(execution_id, "INFO", "当前解释器已具备运行依赖，无需安装（force=true 可强制重建）")
        send_finished(execution_id, "SUCCESS", data=data)
        return

    uv = uv_executable()
    send_output(execution_id, "INFO",
                f"安装方式: {('uv ' + uv) if uv else 'python -m venv + pip（未检测到 uv）'}")
    result = create_package_env(package_dir, python_spec=input_data.get("python") or None)
    for line in result["log"]:
        send_output(execution_id, "INFO", line)

    python_exe = result.get("python")
    if not result["ok"] or not python_exe or not interpreter_has_dependencies(python_exe):
        hint = ("未检测到 uv，建议安装后重试： curl -LsSf https://astral.sh/uv/install.sh | sh"
                if not uv else "请检查网络/权限后重试")
        send_finished(execution_id, "FAILED", error=f"ENV_SETUP_FAILED: 环境安装失败；{hint}")
        return

    data = {
        "status": "installed",
        "method": result["method"],
        "env_path": os.path.dirname(os.path.dirname(python_exe)),
        "python": python_exe,
        "python_version": interpreter_python_version(python_exe),
        "dependencies": dependency_versions(python_exe),
    }
    send_output(execution_id, "INFO", f"环境就绪：{python_exe}（{data['python_version']}）")
    send_finished(execution_id, "SUCCESS", data=data)


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


def _decode_material(value: str, label: str) -> bytes:
    """注入的证书/私钥：接受 PEM 文本或 base64 编码的 DER。"""
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{label}: 注入值必须是非空字符串（PEM 文本或 base64 DER）")
    if "BEGIN" in value:
        return value.encode('utf-8')
    try:
        return base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError) as e:
        raise ValueError(f"{label}: 既不是 PEM 文本也不是合法 base64（{e}）")


def _load_private_key_auto(data: bytes):
    if data.lstrip().startswith(b'-----BEGIN'):
        return load_private_key_from_pem(data)
    return load_private_key_from_der(data)


def _load_certificate_auto(data: bytes):
    if data.lstrip().startswith(b'-----BEGIN'):
        return load_certificate_from_pem(data)
    return load_certificate_from_der(data)


def _material_bytes(input_data: Dict[str, Any], key: str, default_path: str, label: str) -> bytes:
    """证书/私钥来源：优先输入参数注入，其次包内默认文件。"""
    override = input_data.get(key)
    if override:
        logger.info(f"{label}: 使用输入参数 {key} 注入（覆盖 {os.path.basename(default_path)}）")
        return _decode_material(override, key)
    if not os.path.exists(default_path):
        raise FileNotFoundError(
            f"{label} 缺失：{default_path}"
            f"（可用输入参数 {key} 注入 PEM 文本或 base64 DER）")
    return open(default_path, 'rb').read()


def _optional_material_bytes(input_data: Dict[str, Any], key: str,
                             default_path: str) -> Optional[bytes]:
    if input_data.get(key):
        return _decode_material(input_data[key], key)
    if os.path.exists(default_path):
        return open(default_path, 'rb').read()
    return None


def load_identity(key_data: bytes, cert_data: bytes) -> PkiIdentity:
    return PkiIdentity(_load_private_key_auto(key_data), [_load_certificate_auto(cert_data)])


def load_pki_from_resources(resources_dir: str,
                            input_data: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """加载 DPauth / DPpb / CI，以及（可选的）eIM 证书与私钥。

    默认取包内资源目录：
        resources_dir/certs/
            SK_S_SM_DPauth_ECDSA_NIST.pem      CERT_S_SM_DPauth_ECDSA_NIST.der
            SK_S_SM_DPpb_ECDSA_NIST.pem        CERT_S_SM_DPpb_ECDSA_NIST.der
            CERT_CI_ECDSA_NIST.pem
            SK_EIM_ECDSA_NIST.pem              CERT_EIM_ECDSA_NIST.der   (间接模式)

    每一项都可用输入参数**外部注入**覆盖（PEM 文本或 base64 DER）：
        dp_auth_key / dp_auth_cert / dp_pb_key / dp_pb_cert / ci_cert / eim_key / eim_cert
    """
    input_data = input_data or {}
    certs_dir = os.path.join(resources_dir, "certs")

    def default(name: str) -> str:
        return os.path.join(certs_dir, name)

    injected = sorted(k for k in (
        "dp_auth_key", "dp_auth_cert", "dp_pb_key", "dp_pb_cert", "ci_cert", "eim_key", "eim_cert",
    ) if input_data.get(k))

    dp_auth = load_identity(
        _material_bytes(input_data, "dp_auth_key", default("SK_S_SM_DPauth_ECDSA_NIST.pem"), "DPauth 私钥"),
        _material_bytes(input_data, "dp_auth_cert", default("CERT_S_SM_DPauth_ECDSA_NIST.der"), "DPauth 证书"),
    )
    dp_pb = load_identity(
        _material_bytes(input_data, "dp_pb_key", default("SK_S_SM_DPpb_ECDSA_NIST.pem"), "DP Profile Binding 私钥"),
        _material_bytes(input_data, "dp_pb_cert", default("CERT_S_SM_DPpb_ECDSA_NIST.der"), "DP Profile Binding 证书"),
    )
    ci_cert = _load_certificate_auto(
        _material_bytes(input_data, "ci_cert", default("CERT_CI_ECDSA_NIST.pem"), "CI 根证书")
    )

    eim_identity: Optional[PkiIdentity] = None
    eim_key = _optional_material_bytes(input_data, "eim_key", default("SK_EIM_ECDSA_NIST.pem"))
    eim_cert = _optional_material_bytes(input_data, "eim_cert", default("CERT_EIM_ECDSA_NIST.der"))
    if eim_key and eim_cert:
        eim_identity = load_identity(eim_key, eim_cert)

    return {
        "dp_auth_identity": dp_auth,
        "dp_pb_identity": dp_pb,
        "ci_cert": ci_cert,
        "eim_identity": eim_identity,
        "injected": injected,
    }


def _decode_payload(value: str) -> bytes:
    """注入的 UPP：十六进制文本或 base64。"""
    text = "".join(value.split())
    if text and len(text) % 2 == 0 and re.fullmatch(r'[0-9a-fA-F]+', text):
        return bytes.fromhex(text)
    return base64.b64decode(value)


def load_profile_payload(resources_dir: str, iccid: str,
                         payload_override: Optional[str] = None) -> bytes:
    """加载 Profile Payload（UPP）：输入注入 > 按 ICCID 匹配 > 默认文件名。"""
    import glob

    if payload_override:
        logger.info("Profile payload: 使用输入参数 upp_payload 注入")
        return _decode_payload(payload_override)

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
        pki = load_pki_from_resources(resources_dir, input_data)
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
            payload=load_profile_payload(resources_dir, input_data["iccid"],
                                         input_data.get("upp_payload")),
            icon=icon,
            icon_type=icon_type,
        ))

        injected = list(pki.get("injected") or [])
        if input_data.get("upp_payload"):
            injected.append("upp_payload")
        if injected:
            self._output("INFO", f"使用外部注入的材料: {', '.join(sorted(injected))}")

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
            # Le 是一个字节：0 表示 256（61 00 = 还剩 256 字节）
            le = sw2
            self._action(ApduCommand(cla=self.last_cla or 0x00, ins=0xC0, p1=0x00, p2=0x00, le=le,
                                     action_id=f"{action_id}.get-response",
                                     name="GET RESPONSE",
                                     description="T=0 大响应后续读取"))
            return

        # eUICC 异步响应：91XX 需 FETCH
        if sw1 == 0x91 and self.follow_ups < MAX_TRANSPORT_FOLLOW_UPS:
            self.follow_ups += 1
            le = sw2
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

            # ① 环境准备（只用标准库，缺依赖时也能响应）
            if input_data.get("operation") == "setup_env":
                run_setup_env(execution_id, input_data)
                continue

            # ② 业务操作前必须已具备运行依赖，否则明确告知「先安装」
            if not DEPENDENCIES_READY:
                send_finished(execution_id, "FAILED", error=(
                    "ENV_NOT_READY: 技能自带执行环境未就绪 "
                    f"({IMPORT_ERROR})。请先执行安装：以 "
                    '{"operation": "setup_env"} 调用本技能，或运行 bash scripts/setup-env.sh'
                    "（详见 SKILL.md「运行环境」）"))
                continue

            error = validate_input(input_data)
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
