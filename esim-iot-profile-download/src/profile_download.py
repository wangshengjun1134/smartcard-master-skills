"""Profile 下载 / eIM 启用业务流程

对齐 Java 参考实现（IOT_PERF_TEST_Install_Enable_Profile / ScriptTaskProcesser）：

    准备 + Cleanup : EuiccMemoryReset(BF34) → ListNotification(BF28) → RemoveNotification(BF30)
    Profile 安装   : GetEuiccInfo1(BF20) → GetEuiccChallenge(BF2E) → AuthenticateServer(BF38)
                     → PrepareDownload(BF21) → LoadProfilePackage(BF36)
    PostInstall    : COLDRESET + IC1/IC2 + SELECT ISD-R
    eIM 启用        : AddInitialEim(BF57) → LoadEuiccPackage Enable PSMO(BF51)
                     → 校验 enableResult → PostEnable COLDRESET + IC1/IC2 + SELECT ISD-R
                     → GetProfilesInfo(BF2D) → 校验 profileState
    FinalCleanup   : EuiccMemoryReset + ListNotification + RemoveNotification

设计要点（对齐 SmartCard Agent Skills Dev v1.1）：
  * 语义 Step 枚举驱动流程（§8），不用裸整数步骤号
  * 每个 Step 产出 0..N 个 Skill Action（APDU / RESET_CARD / WAIT）交给 Runtime 执行（§4）
  * Skill 不直接操作读卡器（§17）、不输出密钥（§14）
  * 多动作 Step 只把「最后一条动作的响应」交给下一步（与 Java 平台行为一致）
"""

from enum import IntEnum
from typing import Dict, List, Optional, Tuple
import logging

from .apdu_builder import (
    ApduCommand, select_mf, select_mf_retry, terminal_capability, terminal_profile,
    fetch, status, manage_channel_open, select_isdr,
    get_euicc_info1, get_euicc_challenge,
    euicc_memory_reset, list_notification, remove_notification,
    get_profiles_info, store_data,
)
from .skill_actions import ResetCardAction, WaitAction, with_meta
from .local_eim import LocalEim
from .sgp32_codec import verify_enable_result_ok, Sgp32CodecError
from .pki_manager import PkiIdentity
from .smdp_plus import LocalSmdpPlus
from .asn1_codec import (
    encode_bf38_authenticate_server_request,
    encode_bf21_prepare_download_request,
    decode_bf2e_challenge,
)
from .utils import chunk_bytes, digits_to_bcd

logger = logging.getLogger(__name__)

MAX_STORE_DATA_CHUNK = 255


def _read_tlv(data: bytes, offset: int):
    """读取一个 BER-TLV，返回 (tag, value, next_offset)。tag 为整数（如 0xBF2F、0x9F70）。"""
    tag = data[offset]
    offset += 1
    if (tag & 0x1F) == 0x1F:
        tag = (tag << 8) | data[offset]
        offset += 1
    length = data[offset]
    offset += 1
    if length & 0x80:
        count = length & 0x7F
        length = int.from_bytes(data[offset:offset + count], 'big')
        offset += count
    return tag, data[offset:offset + length], offset + length


def iter_tlvs(data: bytes):
    """递归遍历 BER-TLV，产出 (tag, value)；构造类型自动向内展开。"""
    if not data:
        return
    pos = 0
    end = len(data)
    while pos < end:
        try:
            tag, value, pos = _read_tlv(data, pos)
        except (IndexError, ValueError):
            return
        yield tag, value
        if tag & 0x20:                      # constructed（SEQUENCE / 上下文构造类型）
            yield from iter_tlvs(value)


class ProfileDownloadError(Exception):
    """Profile 下载异常"""
    pass


class Step(IntEnum):
    """流程语义状态（Dev Spec v1.1 §8：不要用裸整数 step）。"""
    DONE = -1
    COLD_START = 0
    PREP_SELECT_MF = 1
    PREP_SELECT_MF_TC = 2
    PREP_TERMINAL_PROFILE = 3
    PREP_STATUS_CHANNEL = 4
    PREP_SELECT_ISDR = 5
    CLEANUP_MEMORY_RESET = 6
    CLEANUP_FETCH_REFRESH = 7
    CLEANUP_LIST_NOTIFICATION = 8
    CLEANUP_REMOVE_NOTIFICATION = 9
    INSTALL_SELECT_MF = 10
    INSTALL_SELECT_MF_TC = 11
    INSTALL_TERMINAL_PROFILE = 12
    INSTALL_STATUS_CHANNEL = 13
    INSTALL_SELECT_ISDR = 14
    GET_EUICC_INFO1 = 15
    GET_EUICC_CHALLENGE = 16
    AUTHENTICATE_SERVER = 17
    PREPARE_DOWNLOAD = 18
    LOAD_PROFILE_PACKAGE = 19
    POST_INSTALL_RESET = 20
    POST_INSTALL_SELECT_ISDR = 21
    ADD_INITIAL_EIM = 22
    LOAD_EUICC_PACKAGE_ENABLE = 23
    VERIFY_ENABLE = 24
    FETCH_ENABLE_REFRESH = 25
    POST_ENABLE_RESET = 26
    POST_ENABLE_SELECT_ISDR = 27
    GET_PROFILES_INFO = 28
    VERIFY_PROFILE_STATE = 29
    FINAL_CLEANUP_MEMORY_RESET = 30
    FINAL_CLEANUP_FETCH_REFRESH = 31
    FINAL_CLEANUP_LIST_NOTIFICATION = 32
    FINAL_CLEANUP_REMOVE_NOTIFICATION = 33
    ROUND_CHECK = 34


# 每个 Step 的语义标签 → Action id 前缀 / UI 名称（Dev Spec v1.1 §12）
_STEP_LABELS: Dict[Step, str] = {
    Step.COLD_START: "card.cold-start",
    Step.PREP_SELECT_MF: "prep.select-mf",
    Step.PREP_SELECT_MF_TC: "prep.select-mf-terminal-capability",
    Step.PREP_TERMINAL_PROFILE: "prep.terminal-profile",
    Step.PREP_STATUS_CHANNEL: "prep.status-open-channel",
    Step.PREP_SELECT_ISDR: "prep.select-isdr",
    Step.CLEANUP_MEMORY_RESET: "cleanup.memory-reset",
    Step.CLEANUP_FETCH_REFRESH: "cleanup.fetch-refresh",
    Step.CLEANUP_LIST_NOTIFICATION: "cleanup.list-notification",
    Step.CLEANUP_REMOVE_NOTIFICATION: "cleanup.remove-notification",
    Step.INSTALL_SELECT_MF: "install.select-mf",
    Step.INSTALL_SELECT_MF_TC: "install.select-mf-terminal-capability",
    Step.INSTALL_TERMINAL_PROFILE: "install.terminal-profile",
    Step.INSTALL_STATUS_CHANNEL: "install.status-open-channel",
    Step.INSTALL_SELECT_ISDR: "install.select-isdr",
    Step.GET_EUICC_INFO1: "download.get-euicc-info1",
    Step.GET_EUICC_CHALLENGE: "download.get-euicc-challenge",
    Step.AUTHENTICATE_SERVER: "download.authenticate-server",
    Step.PREPARE_DOWNLOAD: "download.prepare-download",
    Step.LOAD_PROFILE_PACKAGE: "download.load-profile-package",
    Step.POST_INSTALL_RESET: "postinstall.cold-reset",
    Step.POST_INSTALL_SELECT_ISDR: "postinstall.select-isdr",
    Step.ADD_INITIAL_EIM: "eim.add-initial-eim",
    Step.LOAD_EUICC_PACKAGE_ENABLE: "eim.load-euicc-package-enable",
    Step.VERIFY_ENABLE: "eim.verify-enable-result",
    Step.FETCH_ENABLE_REFRESH: "eim.fetch-enable-refresh",
    Step.POST_ENABLE_RESET: "postenable.cold-reset",
    Step.POST_ENABLE_SELECT_ISDR: "postenable.select-isdr",
    Step.GET_PROFILES_INFO: "verify.get-profiles-info",
    Step.VERIFY_PROFILE_STATE: "verify.profile-state",
    Step.FINAL_CLEANUP_MEMORY_RESET: "final-cleanup.memory-reset",
    Step.FINAL_CLEANUP_FETCH_REFRESH: "final-cleanup.fetch-refresh",
    Step.FINAL_CLEANUP_LIST_NOTIFICATION: "final-cleanup.list-notification",
    Step.FINAL_CLEANUP_REMOVE_NOTIFICATION: "final-cleanup.remove-notification",
    Step.ROUND_CHECK: "round.check",
}


class ProfileDownloadFlow:
    """Profile 下载流程控制器

    每个 `execute_step()` 返回该步骤要执行的 Action 列表；步骤内部通过
    `next_step()` 决定后续步骤。响应数据（apdu_response/sw）为「上一步最后一条动作」的结果。
    """

    def __init__(
        self,
        eid: str,
        smdp_address: str,
        matching_id: str,
        iccid: str,
        profile_id: str,
        smdp_plus: LocalSmdpPlus,
        mode: str = "indirect",
        eim_id: Optional[str] = None,
        eim_identity: Optional[PkiIdentity] = None,
        eim_initial_counter: int = 1,
        eim_enable_counter: int = 2,
        tac: bytes = b'\x00\x00\x00\x00',
        total_rounds: int = 1,
        wait_after_reset_ms: int = 100,
    ):
        self.eid = eid
        self.smdp_address = smdp_address
        self.matching_id = matching_id
        self.iccid = iccid
        self.profile_id = profile_id
        self.smdp_plus = smdp_plus
        self.mode = mode
        self.eim_id = eim_id
        self.tac = tac
        self.total_rounds = total_rounds
        self.wait_after_reset_ms = wait_after_reset_ms

        # eIM（间接模式）：Java 参考脚本用非交换 BCD 打包 PSMO 的 ICCID
        # （ScriptTaskProcesser.digitsToBcd），此处保持对齐；如需交换 BCD 可显式覆盖。
        self.eim: Optional[LocalEim] = None
        self.eim_initial_counter = eim_initial_counter
        self.eim_enable_counter = eim_enable_counter
        self.psmo_iccid_bcd: bytes = digits_to_bcd(iccid)
        if mode == "indirect":
            if not eim_id:
                raise ProfileDownloadError("eim_id is required in indirect mode")
            if eim_identity is None:
                raise ProfileDownloadError(
                    "eIM 证书/私钥缺失：indirect 模式需要 CERT_EIM / SK_EIM（见 CERTIFICATE_GUIDE.md）"
                )
            self.eim = LocalEim(eim_identity)

        # 执行上下文
        self.logical_channel: int = 0
        self.current_round: int = 1
        self.current_step: Step = Step.COLD_START
        self.finished: bool = False

        # 中间数据
        self.transaction_id: Optional[str] = None
        self._euicc_info1_response: Optional[bytes] = None
        self._authenticate_server_response: Optional[bytes] = None
        self._prepare_download_response: Optional[bytes] = None

        # 结果（供 final result 上报，禁止硬编码）
        self.enable_result: Optional[int] = None
        self.enable_result_note: str = ""
        self.profile_state: Optional[int] = None
        self.isdp_aid: Optional[str] = None
        self.warnings: List[str] = []
        self.atr: Optional[str] = None

    # ------------------------------------------------------------------ 基础

    def get_current_step(self) -> int:
        return int(self.current_step)

    def next_step(self, step: Step):
        self.current_step = Step(step)

    def result_summary(self) -> Dict[str, object]:
        """执行结果汇总（真实观测值，不硬编码）。"""
        state_names = {0: "DISABLED", 1: "ENABLED"}
        summary: Dict[str, object] = {
            "iccid": self.iccid,
            "profile_id": self.profile_id,
            "eid": self.eid,
            "mode": self.mode,
            "rounds_completed": self.current_round,
            "profile_state": state_names.get(self.profile_state, "UNKNOWN"),
            "verified": self.profile_state == 1,
        }
        if self.isdp_aid:
            summary["isdp_aid"] = self.isdp_aid
        if self.enable_result is not None:
            summary["enable_result"] = self.enable_result
        if self.enable_result_note:
            summary["enable_result_note"] = self.enable_result_note
        if self.warnings:
            summary["warnings"] = list(self.warnings)
        return summary

    def execute_step(self, step: int, apdu_response: Optional[bytes] = None,
                     sw: Optional[str] = None) -> List[object]:
        """执行指定 Step，返回要交给 Runtime 的 Action 列表。"""
        try:
            step_enum = Step(step)
        except ValueError:
            raise ProfileDownloadError(f"Unknown step: {step}")

        handler = self._dispatch().get(step_enum)
        if handler is None:
            raise ProfileDownloadError(f"Unknown step: {step}")

        try:
            actions = handler(apdu_response, sw) or []
        except ProfileDownloadError:
            raise
        except Exception as e:
            logger.error(f"Step {step_enum.name} failed: {e}", exc_info=True)
            raise ProfileDownloadError(f"Step {step_enum.name} failed: {e}")

        label = _STEP_LABELS.get(step_enum, step_enum.name.lower())
        description = (handler.__doc__ or "").strip().splitlines()[0] if handler.__doc__ else ""
        return [
            with_meta(action,
                      action_id=f"{label}.{index}",
                      name=label,
                      description=description)
            for index, action in enumerate(actions)
        ]

    def _dispatch(self) -> Dict[Step, object]:
        return {
            Step.COLD_START: self._step_cold_start,
            Step.PREP_SELECT_MF: self._step_ic0_plain,
            Step.PREP_SELECT_MF_TC: self._step_ic1_plain,
            Step.PREP_TERMINAL_PROFILE: self._step_ic2_plain,
            Step.PREP_STATUS_CHANNEL: self._step_ic3_plain,
            Step.PREP_SELECT_ISDR: self._step_open_channel_select_isdr_plain,
            Step.CLEANUP_MEMORY_RESET: self._step_cleanup0,
            Step.CLEANUP_FETCH_REFRESH: self._step_cleanup1,
            Step.CLEANUP_LIST_NOTIFICATION: self._step_cleanup2,
            Step.CLEANUP_REMOVE_NOTIFICATION: self._step_cleanup3,
            Step.INSTALL_SELECT_MF: self._step_ic0,
            Step.INSTALL_SELECT_MF_TC: self._step_ic1,
            Step.INSTALL_TERMINAL_PROFILE: self._step_ic2,
            Step.INSTALL_STATUS_CHANNEL: self._step_ic3,
            Step.INSTALL_SELECT_ISDR: self._step_open_channel_select_isdr,
            Step.GET_EUICC_INFO1: self._step_get_euicc_info1,
            Step.GET_EUICC_CHALLENGE: self._step_get_euicc_challenge,
            Step.AUTHENTICATE_SERVER: self._step_authenticate_server,
            Step.PREPARE_DOWNLOAD: self._step_prepare_download,
            Step.LOAD_PROFILE_PACKAGE: self._step_load_profile_package,
            Step.POST_INSTALL_RESET: self._step_post_install_reset,
            Step.POST_INSTALL_SELECT_ISDR: self._step_post_install_select_isdr,
            Step.ADD_INITIAL_EIM: self._step_add_initial_eim,
            Step.LOAD_EUICC_PACKAGE_ENABLE: self._step_load_euicc_package_enable,
            Step.VERIFY_ENABLE: self._step_verify_enable,
            Step.FETCH_ENABLE_REFRESH: self._step_fetch_enable_refresh,
            Step.POST_ENABLE_RESET: self._step_post_enable_reset,
            Step.POST_ENABLE_SELECT_ISDR: self._step_post_enable_select_isdr,
            Step.GET_PROFILES_INFO: self._step_get_profiles_info,
            Step.VERIFY_PROFILE_STATE: self._step_verify_profile_state,
            Step.FINAL_CLEANUP_MEMORY_RESET: self._step_final_cleanup0,
            Step.FINAL_CLEANUP_FETCH_REFRESH: self._step_final_cleanup1,
            Step.FINAL_CLEANUP_LIST_NOTIFICATION: self._step_final_cleanup2,
            Step.FINAL_CLEANUP_REMOVE_NOTIFICATION: self._step_final_cleanup3,
            Step.ROUND_CHECK: self._step_round_check,
        }

    # ------------------------------------------------------- 复用的小工具

    @staticmethod
    def _channel_from_open_response(response: Optional[bytes]) -> Optional[int]:
        """MANAGE_CHANNEL OPEN 的响应首字节即新逻辑通道号。"""
        if response and len(response) > 0 and 1 <= response[0] <= 19:
            return response[0]
        return None

    @staticmethod
    def _store_data_actions(channel: int, data: bytes, desc: str,
                            sensitive: bool = False) -> List[ApduCommand]:
        """按 Java storeDataBytes 分段：每块 ≤255 字节，块号从 0 起，末块 P1=0x91。"""
        actions: List[ApduCommand] = []
        segments = chunk_bytes(data, MAX_STORE_DATA_CHUNK)
        for index, segment in enumerate(segments):
            is_last = index == len(segments) - 1
            command = store_data(channel, index, is_last, segment)
            command.name = f"{desc} #{index}"
            command.description = f"{desc} StoreData 分块 #{index}/{len(segments) - 1}"
            command.sensitive = sensitive
            actions.append(command)
        return actions

    @staticmethod
    def _notification_sequences(response: Optional[bytes]) -> List[bytes]:
        """从 ListNotification(BF28) 响应解析待处理通知序号。

        BF28 { notificationListOk(A0) { BF2F { seqNumber(80) ... } } }
        与 Java 参考不同之处：seqNumber 是 INTEGER，可能只占 1 字节
        （实测本卡为 `80 01 <seq>`），这里 1~2 字节都接受并统一补齐为 2 字节
        （Java `notificationSequences` 只认 2 字节，故其从未真正清掉通知）。
        """
        sequences: List[bytes] = []
        for tag, value in iter_tlvs(response or b''):
            if tag != 0xBF2F:
                continue
            for field_tag, field_value in iter_tlvs(value):
                if field_tag == 0x80 and 1 <= len(field_value) <= 2:
                    sequences.append(field_value.rjust(2, b'\x00'))
        return sequences

    def _reset_actions(self, reason: str) -> List[object]:
        """冷复位动作：RESET_CARD + 短暂 WAIT（传输层节奏，Dev Spec §4）。"""
        return [
            ResetCardAction(description=f"{reason}：冷复位卡片（对应 Java icSequence 的 coldReset）"),
            WaitAction(milliseconds=self.wait_after_reset_ms,
                       description=f"{reason}：等待卡片上电稳定"),
        ]

    # ========== 阶段 1: 初始化与准备 ==========

    def _step_cold_start(self, apdu_response=None, sw=None) -> List[object]:
        """ColdStart：冷复位 + 等待"""
        logger.info("Step COLD_START")
        self.current_round = 1
        self.next_step(Step.PREP_SELECT_MF)
        return self._reset_actions("ColdStart")

    def _step_ic0_plain(self, apdu_response=None, sw=None) -> List[ApduCommand]:
        """IC1: SELECT MF（准备阶段）"""
        logger.info("Step PREP_SELECT_MF")
        self.next_step(Step.PREP_SELECT_MF_TC)
        return [select_mf(0)]

    def _step_ic1_plain(self, apdu_response=None, sw=None) -> List[ApduCommand]:
        """IC1: SELECT MF + TERMINAL CAPABILITY（准备阶段）"""
        logger.info("Step PREP_SELECT_MF_TC")
        self.next_step(Step.PREP_TERMINAL_PROFILE)
        return [select_mf_retry(0), terminal_capability(0)]

    def _step_ic2_plain(self, apdu_response=None, sw=None) -> List[ApduCommand]:
        """IC2: TERMINAL PROFILE（准备阶段）"""
        logger.info("Step PREP_TERMINAL_PROFILE")
        self.next_step(Step.PREP_STATUS_CHANNEL)
        return [terminal_profile(0)]

    def _step_ic3_plain(self, apdu_response=None, sw=None) -> List[ApduCommand]:
        """IC2: STATUS + MANAGE_CHANNEL OPEN（准备阶段）"""
        logger.info("Step PREP_STATUS_CHANNEL")
        self.next_step(Step.PREP_SELECT_ISDR)
        self.logical_channel = 0
        return [status(0), manage_channel_open()]

    def _step_open_channel_select_isdr_plain(self, apdu_response=None, sw=None) -> List[ApduCommand]:
        """SELECT ISD-R（准备阶段，通道取自 MANAGE_CHANNEL 响应）"""
        channel = self._channel_from_open_response(apdu_response) or 1
        self.logical_channel = channel
        logger.info(f"Step PREP_SELECT_ISDR (channel={channel})")
        self.next_step(Step.CLEANUP_MEMORY_RESET)
        return [select_isdr(channel)]

    # ========== 阶段 2: Cleanup ==========

    def _step_cleanup0(self, apdu_response=None, sw=None) -> List[ApduCommand]:
        """Cleanup: EuiccMemoryReset(BF34)"""
        logger.info("Step CLEANUP_MEMORY_RESET")
        self.next_step(Step.CLEANUP_FETCH_REFRESH)
        return [euicc_memory_reset(self.logical_channel)]

    def _step_cleanup1(self, apdu_response=None, sw=None) -> List[ApduCommand]:
        """Cleanup: 处理 91XX（FETCH REFRESH）"""
        logger.info("Step CLEANUP_FETCH_REFRESH")
        self.next_step(Step.CLEANUP_LIST_NOTIFICATION)
        if sw and sw.startswith("91"):
            return [fetch(self.logical_channel, int(sw[2:], 16))]
        return []

    def _step_cleanup2(self, apdu_response=None, sw=None) -> List[ApduCommand]:
        """Cleanup: ListNotification(BF28)"""
        logger.info("Step CLEANUP_LIST_NOTIFICATION")
        self.next_step(Step.CLEANUP_REMOVE_NOTIFICATION)
        return [list_notification(self.logical_channel)]

    def _step_cleanup3(self, apdu_response=None, sw=None) -> List[ApduCommand]:
        """Cleanup: RemoveNotification(BF30) × N"""
        logger.info("Step CLEANUP_REMOVE_NOTIFICATION")
        self.next_step(Step.INSTALL_SELECT_MF)
        sequences = self._notification_sequences(apdu_response)
        if not sequences:
            logger.info("Cleanup: 无待处理通知")
        return [remove_notification(self.logical_channel, seq) for seq in sequences]

    # ========== 阶段 3: Profile 安装 IC1/IC2 ==========

    def _step_ic0(self, apdu_response=None, sw=None) -> List[ApduCommand]:
        """IC1: SELECT MF（安装阶段）"""
        logger.info("Step INSTALL_SELECT_MF")
        self.next_step(Step.INSTALL_SELECT_MF_TC)
        return [select_mf(0)]

    def _step_ic1(self, apdu_response=None, sw=None) -> List[ApduCommand]:
        """IC1: SELECT MF + TERMINAL CAPABILITY（安装阶段）"""
        logger.info("Step INSTALL_SELECT_MF_TC")
        self.next_step(Step.INSTALL_TERMINAL_PROFILE)
        return [select_mf_retry(0), terminal_capability(0)]

    def _step_ic2(self, apdu_response=None, sw=None) -> List[ApduCommand]:
        """IC2: TERMINAL PROFILE（安装阶段）"""
        logger.info("Step INSTALL_TERMINAL_PROFILE")
        self.next_step(Step.INSTALL_STATUS_CHANNEL)
        return [terminal_profile(0)]

    def _step_ic3(self, apdu_response=None, sw=None) -> List[ApduCommand]:
        """IC2: STATUS + MANAGE_CHANNEL OPEN（安装阶段）"""
        logger.info("Step INSTALL_STATUS_CHANNEL")
        self.next_step(Step.INSTALL_SELECT_ISDR)
        self.logical_channel = 0
        return [status(0), manage_channel_open()]

    def _step_open_channel_select_isdr(self, apdu_response=None, sw=None) -> List[ApduCommand]:
        """SELECT ISD-R（安装阶段，通道取自 MANAGE_CHANNEL 响应）"""
        channel = self._channel_from_open_response(apdu_response) or 1
        self.logical_channel = channel
        logger.info(f"Step INSTALL_SELECT_ISDR (channel={channel})")
        self.next_step(Step.GET_EUICC_INFO1)
        return [select_isdr(channel)]

    # ========== 阶段 4: 下载链（BF20 → BF2E → BF38 → BF21 → BF36） ==========

    def _step_get_euicc_info1(self, apdu_response=None, sw=None) -> List[ApduCommand]:
        """GetEuiccInfo1(BF20)"""
        logger.info("Step GET_EUICC_INFO1")
        self.next_step(Step.GET_EUICC_CHALLENGE)
        return [get_euicc_info1(self.logical_channel)]

    def _step_get_euicc_challenge(self, apdu_response=None, sw=None) -> List[ApduCommand]:
        """GetEuiccChallenge(BF2E)"""
        logger.info("Step GET_EUICC_CHALLENGE")
        self._euicc_info1_response = apdu_response
        self.next_step(Step.AUTHENTICATE_SERVER)
        return [get_euicc_challenge(self.logical_channel)]

    def _step_authenticate_server(self, apdu_response=None, sw=None) -> List[ApduCommand]:
        """AuthenticateServer(BF38)：本地 SM-DP+ InitiateAuthentication"""
        logger.info("Step AUTHENTICATE_SERVER")
        euicc_challenge = decode_bf2e_challenge(apdu_response) if apdu_response else b'\x00' * 16

        auth_result = self.smdp_plus.initiate_authentication(
            matching_id=self.matching_id,
            eid=self.eid,
            euicc_challenge=euicc_challenge,
            euicc_info1=self._euicc_info1_response or b'',
            smdp_address=self.smdp_address,
        )
        self.transaction_id = auth_result['transaction_id']
        bf38 = encode_bf38_authenticate_server_request(
            server_signed1=auth_result['server_signed1'],
            server_signature1=auth_result['server_signature1'],
            euicc_ci_pk_id=auth_result['euicc_ci_pk_id'],
            server_certificate=auth_result['server_certificate'],
            matching_id=self.matching_id,
            tac=self.tac,
        )
        self.next_step(Step.PREPARE_DOWNLOAD)
        logger.info(f"AuthenticateServer: {len(bf38)} bytes")
        return self._store_data_actions(self.logical_channel, bf38, "AuthenticateServer(BF38)",
                                        sensitive=True)

    def _step_prepare_download(self, apdu_response=None, sw=None) -> List[ApduCommand]:
        """PrepareDownload(BF21)：本地 SM-DP+ AuthenticateClient"""
        logger.info("Step PREPARE_DOWNLOAD")
        self._authenticate_server_response = apdu_response

        session = self._require_session("AuthenticateServer")

        auth_client_result = self.smdp_plus.authenticate_client(
            transaction_id=session.transaction_id,
            authenticate_server_response=apdu_response or b'',
        )
        bf21 = encode_bf21_prepare_download_request(
            smdp_signed2=auth_client_result['smdp_signed2'],
            smdp_signature2=auth_client_result['smdp_signature2'],
            smdp_certificate=auth_client_result['smdp_certificate'],
        )
        self.next_step(Step.LOAD_PROFILE_PACKAGE)
        logger.info(f"PrepareDownload: {len(bf21)} bytes")
        return self._store_data_actions(self.logical_channel, bf21, "PrepareDownload(BF21)",
                                        sensitive=True)

    def _step_load_profile_package(self, apdu_response=None, sw=None) -> List[ApduCommand]:
        """LoadProfilePackage(BF36)：本地 SM-DP+ GetBoundProfilePackage"""
        logger.info("Step LOAD_PROFILE_PACKAGE")
        self._prepare_download_response = apdu_response

        session = self._require_session("PrepareDownload")

        bpp_der = self.smdp_plus.get_bound_profile_package(
            transaction_id=session.transaction_id,
            prepare_download_response=apdu_response or b'',
        )
        segments = self.smdp_plus.get_bpp_segments(session.transaction_id)
        self.next_step(Step.POST_INSTALL_RESET)

        actions: List[ApduCommand] = []
        for block_number, p1, segment in segments:
            command = store_data(self.logical_channel, block_number, p1 == 0x91, segment)
            command.name = f"LoadProfilePackage(BF36) blk{block_number}"
            command.description = "BPP StoreData 分块（块号在 ASN.1 对象内计数，p1=%02X）" % p1
            command.sensitive = True
            actions.append(command)
        logger.info(f"LoadProfilePackage: {len(bpp_der)} bytes in {len(segments)} blocks")
        return actions

    # ========== 阶段 5: PostInstall + eIM 启用 ==========

    def _step_post_install_reset(self, apdu_response=None, sw=None) -> List[object]:
        """PostInstall：冷复位 + IC1/IC2 + 打开通道（Java case 21）"""
        logger.info("Step POST_INSTALL_RESET")
        self.next_step(Step.POST_INSTALL_SELECT_ISDR)
        self.logical_channel = 0
        return self._reset_actions("PostInstall") + [
            select_mf(0), terminal_capability(0), terminal_profile(0), manage_channel_open(),
        ]

    def _step_post_install_select_isdr(self, apdu_response=None, sw=None) -> List[ApduCommand]:
        """PostInstall：SELECT ISD-R（Java case 22）"""
        channel = self._channel_from_open_response(apdu_response) or 1
        self.logical_channel = channel
        logger.info(f"Step POST_INSTALL_SELECT_ISDR (channel={channel})")
        self.next_step(Step.ADD_INITIAL_EIM)
        return [select_isdr(channel)]

    def _step_add_initial_eim(self, apdu_response=None, sw=None) -> List[ApduCommand]:
        """AddInitialEim(BF57)：向 eUICC 写入 eIM 配置（Java case 23）"""
        if self.mode != "indirect":
            self.next_step(Step.POST_ENABLE_RESET)
            return []
        logger.info("Step ADD_INITIAL_EIM")
        bf57 = self.eim.build_add_initial_eim(self.eim_id, self.eim_initial_counter)
        self.next_step(Step.LOAD_EUICC_PACKAGE_ENABLE)
        return self._store_data_actions(self.logical_channel, bf57, "AddInitialEim(BF57)")

    def _step_load_euicc_package_enable(self, apdu_response=None, sw=None) -> List[ApduCommand]:
        """LoadEuiccPackage Enable PSMO(BF51)：eIM 启用 Profile（Java case 24）"""
        if self.mode != "indirect":
            self.next_step(Step.POST_ENABLE_RESET)
            return []
        logger.info("Step LOAD_EUICC_PACKAGE_ENABLE")
        bf51 = self.eim.build_enable_package(
            self.eim_id,
            self._eid_octets(),
            self.eim_enable_counter,
            self.psmo_iccid_bcd,
        )
        self.next_step(Step.VERIFY_ENABLE)
        return self._store_data_actions(self.logical_channel, bf51, "LoadEuiccPackage(enable)")

    def _step_verify_enable(self, apdu_response=None, sw=None) -> List[ApduCommand]:
        """Verify EnableResult：解析 BF51 的 EuiccPackageResult（Java case 25）"""
        if self.mode != "indirect":
            self.next_step(Step.POST_ENABLE_RESET)
            return []
        logger.info("Step VERIFY_ENABLE")
        self.next_step(Step.FETCH_ENABLE_REFRESH)
        if apdu_response:
            try:
                self.enable_result = verify_enable_result_ok(apdu_response)
                logger.info(f"enableResult = ok({self.enable_result})")
            except Sgp32CodecError as e:
                self.enable_result_note = str(e)
                self.warnings.append(f"enableResult 校验未通过：{e}")
                logger.warning(f"enableResult 校验未通过：{e}")
        else:
            # 本测试卡实测：LoadEuiccPackage(enable) 返回空响应 + SW=9000，
            # Java 参考脚本同样容错处理（后续以 GetProfilesInfo 的 profileState 为准）
            self.enable_result_note = "空响应（无可解析的 EuiccPackageResult）"
            self.warnings.append("eIM enable 返回空响应，改用 GetProfilesInfo 校验 profileState")
            logger.warning("eIM enable 返回空响应，改用 GetProfilesInfo 校验 profileState")
        return []

    def _step_fetch_enable_refresh(self, apdu_response=None, sw=None) -> List[ApduCommand]:
        """处理 enable 后的 91XX（FETCH 结果/REFRESH）（Java case 26）"""
        if self.mode != "indirect":
            self.next_step(Step.POST_ENABLE_RESET)
            return []
        logger.info("Step FETCH_ENABLE_REFRESH")
        self.next_step(Step.POST_ENABLE_RESET)
        if sw and sw.startswith("91"):
            return [fetch(self.logical_channel, int(sw[2:], 16))]
        return []

    def _step_post_enable_reset(self, apdu_response=None, sw=None) -> List[object]:
        """PostEnable：冷复位 + IC1/IC2 + 打开通道（Java case 27）"""
        logger.info("Step POST_ENABLE_RESET")
        self.next_step(Step.POST_ENABLE_SELECT_ISDR)
        self.logical_channel = 0
        return self._reset_actions("PostEnable") + [
            select_mf(0), terminal_capability(0), terminal_profile(0), manage_channel_open(),
        ]

    def _step_post_enable_select_isdr(self, apdu_response=None, sw=None) -> List[ApduCommand]:
        """PostEnable：SELECT ISD-R（Java case 28）"""
        channel = self._channel_from_open_response(apdu_response) or 1
        self.logical_channel = channel
        logger.info(f"Step POST_ENABLE_SELECT_ISDR (channel={channel})")
        self.next_step(Step.GET_PROFILES_INFO)
        return [select_isdr(channel)]

    def _step_get_profiles_info(self, apdu_response=None, sw=None) -> List[ApduCommand]:
        """GetProfilesInfo(BF2D)（Java case 29）"""
        logger.info("Step GET_PROFILES_INFO")
        self.next_step(Step.VERIFY_PROFILE_STATE)
        return [get_profiles_info(self.logical_channel)]

    def _step_verify_profile_state(self, apdu_response=None, sw=None) -> List[ApduCommand]:
        """Verify Profile State：以 GetProfilesInfo 的 9F70 为准（Java case 30）"""
        logger.info("Step VERIFY_PROFILE_STATE")
        self.next_step(Step.FINAL_CLEANUP_MEMORY_RESET)
        state, aid = self._parse_profile_state(apdu_response)
        self.profile_state = state
        self.isdp_aid = aid
        state_name = {0: "DISABLED", 1: "ENABLED"}.get(state, "UNKNOWN")
        logger.info(f"profileState = {state_name} (raw={state}), ISD-P AID = {aid}")
        if state != 1:
            self.warnings.append(f"profileState={state_name}，未达到 ENABLED")
        return []

    @staticmethod
    def _parse_profile_state(response: Optional[bytes]) -> Tuple[Optional[int], Optional[str]]:
        """从 GetProfilesInfo(BF2D) 响应中提取 profileState(9F70) 与 ISD-P AID(4F)。

        取响应中最后出现的 9F70/4F（卡上通常只列出一个 Profile；
        多 Profile 时以最后一个条目为准，配合 profile_state 判读）。
        """
        state: Optional[int] = None
        aid: Optional[str] = None
        for tag, value in iter_tlvs(response or b''):
            if tag == 0x4F and len(value) >= 5:
                aid = value.hex().upper()
            elif tag == 0x9F70 and len(value) >= 1:
                state = value[-1]
        return state, aid

    # ========== 阶段 6: FinalCleanup / 轮次 ==========

    def _step_final_cleanup0(self, apdu_response=None, sw=None) -> List[ApduCommand]:
        """FinalCleanup: EuiccMemoryReset(BF34)"""
        logger.info("Step FINAL_CLEANUP_MEMORY_RESET")
        self.next_step(Step.FINAL_CLEANUP_FETCH_REFRESH)
        return [euicc_memory_reset(self.logical_channel)]

    def _step_final_cleanup1(self, apdu_response=None, sw=None) -> List[ApduCommand]:
        """FinalCleanup: 处理 91XX（FETCH）"""
        logger.info("Step FINAL_CLEANUP_FETCH_REFRESH")
        self.next_step(Step.FINAL_CLEANUP_LIST_NOTIFICATION)
        if sw and sw.startswith("91"):
            return [fetch(self.logical_channel, int(sw[2:], 16))]
        return []

    def _step_final_cleanup2(self, apdu_response=None, sw=None) -> List[ApduCommand]:
        """FinalCleanup: ListNotification(BF28)"""
        logger.info("Step FINAL_CLEANUP_LIST_NOTIFICATION")
        self.next_step(Step.FINAL_CLEANUP_REMOVE_NOTIFICATION)
        return [list_notification(self.logical_channel)]

    def _step_final_cleanup3(self, apdu_response=None, sw=None) -> List[ApduCommand]:
        """FinalCleanup: RemoveNotification(BF30) × N"""
        logger.info("Step FINAL_CLEANUP_REMOVE_NOTIFICATION")
        self.next_step(Step.ROUND_CHECK)
        sequences = self._notification_sequences(apdu_response)
        return [remove_notification(self.logical_channel, seq) for seq in sequences]

    def _step_round_check(self, apdu_response=None, sw=None) -> List[ApduCommand]:
        """Round Check：多轮次循环或结束"""
        logger.info(f"Step ROUND_CHECK {self.current_round}/{self.total_rounds}")
        if self.current_round >= self.total_rounds:
            self.finished = True
            self.next_step(Step.DONE)
            return []
        self.current_round += 1
        self.next_step(Step.INSTALL_SELECT_MF)
        return []

    # --------------------------------------------------------------- 工具

    def _require_session(self, stage: str):
        """按 transaction_id 取回 SM-DP+ 会话（会话在 InitiateAuthentication 时按
        transaction_id 建立，不能用 matching_id 索引）。"""
        session = self.smdp_plus.get_session(self.transaction_id) if self.transaction_id else None
        if not session:
            raise ProfileDownloadError(f"No active SM-DP+ session ({stage} 未完成?)")
        return session

    def _eid_octets(self) -> bytes:
        """EID → 16 字节（EID 打包为非半字节交换，等价 Java hexToBytes(EID)）。"""
        try:
            return bytes.fromhex(self.eid)
        except ValueError:
            raise ProfileDownloadError(f"invalid eid: {self.eid}")
