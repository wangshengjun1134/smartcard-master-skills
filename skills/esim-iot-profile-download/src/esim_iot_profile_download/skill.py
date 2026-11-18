"""eSIM IoT Profile Download Skill 主模块

实现 eSIM Profile 下载与启用的核心流程。
"""

from smartcard_skill_sdk import (
    Skill, SkillContext, SkillSession, SkillResult,
    Action, ActionType, ActionResult
)
from .state_machine import EsimState, STATE_TRANSITIONS, INDIRECT_MODE_TRANSITIONS
from .apdu_builder import ApduBuilder, ResponseParser
from .asn1_codec import (
    _iter_tlvs,
    encode_server_signed1,
    encode_bf38_authenticate_server_request,
    check_authenticate_server_response,
    decode_authenticate_server_ok,
    encode_application_signature,
    encode_smdp_signed2,
    encode_bf21_prepare_download_request,
    decode_prepare_download_response,
    decode_euicc_info1,
    decode_bf2e_challenge,
    decode_profile_installation_result,
    decode_notification_sequences,
    decode_remove_notification_result,
    encode_bf57_add_initial_eim,
    extract_spki,
    decode_add_initial_eim_response,
    decode_memory_reset_result,
    encode_enable_psmo,
    encode_psmo_list,
    encode_euicc_package_signed,
    encode_bf51_euicc_package_request,
    sign_euicc_package,
    decode_euicc_package_result,
    decode_profiles_info,
    Asn1CodecError,
    generate_bpp
)
from .resources import ResourceManager, CertificateManager, ProfileManager, ResourceLoadError


def _load_ec_private_key(key_bytes: bytes):
    """加载 EC 私钥，支持 PEM 和 DER 格式"""
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.backends import default_backend

    if key_bytes.startswith(b"-----BEGIN"):
        return serialization.load_pem_private_key(key_bytes, password=None, backend=default_backend())
    return serialization.load_der_private_key(key_bytes, password=None, backend=default_backend())


def _ber_total_length(data: bytes) -> int:
    """按 BER 头部计算整条 TLV 的总字节数（tag + len + value）"""
    if len(data) < 2:
        return -1
    pos = 1
    if (data[0] & 0x1F) == 0x1F:
        if len(data) < 3:
            return -1
        pos = 2
    lb = data[pos]
    pos += 1
    if lb & 0x80:
        n = lb & 0x7F
        if len(data) < pos + n:
            return -1
        length = int.from_bytes(data[pos:pos + n], 'big')
        pos += n
    else:
        length = lb
    return pos + length


def _der_signature_to_raw(der_signature: bytes) -> bytes:
    """把 DER 编码的 ECDSA 签名转为 64 字节裸 r||s

    SGP.22 的 serverSignature1/smdpSignature2 是 OCTET STRING(SIZE(64))，
    即 r(32)||s(32)；cryptography 默认输出 DER SEQUENCE{r,s}，直接下发会被 eUICC 拒绝。
    """
    from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

    if not der_signature or der_signature[0] != 0x30:
        return der_signature

    r, s = decode_dss_signature(der_signature)
    return r.to_bytes(32, 'big') + s.to_bytes(32, 'big')


class EsimIotProfileDownloadSkill(Skill):
    """eSIM IoT Profile Download Skill

    核心流程：
    1. 初始化与准备（COLDRESET → SELECT ISD-R）
    2. Profile 安装（AuthenticateServer → LoadProfilePackage）
    3. 后安装处理（COLDRESET → GetProfilesInfo）
    4. eIM 启用（间接模式：AddInitialEim → EnablePSMO）
    """

    def get_manifest(self) -> dict:
        return {
            "skillId": "esim.iot-profile-download",
            "name": "eSIM IoT Profile Download",
            "description": "IoT eSIM Profile 下载与启用",
            "version": "1.0.0",
            "requiresReader": True,
            "supportsSession": True
        }
    
    def init(self, ctx: SkillContext, params: dict) -> dict:
        """初始化 Skill"""
        session = ctx.sessions.create(params, ctx.skill_id)

        # 保存输入参数
        session.data["params"] = params
        session.data["mode"] = params.get("mode", "indirect")
        session.data["state"] = EsimState.START

        # 初始化资源管理器
        resources_dir = params.get("resources_dir")
        try:
            resource_manager = ResourceManager(resources_dir)
            cert_manager = CertificateManager(resource_manager)
            profile_manager = ProfileManager(resource_manager)

            # 预加载证书
            session.data["dp_auth_cert"] = cert_manager.get_dp_auth_cert().hex().upper()
            session.data["dp_auth_key"] = cert_manager.get_dp_auth_key().hex().upper()
            session.data["dp_pb_cert"] = cert_manager.get_dp_pb_cert().hex().upper()
            session.data["dp_pb_key"] = cert_manager.get_dp_pb_key().hex().upper()
            session.data["ci_cert"] = cert_manager.get_ci_cert().hex().upper()

            # 间接模式需要 eIM 证书
            if session.data["mode"] == "indirect":
                session.data["eim_cert"] = cert_manager.get_eim_cert().hex().upper()
                session.data["eim_key"] = cert_manager.get_eim_key().hex().upper()

            # 预加载 Profile 包
            iccid = params.get("iccid", "")
            if iccid:
                try:
                    session.data["profile_package"] = profile_manager.get_profile_package(iccid)
                except ResourceLoadError as e:
                    ctx.output.text(f"警告: {e}")

            ctx.output.info("资源加载完成")

        except ResourceLoadError as e:
            ctx.output.text(f"警告: 资源加载失败 - {e}")
            # 继续执行，但某些步骤可能失败

        # 保存修改后的 session（create 时已经保存了一次，但 data 被修改了需要再次保存）
        ctx.sessions.save(session, ctx.skill_id)

        return {
            "sessionId": session.session_id,
            "manifest": self.get_manifest(),
            "status": "INITIALIZED"
        }
    
    def start(self, ctx: SkillContext, session: SkillSession) -> SkillResult:
        """启动执行"""
        ctx.output.info("开始 eSIM Profile 下载流程")
        
        # 第一步：冷复位
        session.data["state"] = EsimState.WAIT_RESET
        ctx.sessions.save(session, ctx.skill_id)
        
        return self._do_reset(ctx, session)
    
    def handle_action_result(
        self, ctx: SkillContext, result: ActionResult, session: SkillSession
    ) -> SkillResult:
        """处理 Action 结果"""
        current_state = session.data.get("state", EsimState.START)

        # 检查 APDU 执行状态
        if result.status.value != "OK":
            session.data["state"] = EsimState.FAILED
            return SkillResult.failed(
                session.session_id,
                "APDU_ERROR",
                f"APDU 执行失败: {result.status}"
            )

        # 解析 SW
        sw = result.data.get("sw", "")
        response = result.data.get("response", "")

        # ===== 统一处理 61XX(GET RESPONSE) / 91XX(FETCH) =====
        # 任何 APDU 返回 61XX/91XX 都先取完剩余数据并累积，再按原状态继续。
        if sw.startswith(("61", "91")) and len(sw) == 4:
            if current_state in (EsimState.WAIT_GET_RESPONSE, EsimState.WAIT_FETCH):
                accumulated = session.data.pop("response_accum", "") + response
            else:
                session.data["previous_state"] = current_state
                accumulated = response
            return self._continue_collect(ctx, session, accumulated, sw)

        if current_state in (EsimState.WAIT_GET_RESPONSE, EsimState.WAIT_FETCH):
            # 这是 GET RESPONSE / FETCH 自己的结果，需要回到被打断的状态继续
            accumulated = session.data.pop("response_accum", "") + response
            pending_kind = session.data.pop("pending_kind", "61")
            previous_state = session.data.pop("previous_state", current_state)

            if sw not in ("9000", ""):
                if pending_kind == "91":
                    # 部分卡对 ES10 命令也回 91XX，但 FETCH 不受支持(6D00)：
                    # 说明原命令本身已完成，按成功继续。
                    sw = "9000"
                else:
                    session.data["state"] = EsimState.FAILED
                    return SkillResult.failed(
                        session.session_id,
                        "GET_RESPONSE_FAILED",
                        f"GET RESPONSE 失败: {sw}"
                    )
            return self._continue_from_state(ctx, session, previous_state, accumulated, sw)

        sw_parsed = ResponseParser.parse_sw(sw)

        if sw_parsed["status"] == "ERROR":
            session.data["state"] = EsimState.FAILED
            return SkillResult.failed(
                session.session_id,
                "APDU_STATUS_ERROR",
                f"卡片返回错误: {sw_parsed.get('message', sw)}"
            )
        
        # 根据当前状态处理响应
        if current_state == EsimState.WAIT_RESET:
            return self._do_select_mf(ctx, session)

        elif current_state == EsimState.WAIT_SELECT_MF:
            return self._do_terminal_capability(ctx, session)

        elif current_state == EsimState.WAIT_TERMINAL_CAPABILITY:
            return self._do_terminal_profile(ctx, session)

        elif current_state == EsimState.WAIT_TERMINAL_PROFILE:
            return self._do_status(ctx, session)

        elif current_state == EsimState.WAIT_TERMINAL_RESPONSE:
            # TERMINAL RESPONSE 之后若还有 proactive 命令，继续 FETCH/应答
            next_terminal = self._do_terminal_response(ctx, session, result.data.get("response", ""))
            if next_terminal:
                return next_terminal
            return self._do_status(ctx, session)

        elif current_state == EsimState.WAIT_STATUS:
            return self._do_manage_channel(ctx, session)

        elif current_state == EsimState.WAIT_MANAGE_CHANNEL:
            # 保存通道号
            response = result.data.get("response", "")
            if len(response) >= 2:
                session.data["channel"] = int(response[:2], 16)
            return self._do_select_isdr(ctx, session)

        elif current_state == EsimState.WAIT_SELECT_ISDR:
            # SELECT ISD-R 完成后，进入清理阶段
            return self._do_euicc_memory_reset(ctx, session)

        elif current_state == EsimState.WAIT_EUICC_MEMORY_RESET:
            failure = self._check_memory_reset_result(ctx, session, result.data.get("response", ""))
            if failure:
                return failure
            return self._do_list_notification(ctx, session)

        elif current_state == EsimState.WAIT_LIST_NOTIFICATION:
            # ListNotification 完成后，进入 RemoveNotification
            return self._do_remove_notification(ctx, session, result)

        elif current_state == EsimState.WAIT_REMOVE_NOTIFICATION:
            return self._handle_remove_notification_result(
                ctx, session, result.data.get("response", "")
            )

        elif current_state == EsimState.WAIT_CLEANUP_RESET:
            return self._do_cleanup_open_channel(ctx, session)

        elif current_state == EsimState.WAIT_CLEANUP_OPEN_CHANNEL:
            channel_hex = result.data.get("response", "")
            if len(channel_hex) >= 2:
                session.data["channel"] = int(channel_hex[:2], 16)
            return self._do_cleanup_select_isdr(ctx, session)

        elif current_state == EsimState.WAIT_CLEANUP_SELECT_ISDR:
            return self._do_get_euicc_challenge(ctx, session)

        elif current_state == EsimState.WAIT_GET_EUICC_CHALLENGE:
            # 保存挑战值，然后获取 EuiccInfo1
            response = result.data.get("response", "")
            try:
                response_bytes = bytes.fromhex(response)
                challenge = decode_bf2e_challenge(response_bytes)
                session.data["challenge"] = challenge.hex().upper()
            except Exception as e:
                ctx.output.text(f"警告: 无法解析 Challenge: {e}")
                session.data["challenge"] = response
            return self._do_get_euicc_info(ctx, session)

        elif current_state == EsimState.WAIT_GET_EUICC_INFO:
            # 解析 eUICC 信息
            response = result.data.get("response", "")
            try:
                response_bytes = bytes.fromhex(response)
                euicc_info = decode_euicc_info1(response_bytes)
                # 转为可 JSON 序列化的格式（bytes -> hex 字符串）
                serializable_info = {}
                for k, v in euicc_info.items():
                    if isinstance(v, list):
                        serializable_info[k] = [item.hex().upper() if isinstance(item, bytes) else item for item in v]
                    elif isinstance(v, bytes):
                        serializable_info[k] = v.hex().upper()
                    else:
                        serializable_info[k] = v
                session.data["euicc_info"] = serializable_info
                # 保存 euiccCiPkId（hex 字符串）供后续认证使用
                ver_ids = euicc_info.get("verification_ci_pk_ids") or []
                if ver_ids:
                    session.data["euicc_ci_pk_id"] = ver_ids[0].hex().upper()
                    ctx.output.text(f"提取 euiccCiPKId: {ver_ids[0].hex().upper()}")
            except Exception as e:
                ctx.output.text(f"警告: 无法解析 EuiccInfo1: {e}")
            # 间接模式下 eIM 必须先配置，之后才由 eIM 驱动下载
            if session.data.get("mode") == "indirect" and not session.data.get("eim_added"):
                return self._do_add_initial_eim(ctx, session, purpose="pre_install")
            return self._do_authenticate_server(ctx, session)

        elif current_state == EsimState.WAIT_AUTHENTICATE_SERVER:
            # 检查是否有待发送的分块 APDU
            pending_apdus = session.data.get("pending_apdus", [])
            if pending_apdus:
                # 还有后续分块，继续发送
                next_apdu = pending_apdus.pop(0)
                session.data["pending_apdus"] = pending_apdus
                action = self._build_apdu_action("esim.authenticate-server-continue", "服务器认证(续)", next_apdu, sensitive=True)
                return SkillResult.continue_with(session.session_id, action)
            
            # 所有分块发送完成，解析响应
            response = result.data.get("response", "")
            if not response:
                return SkillResult.failed(
                    session.session_id,
                    "AUTHENTICATE_SERVER_NO_RESPONSE",
                    "AuthenticateServer 未返回数据，无法继续 PrepareDownload"
                )
            try:
                response_bytes = bytes.fromhex(response)
                auth_status = check_authenticate_server_response(response_bytes)
                if not auth_status["ok"]:
                    return SkillResult.failed(
                        session.session_id,
                        "AUTHENTICATE_SERVER_FAILED",
                        f"卡片拒绝认证: errorCode={auth_status['error_code']} "
                        f"({auth_status['error_name']})"
                    )
                auth_ok = decode_authenticate_server_ok(response_bytes)
                session.data["transaction_id"] = auth_ok["transaction_id"] or auth_status.get("transaction_id") or "01"
                session.data["euicc_signature1"] = auth_ok["euicc_signature1"].hex().upper()
                ctx.output.text(f"认证成功, transaction_id={session.data['transaction_id']}")
            except Exception as e:
                return SkillResult.failed(
                    session.session_id,
                    "AUTHENTICATE_SERVER_PARSE_ERROR",
                    f"无法解析 AuthenticateServer 响应: {e}"
                )
            return self._do_prepare_download(ctx, session)

        elif current_state == EsimState.WAIT_PREPARE_DOWNLOAD:
            # 检查是否有待发送的分块 APDU
            pending_apdus = session.data.get("pending_apdus", [])
            if pending_apdus:
                # 还有后续分块，继续发送
                next_apdu = pending_apdus.pop(0)
                session.data["pending_apdus"] = pending_apdus
                action = self._build_apdu_action("esim.prepare-download-continue", "准备下载(续)", next_apdu)
                return SkillResult.continue_with(session.session_id, action)
            
            # 所有分块发送完成，解析响应
            response = result.data.get("response", "")
            try:
                response_bytes = bytes.fromhex(response)
                pd_response = decode_prepare_download_response(response_bytes)
                if pd_response.get("transaction_id"):
                    session.data["transaction_id"] = pd_response["transaction_id"]
                euicc_otpk = pd_response.get("euicc_otpk", b"")
                if euicc_otpk:
                    session.data["euicc_otpk"] = euicc_otpk.hex().upper()
                    ctx.output.text(f"获取到 eUICC OTPK: {euicc_otpk[:20].hex()}...")
                else:
                    ctx.output.text("警告: PrepareDownload 响应中没有 euicc_otpk")
                    # 尝试从 EuiccInfo1 中获取 euiccCiPkId 作为备用
                    euicc_info = session.data.get("euicc_info", {})
                    if "verification_ci_pk_ids" in euicc_info and euicc_info["verification_ci_pk_ids"]:
                        ctx.output.text("使用 euiccCiPkId 作为备用 OTPK")
                        # 注意：这不是正确的 OTPK，只是用于测试
                        session.data["euicc_otpk"] = "04" + "00" * 64  # 假的 OTPK
            except Exception as e:
                ctx.output.text(f"警告: 无法解析 PrepareDownload 响应: {e}")
            return self._do_load_profile_package(ctx, session)

        elif current_state == EsimState.WAIT_LOAD_PROFILE_PACKAGE:
            # 检查是否有待发送的分块 APDU
            pending_apdus = session.data.get("pending_apdus", [])
            if pending_apdus:
                # 还有后续分块，继续发送
                next_apdu = pending_apdus.pop(0)
                session.data["pending_apdus"] = pending_apdus
                action = self._build_apdu_action("esim.load-profile-package-continue", "加载 Profile 包(续)", next_apdu)
                return SkillResult.continue_with(session.session_id, action)

            failure = self._check_installation_result(ctx, session, result.data.get("response", ""))
            if failure:
                return failure
            return self._do_post_install_reset(ctx, session)

        elif current_state == EsimState.WAIT_POST_INSTALL_RESET:
            return self._do_post_install_ic1(ctx, session)

        elif current_state == EsimState.WAIT_POST_INSTALL_IC1:
            # 保存卡分配的通道号
            response = result.data.get("response", "")
            if len(response) >= 2:
                session.data["post_install_channel"] = int(response[:2], 16)
                session.data["channel"] = int(response[:2], 16)
            return self._do_post_install_ic2(ctx, session)

        elif current_state == EsimState.WAIT_POST_INSTALL_IC2:
            return self._do_post_install_select_isdr(ctx, session)

        elif current_state == EsimState.WAIT_POST_INSTALL_SELECT_ISDR:
            return self._do_get_profiles_info(ctx, session)

        elif current_state == EsimState.WAIT_GET_PROFILES_INFO:
            # 保存响应供后续解析
            response = result.data.get("response", "")
            session.data["profiles_info_response"] = response

            # 检查是否需要 eIM 启用
            mode = session.data.get("mode", "indirect")
            if mode == "indirect":
                return self._do_enable_psmo(ctx, session)
            else:
                # 直接模式，验证状态后完成
                return self._verify_and_complete(ctx, session)

        elif current_state == EsimState.WAIT_ADD_INITIAL_EIM:
            return self._check_add_initial_eim_result(ctx, session, result.data.get("response", ""))

        elif current_state == EsimState.WAIT_ENABLE_PSMO:
            return self._check_euicc_package_result(ctx, session, result.data.get("response", ""))

        elif current_state == EsimState.WAIT_POST_ENABLE_RESET:
            return self._do_post_enable_ic(ctx, session)

        elif current_state == EsimState.WAIT_POST_ENABLE_IC:
            response = result.data.get("response", "")
            if len(response) >= 2:
                session.data["channel"] = int(response[:2], 16)
            return self._do_post_enable_select_isdr(ctx, session)

        elif current_state == EsimState.WAIT_POST_ENABLE_SELECT_ISDR:
            return self._do_verify_profile_state(ctx, session)

        elif current_state == EsimState.WAIT_VERIFY_PROFILE_STATE:
            # 保存响应供最终验证
            response = result.data.get("response", "")
            session.data["profiles_info_response"] = response
            return self._verify_and_complete(ctx, session)

        # 未知状态
        return SkillResult.failed(
            session.session_id,
            "UNKNOWN_STATE",
            f"未知状态: {current_state}"
        )
    
    # ========== 初始化与准备阶段 ==========
    
    def _do_reset(self, ctx: SkillContext, session: SkillSession) -> SkillResult:
        """冷复位卡片"""
        ctx.output.text("步骤 1: 冷复位卡片")
        session.data["state"] = EsimState.WAIT_RESET
        
        action = Action(
            action_id="esim.reset-card",
            type=ActionType.RESET_CARD,
            name="冷复位",
            description="冷复位 eUICC 卡片",
            sensitive=False
        )
        return SkillResult.continue_with(session.session_id, action)
    
    def _do_select_mf(self, ctx: SkillContext, session: SkillSession) -> SkillResult:
        """SELECT MF"""
        ctx.output.text("步骤 2: 选择主文件 (MF)")
        session.data["state"] = EsimState.WAIT_SELECT_MF
        
        apdu = ApduBuilder.select_mf()
        action = self._build_apdu_action("esim.select-mf", "选择主文件", apdu)
        return SkillResult.continue_with(session.session_id, action)
    
    def _do_terminal_capability(self, ctx: SkillContext, session: SkillSession) -> SkillResult:
        """TERMINAL CAPABILITY"""
        ctx.output.text("步骤 3: 设置终端能力")
        session.data["state"] = EsimState.WAIT_TERMINAL_CAPABILITY
        
        apdu = ApduBuilder.terminal_capability()
        action = self._build_apdu_action("esim.terminal-capability", "设置终端能力", apdu)
        return SkillResult.continue_with(session.session_id, action)
    
    def _do_terminal_profile(self, ctx: SkillContext, session: SkillSession) -> SkillResult:
        """TERMINAL PROFILE"""
        ctx.output.text("步骤 4: 设置终端配置")
        session.data["state"] = EsimState.WAIT_TERMINAL_PROFILE
        
        apdu = ApduBuilder.terminal_profile()
        action = self._build_apdu_action("esim.terminal-profile", "设置终端配置", apdu)
        return SkillResult.continue_with(session.session_id, action)
    
    def _do_terminal_response(self, ctx: SkillContext, session: SkillSession, fetched_hex: str) -> SkillResult:
        """对 FETCH 到的 proactive 命令回 TERMINAL RESPONSE

        fetched 为 D0xx Proactive Command TLV，取其 81 03 <Command Details> 组成
        TERMINAL RESPONSE: 80 14 00 00 Lc 8103<details> 82 02 82 81 83 01 00
        """
        response_bytes = bytes.fromhex(fetched_hex) if fetched_hex else b""
        details = None
        inner = response_bytes[2:] if response_bytes[:1] == b'\xd0' else response_bytes
        for field_tag, value, _ in _iter_tlvs(inner):
            if field_tag == 0x81 and len(value) == 3:
                details = value
                break
        if details is None:
            return None

        data = "8103" + details.hex().upper() + "82028281" + "830100"
        apdu = f"80140000{len(data) // 2:02X}{data}"
        session.data["state"] = EsimState.WAIT_TERMINAL_RESPONSE
        action = self._build_apdu_action("esim.terminal-response", "TERMINAL RESPONSE", apdu)
        return SkillResult.continue_with(session.session_id, action)

    def _do_status(self, ctx: SkillContext, session: SkillSession) -> SkillResult:
        """STATUS"""
        ctx.output.text("步骤 5: 获取卡片状态")
        session.data["state"] = EsimState.WAIT_STATUS
        
        apdu = ApduBuilder.status()
        action = self._build_apdu_action("esim.status", "获取卡片状态", apdu)
        return SkillResult.continue_with(session.session_id, action)
    
    def _do_manage_channel(self, ctx: SkillContext, session: SkillSession) -> SkillResult:
        """MANAGE CHANNEL"""
        ctx.output.text("步骤 6: 管理逻辑通道")
        session.data["state"] = EsimState.WAIT_MANAGE_CHANNEL
        
        apdu = ApduBuilder.manage_channel(mode=0x00)  # 打开新通道
        action = self._build_apdu_action("esim.manage-channel", "打开逻辑通道", apdu)
        return SkillResult.continue_with(session.session_id, action)
    
    def _do_select_isdr(self, ctx: SkillContext, session: SkillSession) -> SkillResult:
        """SELECT ISD-R"""
        ctx.output.text("步骤 7: 选择 ISD-R")
        session.data["state"] = EsimState.WAIT_SELECT_ISDR

        # 使用之前打开的逻辑通道
        channel = session.data.get("channel", 0)
        apdu = ApduBuilder.select_isdr(channel=channel)
        action = self._build_apdu_action("esim.select-isdr", "选择 ISD-R", apdu)
        return SkillResult.continue_with(session.session_id, action)

    # ========== 清理阶段（下载前清理）==========

    def _do_euicc_memory_reset(self, ctx: SkillContext, session: SkillSession) -> SkillResult:
        """EuiccMemoryReset - 重置 eUICC 内存，清除之前的下载状态"""
        ctx.output.text("步骤 7.1: 清理 - 重置 eUICC 内存")
        session.data["state"] = EsimState.WAIT_EUICC_MEMORY_RESET

        channel = session.data.get("channel", 0)
        apdu = ApduBuilder.euicc_memory_reset(channel=channel)
        action = self._build_apdu_action("esim.euicc-memory-reset", "重置 eUICC 内存", apdu)
        return SkillResult.continue_with(session.session_id, action)

    def _continue_collect(self, ctx: SkillContext, session: SkillSession, accumulated: str, sw: str) -> SkillResult:
        """累积数据并继续取数：61XX → GET RESPONSE，91XX → FETCH"""
        session.data["response_accum"] = accumulated
        kind = sw[:2]
        session.data["pending_kind"] = "61" if kind == "61" else "91"
        if kind == "61":
            return self._do_get_response(ctx, session, int(sw[2:], 16))
        return self._do_fetch(ctx, session, int(sw[2:], 16))

    def _do_get_response(self, ctx: SkillContext, session: SkillSession, length: int) -> SkillResult:
        """GET RESPONSE - 处理 61XX 响应，获取更多数据"""
        ctx.output.text(f"处理 61XX 响应 - GET RESPONSE (length={length})")
        session.data["state"] = EsimState.WAIT_GET_RESPONSE

        channel = session.data.get("channel", 0)
        # GET RESPONSE: CLA = 通道号, INS = C0
        cla = channel & 0x03
        apdu = f"{cla:02X}C00000{length:02X}"
        action = self._build_apdu_action("esim.get-response", "GET RESPONSE", apdu)
        return SkillResult.continue_with(session.session_id, action)

    def _do_fetch(self, ctx: SkillContext, session: SkillSession, length: int) -> SkillResult:
        """FETCH - 处理 91XX 异步响应"""
        ctx.output.text(f"处理 91XX 响应 - FETCH (length={length})")
        session.data["state"] = EsimState.WAIT_FETCH

        channel = session.data.get("channel", 0)
        apdu = ApduBuilder.fetch(length, channel=channel)
        action = self._build_apdu_action("esim.fetch", "FETCH", apdu)
        return SkillResult.continue_with(session.session_id, action)

    def _continue_from_state(
        self, 
        ctx: SkillContext, 
        session: SkillSession, 
        previous_state: str,
        response: str,
        sw: str
    ) -> SkillResult:
        """根据之前的状态继续执行流程
        
        在处理完 61XX/91XX 响应后，根据之前被中断的状态继续执行。
        """
        # 构造一个模拟的 ActionResult 数据
        class MockResult:
            def __init__(self, resp, status_word):
                self.data = {"response": resp, "sw": status_word}
                self.status = type('Status', (), {'value': 'OK'})()
        
        mock_result = MockResult(response, sw)
        
        # 根据 previous_state 继续执行
        if previous_state == EsimState.WAIT_SELECT_MF:
            return self._do_terminal_capability(ctx, session)
        elif previous_state == EsimState.WAIT_TERMINAL_CAPABILITY:
            return self._do_terminal_profile(ctx, session)
        elif previous_state == EsimState.WAIT_TERMINAL_PROFILE:
            next_terminal = self._do_terminal_response(ctx, session, response)
            if next_terminal:
                return next_terminal
            return self._do_status(ctx, session)
        elif previous_state == EsimState.WAIT_TERMINAL_RESPONSE:
            next_terminal = self._do_terminal_response(ctx, session, response)
            if next_terminal:
                return next_terminal
            return self._do_status(ctx, session)
        elif previous_state == EsimState.WAIT_STATUS:
            return self._do_manage_channel(ctx, session)
        elif previous_state == EsimState.WAIT_MANAGE_CHANNEL:
            # 保存通道号
            if len(response) >= 2:
                session.data["channel"] = int(response[:2], 16)
            return self._do_select_isdr(ctx, session)
        elif previous_state == EsimState.WAIT_SELECT_ISDR:
            return self._do_euicc_memory_reset(ctx, session)
        elif previous_state == EsimState.WAIT_EUICC_MEMORY_RESET:
            failure = self._check_memory_reset_result(ctx, session, response)
            if failure:
                return failure
            return self._do_list_notification(ctx, session)
        elif previous_state == EsimState.WAIT_LIST_NOTIFICATION:
            return self._do_remove_notification(ctx, session, mock_result)
        elif previous_state == EsimState.WAIT_REMOVE_NOTIFICATION:
            return self._handle_remove_notification_result(ctx, session, response)
        elif previous_state == EsimState.WAIT_CLEANUP_RESET:
            return self._do_cleanup_open_channel(ctx, session)
        elif previous_state == EsimState.WAIT_CLEANUP_OPEN_CHANNEL:
            if len(response) >= 2:
                session.data["channel"] = int(response[:2], 16)
            return self._do_cleanup_select_isdr(ctx, session)
        elif previous_state == EsimState.WAIT_CLEANUP_SELECT_ISDR:
            return self._do_get_euicc_challenge(ctx, session)
        elif previous_state == EsimState.WAIT_GET_EUICC_CHALLENGE:
            # 保存挑战值，然后获取 EuiccInfo1
            try:
                response_bytes = bytes.fromhex(response)
                challenge = decode_bf2e_challenge(response_bytes)
                session.data["challenge"] = challenge.hex().upper()
            except Exception as e:
                ctx.output.text(f"警告: 无法解析 Challenge: {e}")
                session.data["challenge"] = response
            return self._do_get_euicc_info(ctx, session)
        elif previous_state == EsimState.WAIT_GET_EUICC_INFO:
            # 解析 eUICC 信息
            try:
                response_bytes = bytes.fromhex(response)
                euicc_info = decode_euicc_info1(response_bytes)
                # 转为可 JSON 序列化的格式（bytes -> hex 字符串）
                serializable_info = {}
                for k, v in euicc_info.items():
                    if isinstance(v, list):
                        serializable_info[k] = [item.hex().upper() if isinstance(item, bytes) else item for item in v]
                    elif isinstance(v, bytes):
                        serializable_info[k] = v.hex().upper()
                    else:
                        serializable_info[k] = v
                session.data["euicc_info"] = serializable_info
                ver_ids = euicc_info.get("verification_ci_pk_ids") or []
                if ver_ids:
                    session.data["euicc_ci_pk_id"] = ver_ids[0].hex().upper()
                    ctx.output.text(f"提取 euiccCiPKId: {ver_ids[0].hex().upper()}")
            except Exception as e:
                ctx.output.text(f"警告: 无法解析 EuiccInfo1: {e}")
            # 间接模式下 eIM 必须先配置，之后才由 eIM 驱动下载
            if session.data.get("mode") == "indirect" and not session.data.get("eim_added"):
                return self._do_add_initial_eim(ctx, session, purpose="pre_install")
            return self._do_authenticate_server(ctx, session)
        elif previous_state == EsimState.WAIT_AUTHENTICATE_SERVER:
            if not response:
                return SkillResult.failed(
                    session.session_id,
                    "AUTHENTICATE_SERVER_NO_RESPONSE",
                    "AuthenticateServer 未返回数据，无法继续 PrepareDownload"
                )
            try:
                response_bytes = bytes.fromhex(response)
                auth_status = check_authenticate_server_response(response_bytes)
                if not auth_status["ok"]:
                    return SkillResult.failed(
                        session.session_id,
                        "AUTHENTICATE_SERVER_FAILED",
                        f"卡片拒绝认证: errorCode={auth_status['error_code']} "
                        f"({auth_status['error_name']})"
                    )
                auth_ok = decode_authenticate_server_ok(response_bytes)
                session.data["transaction_id"] = auth_ok["transaction_id"] or auth_status.get("transaction_id") or "01"
                session.data["euicc_signature1"] = auth_ok["euicc_signature1"].hex().upper()
                ctx.output.text(f"认证成功, transaction_id={session.data['transaction_id']}")
            except Exception as e:
                return SkillResult.failed(
                    session.session_id,
                    "AUTHENTICATE_SERVER_PARSE_ERROR",
                    f"无法解析 AuthenticateServer 响应: {e}"
                )
            return self._do_prepare_download(ctx, session)
        elif previous_state == EsimState.WAIT_PREPARE_DOWNLOAD:
            # 解析 PrepareDownload 响应
            try:
                response_bytes = bytes.fromhex(response)
                pd_response = decode_prepare_download_response(response_bytes)
                if pd_response.get("transaction_id"):
                    session.data["transaction_id"] = pd_response["transaction_id"]
                session.data["euicc_otpk"] = pd_response.get("euicc_otpk", b"").hex().upper()
            except Exception as e:
                ctx.output.text(f"警告: 无法解析 PrepareDownload 响应: {e}")
            return self._do_load_profile_package(ctx, session)
        elif previous_state == EsimState.WAIT_LOAD_PROFILE_PACKAGE:
            failure = self._check_installation_result(ctx, session, response)
            if failure:
                return failure
            return self._do_post_install_reset(ctx, session)
        elif previous_state == EsimState.WAIT_POST_INSTALL_RESET:
            return self._do_post_install_ic1(ctx, session)
        elif previous_state == EsimState.WAIT_POST_INSTALL_IC1:
            if len(response) >= 2:
                session.data["post_install_channel"] = int(response[:2], 16)
                session.data["channel"] = int(response[:2], 16)
            return self._do_post_install_ic2(ctx, session)
        elif previous_state == EsimState.WAIT_POST_INSTALL_IC2:
            return self._do_post_install_select_isdr(ctx, session)
        elif previous_state == EsimState.WAIT_POST_INSTALL_SELECT_ISDR:
            return self._do_get_profiles_info(ctx, session)
        elif previous_state == EsimState.WAIT_GET_PROFILES_INFO:
            session.data["profiles_info_response"] = response
            mode = session.data.get("mode", "indirect")
            if mode == "indirect":
                return self._do_enable_psmo(ctx, session)
            else:
                return self._verify_and_complete(ctx, session)
        elif previous_state == EsimState.WAIT_ADD_INITIAL_EIM:
            return self._check_add_initial_eim_result(ctx, session, response)
        elif previous_state == EsimState.WAIT_ENABLE_PSMO:
            return self._check_euicc_package_result(ctx, session, response)
        elif previous_state == EsimState.WAIT_POST_ENABLE_RESET:
            return self._do_post_enable_ic(ctx, session)
        elif previous_state == EsimState.WAIT_POST_ENABLE_IC:
            if len(response) >= 2:
                session.data["channel"] = int(response[:2], 16)
            return self._do_post_enable_select_isdr(ctx, session)
        elif previous_state == EsimState.WAIT_POST_ENABLE_SELECT_ISDR:
            return self._do_verify_profile_state(ctx, session)
        elif previous_state == EsimState.WAIT_VERIFY_PROFILE_STATE:
            session.data["profiles_info_response"] = response
            return self._verify_and_complete(ctx, session)
        else:
            return SkillResult.failed(
                session.session_id,
                "UNKNOWN_PREVIOUS_STATE",
                f"未知的之前状态: {previous_state}"
            )

    def _do_list_notification(self, ctx: SkillContext, session: SkillSession) -> SkillResult:
        """ListNotification - 列出待处理的通知"""
        ctx.output.text("步骤 7.3: 清理 - 列出通知")
        session.data["state"] = EsimState.WAIT_LIST_NOTIFICATION

        channel = session.data.get("channel", 0)
        apdu = ApduBuilder.list_notification(channel=channel)
        action = self._build_apdu_action("esim.list-notification", "列出通知", apdu)
        return SkillResult.continue_with(session.session_id, action)

    def _do_remove_notification(self, ctx: SkillContext, session: SkillSession, result: ActionResult) -> SkillResult:
        """RemoveNotification - 删除通知（逐个删除全部安装类通知）"""
        ctx.output.text("步骤 7.4: 清理 - 删除通知")
        session.data["state"] = EsimState.WAIT_REMOVE_NOTIFICATION

        response = result.data.get("response", "")

        # 解析 RetrieveNotificationsList 响应，收集全部 seqNumber
        sequences = []
        if response:
            try:
                sequences = decode_notification_sequences(bytes.fromhex(response))
            except Exception as e:
                ctx.output.text(f"警告: 无法解析通知列表: {e}")

        if not sequences:
            ctx.output.text("无待处理通知")
            return self._do_get_euicc_challenge(ctx, session)

        session.data["remove_sequences"] = sequences
        session.data["remove_index"] = 0
        return self._do_remove_next_notification(ctx, session)

    def _handle_remove_notification_result(self, ctx: SkillContext, session: SkillSession, response_hex: str) -> SkillResult:
        """校验 RemoveNotificationResponse 并继续删除下一条

        通知可能因对应 Profile 已被 EuiccMemoryReset 删除而无法移除（6985）；
        此类失败会让 eUICC 拒绝后续 ES10 命令，必须冷复位恢复。
        """
        remove_result = -1
        if response_hex:
            try:
                remove_result = decode_remove_notification_result(bytes.fromhex(response_hex))
            except Exception:
                pass

        if remove_result != 0:
            ctx.output.text(
                f"警告: RemoveNotification removeResult={remove_result}，冷复位恢复卡片状态"
            )
            return self._do_cleanup_recover(ctx, session)

        session.data["remove_index"] = session.data.get("remove_index", 0) + 1
        return self._do_remove_next_notification(ctx, session)

    def _do_cleanup_recover(self, ctx: SkillContext, session: SkillSession) -> SkillResult:
        """清理阶段失败后恢复：冷复位卡片并重新建立逻辑通道"""
        ctx.output.text("清理恢复: 冷复位")
        session.data["state"] = EsimState.WAIT_CLEANUP_RESET
        session.data.pop("remove_sequences", None)
        session.data.pop("remove_index", None)

        action = Action(
            action_id="esim.cleanup-reset",
            type=ActionType.RESET_CARD,
            name="冷复位(清理恢复)",
            description="清理失败后冷复位恢复卡片状态",
            sensitive=False
        )
        return SkillResult.continue_with(session.session_id, action)

    def _do_cleanup_open_channel(self, ctx: SkillContext, session: SkillSession) -> SkillResult:
        """恢复：重新打开逻辑通道（由卡分配通道号）"""
        ctx.output.text("清理恢复: 打开逻辑通道")
        session.data["state"] = EsimState.WAIT_CLEANUP_OPEN_CHANNEL

        apdu = ApduBuilder.manage_channel(mode=0x00, channel=0)
        action = self._build_apdu_action("esim.cleanup-open-channel", "打开逻辑通道", apdu)
        return SkillResult.continue_with(session.session_id, action)

    def _do_cleanup_select_isdr(self, ctx: SkillContext, session: SkillSession) -> SkillResult:
        """恢复：重新选择 ISD-R"""
        ctx.output.text("清理恢复: 选择 ISD-R")
        session.data["state"] = EsimState.WAIT_CLEANUP_SELECT_ISDR

        channel = session.data.get("channel", 1)
        apdu = ApduBuilder.select_isdr(channel=channel)
        action = self._build_apdu_action("esim.cleanup-select-isdr", "选择 ISD-R", apdu)
        return SkillResult.continue_with(session.session_id, action)

    def _do_remove_next_notification(self, ctx: SkillContext, session: SkillSession) -> SkillResult:
        """发送下一条 RemoveNotification；全部完成后进入 Profile 安装阶段"""
        sequences = session.data.get("remove_sequences", [])
        index = session.data.get("remove_index", 0)

        if index >= len(sequences):
            session.data.pop("remove_sequences", None)
            session.data.pop("remove_index", None)
            ctx.output.text("通知清理完成")
            return self._do_get_euicc_challenge(ctx, session)

        session.data["state"] = EsimState.WAIT_REMOVE_NOTIFICATION
        sequence = sequences[index]
        ctx.output.text(f"删除通知 seq={sequence} ({index + 1}/{len(sequences)})")

        channel = session.data.get("channel", 0)
        apdu = ApduBuilder.remove_notification(sequence, channel=channel)
        action = self._build_apdu_action("esim.remove-notification", "删除通知", apdu)
        return SkillResult.continue_with(session.session_id, action)

    # ========== Profile 安装阶段 ==========
    
    def _do_get_euicc_info(self, ctx: SkillContext, session: SkillSession) -> SkillResult:
        """GetEuiccInfo1"""
        ctx.output.text("步骤 8: 获取 eUICC 信息")
        session.data["state"] = EsimState.WAIT_GET_EUICC_INFO

        channel = session.data.get("channel", 0)
        apdu = ApduBuilder.get_euicc_info1(channel=channel)
        action = self._build_apdu_action("esim.get-euicc-info", "获取 eUICC 信息", apdu)
        return SkillResult.continue_with(session.session_id, action)

    def _do_get_euicc_challenge(self, ctx: SkillContext, session: SkillSession) -> SkillResult:
        """GetEuiccChallenge"""
        ctx.output.text("步骤 9: 获取 eUICC 挑战值")
        session.data["state"] = EsimState.WAIT_GET_EUICC_CHALLENGE

        channel = session.data.get("channel", 0)
        apdu = ApduBuilder.get_euicc_challenge(channel=channel)
        action = self._build_apdu_action("esim.get-euicc-challenge", "获取挑战值", apdu)
        return SkillResult.continue_with(session.session_id, action)
    
    def _do_authenticate_server(self, ctx: SkillContext, session: SkillSession) -> SkillResult:
        """AuthenticateServer

        构造 ASN.1 编码的认证数据，使用真实私钥签名
        """
        ctx.output.text("步骤 10: 服务器认证")
        session.data["state"] = EsimState.WAIT_AUTHENTICATE_SERVER

        # 从会话数据中获取参数
        params = session.data.get("params", {})
        # 参考实现不在 ctxParams1 内携带 matchingId（由 SM-DP+ 侧按激活码匹配）
        matching_id = params.get("matching_id_in_auth", "")
        tac = bytes.fromhex(params.get("tac", "00000000"))
        device_identifier = bytes.fromhex(params.get("imei", "0000000011111111"))

        # eUICC 挑战值（16 字节）
        challenge_hex = session.data.get("challenge", "")
        try:
            euicc_challenge = bytes.fromhex(challenge_hex)[:16].ljust(16, b'\x00')
        except Exception:
            euicc_challenge = bytes(16)

        # transactionId: 参考实现使用 1 字节 "01"（可通过参数覆盖）
        transaction_id = params.get("transaction_id", "01")
        # 记录本次会话使用的 transactionId，PrepareDownload 必须复用同一个值
        session.data["transaction_id"] = transaction_id

        # 获取证书数据
        dp_auth_cert = session.data.get("dp_auth_cert", "")
        dp_auth_key_hex = session.data.get("dp_auth_key", "")
        euicc_ci_pk_id = session.data.get("euicc_ci_pk_id", "0102030405060708")

        # SM-DP+ 地址和服务器挑战值（参考实现使用随机 16 字节）
        server_address = params.get("smdp_address", "testsmdpplus1.example.com")
        import os as _os
        server_challenge = _os.urandom(16)

        # 构造 ServerSigned1 SEQUENCE
        try:
            server_signed1 = encode_server_signed1(
                transaction_id=bytes.fromhex(transaction_id),
                euicc_challenge=euicc_challenge,
                server_address=server_address,
                server_challenge=server_challenge
            )
        except Asn1CodecError as e:
            return SkillResult.failed(
                session.session_id,
                "ASN1_ENCODE_ERROR",
                f"ServerSigned1 编码失败: {e}"
            )

        # 使用真实私钥对 ServerSigned1 签名
        server_signature1 = b""
        try:
            if dp_auth_key_hex:
                from cryptography.hazmat.primitives import hashes
                from cryptography.hazmat.primitives.asymmetric import ec

                # 加载私钥（支持 PEM 和 DER 格式）
                private_key_bytes = bytes.fromhex(dp_auth_key_hex)
                private_key = _load_ec_private_key(private_key_bytes)

                # 对完整的 ServerSigned1 DER 数据签名
                signature = private_key.sign(server_signed1, ec.ECDSA(hashes.SHA256()))
                server_signature1 = _der_signature_to_raw(signature)

                ctx.output.text(f"签名成功，签名长度: {len(server_signature1)} 字节")
        except Exception as e:
            ctx.output.text(f"警告: 签名失败，使用占位数据 - {e}")
            server_signature1 = bytes(64)  # 占位签名

        # 服务器证书
        server_certificate = bytes.fromhex(dp_auth_cert) if dp_auth_cert else b""

        try:
            auth_data = encode_bf38_authenticate_server_request(
                server_signed1=server_signed1,
                server_signature1=server_signature1,
                euicc_ci_pk_id=bytes.fromhex(euicc_ci_pk_id) if isinstance(euicc_ci_pk_id, str) else euicc_ci_pk_id,
                server_certificate=server_certificate,
                matching_id=matching_id,
                tac=tac,
                device_identifier=device_identifier
            )
            auth_data_hex = auth_data.hex().upper()
        except Asn1CodecError as e:
            return SkillResult.failed(
                session.session_id,
                "ASN1_ENCODE_ERROR",
                f"ASN.1 编码失败: {e}"
            )

        channel = session.data.get("channel", 0)
        apdu_list = ApduBuilder.authenticate_server(auth_data_hex, channel=channel)
        
        # 如果只有一条 APDU，直接发送
        if len(apdu_list) == 1:
            action = self._build_apdu_action("esim.authenticate-server", "服务器认证", apdu_list[0], sensitive=True)
            return SkillResult.continue_with(session.session_id, action)
        
        # 如果有多条 APDU（分块），保存后续 APDU 到 session
        session.data["pending_apdus"] = apdu_list[1:]
        action = self._build_apdu_action("esim.authenticate-server", "服务器认证", apdu_list[0], sensitive=True)
        return SkillResult.continue_with(session.session_id, action)

    def _do_prepare_download(self, ctx: SkillContext, session: SkillSession) -> SkillResult:
        """PrepareDownload，使用真实私钥签名"""
        ctx.output.text("步骤 11: 准备下载")
        session.data["state"] = EsimState.WAIT_PREPARE_DOWNLOAD

        # transactionId 必须与 AuthenticateServer 请求中发送的一致；
        # 用 16 字节默认值会被 eUICC 判为会话不匹配（6985）。
        transaction_id = session.data.get("transaction_id") or "01"

        # 编码 SmdpSigned2
        try:
            smdp_signed2 = encode_smdp_signed2(
                transaction_id=transaction_id,
                confirmation_code_required=False
            )
        except Asn1CodecError as e:
            return SkillResult.failed(
                session.session_id,
                "ASN1_ENCODE_ERROR",
                f"SmdpSigned2 编码失败: {e}"
            )

        # 使用真实私钥签名
        smdp_signature2 = b""
        try:
            dp_pb_key_hex = session.data.get("dp_pb_key", "")
            if dp_pb_key_hex:
                from cryptography.hazmat.primitives import hashes
                from cryptography.hazmat.primitives.asymmetric import ec

                # 加载私钥（支持 PEM 和 DER 格式）
                private_key_bytes = bytes.fromhex(dp_pb_key_hex)
                private_key = _load_ec_private_key(private_key_bytes)

                # 签名输入 = smdpSigned2 || [APPLICATION 55] euiccSignature1
                euicc_signature1_hex = session.data.get("euicc_signature1", "")
                signature_input = smdp_signed2 + encode_application_signature(
                    bytes.fromhex(euicc_signature1_hex)
                )
                signature = private_key.sign(signature_input, ec.ECDSA(hashes.SHA256()))
                smdp_signature2 = _der_signature_to_raw(signature)

                ctx.output.text(f"PrepareDownload 签名成功，签名长度: {len(smdp_signature2)} 字节")
        except Exception as e:
            ctx.output.text(f"警告: PrepareDownload 签名失败，使用占位数据 - {e}")
            smdp_signature2 = bytes(64)  # 占位签名

        # 获取服务器证书
        dp_pb_cert = session.data.get("dp_pb_cert", "")
        smdp_certificate = bytes.fromhex(dp_pb_cert) if dp_pb_cert else b""

        try:
            download_data = encode_bf21_prepare_download_request(
                smdp_signed2=smdp_signed2,
                smdp_signature2=smdp_signature2,
                smdp_certificate=smdp_certificate
            )
            download_data_hex = download_data.hex().upper()
        except Asn1CodecError as e:
            return SkillResult.failed(
                session.session_id,
                "ASN1_ENCODE_ERROR",
                f"PrepareDownload 编码失败: {e}"
            )

        # 自检：BF21 声明的 TLV 长度必须与实际字节数一致，否则 eUICC 会返回 6985
        if not download_data.startswith(b'\xbf\x21'):
            return SkillResult.failed(
                session.session_id,
                "ASN1_ENCODE_ERROR",
                "PrepareDownload 数据缺少 BF21 标签"
            )
        declared = _ber_total_length(download_data)
        if declared != len(download_data):
            return SkillResult.failed(
                session.session_id,
                "ASN1_ENCODE_ERROR",
                f"PrepareDownload 长度不一致: 声明 {declared} 字节，实际 {len(download_data)} 字节"
            )

        channel = session.data.get("channel", 0)
        apdu_list = ApduBuilder.prepare_download(download_data_hex, channel=channel)

        # 如果只有一条 APDU，直接发送
        if len(apdu_list) == 1:
            action = self._build_apdu_action("esim.prepare-download", "准备下载", apdu_list[0])
            return SkillResult.continue_with(session.session_id, action)

        # 如果有多条 APDU（分块），保存后续 APDU 到 session
        session.data["pending_apdus"] = apdu_list[1:]
        action = self._build_apdu_action("esim.prepare-download", "准备下载", apdu_list[0])
        return SkillResult.continue_with(session.session_id, action)
    
    def _do_load_profile_package(self, ctx: SkillContext, session: SkillSession) -> SkillResult:
        """LoadProfilePackage

        加载 Profile 包数据 - 生成 BPP 并按照 ASN.1 结构分块发送
        """
        ctx.output.text("步骤 12: 加载 Profile 包")
        session.data["state"] = EsimState.WAIT_LOAD_PROFILE_PACKAGE

        # 从会话数据中获取 Profile 包（UPP 格式）
        package_data = session.data.get("profile_package", "")

        if not package_data:
            # 如果没有预加载的包数据，使用空包占位
            ctx.output.text("警告: 未提供 Profile 包数据，使用空包占位")
            package_data = "3000"  # 空 SEQUENCE

        # 获取必要的参数
        params = session.data.get("params", {})
        transaction_id = session.data.get("transaction_id", "00000000000000000000000000000000")
        eid = params.get("eid", "89049032123451234512345678901235")
        iccid = params.get("iccid", "8929901012345678905F")
        profile_id = params.get("profile_id", "A0000005591010FFFFFFFF8900001000")
        
        # 获取 eUICC OTPK (从 PrepareDownload 响应中获取)
        euicc_otpk_hex = session.data.get("euicc_otpk", "")
        if not euicc_otpk_hex or len(euicc_otpk_hex) != 130 or euicc_otpk_hex.startswith("00" * 65):
            # 没有有效的 eUICC OTPK 无法生成合规 BPP，不能发送全零占位数据
            return SkillResult.failed(
                session.session_id,
                "EUICC_OTPK_MISSING",
                "缺少有效的 eUICC OTPK（PrepareDownload 未成功），无法生成 Bound Profile Package"
            )
        euicc_otpk = bytes.fromhex(euicc_otpk_hex)

        # 获取 DP+ Profile Binding 证书和私钥
        dp_pb_cert = session.data.get("dp_pb_cert", "")
        dp_pb_key = session.data.get("dp_pb_key", "")
        
        # 生成 BPP
        try:
            if dp_pb_cert and dp_pb_key:
                ctx.output.text("生成 BPP (Bound Profile Package)...")
                bpp_bytes = generate_bpp(
                    transaction_id=transaction_id,
                    eid=eid,
                    euicc_otpk=euicc_otpk,
                    profile_package=bytes.fromhex(package_data),
                    iccid=iccid,
                    profile_id=profile_id,
                    profile_name=params.get("profile_name", "Operational Profile Name 1"),
                    dp_pb_private_key_pem=bytes.fromhex(dp_pb_key),
                    dp_pb_cert_der=bytes.fromhex(dp_pb_cert),
                    service_provider_name=params.get("spn", "SP Name 1"),
                    profile_class=int(params.get("profile_class", 2))
                )
                bpp_hex = bpp_bytes.hex().upper()
                ctx.output.text(f"BPP 生成成功，长度: {len(bpp_bytes)} 字节")
            else:
                # 没有证书，使用简化的 UPP 包装
                ctx.output.text("警告: 缺少 DP+ 证书，使用简化的 UPP 包装")
                bpp_hex = package_data
        except Exception as e:
            ctx.output.text(f"BPP 生成失败: {e}，使用简化的 UPP 包装")
            bpp_hex = package_data

        channel = session.data.get("channel", 0)
        # load_profile_package 方法会按照 BPP 结构分块
        apdu_list = ApduBuilder.load_profile_package(bpp_hex, channel=channel)

        # 如果只有一条 APDU，直接发送
        if len(apdu_list) == 1:
            action = self._build_apdu_action("esim.load-profile-package", "加载 Profile 包", apdu_list[0])
            return SkillResult.continue_with(session.session_id, action)

        # 如果有多条 APDU（分块），保存后续 APDU 到 session
        session.data["pending_apdus"] = apdu_list[1:]
        action = self._build_apdu_action("esim.load-profile-package", "加载 Profile 包", apdu_list[0])
        return SkillResult.continue_with(session.session_id, action)
    
    # ========== 后安装处理 ==========
    
    def _check_memory_reset_result(self, ctx: SkillContext, session: SkillSession, response_hex: str):
        """校验 EuiccMemoryResetResponse；0(ok)/1(nothingToDelete) 视为成功"""
        if not response_hex:
            return None
        try:
            reset_result = decode_memory_reset_result(bytes.fromhex(response_hex))
        except Exception as e:
            ctx.output.text(f"警告: 无法解析 EuiccMemoryResetResponse: {e}")
            return None

        if reset_result in (0, 1):
            ctx.output.text(f"EuiccMemoryReset 结果: {reset_result}")
            return None
        if reset_result is None:
            return None

        session.data["state"] = EsimState.FAILED
        return SkillResult.failed(
            session.session_id,
            "EUICC_MEMORY_RESET_FAILED",
            f"EuiccMemoryReset 失败: resetResult={reset_result} (0=ok, 1=nothingToDelete, 5=catBusy)"
        )

    def _check_installation_result(self, ctx: SkillContext, session: SkillSession, response_hex: str):
        """检查 ProfileInstallationResult (BF37)

        Returns:
            None 表示安装成功或响应不含 BF37；否则返回 FAILED 的 SkillResult
        """
        if not response_hex or not response_hex.upper().startswith("BF37"):
            return None

        try:
            pir = decode_profile_installation_result(bytes.fromhex(response_hex))
        except Exception as e:
            ctx.output.text(f"警告: 无法解析 ProfileInstallationResult: {e}")
            return None

        if pir["ok"]:
            session.data["profile_installation_result"] = pir
            ctx.output.text("Profile 安装成功 (ProfileInstallationResult = success)")
            return None

        session.data["state"] = EsimState.FAILED
        return SkillResult.failed(
            session.session_id,
            "PROFILE_INSTALLATION_FAILED",
            f"Profile 安装失败: bppCommand={pir['bpp_command'] or '?'}({pir['bpp_command_id']}) "
            f"errorReason={pir['error_reason']} ({pir['error_name']})"
        )

    def _do_post_install_reset(self, ctx: SkillContext, session: SkillSession) -> SkillResult:
        """后安装冷复位"""
        ctx.output.text("步骤 13: 后安装冷复位")
        session.data["state"] = EsimState.WAIT_POST_INSTALL_RESET
        
        action = Action(
            action_id="esim.post-install-reset",
            type=ActionType.RESET_CARD,
            name="冷复位",
            description="后安装冷复位",
            sensitive=False
        )
        return SkillResult.continue_with(session.session_id, action)
    
    def _do_post_install_ic1(self, ctx: SkillContext, session: SkillSession) -> SkillResult:
        """IC1: 冷复位后重新打开逻辑通道（由卡分配通道号）"""
        ctx.output.text("步骤 14: 初始化通道")
        session.data["state"] = EsimState.WAIT_POST_INSTALL_IC1

        apdu = ApduBuilder.manage_channel(mode=0x00, channel=0)
        action = self._build_apdu_action("esim.post-install-ic1", "初始化通道", apdu)
        return SkillResult.continue_with(session.session_id, action)

    def _do_post_install_ic2(self, ctx: SkillContext, session: SkillSession) -> SkillResult:
        """IC2: 通道已就绪，直接选择 ISD-R"""
        return self._do_post_install_select_isdr(ctx, session)

    def _do_post_install_select_isdr(self, ctx: SkillContext, session: SkillSession) -> SkillResult:
        """后安装 SELECT ISD-R"""
        ctx.output.text("步骤 16: 重新选择 ISD-R")
        session.data["state"] = EsimState.WAIT_POST_INSTALL_SELECT_ISDR

        channel = session.data.get("post_install_channel", 1)
        apdu = ApduBuilder.select_isdr(channel=channel)
        action = self._build_apdu_action("esim.post-install-select-isdr", "选择 ISD-R", apdu)
        return SkillResult.continue_with(session.session_id, action)

    def _do_get_profiles_info(self, ctx: SkillContext, session: SkillSession) -> SkillResult:
        """GetProfilesInfo"""
        ctx.output.text("步骤 17: 获取 Profile 信息")
        session.data["state"] = EsimState.WAIT_GET_PROFILES_INFO

        channel = session.data.get("post_install_channel", 1)
        apdu = ApduBuilder.get_profiles_info(channel=channel)
        action = self._build_apdu_action("esim.get-profiles-info", "获取 Profile 信息", apdu)
        return SkillResult.continue_with(session.session_id, action)
    
    # ========== eIM 启用阶段（间接模式）==========
    
    def _do_add_initial_eim(self, ctx: SkillContext, session: SkillSession, purpose: str = "pre_enable") -> SkillResult:
        """AddInitialEim (BF57)

        Args:
            purpose: "pre_install"（下载前，SGP.33 间接模式）或 "pre_enable"（启用前）
        """
        ctx.output.text("添加初始 eIM")
        session.data["state"] = EsimState.WAIT_ADD_INITIAL_EIM
        session.data["add_eim_purpose"] = purpose

        params = session.data.get("params", {})
        eim_id = params.get("eim_id", "testeim1")
        eim_fqdn = params.get("eim_fqdn", "eimfqdn.example.com")
        eim_id_type = int(params.get("eim_id_type", 3))
        eim_counter = int(params.get("eim_initial_counter", 1))

        eim_cert_hex = session.data.get("eim_cert", "")
        if not eim_cert_hex:
            return SkillResult.failed(
                session.session_id,
                "EIM_CERT_MISSING",
                "缺少 eIM 证书，无法编码 AddInitialEim"
            )

        try:
            spki = extract_spki(bytes.fromhex(eim_cert_hex))
            eim_data = encode_bf57_add_initial_eim(
                eim_id=eim_id,
                counter_value=eim_counter,
                eim_public_key_spki=spki,
                eim_fqdn=eim_fqdn,
                eim_id_type=eim_id_type
            )
            eim_data_hex = eim_data.hex().upper()
        except Asn1CodecError as e:
            return SkillResult.failed(
                session.session_id,
                "ASN1_ENCODE_ERROR",
                f"AddInitialEim 编码失败: {e}"
            )

        channel = session.data.get("channel", 0)
        apdu = ApduBuilder.add_initial_eim(eim_data_hex, channel=channel)
        action = self._build_apdu_action("esim.add-initial-eim", "添加初始 eIM", apdu)
        return SkillResult.continue_with(session.session_id, action)

    def _do_enable_psmo(self, ctx: SkillContext, session: SkillSession) -> SkillResult:
        """LoadEuiccPackage(BF51) — enable PSMO，eIM 签名"""
        ctx.output.text("启用 Profile (LoadEuiccPackage)")
        session.data["state"] = EsimState.WAIT_ENABLE_PSMO

        params = session.data.get("params", {})
        eim_id = params.get("eim_id", "testeim1")
        eim_counter = int(params.get("eim_enable_counter", 2))
        eid = params.get("eid", "")
        iccid_bcd = self._encode_iccid_bcd(params.get("iccid", ""))

        eim_key_hex = session.data.get("eim_key", "")
        if not eim_key_hex:
            return SkillResult.failed(
                session.session_id,
                "EIM_KEY_MISSING",
                "缺少 eIM 私钥，无法签名 EuiccPackage"
            )

        try:
            psmo = encode_enable_psmo(bytes.fromhex(iccid_bcd))
            psmo_list = encode_psmo_list(psmo)
            signed = encode_euicc_package_signed(
                eim_id=eim_id,
                eid=bytes.fromhex(eid),
                counter_value=eim_counter,
                euicc_package=psmo_list
            )
            eim_private_key = _load_ec_private_key(bytes.fromhex(eim_key_hex))
            signature = sign_euicc_package(signed, eim_private_key)
            request = encode_bf51_euicc_package_request(signed, signature)
            request_hex = request.hex().upper()
        except Asn1CodecError as e:
            return SkillResult.failed(
                session.session_id,
                "ASN1_ENCODE_ERROR",
                f"EuiccPackageRequest 编码失败: {e}"
            )

        channel = session.data.get("post_install_channel", 1)
        apdu = ApduBuilder.enable_psmo(request_hex, channel=channel)
        action = self._build_apdu_action("esim.enable-psmo", "启用 Profile", apdu)
        return SkillResult.continue_with(session.session_id, action)

    def _check_add_initial_eim_result(self, ctx: SkillContext, session: SkillSession, response_hex: str) -> SkillResult:
        """解析 AddInitialEimResponse，成功后按 purpose 继续流程"""
        try:
            eim_result = decode_add_initial_eim_response(bytes.fromhex(response_hex))
        except Exception as e:
            return SkillResult.failed(
                session.session_id,
                "ADD_INITIAL_EIM_FAILED",
                f"无法解析 AddInitialEim 响应: {e}"
            )

        if not eim_result["ok"]:
            # associatedEimAlreadyExists(2) 视为可接受：卡上已配置该 eIM，重跑时直接继续
            if eim_result["error_code"] == 2:
                ctx.output.text("eIM 已存在，跳过配置")
            else:
                return SkillResult.failed(
                    session.session_id,
                    "ADD_INITIAL_EIM_FAILED",
                    f"AddInitialEim 失败: errorCode={eim_result['error_code']} "
                    f"({eim_result['error_name']})"
                )

        session.data["eim_added"] = True
        session.data["eim_association_token"] = eim_result["association_token"]
        if eim_result["ok"]:
            ctx.output.text(
                f"AddInitialEim 成功, associationToken={eim_result['association_token']}"
            )

        purpose = session.data.get("add_eim_purpose", "pre_enable")
        if purpose == "pre_install":
            return self._do_authenticate_server(ctx, session)
        return self._do_enable_psmo(ctx, session)

    def _check_euicc_package_result(self, ctx: SkillContext, session: SkillSession, response_hex: str) -> SkillResult:
        """解析 EuiccPackageResult，成功则进入启用后复位"""
        try:
            pkg_result = decode_euicc_package_result(bytes.fromhex(response_hex))
        except Exception as e:
            return SkillResult.failed(
                session.session_id,
                "EUICC_PACKAGE_FAILED",
                f"无法解析 EuiccPackageResult: {e}"
            )

        if not pkg_result["ok"]:
            return SkillResult.failed(
                session.session_id,
                "EUICC_PACKAGE_FAILED",
                f"启用 Profile 失败: enableResult={pkg_result['enable_result']} "
                f"errorCode={pkg_result['error_code']} ({pkg_result['error_name']})"
            )

        session.data["euicc_package_result"] = pkg_result
        ctx.output.text("Profile 启用成功")
        return self._do_post_enable_reset(ctx, session)
    
    def _encode_iccid_bcd(self, iccid: str) -> str:
        """将 ICCID 字符串转换为 BCD 编码（半字节交换）
        
        例如: "89860012345678901234" -> "986810325476981032F4"
        """
        # 确保长度为偶数
        if len(iccid) % 2 != 0:
            iccid = iccid + "F"
        
        # 半字节交换
        result = ""
        for i in range(0, len(iccid), 2):
            result += iccid[i + 1] + iccid[i]
        
        return result
    
    def _do_post_enable_reset(self, ctx: SkillContext, session: SkillSession) -> SkillResult:
        """启用后冷复位"""
        ctx.output.text("步骤 20: 启用后冷复位")
        session.data["state"] = EsimState.WAIT_POST_ENABLE_RESET
        
        action = Action(
            action_id="esim.post-enable-reset",
            type=ActionType.RESET_CARD,
            name="冷复位",
            description="启用后冷复位",
            sensitive=False
        )
        return SkillResult.continue_with(session.session_id, action)
    
    def _do_post_enable_ic(self, ctx: SkillContext, session: SkillSession) -> SkillResult:
        """启用后冷复位完毕，重新打开逻辑通道（由卡分配通道号）"""
        ctx.output.text("步骤 20.1: 重新打开逻辑通道")
        session.data["state"] = EsimState.WAIT_POST_ENABLE_IC

        apdu = ApduBuilder.manage_channel(mode=0x00, channel=0)
        action = self._build_apdu_action("esim.post-enable-ic", "打开逻辑通道", apdu)
        return SkillResult.continue_with(session.session_id, action)

    def _do_post_enable_select_isdr(self, ctx: SkillContext, session: SkillSession) -> SkillResult:
        """启用后 SELECT ISD-R"""
        ctx.output.text("步骤 21: 重新选择 ISD-R")
        session.data["state"] = EsimState.WAIT_POST_ENABLE_SELECT_ISDR

        channel = session.data.get("channel", 1)
        apdu = ApduBuilder.select_isdr(channel=channel)
        action = self._build_apdu_action("esim.post-enable-select-isdr", "选择 ISD-R", apdu)
        return SkillResult.continue_with(session.session_id, action)

    def _do_verify_profile_state(self, ctx: SkillContext, session: SkillSession) -> SkillResult:
        """验证 Profile 状态"""
        ctx.output.text("步骤 22: 验证 Profile 状态")
        session.data["state"] = EsimState.WAIT_VERIFY_PROFILE_STATE

        channel = session.data.get("channel", 1)
        apdu = ApduBuilder.get_profiles_info(channel=channel)
        action = self._build_apdu_action("esim.verify-profile-state", "验证 Profile 状态", apdu)
        return SkillResult.continue_with(session.session_id, action)
    
    # ========== 辅助方法 ==========
    
    def _build_apdu_action(
        self, action_id: str, name: str, apdu: str, sensitive: bool = False
    ) -> Action:
        """构建 APDU Action"""
        return Action(
            action_id=action_id,
            type=ActionType.APDU,
            name=name,
            description=f"发送 APDU: {apdu[:20]}..." if len(apdu) > 20 else f"发送 APDU: {apdu}",
            sensitive=sensitive,
            payload={"apdu": apdu, "expectedStatus": ["9000"]}
        )
    
    def _verify_and_complete(self, ctx: SkillContext, session: SkillSession) -> SkillResult:
        """验证并完成"""
        # 解析 GetProfilesInfo 响应，验证 profileState
        response = session.data.get("profiles_info_response", "")
        
        profile_state = "UNKNOWN"
        verified = False
        
        if response:
            try:
                response_bytes = bytes.fromhex(response)
                profiles_info = decode_profiles_info(response_bytes)
                profile_state = profiles_info.get("profile_state", "UNKNOWN")
                verified = (profile_state == "ENABLED")
            except Exception as e:
                ctx.output.text(f"警告: 无法解析 Profile 状态: {e}")
        
        if verified:
            ctx.output.info(f"eSIM Profile 下载流程完成，状态: {profile_state}")
        else:
            ctx.output.text(f"警告: Profile 状态为 {profile_state}，未确认启用")
        
        session.data["state"] = EsimState.SUCCESS
        
        result_data = {
            "iccid": session.data["params"].get("iccid", ""),
            "profile_id": session.data["params"].get("profile_id", ""),
            "eid": session.data["params"].get("eid", ""),
            "mode": session.data.get("mode", "indirect"),
            "profile_state": profile_state,
            "verified": verified,
        }
        
        return SkillResult.success(session.session_id, result_data)
