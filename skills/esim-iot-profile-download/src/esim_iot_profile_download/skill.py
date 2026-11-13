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
    encode_bf38_authenticate_server_request,
    encode_smdp_signed2,
    encode_bf21_prepare_download_request,
    decode_prepare_download_response,
    decode_euicc_info1,
    decode_bf2e_challenge,
    encode_bf57_add_initial_eim,
    encode_bf51_enable_psmo,
    decode_profiles_info,
    Asn1CodecError
)
from .resources import ResourceManager, CertificateManager, ProfileManager, ResourceLoadError


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
            # EuiccMemoryReset 完成后，处理可能的 91XX 响应
            sw = result.data.get("sw", "")
            if sw.startswith("91"):
                return self._do_fetch_refresh(ctx, session, int(sw[2:], 16))
            return self._do_list_notification(ctx, session)
        
        elif current_state == EsimState.WAIT_FETCH_REFRESH:
            # FETCH REFRESH 完成后，进入 ListNotification
            return self._do_list_notification(ctx, session)
        
        elif current_state == EsimState.WAIT_LIST_NOTIFICATION:
            # ListNotification 完成后，进入 RemoveNotification
            return self._do_remove_notification(ctx, session, result)
        
        elif current_state == EsimState.WAIT_REMOVE_NOTIFICATION:
            # RemoveNotification 完成后，进入 Profile 安装阶段
            return self._do_get_euicc_info(ctx, session)
        
        elif current_state == EsimState.WAIT_GET_EUICC_INFO:
            # 解析 eUICC 信息
            response = result.data.get("response", "")
            try:
                response_bytes = bytes.fromhex(response)
                euicc_info = decode_euicc_info1(response_bytes)
                session.data["euicc_info"] = euicc_info
                # 保存 euiccCiPkId 供后续认证使用
                if "verification_ci_pk_ids" in euicc_info and euicc_info["verification_ci_pk_ids"]:
                    session.data["euicc_ci_pk_id"] = euicc_info["verification_ci_pk_ids"][0]
            except Exception as e:
                ctx.output.text(f"警告: 无法解析 EuiccInfo1: {e}")
            return self._do_get_euicc_challenge(ctx, session)
        
        elif current_state == EsimState.WAIT_GET_EUICC_CHALLENGE:
            # 保存挑战值
            response = result.data.get("response", "")
            try:
                response_bytes = bytes.fromhex(response)
                challenge = decode_bf2e_challenge(response_bytes)
                session.data["challenge"] = challenge.hex().upper()
            except Exception as e:
                ctx.output.text(f"警告: 无法解析 Challenge: {e}")
                session.data["challenge"] = response
            return self._do_authenticate_server(ctx, session)
        
        elif current_state == EsimState.WAIT_AUTHENTICATE_SERVER:
            # 解析 AuthenticateServer 响应，保存 transaction_id
            response = result.data.get("response", "")
            # 响应中可能包含 transaction_id，这里简化处理
            # 实际应该从响应中解析
            return self._do_prepare_download(ctx, session)
        
        elif current_state == EsimState.WAIT_PREPARE_DOWNLOAD:
            # 解析 PrepareDownload 响应，提取 euicc_otpk
            response = result.data.get("response", "")
            try:
                response_bytes = bytes.fromhex(response)
                pd_response = decode_prepare_download_response(response_bytes)
                session.data["transaction_id"] = pd_response.get("transaction_id", "")
                session.data["euicc_otpk"] = pd_response.get("euicc_otpk", b"").hex().upper()
            except Exception as e:
                ctx.output.text(f"警告: 无法解析 PrepareDownload 响应: {e}")
            return self._do_load_profile_package(ctx, session)
        
        elif current_state == EsimState.WAIT_LOAD_PROFILE_PACKAGE:
            return self._do_post_install_reset(ctx, session)
        
        elif current_state == EsimState.WAIT_POST_INSTALL_RESET:
            return self._do_post_install_ic1(ctx, session)
        
        elif current_state == EsimState.WAIT_POST_INSTALL_IC1:
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
                return self._do_add_initial_eim(ctx, session)
            else:
                # 直接模式，验证状态后完成
                return self._verify_and_complete(ctx, session)
        
        elif current_state == EsimState.WAIT_ADD_INITIAL_EIM:
            return self._do_enable_psmo(ctx, session)
        
        elif current_state == EsimState.WAIT_ENABLE_PSMO:
            return self._do_post_enable_reset(ctx, session)
        
        elif current_state == EsimState.WAIT_POST_ENABLE_RESET:
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

        apdu = ApduBuilder.select_isdr()
        action = self._build_apdu_action("esim.select-isdr", "选择 ISD-R", apdu)
        return SkillResult.continue_with(session.session_id, action)

    # ========== 清理阶段（下载前清理）==========

    def _do_euicc_memory_reset(self, ctx: SkillContext, session: SkillSession) -> SkillResult:
        """EuiccMemoryReset - 重置 eUICC 内存，清除之前的下载状态"""
        ctx.output.text("步骤 7.1: 清理 - 重置 eUICC 内存")
        session.data["state"] = EsimState.WAIT_EUICC_MEMORY_RESET

        apdu = ApduBuilder.euicc_memory_reset()
        action = self._build_apdu_action("esim.euicc-memory-reset", "重置 eUICC 内存", apdu)
        return SkillResult.continue_with(session.session_id, action)

    def _do_fetch_refresh(self, ctx: SkillContext, session: SkillSession, length: int) -> SkillResult:
        """FETCH - 处理 91XX 异步响应"""
        ctx.output.text(f"步骤 7.2: 清理 - FETCH REFRESH (length={length})")
        session.data["state"] = EsimState.WAIT_FETCH_REFRESH

        apdu = ApduBuilder.fetch(length)
        action = self._build_apdu_action("esim.fetch-refresh", "FETCH REFRESH", apdu)
        return SkillResult.continue_with(session.session_id, action)

    def _do_list_notification(self, ctx: SkillContext, session: SkillSession) -> SkillResult:
        """ListNotification - 列出待处理的通知"""
        ctx.output.text("步骤 7.3: 清理 - 列出通知")
        session.data["state"] = EsimState.WAIT_LIST_NOTIFICATION

        apdu = ApduBuilder.list_notification()
        action = self._build_apdu_action("esim.list-notification", "列出通知", apdu)
        return SkillResult.continue_with(session.session_id, action)

    def _do_remove_notification(self, ctx: SkillContext, session: SkillSession, result: ActionResult) -> SkillResult:
        """RemoveNotification - 删除通知"""
        ctx.output.text("步骤 7.4: 清理 - 删除通知")
        session.data["state"] = EsimState.WAIT_REMOVE_NOTIFICATION

        # 解析 ListNotification 响应，获取通知序号
        response = result.data.get("response", "")
        
        # 如果没有通知，直接跳过
        if not response or response == "":
            ctx.output.text("无待处理通知")
            return self._do_get_euicc_info(ctx, session)
        
        # 解析通知序号（简化处理，实际应解析 ASN.1）
        # 假设响应格式为 BF28048002XXXX，其中 XXXX 是序号
        sequence = "0001"  # 默认序号
        
        # 尝试从响应中提取序号
        if len(response) >= 8:
            # 查找 8002 标签后的序号
            idx = response.find("8002")
            if idx >= 0 and idx + 8 <= len(response):
                sequence = response[idx + 4:idx + 8]
        
        apdu = ApduBuilder.remove_notification(sequence)
        action = self._build_apdu_action("esim.remove-notification", "删除通知", apdu)
        return SkillResult.continue_with(session.session_id, action)

    # ========== Profile 安装阶段 ==========
    
    def _do_get_euicc_info(self, ctx: SkillContext, session: SkillSession) -> SkillResult:
        """GetEuiccInfo1"""
        ctx.output.text("步骤 8: 获取 eUICC 信息")
        session.data["state"] = EsimState.WAIT_GET_EUICC_INFO
        
        apdu = ApduBuilder.get_euicc_info1()
        action = self._build_apdu_action("esim.get-euicc-info", "获取 eUICC 信息", apdu)
        return SkillResult.continue_with(session.session_id, action)
    
    def _do_get_euicc_challenge(self, ctx: SkillContext, session: SkillSession) -> SkillResult:
        """GetEuiccChallenge"""
        ctx.output.text("步骤 9: 获取 eUICC 挑战值")
        session.data["state"] = EsimState.WAIT_GET_EUICC_CHALLENGE
        
        apdu = ApduBuilder.get_euicc_challenge()
        action = self._build_apdu_action("esim.get-euicc-challenge", "获取挑战值", apdu)
        return SkillResult.continue_with(session.session_id, action)
    
    def _do_authenticate_server(self, ctx: SkillContext, session: SkillSession) -> SkillResult:
        """AuthenticateServer
        
        构造 ASN.1 编码的认证数据
        """
        ctx.output.text("步骤 10: 服务器认证")
        session.data["state"] = EsimState.WAIT_AUTHENTICATE_SERVER
        
        # 从会话数据中获取参数
        params = session.data.get("params", {})
        matching_id = params.get("matching_id", "")
        tac = bytes.fromhex(params.get("tac", "00000000"))
        
        # 从挑战值生成 transaction_id
        challenge = session.data.get("challenge", "")
        transaction_id = challenge[:32] if len(challenge) >= 32 else challenge.ljust(32, "0")
        
        # 获取证书数据
        dp_auth_cert = session.data.get("dp_auth_cert", "")
        dp_auth_key = session.data.get("dp_auth_key", "")
        euicc_ci_pk_id = session.data.get("euicc_ci_pk_id", "0102030405060708")
        
        # 构造 server_signed1
        # 实际实现需要：
        # 1. 用 SM-DP+ 私钥签名 transaction_id + challenge
        # 2. 编码为 ASN.1 结构
        # 这里使用简化版本
        server_signed1 = bytes.fromhex("3000")  # 空 SEQUENCE 占位
        
        # 签名 (需要实际 ECDSA 签名，这里使用占位)
        server_signature1 = bytes(64)
        
        # 服务器证书
        server_certificate = bytes.fromhex(dp_auth_cert) if dp_auth_cert else bytes.fromhex("3000")
        
        try:
            auth_data = encode_bf38_authenticate_server_request(
                server_signed1=server_signed1,
                server_signature1=server_signature1,
                euicc_ci_pk_id=bytes.fromhex(euicc_ci_pk_id) if isinstance(euicc_ci_pk_id, str) else euicc_ci_pk_id,
                server_certificate=server_certificate,
                matching_id=matching_id,
                tac=tac
            )
            auth_data_hex = auth_data.hex().upper()
        except Asn1CodecError as e:
            return SkillResult.failed(
                session.session_id,
                "ASN1_ENCODE_ERROR",
                f"ASN.1 编码失败: {e}"
            )
        
        apdu = ApduBuilder.authenticate_server(auth_data_hex)
        action = self._build_apdu_action("esim.authenticate-server", "服务器认证", apdu, sensitive=True)
        return SkillResult.continue_with(session.session_id, action)
    
    def _do_prepare_download(self, ctx: SkillContext, session: SkillSession) -> SkillResult:
        """PrepareDownload"""
        ctx.output.text("步骤 11: 准备下载")
        session.data["state"] = EsimState.WAIT_PREPARE_DOWNLOAD
        
        # 从 AuthenticateServer 响应中获取 transaction_id
        transaction_id = session.data.get("transaction_id", "00000000000000000000000000000000")
        
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
        
        # 签名 (需要实际 ECDSA 签名，这里使用占位)
        smdp_signature2 = bytes(64)
        
        # 获取服务器证书
        dp_pb_cert = session.data.get("dp_pb_cert", "")
        smdp_certificate = bytes.fromhex(dp_pb_cert) if dp_pb_cert else bytes.fromhex("3000")
        
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
        
        apdu = ApduBuilder.prepare_download(download_data_hex)
        action = self._build_apdu_action("esim.prepare-download", "准备下载", apdu)
        return SkillResult.continue_with(session.session_id, action)
    
    def _do_load_profile_package(self, ctx: SkillContext, session: SkillSession) -> SkillResult:
        """LoadProfilePackage
        
        加载 Profile 包数据
        """
        ctx.output.text("步骤 12: 加载 Profile 包")
        session.data["state"] = EsimState.WAIT_LOAD_PROFILE_PACKAGE
        
        # 从会话数据中获取 Profile 包（实际应从资源文件或参数中加载）
        package_data = session.data.get("profile_package", "")
        
        if not package_data:
            # 如果没有预加载的包数据，使用空包占位
            ctx.output.text("警告: 未提供 Profile 包数据，使用空包占位")
            package_data = "3000"  # 空 SEQUENCE
        
        apdu = ApduBuilder.load_profile_package(package_data, block_number=0, is_last=True)
        action = self._build_apdu_action("esim.load-profile-package", "加载 Profile 包", apdu)
        return SkillResult.continue_with(session.session_id, action)
    
    # ========== 后安装处理 ==========
    
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
        """IC1 (Initialize Channel 1)"""
        ctx.output.text("步骤 14: 初始化通道 1")
        session.data["state"] = EsimState.WAIT_POST_INSTALL_IC1
        
        # IC1 通常是 MANAGE CHANNEL + SELECT
        apdu = ApduBuilder.manage_channel(mode=0x00, channel=1)
        action = self._build_apdu_action("esim.post-install-ic1", "初始化通道 1", apdu)
        return SkillResult.continue_with(session.session_id, action)
    
    def _do_post_install_ic2(self, ctx: SkillContext, session: SkillSession) -> SkillResult:
        """IC2 (Initialize Channel 2)"""
        ctx.output.text("步骤 15: 初始化通道 2")
        session.data["state"] = EsimState.WAIT_POST_INSTALL_IC2
        
        apdu = ApduBuilder.manage_channel(mode=0x00, channel=2)
        action = self._build_apdu_action("esim.post-install-ic2", "初始化通道 2", apdu)
        return SkillResult.continue_with(session.session_id, action)
    
    def _do_post_install_select_isdr(self, ctx: SkillContext, session: SkillSession) -> SkillResult:
        """后安装 SELECT ISD-R"""
        ctx.output.text("步骤 16: 重新选择 ISD-R")
        session.data["state"] = EsimState.WAIT_POST_INSTALL_SELECT_ISDR
        
        apdu = ApduBuilder.select_isdr()
        action = self._build_apdu_action("esim.post-install-select-isdr", "选择 ISD-R", apdu)
        return SkillResult.continue_with(session.session_id, action)
    
    def _do_get_profiles_info(self, ctx: SkillContext, session: SkillSession) -> SkillResult:
        """GetProfilesInfo"""
        ctx.output.text("步骤 17: 获取 Profile 信息")
        session.data["state"] = EsimState.WAIT_GET_PROFILES_INFO
        
        apdu = ApduBuilder.get_profiles_info()
        action = self._build_apdu_action("esim.get-profiles-info", "获取 Profile 信息", apdu)
        return SkillResult.continue_with(session.session_id, action)
    
    # ========== eIM 启用阶段（间接模式）==========
    
    def _do_add_initial_eim(self, ctx: SkillContext, session: SkillSession) -> SkillResult:
        """AddInitialEim"""
        ctx.output.text("步骤 18: 添加初始 eIM")
        session.data["state"] = EsimState.WAIT_ADD_INITIAL_EIM
        
        # 从会话数据中获取参数
        params = session.data.get("params", {})
        eim_id = params.get("eim_id", "default-eim")
        eim_counter = params.get("eim_initial_counter", 1)
        
        # 获取 eIM 证书
        eim_cert_hex = session.data.get("eim_cert", "")
        eim_certificate = bytes.fromhex(eim_cert_hex) if eim_cert_hex else b""
        
        try:
            eim_data = encode_bf57_add_initial_eim(
                eim_id=eim_id,
                eim_counter=eim_counter,
                eim_certificate=eim_certificate
            )
            eim_data_hex = eim_data.hex().upper()
        except Asn1CodecError as e:
            return SkillResult.failed(
                session.session_id,
                "ASN1_ENCODE_ERROR",
                f"AddInitialEim 编码失败: {e}"
            )
        
        apdu = ApduBuilder.add_initial_eim(eim_data_hex)
        action = self._build_apdu_action("esim.add-initial-eim", "添加初始 eIM", apdu)
        return SkillResult.continue_with(session.session_id, action)
    
    def _do_enable_psmo(self, ctx: SkillContext, session: SkillSession) -> SkillResult:
        """EnablePSMO"""
        ctx.output.text("步骤 19: 启用 PSMO")
        session.data["state"] = EsimState.WAIT_ENABLE_PSMO
        
        # 从会话数据中获取参数
        params = session.data.get("params", {})
        iccid = params.get("iccid", "")
        profile_id = params.get("profile_id", "")
        eim_counter = params.get("eim_enable_counter", 2)
        
        # ICCID 需要 BCD 编码（半字节交换）
        iccid_bcd = self._encode_iccid_bcd(iccid)
        
        try:
            enable_data = encode_bf51_enable_psmo(
                iccid=iccid_bcd,
                profile_id=profile_id,
                eim_counter=eim_counter
            )
            enable_data_hex = enable_data.hex().upper()
        except Asn1CodecError as e:
            return SkillResult.failed(
                session.session_id,
                "ASN1_ENCODE_ERROR",
                f"EnablePSMO 编码失败: {e}"
            )
        
        apdu = ApduBuilder.enable_psmo(enable_data_hex)
        action = self._build_apdu_action("esim.enable-psmo", "启用 PSMO", apdu)
        return SkillResult.continue_with(session.session_id, action)
    
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
    
    def _do_post_enable_select_isdr(self, ctx: SkillContext, session: SkillSession) -> SkillResult:
        """启用后 SELECT ISD-R"""
        ctx.output.text("步骤 21: 重新选择 ISD-R")
        session.data["state"] = EsimState.WAIT_POST_ENABLE_SELECT_ISDR
        
        apdu = ApduBuilder.select_isdr()
        action = self._build_apdu_action("esim.post-enable-select-isdr", "选择 ISD-R", apdu)
        return SkillResult.continue_with(session.session_id, action)
    
    def _do_verify_profile_state(self, ctx: SkillContext, session: SkillSession) -> SkillResult:
        """验证 Profile 状态"""
        ctx.output.text("步骤 22: 验证 Profile 状态")
        session.data["state"] = EsimState.WAIT_VERIFY_PROFILE_STATE
        
        apdu = ApduBuilder.get_profiles_info()
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
