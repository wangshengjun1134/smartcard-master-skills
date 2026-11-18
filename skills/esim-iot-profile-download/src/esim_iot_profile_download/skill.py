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
        response = result.data.get("response", "")
        
        # 处理 61XX 响应 (更多数据可用)
        # Skill 需要发送 GET RESPONSE 命令获取剩余数据
        if sw.startswith("61") and len(sw) == 4:
            # 保存当前状态，以便在获取完整响应后继续
            session.data["previous_state"] = current_state
            session.data["pending_response"] = response
            return self._do_get_response(ctx, session, int(sw[2:], 16))
        
        # 处理 91XX 响应 (eUICC 异步响应)
        # Skill 需要发送 FETCH 命令获取数据
        if sw.startswith("91") and len(sw) == 4:
            # 保存当前状态，以便在获取完整响应后继续
            session.data["previous_state"] = current_state
            session.data["pending_response"] = response
            return self._do_fetch(ctx, session, int(sw[2:], 16))

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
                return self._do_fetch(ctx, session, int(sw[2:], 16))
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
            if response:
                try:
                    # AuthenticateServer 响应格式: BF38 [length] { [0] transactionId, ... }
                    response_bytes = bytes.fromhex(response)
                    offset = 0
                    
                    # 跳过 BF38 tag
                    if response_bytes[offset] == 0xBF and response_bytes[offset + 1] == 0x38:
                        offset += 2
                    
                    # 跳过 length
                    length_byte = response_bytes[offset]
                    offset += 1
                    if length_byte & 0x80:
                        num_bytes = length_byte & 0x7F
                        offset += num_bytes
                    
                    # 查找 [0] transactionId
                    if offset < len(response_bytes) and response_bytes[offset] == 0x80:
                        offset += 1
                        tid_len = response_bytes[offset]
                        offset += 1
                        transaction_id = response_bytes[offset:offset + tid_len].hex().upper()
                        session.data["transaction_id"] = transaction_id
                        ctx.output.text(f"从 AuthenticateServer 响应中提取 transaction_id: {transaction_id[:16]}...")
                except Exception as e:
                    ctx.output.text(f"警告: 无法解析 AuthenticateServer 响应: {e}")
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
                session.data["transaction_id"] = pd_response.get("transaction_id", "")
                session.data["euicc_otpk"] = pd_response.get("euicc_otpk", b"").hex().upper()
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

        # 处理 61XX 响应 (GET RESPONSE)
        elif current_state == EsimState.WAIT_GET_RESPONSE:
            # 获取保存的原始响应数据
            pending_response = session.data.get("pending_response", "")
            new_response = result.data.get("response", "")
            sw = result.data.get("sw", "")
            
            # 合并响应数据
            full_response = pending_response + new_response
            
            # 检查是否还有更多数据 (链式 61XX)
            if sw.startswith("61") and len(sw) == 4:
                session.data["pending_response"] = full_response
                return self._do_get_response(ctx, session, int(sw[2:], 16))
            
            # 响应完成，清除临时数据
            previous_state = session.data.pop("previous_state", None)
            session.data.pop("pending_response", None)
            
            # 根据 previous_state 继续执行
            return self._continue_from_state(ctx, session, previous_state, full_response, sw)

        # 处理 91XX 响应 (FETCH)
        elif current_state == EsimState.WAIT_FETCH:
            # 获取保存的原始响应数据
            pending_response = session.data.get("pending_response", "")
            new_response = result.data.get("response", "")
            sw = result.data.get("sw", "")
            
            # 合并响应数据
            full_response = pending_response + new_response
            
            # 检查是否还有更多数据 (链式 91XX)
            if sw.startswith("91") and len(sw) == 4:
                session.data["pending_response"] = full_response
                return self._do_fetch(ctx, session, int(sw[2:], 16))
            
            # 响应完成，清除临时数据
            previous_state = session.data.pop("previous_state", None)
            session.data.pop("pending_response", None)
            
            # 根据 previous_state 继续执行
            return self._continue_from_state(ctx, session, previous_state, full_response, sw)
        
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

    def _do_fetch_refresh(self, ctx: SkillContext, session: SkillSession, length: int) -> SkillResult:
        """FETCH - 处理 91XX 异步响应"""
        ctx.output.text(f"步骤 7.2: 清理 - FETCH REFRESH (length={length})")
        session.data["state"] = EsimState.WAIT_FETCH_REFRESH

        channel = session.data.get("channel", 0)
        apdu = ApduBuilder.fetch(length, channel=channel)
        action = self._build_apdu_action("esim.fetch-refresh", "FETCH REFRESH", apdu)
        return SkillResult.continue_with(session.session_id, action)

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
            return self._do_list_notification(ctx, session)
        elif previous_state == EsimState.WAIT_FETCH_REFRESH:
            return self._do_list_notification(ctx, session)
        elif previous_state == EsimState.WAIT_LIST_NOTIFICATION:
            return self._do_remove_notification(ctx, session, mock_result)
        elif previous_state == EsimState.WAIT_REMOVE_NOTIFICATION:
            return self._do_get_euicc_info(ctx, session)
        elif previous_state == EsimState.WAIT_GET_EUICC_INFO:
            # 解析 eUICC 信息
            try:
                response_bytes = bytes.fromhex(response)
                euicc_info = decode_euicc_info1(response_bytes)
                session.data["euicc_info"] = euicc_info
                if "verification_ci_pk_ids" in euicc_info and euicc_info["verification_ci_pk_ids"]:
                    session.data["euicc_ci_pk_id"] = euicc_info["verification_ci_pk_ids"][0]
            except Exception as e:
                ctx.output.text(f"警告: 无法解析 EuiccInfo1: {e}")
            return self._do_get_euicc_challenge(ctx, session)
        elif previous_state == EsimState.WAIT_GET_EUICC_CHALLENGE:
            # 保存挑战值
            try:
                response_bytes = bytes.fromhex(response)
                challenge = decode_bf2e_challenge(response_bytes)
                session.data["challenge"] = challenge.hex().upper()
            except Exception as e:
                ctx.output.text(f"警告: 无法解析 Challenge: {e}")
                session.data["challenge"] = response
            return self._do_authenticate_server(ctx, session)
        elif previous_state == EsimState.WAIT_AUTHENTICATE_SERVER:
            return self._do_prepare_download(ctx, session)
        elif previous_state == EsimState.WAIT_PREPARE_DOWNLOAD:
            # 解析 PrepareDownload 响应
            try:
                response_bytes = bytes.fromhex(response)
                pd_response = decode_prepare_download_response(response_bytes)
                session.data["transaction_id"] = pd_response.get("transaction_id", "")
                session.data["euicc_otpk"] = pd_response.get("euicc_otpk", b"").hex().upper()
            except Exception as e:
                ctx.output.text(f"警告: 无法解析 PrepareDownload 响应: {e}")
            return self._do_load_profile_package(ctx, session)
        elif previous_state == EsimState.WAIT_LOAD_PROFILE_PACKAGE:
            return self._do_post_install_reset(ctx, session)
        elif previous_state == EsimState.WAIT_POST_INSTALL_RESET:
            return self._do_post_install_ic1(ctx, session)
        elif previous_state == EsimState.WAIT_POST_INSTALL_IC1:
            return self._do_post_install_ic2(ctx, session)
        elif previous_state == EsimState.WAIT_POST_INSTALL_IC2:
            return self._do_post_install_select_isdr(ctx, session)
        elif previous_state == EsimState.WAIT_POST_INSTALL_SELECT_ISDR:
            return self._do_get_profiles_info(ctx, session)
        elif previous_state == EsimState.WAIT_GET_PROFILES_INFO:
            session.data["profiles_info_response"] = response
            mode = session.data.get("mode", "indirect")
            if mode == "indirect":
                return self._do_add_initial_eim(ctx, session)
            else:
                return self._verify_and_complete(ctx, session)
        elif previous_state == EsimState.WAIT_ADD_INITIAL_EIM:
            return self._do_enable_psmo(ctx, session)
        elif previous_state == EsimState.WAIT_ENABLE_PSMO:
            return self._do_post_enable_reset(ctx, session)
        elif previous_state == EsimState.WAIT_POST_ENABLE_RESET:
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
        matching_id = params.get("matching_id", "")
        tac = bytes.fromhex(params.get("tac", "00000000"))

        # 从挑战值生成 transaction_id
        challenge = session.data.get("challenge", "")
        transaction_id = challenge[:32] if len(challenge) >= 32 else challenge.ljust(32, "0")

        # 获取证书数据
        dp_auth_cert = session.data.get("dp_auth_cert", "")
        dp_auth_key_hex = session.data.get("dp_auth_key", "")
        euicc_ci_pk_id = session.data.get("euicc_ci_pk_id", "0102030405060708")

        # 使用真实私钥签名
        server_signature1 = b""
        try:
            if dp_auth_key_hex:
                from cryptography.hazmat.primitives import hashes
                from cryptography.hazmat.primitives.asymmetric import ec
                from cryptography.hazmat.backends import default_backend
                
                # 加载私钥
                private_key_bytes = bytes.fromhex(dp_auth_key_hex)
                private_key = ec.derive_private_key(
                    int.from_bytes(private_key_bytes, 'big'),
                    ec.SECP256R1(),
                    default_backend()
                )
                
                # 签名数据 = transaction_id + challenge
                sign_data = bytes.fromhex(transaction_id + challenge)
                
                # 使用 ECDSA + SHA256 签名
                signature = private_key.sign(sign_data, ec.ECDSA(hashes.SHA256()))
                server_signature1 = signature
                
                ctx.output.text(f"签名成功，签名长度: {len(signature)} 字节")
        except Exception as e:
            ctx.output.text(f"警告: 签名失败，使用占位数据 - {e}")
            server_signature1 = bytes(64)  # 占位签名

        # 构造 server_signed1 (简化版本，实际应包含更多字段)
        # 这里使用 transaction_id 作为 signed1 的主要内容
        server_signed1 = bytes.fromhex(transaction_id)

        # 服务器证书
        server_certificate = bytes.fromhex(dp_auth_cert) if dp_auth_cert else b""

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

        # 使用真实私钥签名
        smdp_signature2 = b""
        try:
            dp_pb_key_hex = session.data.get("dp_pb_key", "")
            if dp_pb_key_hex:
                from cryptography.hazmat.primitives import hashes
                from cryptography.hazmat.primitives.asymmetric import ec
                from cryptography.hazmat.backends import default_backend
                
                # 加载私钥
                private_key_bytes = bytes.fromhex(dp_pb_key_hex)
                private_key = ec.derive_private_key(
                    int.from_bytes(private_key_bytes, 'big'),
                    ec.SECP256R1(),
                    default_backend()
                )
                
                # 签名数据 = smdp_signed2
                signature = private_key.sign(smdp_signed2, ec.ECDSA(hashes.SHA256()))
                smdp_signature2 = signature
                
                ctx.output.text(f"PrepareDownload 签名成功，签名长度: {len(signature)} 字节")
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

        加载 Profile 包数据 - 按照 BPP 的 ASN.1 结构分块发送
        """
        ctx.output.text("步骤 12: 加载 Profile 包")
        session.data["state"] = EsimState.WAIT_LOAD_PROFILE_PACKAGE

        # 从会话数据中获取 Profile 包（实际应从资源文件或参数中加载）
        package_data = session.data.get("profile_package", "")

        if not package_data:
            # 如果没有预加载的包数据，使用空包占位
            ctx.output.text("警告: 未提供 Profile 包数据，使用空包占位")
            package_data = "3000"  # 空 SEQUENCE

        channel = session.data.get("channel", 0)
        # 新的 load_profile_package 方法会按照 BPP 结构分块
        apdu_list = ApduBuilder.load_profile_package(package_data, channel=channel)

        # 如果只有一条 APDU，直接发送
        if len(apdu_list) == 1:
            action = self._build_apdu_action("esim.load-profile-package", "加载 Profile 包", apdu_list[0])
            return SkillResult.continue_with(session.session_id, action)

        # 如果有多条 APDU（分块），保存后续 APDU 到 session
        session.data["pending_apdus"] = apdu_list[1:]
        action = self._build_apdu_action("esim.load-profile-package", "加载 Profile 包", apdu_list[0])
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

        # 后安装阶段使用通道 2 (IC2)
        channel = session.data.get("post_install_channel", 2)
        apdu = ApduBuilder.select_isdr(channel=channel)
        action = self._build_apdu_action("esim.post-install-select-isdr", "选择 ISD-R", apdu)
        return SkillResult.continue_with(session.session_id, action)

    def _do_get_profiles_info(self, ctx: SkillContext, session: SkillSession) -> SkillResult:
        """GetProfilesInfo"""
        ctx.output.text("步骤 17: 获取 Profile 信息")
        session.data["state"] = EsimState.WAIT_GET_PROFILES_INFO

        # 使用通道 2 (IC2)
        channel = session.data.get("post_install_channel", 2)
        apdu = ApduBuilder.get_profiles_info(channel=channel)
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
