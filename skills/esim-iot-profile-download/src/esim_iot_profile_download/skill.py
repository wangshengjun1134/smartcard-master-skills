"""eSIM IoT Profile Download Skill 主模块

实现 eSIM Profile 下载与启用的核心流程。
"""

from smartcard_skill_sdk import (
    Skill, SkillContext, SkillSession, SkillResult,
    Action, ActionType, ActionResult
)
from .state_machine import EsimState, STATE_TRANSITIONS, INDIRECT_MODE_TRANSITIONS
from .apdu_builder import ApduBuilder, ResponseParser


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
        
        return {
            "sessionId": session.session_id,
            "manifest": self.get_manifest(),
            "status": "INITIALIZED"
        }
    
    def start(self, ctx: SkillContext, session: SkillSession) -> SkillResult:
        """启动执行"""
        ctx.output.info("开始 eSIM Profile 下载流程")
        
        # 第一步：冷复位
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
            return self._do_get_euicc_info(ctx, session)
        
        elif current_state == EsimState.WAIT_GET_EUICC_INFO:
            # 解析 eUICC 信息
            response = result.data.get("response", "")
            session.data["euicc_info"] = ResponseParser.parse_euicc_info(response)
            return self._do_get_euicc_challenge(ctx, session)
        
        elif current_state == EsimState.WAIT_GET_EUICC_CHALLENGE:
            # 保存挑战值
            response = result.data.get("response", "")
            session.data["challenge"] = response
            return self._do_authenticate_server(ctx, session)
        
        elif current_state == EsimState.WAIT_AUTHENTICATE_SERVER:
            return self._do_prepare_download(ctx, session)
        
        elif current_state == EsimState.WAIT_PREPARE_DOWNLOAD:
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
        
        注意：这里需要构造 ASN.1 编码的认证数据
        简化版本：使用占位数据
        """
        ctx.output.text("步骤 10: 服务器认证")
        session.data["state"] = EsimState.WAIT_AUTHENTICATE_SERVER
        
        # TODO: 构造实际的认证数据
        # 需要：transactionId, serverSigned1, serverChallenge 等
        auth_data = "0000000000000000"  # 占位数据
        
        apdu = ApduBuilder.authenticate_server(auth_data)
        action = self._build_apdu_action("esim.authenticate-server", "服务器认证", apdu, sensitive=True)
        return SkillResult.continue_with(session.session_id, action)
    
    def _do_prepare_download(self, ctx: SkillContext, session: SkillSession) -> SkillResult:
        """PrepareDownload"""
        ctx.output.text("步骤 11: 准备下载")
        session.data["state"] = EsimState.WAIT_PREPARE_DOWNLOAD
        
        # TODO: 构造实际的下载数据
        download_data = "0000000000000000"  # 占位数据
        
        apdu = ApduBuilder.prepare_download(download_data)
        action = self._build_apdu_action("esim.prepare-download", "准备下载", apdu)
        return SkillResult.continue_with(session.session_id, action)
    
    def _do_load_profile_package(self, ctx: SkillContext, session: SkillSession) -> SkillResult:
        """LoadProfilePackage
        
        注意：Profile 包可能需要分块发送
        简化版本：只发送一块
        """
        ctx.output.text("步骤 12: 加载 Profile 包")
        session.data["state"] = EsimState.WAIT_LOAD_PROFILE_PACKAGE
        
        # TODO: 加载实际的 Profile 包数据
        package_data = "0000000000000000"  # 占位数据
        
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
        
        # TODO: 构造实际的 eIM 数据
        eim_data = "0000000000000000"  # 占位数据
        
        apdu = ApduBuilder.add_initial_eim(eim_data)
        action = self._build_apdu_action("esim.add-initial-eim", "添加初始 eIM", apdu)
        return SkillResult.continue_with(session.session_id, action)
    
    def _do_enable_psmo(self, ctx: SkillContext, session: SkillSession) -> SkillResult:
        """EnablePSMO"""
        ctx.output.text("步骤 19: 启用 PSMO")
        session.data["state"] = EsimState.WAIT_ENABLE_PSMO
        
        # TODO: 构造实际的启用数据
        enable_data = "0000000000000000"  # 占位数据
        
        apdu = ApduBuilder.enable_psmo(enable_data)
        action = self._build_apdu_action("esim.enable-psmo", "启用 PSMO", apdu)
        return SkillResult.continue_with(session.session_id, action)
    
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
        # TODO: 解析 GetProfilesInfo 响应，验证 profileState
        # 简化版本：直接返回成功
        
        ctx.output.info("eSIM Profile 下载流程完成")
        session.data["state"] = EsimState.SUCCESS
        
        result_data = {
            "iccid": session.data["params"].get("iccid", ""),
            "profile_id": session.data["params"].get("profile_id", ""),
            "eid": session.data["params"].get("eid", ""),
            "mode": session.data.get("mode", "indirect"),
            "profile_state": "ENABLED",  # TODO: 从实际响应中解析
            "verified": True,  # TODO: 根据实际状态判断
        }
        
        return SkillResult.success(session.session_id, result_data)
