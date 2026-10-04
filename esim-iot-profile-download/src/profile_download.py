"""Profile 下载业务流程"""

from typing import Optional, List, Dict, Any
import logging

from .apdu_builder import (
    ApduCommand, cold_reset, reset, select_mf, select_mf_retry,
    terminal_capability, terminal_profile, fetch, status,
    manage_channel_open, select_isdr,
    get_euicc_info1, get_euicc_challenge,
    euicc_memory_reset, list_notification, remove_notification,
    get_profiles_info, store_data,
)
from .smdp_plus import LocalSmdpPlus, SmdpPlusError
from .asn1_codec import (
    encode_bf38_authenticate_server_request,
    encode_bf21_prepare_download_request,
    decode_bf2e_challenge,
    decode_bf37_profile_installation_result,
)
from .state_machine import DownloadSession, DownloadSessionState
from .utils import bytes_to_hex, chunk_bytes

logger = logging.getLogger(__name__)


class ProfileDownloadError(Exception):
    """Profile 下载异常"""
    pass


class ProfileDownloadFlow:
    """Profile 下载流程控制器"""
    
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
        tac: bytes = b'\x00\x00\x00\x00',
        total_rounds: int = 1,
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
        
        # 执行上下文
        self.logical_channel: int = 0
        self.current_round: int = 1
        self.current_step: int = 0
        self.session: Optional[DownloadSession] = None
        
        # BF36 分段状态
        self.bf36_segments: List[bytes] = []
        self.bf36_index: int = 0
        
        # 中间数据
        self._euicc_info1_response: Optional[bytes] = None
        self._euicc_challenge_response: Optional[bytes] = None
        self._authenticate_server_response: Optional[bytes] = None
        self._prepare_download_response: Optional[bytes] = None
    
    def get_current_step(self) -> int:
        return self.current_step
    
    def next_step(self, step: int):
        self.current_step = step
    
    def execute_step(self, step: int, apdu_response: Optional[bytes] = None, sw: Optional[str] = None) -> List[ApduCommand]:
        """执行指定步骤"""
        try:
            if step == 0: return self._step_cold_start()
            elif step == 1: return self._step_ic0_plain()
            elif step == 2: return self._step_ic1_plain()
            elif step == 3: return self._step_ic2_plain()
            elif step == 4: return self._step_ic3_plain()
            elif step == 5: return self._step_open_channel_select_isdr_plain()
            elif step == 6: return self._step_cleanup0()
            elif step == 7: return self._step_cleanup1(sw)
            elif step == 8: return self._step_cleanup2()
            elif step == 9: return self._step_cleanup3(apdu_response)
            elif step == 10: return self._step_ic0()
            elif step == 11: return self._step_ic1()
            elif step == 12: return self._step_ic2()
            elif step == 13: return self._step_ic3()
            elif step == 14: return self._step_open_channel_select_isdr()
            elif step == 15: return self._step_get_euicc_info1()
            elif step == 16: return self._step_get_euicc_challenge()
            elif step == 17: return self._step_authenticate_server(apdu_response)
            elif step == 18: return self._step_prepare_download(apdu_response)
            elif step == 19: return self._step_load_profile_package(apdu_response)
            elif step == 20: return self._step_post_install_reset()
            elif step == 21: return self._step_add_initial_eim()
            elif step == 22: return self._step_load_euicc_package_enable()
            elif step == 23: return self._step_verify_enable()
            elif step == 24: return self._step_fetch_enable_refresh(apdu_response)
            elif step == 25: return self._step_post_enable_reset()
            elif step == 26: return self._step_get_profiles_info()
            elif step == 27: return self._step_verify_profile_state(apdu_response)
            elif step == 28: return self._step_final_cleanup0()
            elif step == 29: return self._step_final_cleanup1(sw)
            elif step == 30: return self._step_final_cleanup2()
            elif step == 31: return self._step_final_cleanup3(apdu_response)
            elif step == 32: return self._step_round_check()
            else:
                raise ProfileDownloadError(f"Unknown step: {step}")
        except ProfileDownloadError:
            raise
        except Exception as e:
            logger.error(f"Step {step} execution failed: {e}", exc_info=True)
            raise ProfileDownloadError(f"Step {step} failed: {e}")
    
    # ========== 阶段 0-3: 初始化和准备 ==========
    
    def _step_cold_start(self) -> List[ApduCommand]:
        logger.info("Step 0: ColdStart")
        self.current_round = 1
        self.next_step(1)
        return [cold_reset(), reset()]
    
    def _step_ic0_plain(self) -> List[ApduCommand]:
        logger.info("Step 1: IC1 SELECT MF (preparation)")
        self.next_step(2)
        return [select_mf(0)]
    
    def _step_ic1_plain(self) -> List[ApduCommand]:
        logger.info("Step 2: IC1 SELECT MF + TERMINAL CAPABILITY (preparation)")
        self.next_step(3)
        return [select_mf_retry(0), terminal_capability(0)]
    
    def _step_ic2_plain(self) -> List[ApduCommand]:
        logger.info("Step 3: TERMINAL PROFILE (preparation)")
        self.next_step(4)
        return [terminal_profile(0)]
    
    def _step_ic3_plain(self) -> List[ApduCommand]:
        logger.info("Step 4: IC2 STATUS + MANAGE_CHANNEL (preparation)")
        self.next_step(5)
        return [status(0), manage_channel_open()]
    
    def _step_open_channel_select_isdr_plain(self) -> List[ApduCommand]:
        logger.info("Step 5: SELECT ISD-R (preparation)")
        self.logical_channel = 1
        self.next_step(6)
        return [select_isdr(self.logical_channel)]
    
    def _step_cleanup0(self) -> List[ApduCommand]:
        logger.info("Step 6: Cleanup EuiccMemoryReset")
        self.next_step(7)
        return [euicc_memory_reset(self.logical_channel)]
    
    def _step_cleanup1(self, sw: Optional[str] = None) -> List[ApduCommand]:
        logger.info("Step 7: Cleanup FETCH REFRESH")
        self.next_step(8)
        if sw and sw.startswith("91"):
            return [fetch(self.logical_channel, int(sw[2:], 16))]
        return []
    
    def _step_cleanup2(self) -> List[ApduCommand]:
        logger.info("Step 8: Cleanup ListNotification")
        self.next_step(9)
        return [list_notification(self.logical_channel)]
    
    def _step_cleanup3(self, apdu_response: Optional[bytes] = None) -> List[ApduCommand]:
        logger.info("Step 9: Cleanup RemoveNotification")
        self.next_step(10)
        sequences = self._extract_notification_sequences(apdu_response)
        return [remove_notification(self.logical_channel, seq) for seq in sequences]
    
    def _extract_notification_sequences(self, response: Optional[bytes]) -> List[bytes]:
        if not response:
            return []
        return []
    
    # ========== 阶段 4: Profile 安装 IC1/IC2 ==========
    
    def _step_ic0(self) -> List[ApduCommand]:
        logger.info("Step 10: IC1 SELECT MF (install)")
        self.next_step(11)
        return [select_mf(0)]
    
    def _step_ic1(self) -> List[ApduCommand]:
        logger.info("Step 11: IC1 SELECT MF + TERMINAL CAPABILITY (install)")
        self.next_step(12)
        return [select_mf_retry(0), terminal_capability(0)]
    
    def _step_ic2(self) -> List[ApduCommand]:
        logger.info("Step 12: TERMINAL PROFILE (install)")
        self.next_step(13)
        return [terminal_profile(0)]
    
    def _step_ic3(self) -> List[ApduCommand]:
        logger.info("Step 13: IC2 STATUS + MANAGE_CHANNEL (install)")
        self.next_step(14)
        return [status(0), manage_channel_open()]
    
    def _step_open_channel_select_isdr(self) -> List[ApduCommand]:
        logger.info("Step 14: SELECT ISD-R (install)")
        self.logical_channel = 1
        self.next_step(15)
        return [select_isdr(self.logical_channel)]
    
    # ========== 阶段 5: 直接模式下载链 ==========
    
    def _step_get_euicc_info1(self) -> List[ApduCommand]:
        logger.info("Step 15: GetEuiccInfo1 (BF20)")
        self.next_step(16)
        return [get_euicc_info1(self.logical_channel)]
    
    def _step_get_euicc_challenge(self) -> List[ApduCommand]:
        logger.info("Step 16: GetEuiccChallenge (BF2E)")
        self.next_step(17)
        return [get_euicc_challenge(self.logical_channel)]
    
    def _step_authenticate_server(self, apdu_response: Optional[bytes] = None) -> List[ApduCommand]:
        """步骤 17: AuthenticateServer (BF38) - 本地 SM-DP+ 实现"""
        logger.info("Step 17: AuthenticateServer (BF38)")
        
        try:
            # 保存上一步响应
            self._euicc_info1_response = apdu_response  # BF20
            
            # 获取 BF2E challenge
            euicc_challenge = decode_bf2e_challenge(apdu_response) if apdu_response else os.urandom(16)
            
            # 调用本地 SM-DP+ InitiateAuthentication
            auth_result = self.smdp_plus.initiate_authentication(
                matching_id=self.matching_id,
                eid=self.eid,
                euicc_challenge=euicc_challenge,
                euicc_info1=self._euicc_info1_response if self._euicc_info1_response else b'',
                smdp_address=self.smdp_address,
            )
            
            # 编码 BF38
            bf38 = encode_bf38_authenticate_server_request(
                server_signed1=auth_result['server_signed1'],
                server_signature1=auth_result['server_signature1'],
                euicc_ci_pk_id=auth_result['euicc_ci_pk_id'],
                server_certificate=auth_result['server_certificate'],
                matching_id=self.matching_id,
                tac=self.tac,
            )
            
            # 分段发送 StoreData
            segments = chunk_bytes(bf38, 255)
            self.next_step(18)
            
            apdus = []
            for i, segment in enumerate(segments):
                is_last = (i == len(segments) - 1)
                apdus.append(store_data(self.logical_channel, i, is_last, segment))
            
            logger.info(f"AuthenticateServer: {len(bf38)} bytes in {len(segments)} segments")
            return apdus
        
        except Exception as e:
            raise ProfileDownloadError(f"AuthenticateServer failed: {e}")
    
    def _step_prepare_download(self, apdu_response: Optional[bytes] = None) -> List[ApduCommand]:
        """步骤 18: PrepareDownload (BF21) - 本地 SM-DP+ 实现"""
        logger.info("Step 18: PrepareDownload (BF21)")
        
        try:
            # 保存 BF38 响应
            self._authenticate_server_response = apdu_response
            
            # 获取 transaction_id
            session = self.smdp_plus.get_session(self.matching_id)
            if not session:
                raise ProfileDownloadError("No active session found")
            
            # 调用本地 SM-DP+ AuthenticateClient
            auth_client_result = self.smdp_plus.authenticate_client(
                transaction_id=session.transaction_id,
                authenticate_server_response=apdu_response if apdu_response else b'',
            )
            
            # 编码 BF21
            bf21 = encode_bf21_prepare_download_request(
                smdp_signed2=auth_client_result['smdp_signed2'],
                smdp_signature2=auth_client_result['smdp_signature2'],
                smdp_certificate=auth_client_result['smdp_certificate'],
            )
            
            # 分段发送
            segments = chunk_bytes(bf21, 255)
            self.next_step(19)
            
            apdus = []
            for i, segment in enumerate(segments):
                is_last = (i == len(segments) - 1)
                apdus.append(store_data(self.logical_channel, i, is_last, segment))
            
            logger.info(f"PrepareDownload: {len(bf21)} bytes in {len(segments)} segments")
            return apdus
        
        except Exception as e:
            raise ProfileDownloadError(f"PrepareDownload failed: {e}")
    
    def _step_load_profile_package(self, apdu_response: Optional[bytes] = None) -> List[ApduCommand]:
        """步骤 19: LoadProfilePackage (BF36) - 本地 SM-DP+ 实现"""
        logger.info("Step 19: LoadProfilePackage (BF36)")
        
        try:
            # 保存 BF21 响应
            self._prepare_download_response = apdu_response
            
            # 获取 transaction_id
            session = self.smdp_plus.get_session(self.matching_id)
            if not session:
                raise ProfileDownloadError("No active session found")
            
            # 调用本地 SM-DP+ GetBoundProfilePackage
            bpp_der = self.smdp_plus.get_bound_profile_package(
                transaction_id=session.transaction_id,
                prepare_download_response=apdu_response if apdu_response else b'',
            )
            
            # 分段发送 BF36
            segments = self.smdp_plus.get_bpp_segments(session.transaction_id)
            self.bf36_segments = [seg for _, seg in segments]
            self.bf36_index = 0
            self.next_step(20)
            
            apdus = []
            for i, (is_last, segment) in enumerate(segments):
                apdus.append(store_data(self.logical_channel, i, is_last, segment))
            
            logger.info(f"LoadProfilePackage: {len(bpp_der)} bytes in {len(segments)} segments")
            return apdus
        
        except Exception as e:
            raise ProfileDownloadError(f"LoadProfilePackage failed: {e}")
    
    # ========== 阶段 6-9: 重置、eIM Enable、验证、Cleanup ==========
    
    def _step_post_install_reset(self) -> List[ApduCommand]:
        logger.info("Step 20: PostInstall COLDRESET + IC1/IC2")
        self.next_step(21)
        self.logical_channel = 0
        return [cold_reset(), select_mf(0), terminal_capability(0), terminal_profile(0), manage_channel_open()]
    
    def _step_add_initial_eim(self) -> List[ApduCommand]:
        if self.mode != "indirect":
            self.next_step(25)
            return []
        logger.info("Step 21: AddInitialEim (BF57)")
        self.next_step(22)
        # TODO: 实现 eIM AddInitialEim
        return []
    
    def _step_load_euicc_package_enable(self) -> List[ApduCommand]:
        if self.mode != "indirect":
            self.next_step(25)
            return []
        logger.info("Step 22: LoadEuiccPackage Enable PSMO (BF51)")
        self.next_step(23)
        # TODO: 实现 eIM Enable PSMO
        return []
    
    def _step_verify_enable(self) -> List[ApduCommand]:
        if self.mode != "indirect":
            self.next_step(25)
            return []
        logger.info("Step 23: Verify EnableResult")
        self.next_step(24)
        return []
    
    def _step_fetch_enable_refresh(self, apdu_response: Optional[bytes] = None) -> List[ApduCommand]:
        if self.mode != "indirect":
            self.next_step(25)
            return []
        logger.info("Step 24: FETCH EnableResult/REFRESH")
        self.next_step(25)
        return []
    
    def _step_post_enable_reset(self) -> List[ApduCommand]:
        logger.info("Step 25: PostEnable COLDRESET + IC1/IC2")
        self.next_step(26)
        self.logical_channel = 0
        return [cold_reset(), select_mf(0), terminal_capability(0), terminal_profile(0), manage_channel_open()]
    
    def _step_get_profiles_info(self) -> List[ApduCommand]:
        logger.info("Step 26: GetProfilesInfo (BF2D)")
        self.next_step(27)
        return [get_profiles_info(self.logical_channel)]
    
    def _step_verify_profile_state(self, apdu_response: Optional[bytes] = None) -> List[ApduCommand]:
        logger.info("Step 27: Verify Profile State = ENABLED")
        self.next_step(28)
        return []
    
    def _step_final_cleanup0(self) -> List[ApduCommand]:
        logger.info("Step 28: FinalCleanup EuiccMemoryReset")
        self.next_step(29)
        return [euicc_memory_reset(self.logical_channel)]
    
    def _step_final_cleanup1(self, sw: Optional[str] = None) -> List[ApduCommand]:
        logger.info("Step 29: FinalCleanup FETCH REFRESH")
        self.next_step(30)
        if sw and sw.startswith("91"):
            return [fetch(self.logical_channel, int(sw[2:], 16))]
        return []
    
    def _step_final_cleanup2(self) -> List[ApduCommand]:
        logger.info("Step 30: FinalCleanup ListNotification")
        self.next_step(31)
        return [list_notification(self.logical_channel)]
    
    def _step_final_cleanup3(self, apdu_response: Optional[bytes] = None) -> List[ApduCommand]:
        logger.info("Step 31: FinalCleanup RemoveNotification")
        self.next_step(32)
        sequences = self._extract_notification_sequences(apdu_response)
        return [remove_notification(self.logical_channel, seq) for seq in sequences]
    
    def _step_round_check(self) -> List[ApduCommand]:
        logger.info(f"Step 32: Round Check {self.current_round}/{self.total_rounds}")
        if self.current_round >= self.total_rounds:
            logger.info(f"All {self.total_rounds} rounds completed")
            self.next_step(-1)
            return []
        self.current_round += 1
        logger.info(f"Starting round {self.current_round}/{self.total_rounds}")
        self.next_step(10)
        return []


import os
