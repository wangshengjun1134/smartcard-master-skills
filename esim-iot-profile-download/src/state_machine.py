"""下载会话状态机"""

from enum import Enum, auto
from typing import Optional


class DownloadSessionState(Enum):
    """下载会话状态"""
    INITIATED = auto()
    CLIENT_AUTHENTICATED = auto()
    PROFILE_DOWNLOADED = auto()
    DELIVERED = auto()
    ENABLED = auto()
    COMPLETED = auto()
    FAILED = auto()


class DownloadSession:
    """下载会话状态管理"""
    
    def __init__(self, transaction_id: str, matching_id: str, eid: str):
        self.transaction_id = transaction_id
        self.matching_id = matching_id
        self.eid = eid
        self.state = DownloadSessionState.INITIATED
        
        # 认证相关
        self.server_challenge: Optional[bytes] = None
        self.euicc_challenge: Optional[bytes] = None
        self.euicc_certificate: Optional[bytes] = None
        self.euicc_otpk: Optional[bytes] = None
        
        # Profile 信息
        self.profile_id: Optional[str] = None
        self.iccid: Optional[str] = None
        self.isdp_aid: Optional[str] = None
        
        # BPP 相关
        self.bpp_data: Optional[bytes] = None
        self.bpp_segments_sent: int = 0
        self.bpp_total_segments: int = 0
        
        # 错误信息
        self.error_code: Optional[str] = None
        self.error_message: Optional[str] = None
    
    def transition_to(self, new_state: DownloadSessionState):
        """切换到新状态"""
        valid_transitions = {
            DownloadSessionState.INITIATED: [
                DownloadSessionState.CLIENT_AUTHENTICATED,
                DownloadSessionState.FAILED,
            ],
            DownloadSessionState.CLIENT_AUTHENTICATED: [
                DownloadSessionState.PROFILE_DOWNLOADED,
                DownloadSessionState.FAILED,
            ],
            DownloadSessionState.PROFILE_DOWNLOADED: [
                DownloadSessionState.DELIVERED,
                DownloadSessionState.ENABLED,
                DownloadSessionState.FAILED,
            ],
            DownloadSessionState.DELIVERED: [
                DownloadSessionState.ENABLED,
                DownloadSessionState.FAILED,
            ],
            DownloadSessionState.ENABLED: [
                DownloadSessionState.COMPLETED,
                DownloadSessionState.FAILED,
            ],
        }
        
        if new_state not in valid_transitions.get(self.state, []):
            raise ValueError(
                f"Invalid state transition: {self.state.name} -> {new_state.name}"
            )
        
        self.state = new_state
    
    def mark_failed(self, error_code: str, error_message: str):
        """标记为失败"""
        self.state = DownloadSessionState.FAILED
        self.error_code = error_code
        self.error_message = error_message

