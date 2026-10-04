"""APDU 命令构建器"""

from typing import Optional, List
from dataclasses import dataclass


@dataclass
class ApduCommand:
    """APDU 命令"""
    cla: int
    ins: int
    p1: int
    p2: int
    data: Optional[bytes] = None
    le: Optional[int] = None
    
    def to_hex(self) -> str:
        """转为十六进制字符串"""
        cmd = f"{self.cla:02X}{self.ins:02X}{self.p1:02X}{self.p2:02X}"
        if self.data:
            cmd += f"{len(self.data):02X}{self.data.hex().upper()}"
        if self.le is not None:
            cmd += f"{self.le:02X}"
        return cmd


@dataclass
class ApduResponse:
    """APDU 响应"""
    sw1: int
    sw2: int
    data: Optional[bytes] = None
    
    @property
    def sw(self) -> str:
        """SW 码字符串"""
        return f"{self.sw1:02X}{self.sw2:02X}"
    
    @property
    def is_success(self) -> bool:
        """是否成功"""
        return self.sw1 == 0x90 and self.sw2 == 0x00
    
    @property
    def needs_fetch(self) -> bool:
        """是否需要 FETCH"""
        return self.sw1 == 0x91
    
    @property
    def fetch_length(self) -> int:
        """FETCH 长度"""
        return self.sw2 if self.needs_fetch else 0


def cold_reset() -> ApduCommand:
    """冷启动 RESET"""
    return ApduCommand(cla=0x00, ins=0x00, p1=0x00, p2=0x00)


def reset() -> ApduCommand:
    """温启动 RESET"""
    return ApduCommand(cla=0x00, ins=0x00, p1=0x00, p2=0x00)


def select_mf(channel: int = 0) -> ApduCommand:
    """SELECT MF"""
    return ApduCommand(cla=channel, ins=0xA4, p1=0x00, p2=0x04, data=bytes([0x3F, 0x00]))


def select_mf_retry(channel: int = 0) -> ApduCommand:
    """SELECT MF (重试)"""
    return ApduCommand(cla=channel, ins=0xA4, p1=0x00, p2=0x0C, data=bytes([0x3F, 0x00]))


def terminal_capability(channel: int = 0) -> ApduCommand:
    """TERMINAL CAPABILITY"""
    return ApduCommand(
        cla=0x80 | channel, ins=0xAA, p1=0x00, p2=0x00,
        data=bytes([0xA9, 0x05, 0x81, 0x00, 0x83, 0x01, 0x07])
    )


def terminal_profile(channel: int = 0) -> ApduCommand:
    """TERMINAL PROFILE"""
    data = bytes([
        0xFF, 0xFF, 0xFF, 0x7F, 0x9D, 0x00, 0xDF, 0xBF,
        0x00, 0x00, 0x1F, 0xE2, 0x00, 0x00, 0x00, 0xC7,
        0xEB, 0x00, 0x00, 0x01, 0x68, 0x00, 0x50, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00,
    ])
    return ApduCommand(cla=0x80 | channel, ins=0x10, p1=0x00, p2=0x00, data=data)


def fetch(channel: int, length: int) -> ApduCommand:
    """FETCH (91XX 响应) - 用于 eUICC 异步响应"""
    return ApduCommand(cla=0x80 | channel, ins=0x12, p1=0x00, p2=0x00, le=length)


def get_response(channel: int, length: int) -> ApduCommand:
    """GET RESPONSE (61XX 响应) - 用于获取额外数据"""
    return ApduCommand(cla=channel, ins=0xC0, p1=0x00, p2=0x00, le=length)


def status(channel: int) -> ApduCommand:
    """STATUS"""
    return ApduCommand(cla=0x80 | channel, ins=0xF2, p1=0x00, p2=0x0C)


def manage_channel_open() -> ApduCommand:
    """MANAGE_CHANNEL OPEN"""
    return ApduCommand(cla=0x00, ins=0x70, p1=0x00, p2=0x00, data=bytes([0x01]))


def select_isdr(channel: int) -> ApduCommand:
    """SELECT ISD-R"""
    data = bytes([
        0xA0, 0x00, 0x00, 0x05, 0x59, 0x10, 0x10, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0x89, 0x00, 0x00, 0x01, 0x00,
    ])
    return ApduCommand(cla=channel, ins=0xA4, p1=0x04, p2=0x00, data=data)


def es10_command(channel: int, ins: int, p1: int, p2: int, data: Optional[bytes] = None) -> ApduCommand:
    """ES10x 命令"""
    return ApduCommand(cla=0x80 | channel, ins=ins, p1=p1, p2=p2, data=data)


def get_euicc_info1(channel: int) -> ApduCommand:
    """GetEuiccInfo1 (BF20)"""
    return es10_command(channel, 0xE2, 0x91, 0x00, bytes([0xBF, 0x20, 0x00, 0x00]))


def get_euicc_challenge(channel: int) -> ApduCommand:
    """GetEuiccChallenge (BF2E)"""
    return es10_command(channel, 0xE2, 0x91, 0x00, bytes([0xBF, 0x2E, 0x00, 0x00]))


def euicc_memory_reset(channel: int) -> ApduCommand:
    """EuiccMemoryReset (BF34)"""
    return es10_command(channel, 0xE2, 0x91, 0x00, bytes([0xBF, 0x34, 0x04, 0x82, 0x02, 0x05, 0xE0]))


def list_notification(channel: int) -> ApduCommand:
    """ListNotification (BF28)"""
    return es10_command(channel, 0xE2, 0x91, 0x00, bytes([0xBF, 0x28, 0x00, 0x00]))


def remove_notification(channel: int, sequence: bytes) -> ApduCommand:
    """RemoveNotification (BF30)"""
    return es10_command(channel, 0xE2, 0x91, 0x00, bytes([0xBF, 0x30, 0x04, 0x80, 0x02]) + sequence)


def get_profiles_info(channel: int) -> ApduCommand:
    """GetProfilesInfo (BF2D)"""
    return es10_command(channel, 0xE2, 0x91, 0x00, bytes([0xBF, 0x2D, 0x00, 0x00]))


def store_data(channel: int, block_number: int, is_last: bool, data: bytes) -> ApduCommand:
    """StoreData 命令"""
    p1 = 0x91 if is_last else 0x11
    return es10_command(channel, 0xE2, p1, block_number, data)
