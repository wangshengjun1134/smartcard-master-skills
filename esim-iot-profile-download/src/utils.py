"""工具函数模块"""

from typing import List


def bytes_to_hex(data) -> str:
    """字节数组转十六进制字符串（兼容 list 和 bytes）"""
    if isinstance(data, list):
        data = bytes(data)
    return data.hex().upper()


def hex_to_bytes(hex_str: str) -> bytes:
    """十六进制字符串转字节数组"""
    cleaned = hex_str.replace(" ", "").replace("\n", "").replace("\r", "")
    return bytes.fromhex(cleaned)


def digits_to_bcd(digits: str) -> bytes:
    """数字字符串转 BCD 编码（奇数长度补 F）"""
    padded = digits if len(digits) % 2 == 0 else digits + "F"
    result = bytearray()
    for i in range(0, len(padded), 2):
        high = int(padded[i]) if padded[i].isdigit() else 0x0F
        low = int(padded[i + 1]) if i + 1 < len(padded) and padded[i + 1].isdigit() else 0x0F
        result.append((high << 4) | low)
    return bytes(result)


def sw_to_string(sw1: int, sw2: int) -> str:
    """SW1/SW2 转字符串"""
    return f"{sw1:02X}{sw2:02X}"


def is_success(sw1: int, sw2: int) -> bool:
    """检查 SW 码是否成功 (9000)"""
    return sw1 == 0x90 and sw2 == 0x00


def needs_fetch(sw1: int, sw2: int) -> bool:
    """检查是否需要 FETCH (91XX)"""
    return sw1 == 0x91


def has_more_data(sw1: int, sw2: int) -> bool:
    """检查是否有更多数据 (61XX)"""
    return sw1 == 0x61


def chunk_bytes(data: bytes, chunk_size: int) -> List[bytes]:
    """将字节数据分块"""
    return [data[i:i + chunk_size] for i in range(0, len(data), chunk_size)]


def validate_iccid(iccid: str) -> bool:
    """验证 ICCID 格式（10-20 位数字）"""
    return 10 <= len(iccid) <= 20 and iccid.isdigit()


def validate_eid(eid: str) -> bool:
    """验证 EID 格式（32 位数字）"""
    return len(eid) == 32 and eid.isdigit()


def validate_matching_id(matching_id: str) -> bool:
    """验证 Matching ID 格式（5-32 字符，字母数字横杠）"""
    import re
    return bool(re.match(r'^[A-Za-z0-9-]{5,32}$', matching_id))
