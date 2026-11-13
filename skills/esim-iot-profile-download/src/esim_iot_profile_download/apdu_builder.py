"""eSIM IoT Profile Download APDU 构造模块

核心 APDU 指令参考 SGP.33 规范和 Java 参考实现。
"""

from typing import Optional


class ApduBuilder:
    """APDU 构造器"""
    
    @staticmethod
    def select_file(file_id: str, p1: int = 0x00, p2: int = 0x00) -> str:
        """SELECT 指令
        
        Args:
            file_id: 文件标识（4 位十六进制）
            p1: P1 参数（选择方式）
            p2: P2 参数
        
        Returns:
            APDU 十六进制字符串
        """
        cla = 0x00
        ins = 0xA4
        lc = 0x02
        return f"{cla:02X}{ins:02X}{p1:02X}{p2:02X}{lc:02X}{file_id}"
    
    @staticmethod
    def select_mf() -> str:
        """SELECT MF (Master File)"""
        return "00A40000023F00"
    
    @staticmethod
    def select_isdr() -> str:
        """SELECT ISD-R (Issuer Security Domain)
        
        ISD-R AID: A0000005591010FFFFFFFF8900000100
        """
        # 使用 DF name 选择
        aid = "A0000005591010FFFFFFFF8900000100"
        cla = 0x00
        ins = 0xA4
        p1 = 0x04  # 按 DF name 选择
        p2 = 0x00
        lc = len(aid) // 2
        return f"{cla:02X}{ins:02X}{p1:02X}{p2:02X}{lc:02X}{aid}"
    
    @staticmethod
    def terminal_capability(capability_data: str = "") -> str:
        """TERMINAL CAPABILITY
        
        设置终端能力，通知卡片支持的功能
        """
        cla = 0x80
        ins = 0xAA
        p1 = 0x00
        p2 = 0x00
        
        if not capability_data:
            # 默认能力数据
            capability_data = "030000"  # 简化版本
        
        lc = len(capability_data) // 2
        return f"{cla:02X}{ins:02X}{p1:02X}{p2:02X}{lc:02X}{capability_data}"
    
    @staticmethod
    def terminal_profile(profile_data: str = "") -> str:
        """TERMINAL PROFILE
        
        设置终端配置
        """
        cla = 0x80
        ins = 0x10
        p1 = 0x00
        p2 = 0x00
        
        if not profile_data:
            # 默认配置数据
            profile_data = "030000"
        
        lc = len(profile_data) // 2
        return f"{cla:02X}{ins:02X}{p1:02X}{p2:02X}{lc:02X}{profile_data}"
    
    @staticmethod
    def status() -> str:
        """STATUS 指令
        
        获取卡片状态
        """
        cla = 0x80
        ins = 0xF2
        p1 = 0x00
        p2 = 0x00
        le = 0x00
        return f"{cla:02X}{ins:02X}{p1:02X}{p2:02X}{le:02X}"
    
    @staticmethod
    def manage_channel(mode: int = 0x00, channel: int = 0x00) -> str:
        """MANAGE CHANNEL
        
        管理逻辑通道
        
        Args:
            mode: 0x00 = 打开, 0x80 = 关闭
            channel: 通道号
        """
        cla = 0x00
        ins = 0x70
        p1 = mode
        p2 = channel
        le = 0x01 if mode == 0x00 else 0x00
        return f"{cla:02X}{ins:02X}{p1:02X}{p2:02X}{le:02X}"
    
    @staticmethod
    def get_euicc_info1() -> str:
        """GetEuiccInfo1 (BF20)
        
        获取 eUICC 信息（EID、默认 SM-DP+ 地址等）
        """
        cla = 0x80
        ins = 0xBF
        p1 = 0x20
        p2 = 0x00
        le = 0x00
        return f"{cla:02X}{ins:02X}{p1:02X}{p2:02X}{le:02X}"
    
    @staticmethod
    def get_euicc_challenge() -> str:
        """GetEuiccChallenge (BF2E)
        
        获取 eUICC 挑战值（用于认证）
        """
        cla = 0x80
        ins = 0xBF
        p1 = 0x2E
        p2 = 0x00
        le = 0x00
        return f"{cla:02X}{ins:02X}{p1:02X}{p2:02X}{le:02X}"
    
    @staticmethod
    def authenticate_server(auth_data: str) -> str:
        """AuthenticateServer (BF38)
        
        服务器认证（SM-DP+ 认证）
        
        Args:
            auth_data: 认证数据（ASN.1 编码）
        """
        cla = 0x80
        ins = 0xBF
        p1 = 0x38
        p2 = 0x00
        
        # 分块处理（如果数据超过 255 字节）
        if len(auth_data) > 510:  # 255 bytes = 510 hex chars
            return ApduBuilder._build_chained_apdu(cla, ins, p1, p2, auth_data)
        
        lc = len(auth_data) // 2
        return f"{cla:02X}{ins:02X}{p1:02X}{p2:02X}{lc:02X}{auth_data}"
    
    @staticmethod
    def prepare_download(download_data: str) -> str:
        """PrepareDownload (BF21)
        
        准备下载 Profile
        
        Args:
            download_data: 下载数据（ASN.1 编码）
        """
        cla = 0x80
        ins = 0xBF
        p1 = 0x21
        p2 = 0x00
        
        if len(download_data) > 510:
            return ApduBuilder._build_chained_apdu(cla, ins, p1, p2, download_data)
        
        lc = len(download_data) // 2
        return f"{cla:02X}{ins:02X}{p1:02X}{p2:02X}{lc:02X}{download_data}"
    
    @staticmethod
    def load_profile_package(package_data: str, block_number: int = 0, is_last: bool = False) -> str:
        """LoadProfilePackage (BF36)
        
        加载 Profile 包（可能需要分块）
        
        Args:
            package_data: Profile 包数据
            block_number: 块号（从 0 开始）
            is_last: 是否为最后一块
        """
        cla = 0x80
        ins = 0xBF
        p1 = 0x36
        p2 = block_number
        
        # 最后一块的 P2 高位置 1
        if is_last:
            p2 |= 0x80
        
        if len(package_data) > 510:
            return ApduBuilder._build_chained_apdu(cla, ins, p1, p2, package_data)
        
        lc = len(package_data) // 2
        return f"{cla:02X}{ins:02X}{p1:02X}{p2:02X}{lc:02X}{package_data}"
    
    @staticmethod
    def get_profiles_info() -> str:
        """GetProfilesInfo (BF2D)
        
        获取 Profile 信息（包括 Profile 状态）
        """
        cla = 0x80
        ins = 0xBF
        p1 = 0x2D
        p2 = 0x00
        le = 0x00
        return f"{cla:02X}{ins:02X}{p1:02X}{p2:02X}{le:02X}"
    
    # ========== 清理相关 APDU ==========
    
    @staticmethod
    def euicc_memory_reset() -> str:
        """EuiccMemoryReset (BF34)
        
        重置 eUICC 内存，清除之前的下载状态
        """
        # ES10 命令格式: 80 E2 91 00 Lc [BF 34 04 82 02 05 E0] Le
        cla = 0x80
        ins = 0xE2
        p1 = 0x91
        p2 = 0x00
        data = "BF3404820205E0"
        lc = len(data) // 2
        le = 0x00
        return f"{cla:02X}{ins:02X}{p1:02X}{p2:02X}{lc:02X}{data}{le:02X}"
    
    @staticmethod
    def fetch(length: int) -> str:
        """FETCH (91XX 响应)
        
        处理 eUICC 异步响应
        """
        cla = 0x80
        ins = 0x12
        p1 = 0x00
        p2 = 0x00
        le = length
        return f"{cla:02X}{ins:02X}{p1:02X}{p2:02X}{le:02X}"
    
    @staticmethod
    def list_notification() -> str:
        """ListNotification (BF28)
        
        列出待处理的通知
        """
        cla = 0x80
        ins = 0xE2
        p1 = 0x91
        p2 = 0x00
        data = "BF2800"
        lc = len(data) // 2
        le = 0x00
        return f"{cla:02X}{ins:02X}{p1:02X}{p2:02X}{lc:02X}{data}{le:02X}"
    
    @staticmethod
    def remove_notification(sequence: str) -> str:
        """RemoveNotification (BF30)
        
        删除指定序号的通知
        
        Args:
            sequence: 通知序号（十六进制字符串）
        """
        cla = 0x80
        ins = 0xE2
        p1 = 0x91
        p2 = 0x00
        data = f"BF30048002{sequence}"
        lc = len(data) // 2
        le = 0x00
        return f"{cla:02X}{ins:02X}{p1:02X}{p2:02X}{lc:02X}{data}{le:02X}"
    
    @staticmethod
    def add_initial_eim(eim_data: str) -> str:
        """AddInitialEim (BF57)
        
        添加初始 eIM（间接模式）
        
        Args:
            eim_data: eIM 数据（ASN.1 编码）
        """
        cla = 0x80
        ins = 0xBF
        p1 = 0x57
        p2 = 0x00
        
        if len(eim_data) > 510:
            return ApduBuilder._build_chained_apdu(cla, ins, p1, p2, eim_data)
        
        lc = len(eim_data) // 2
        return f"{cla:02X}{ins:02X}{p1:02X}{p2:02X}{lc:02X}{eim_data}"
    
    @staticmethod
    def enable_psmo(enable_data: str) -> str:
        """EnablePSMO (BF51)
        
        启用 PSMO（Profile Storage Management Object）
        
        Args:
            enable_data: 启用数据（ASN.1 编码）
        """
        cla = 0x80
        ins = 0xBF
        p1 = 0x51
        p2 = 0x00
        
        if len(enable_data) > 510:
            return ApduBuilder._build_chained_apdu(cla, ins, p1, p2, enable_data)
        
        lc = len(enable_data) // 2
        return f"{cla:02X}{ins:02X}{p1:02X}{p2:02X}{lc:02X}{enable_data}"
    
    @staticmethod
    def _build_chained_apdu(cla: int, ins: int, p1: int, p2: int, data: str) -> str:
        """构造链式 APDU（数据超过 255 字节时）
        
        注意：这里只返回第一块，后续块需要调用者处理
        """
        # 第一块：P1 保持不变，P2 的最高位为 0
        first_block = data[:510]  # 255 bytes
        lc = len(first_block) // 2
        return f"{cla:02X}{ins:02X}{p1:02X}{p2:02X}{lc:02X}{first_block}"


class ResponseParser:
    """响应解析器"""
    
    @staticmethod
    def parse_sw(sw: str) -> dict:
        """解析状态字 (SW)
        
        Args:
            sw: 状态字（4 位十六进制）
        
        Returns:
            解析结果
        """
        sw = sw.upper()
        
        if sw == "9000":
            return {"status": "OK", "message": "成功"}
        elif sw.startswith("61"):
            # 61XX: 还有 XX 字节可用（GET RESPONSE）
            length = int(sw[2:], 16)
            return {"status": "MORE_DATA", "length": length}
        elif sw.startswith("91"):
            # 91XX: eUICC 异步响应（FETCH）
            length = int(sw[2:], 16)
            return {"status": "FETCH_REQUIRED", "length": length}
        elif sw == "6A82":
            return {"status": "ERROR", "message": "文件未找到"}
        elif sw == "6700":
            return {"status": "ERROR", "message": "长度错误"}
        elif sw == "6E00":
            return {"status": "ERROR", "message": "不支持的指令"}
        elif sw == "6D00":
            return {"status": "ERROR", "message": "不支持的 INS"}
        else:
            return {"status": "UNKNOWN", "sw": sw}
    
    @staticmethod
    def parse_euicc_info(data: str) -> dict:
        """解析 GetEuiccInfo1 响应
        
        Args:
            data: 响应数据（不含 SW）
        
        Returns:
            解析结果
        """
        # 简化解析，实际需要 ASN.1 解码
        result = {
            "raw": data,
            "eid": "",
            "smdp_address": "",
        }
        
        # 尝试提取 EID（通常是 32 位数字）
        # 实际应该用 ASN.1 解析
        if len(data) >= 64:
            # 假设 EID 在某个固定位置
            pass
        
        return result
    
    @staticmethod
    def parse_profiles_info(data: str) -> dict:
        """解析 GetProfilesInfo 响应
        
        Args:
            data: 响应数据（不含 SW）
        
        Returns:
            解析结果
        """
        result = {
            "raw": data,
            "profiles": [],
        }
        
        # 简化解析，实际需要 ASN.1 解码
        # 查找 profileState (9F70)
        if "9F70" in data:
            idx = data.find("9F70")
            # 读取长度和值
            pass
        
        return result
