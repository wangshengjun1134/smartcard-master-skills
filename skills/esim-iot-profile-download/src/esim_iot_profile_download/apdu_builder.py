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
        """SELECT MF (Master File)
        
        P2=04: 返回 FCI (File Control Information)
        """
        return "00A40004023F00"
    
    @staticmethod
    def select_isdr(channel: int = 0) -> str:
        """SELECT ISD-R (Issuer Security Domain)

        ISD-R AID: A0000005591010FFFFFFFF8900000100
        
        Args:
            channel: 逻辑通道号 (0-3)，0 表示基本通道
        """
        # 使用 DF name 选择
        aid = "A0000005591010FFFFFFFF8900000100"
        # CLA = 通道号 (00, 01, 02, 03)
        cla = channel & 0x03
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
            # 与参考实现一致：TERMINAL CAPABILITY 声明 eSIM 终端能力
            capability_data = "A9058100830107"

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
            # 与参考实现一致：完整 TERMINAL PROFILE（含 eSIM/ISIM 等能力位）
            profile_data = "FFFFFFFF7F9D00DFBF00001FE2000000C7EB000000016800500000000000000200"

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
    def get_euicc_info1(channel: int = 0) -> str:
        """GetEuiccInfo1 (BF20)

        获取 eUICC 信息（EID、默认 SM-DP+ 地址等）

        ES10 命令格式: (80+channel) E2 91 00 Lc [BF 20 00]
        注意：无 Le 字段
        
        Args:
            channel: 逻辑通道号 (0-3)
        """
        # CLA = 0x80 + 通道号
        cla = 0x80 + (channel & 0x03)
        ins = 0xE2
        p1 = 0x91
        p2 = 0x00
        data = "BF2000"
        lc = len(data) // 2
        return f"{cla:02X}{ins:02X}{p1:02X}{p2:02X}{lc:02X}{data}"

    @staticmethod
    def get_euicc_challenge(channel: int = 0) -> str:
        """GetEuiccChallenge (BF2E)

        获取 eUICC 挑战值（用于认证）

        ES10 命令格式: (80+channel) E2 91 00 Lc [BF 2E 00]
        注意：无 Le 字段
        
        Args:
            channel: 逻辑通道号 (0-3)
        """
        # CLA = 0x80 + 通道号
        cla = 0x80 + (channel & 0x03)
        ins = 0xE2
        p1 = 0x91
        p2 = 0x00
        data = "BF2E00"
        lc = len(data) // 2
        return f"{cla:02X}{ins:02X}{p1:02X}{p2:02X}{lc:02X}{data}"
    
    @staticmethod
    def authenticate_server(auth_data: str, channel: int = 0) -> list:
        """AuthenticateServer (BF38)

        服务器认证（SM-DP+ 认证）

        格式: (80+channel) E2 11 00 Lc [auth_data]
        注意：auth_data 已经是完整的 BF38 数据（包含 BF38 标签和长度）
        
        返回: APDU 列表（如果数据超过 255 字节，会分块）

        Args:
            auth_data: 认证数据（已经是完整的 BF38 数据，包含 BF38 标签）
            channel: 逻辑通道号 (0-3)
            
        Returns:
            APDU 列表（十六进制字符串）
        """
        # CLA = 0x80 + 通道号 (ES10 命令格式)
        cla = 0x80 + (channel & 0x03)
        ins = 0xE2  # ES10 命令
        p1 = 0x11   # 固定参数
        p2 = 0x00

        # auth_data 已经是完整的 BF38 数据（包含 BF38 标签和长度）
        # 不需要再添加 BF38 标签
        data = auth_data

        lc = len(data) // 2
        if lc > 255:
            # 需要分块处理
            return ApduBuilder._build_chained_apdu_list(cla, ins, p1, p2, data)

        return [f"{cla:02X}{ins:02X}{p1:02X}{p2:02X}{lc:02X}{data}"]
    
    @staticmethod
    def prepare_download(download_data: str, channel: int = 0) -> list:
        """PrepareDownload (BF21)

        准备下载 Profile
        
        格式: (80+channel) E2 11 00 Lc [download_data]
        注意：download_data 已经是完整的 BF21 数据（包含 BF21 标签和长度）
        
        返回: APDU 列表（如果数据超过 255 字节，会分块）

        Args:
            download_data: 下载数据（已经是完整的 BF21 数据，包含 BF21 标签）
            channel: 逻辑通道号 (0-3)
            
        Returns:
            APDU 列表（十六进制字符串）
        """
        # CLA = 0x80 + 通道号 (ES10 命令格式)
        cla = 0x80 + (channel & 0x03)
        ins = 0xE2  # ES10 命令
        p1 = 0x11   # 固定参数
        p2 = 0x00

        # download_data 已经是完整的 BF21 数据（包含 BF21 标签和长度）
        # 不需要再添加 BF21 标签
        data = download_data

        lc = len(data) // 2
        if lc > 255:
            return ApduBuilder._build_chained_apdu_list(cla, ins, p1, p2, data)
        
        return [f"{cla:02X}{ins:02X}{p1:02X}{p2:02X}{lc:02X}{data}"]

    @staticmethod
    def load_profile_package(package_data: str, channel: int = 0) -> list:
        """LoadProfilePackage (BF36)

        加载 Profile 包 - 按照 BPP 的 ASN.1 结构分块
        
        根据 SGP.22 规范，BPP 需要按照 ASN.1 结构分割成多个 STORE DATA 对象：
        - BF23 (initialiseSecureChannelRequest) - 第 1 个对象
        - A0 (firstSequenceOf87) - 第 2 个对象（包含第一个 87 TLV）
        - 每个 87 TLV 是独立的对象
        - A1 (sequenceOf88) - 头部是一个对象
        - 每个 88 TLV 是独立的对象
        - A3 (sequenceOf86) - 头部是一个对象
        - 每个 86 TLV 是独立的对象
        
        每个对象的块编号从 0 开始。

        Args:
            package_data: Profile 包数据（BPP 格式，以 BF36 开头）
            channel: 逻辑通道号 (0-3)

        Returns:
            APDU 列表（十六进制字符串）
        """
        # CLA = 0x80 + 通道号 (ES10 命令格式)
        cla = 0x80 + (channel & 0x03)
        ins = 0xE2  # ES10 命令

        # 按照 BPP 结构分块
        store_data_objects = ApduBuilder._parse_bpp_structure(package_data)
        
        # 为每个 STORE DATA 对象生成 APDU 列表
        apdus = []
        for obj_data in store_data_objects:
            obj_apdus = ApduBuilder._build_store_data_apdus(cla, ins, obj_data)
            apdus.extend(obj_apdus)
        
        return apdus

    @staticmethod
    def _parse_bpp_structure(bpp_data: str) -> list:
        """解析 BPP 结构，分割成 STORE DATA 对象
        
        根据 SGP.22 2.5.5 规范和 Java 参考项目实现：
        
        BPP 结构:
        BF36 (外层)
          BF23 (initialiseSecureChannelRequest)
          A0 (firstSequenceOf87) - 包含 87 TLVs
          A1 (sequenceOf88) - 包含 88 TLVs
          A2 (secondSequenceOf87) - 可选
          A3 (sequenceOf86) - 包含 86 TLVs
        
        分块规则：
        1. 第一个对象: BF36头部 + BF23（一起发送）
        2. A0/A2 序列: 头部 + 第一个87 TLV（一起发送），后续87各自独立
        3. A1/A3 序列: 头部（独立发送），每个88/86 TLV各自独立
        """
        # 解析外层 BF36
        offset = 0
        tag = bpp_data[offset:offset+4]
        if tag != "BF36":
            # 如果不是 BF36 开头，直接返回整个数据作为一个对象
            return [bpp_data]
        
        offset += 4
        
        # 读取长度
        len_byte = int(bpp_data[offset:offset+2], 16)
        offset += 2
        if len_byte & 0x80:
            num_bytes = len_byte & 0x7F
            outer_len = int(bpp_data[offset:offset+num_bytes*2], 16)
            offset += num_bytes * 2
        else:
            outer_len = len_byte
        
        # 外层头部（BF36 + 长度）
        outer_header = bpp_data[:offset]
        
        # 解析内部字段
        fields = ApduBuilder._decode_ber_tlv_sequence(bpp_data[offset:])
        
        if not fields or fields[0][0] != "BF23":
            # 如果没有 BF23 开头，返回整个数据
            return [bpp_data]
        
        objects = []
        
        # 第一个对象: BF36头部 + BF23（一起发送）
        bf23_tag, bf23_value = fields[0]
        bf23_encoded = bf23_tag + ApduBuilder._encode_ber_len(len(bf23_value) // 2) + bf23_value
        objects.append(outer_header + bf23_encoded)
        
        # 处理后续字段
        for i in range(1, len(fields)):
            field_tag, field_value = fields[i]
            field_header = field_tag + ApduBuilder._encode_ber_len(len(field_value) // 2)
            
            if field_tag in ["A0", "A2"]:
                # firstSequenceOf87 或 secondSequenceOf87
                # 头部 + 第一个 87 TLV（一起发送）
                children = ApduBuilder._decode_ber_tlv_sequence(field_value)
                if children:
                    # 头部 + 第一个子字段
                    first_child_tag, first_child_value = children[0]
                    first_child_encoded = first_child_tag + ApduBuilder._encode_ber_len(len(first_child_value) // 2) + first_child_value
                    objects.append(field_header + first_child_encoded)
                    # 后续子字段各自作为独立对象
                    for j in range(1, len(children)):
                        child_tag, child_value = children[j]
                        child_encoded = child_tag + ApduBuilder._encode_ber_len(len(child_value) // 2) + child_value
                        objects.append(child_encoded)
                else:
                    # 空的序列，只发送头部
                    objects.append(field_header)
            
            elif field_tag in ["A1", "A3"]:
                # sequenceOf88 或 sequenceOf86
                # 头部（独立发送），每个 88/86 TLV 各自独立发送
                objects.append(field_header)
                children = ApduBuilder._decode_ber_tlv_sequence(field_value)
                for child_tag, child_value in children:
                    child_encoded = child_tag + ApduBuilder._encode_ber_len(len(child_value) // 2) + child_value
                    objects.append(child_encoded)
            
            else:
                # 其他字段直接作为一个对象
                objects.append(field_header + field_value)
        
        return objects

    @staticmethod
    def _decode_ber_tlv_sequence(data: str) -> list:
        """解码 BER-TLV 序列，返回 [(tag, value), ...]"""
        result = []
        offset = 0
        while offset < len(data):
            # 读取标签
            tag_start = offset
            tag_byte = int(data[offset:offset+2], 16)
            offset += 2
            if (tag_byte & 0x1F) == 0x1F:
                # 多字节标签
                while offset < len(data):
                    next_byte = int(data[offset:offset+2], 16)
                    offset += 2
                    if (next_byte & 0x80) == 0:
                        break
            tag = data[tag_start:offset]
            
            # 读取长度
            if offset >= len(data):
                break
            len_byte = int(data[offset:offset+2], 16)
            offset += 2
            if len_byte & 0x80:
                num_bytes = len_byte & 0x7F
                length = int(data[offset:offset+num_bytes*2], 16)
                offset += num_bytes * 2
            else:
                length = len_byte
            
            # 读取值
            value = data[offset:offset+length*2]
            offset += length * 2
            
            result.append((tag, value))
        
        return result

    @staticmethod
    def _encode_ber_len(length: int) -> str:
        """编码 BER 长度"""
        if length < 128:
            return f"{length:02X}"
        elif length < 256:
            return f"81{length:02X}"
        else:
            return f"82{length:04X}"

    @staticmethod
    def _build_store_data_apdus(cla: int, ins: int, data: str) -> list:
        """为一个 STORE DATA 对象构建 APDU 列表
        
        每个对象的块编号从 0 开始。
        """
        apdus = []
        max_block_size = 255  # 每块最大 255 字节
        data_len = len(data) // 2
        
        if data_len <= max_block_size:
            # 数据不超过 255 字节，直接发送
            lc = data_len
            apdus.append(f"{cla:02X}{ins:02X}91{0:02X}{lc:02X}{data}")
        else:
            # 数据超过 255 字节，需要分块
            offset = 0
            block_num = 0
            while offset < len(data):
                block = data[offset:offset+max_block_size*2]
                lc = len(block) // 2
                offset += max_block_size * 2
                
                if offset >= len(data):
                    # 最后一块
                    p1 = 0x91
                else:
                    # 非最后一块
                    p1 = 0x11
                
                apdus.append(f"{cla:02X}{ins:02X}{p1:02X}{block_num:02X}{lc:02X}{block}")
                block_num += 1
        
        return apdus
    
    @staticmethod
    def get_profiles_info(channel: int = 0) -> str:
        """GetProfilesInfo (BF2D)

        获取 Profile 信息（包括 Profile 状态）

        ES10 命令格式: (80+channel) E2 91 00 03 BF 2D 00
        注意：Lc=03, 数据为 BF2D00 (tag + Le=00)
        
        Args:
            channel: 逻辑通道号 (0-3)
        """
        # CLA = 0x80 + 通道号
        cla = 0x80 + (channel & 0x03)
        ins = 0xE2
        p1 = 0x91
        p2 = 0x00
        # 数据: BF2D (tag) + 00 (Le)
        data = "BF2D00"
        lc = len(data) // 2
        return f"{cla:02X}{ins:02X}{p1:02X}{p2:02X}{lc:02X}{data}"
    
    # ========== 清理相关 APDU ==========
    
    @staticmethod
    def euicc_memory_reset(channel: int = 0) -> str:
        """EuiccMemoryReset (BF34)

        重置 eUICC 内存，清除之前的下载状态

        ES10 命令格式: (80+channel) E2 91 00 Lc [BF 34 04 82 02 05 E0]
        注意：无 Le 字段
        
        Args:
            channel: 逻辑通道号 (0-3)
        """
        # CLA = 0x80 + 通道号
        cla = 0x80 + (channel & 0x03)
        ins = 0xE2
        p1 = 0x91
        p2 = 0x00
        data = "BF3404820205E0"
        lc = len(data) // 2
        return f"{cla:02X}{ins:02X}{p1:02X}{p2:02X}{lc:02X}{data}"
    
    @staticmethod
    def fetch(length: int, channel: int = 0) -> str:
        """FETCH (91XX 响应)

        处理 eUICC 异步响应
        
        Args:
            length: 数据长度
            channel: 逻辑通道号 (0-3)
        """
        # CLA = 0x80 + 通道号
        cla = 0x80 + (channel & 0x03)
        ins = 0x12  # FETCH
        p1 = 0x00
        p2 = 0x00
        le = length
        return f"{cla:02X}{ins:02X}{p1:02X}{p2:02X}{le:02X}"
    
    @staticmethod
    def list_notification(channel: int = 0) -> str:
        """ListNotification (BF28)

        列出待处理的通知

        ES10 命令格式: (80+channel) E2 91 00 Lc [BF 28 00]
        注意：无 Le 字段
        
        Args:
            channel: 逻辑通道号 (0-3)
        """
        # CLA = 0x80 + 通道号
        cla = 0x80 + (channel & 0x03)
        ins = 0xE2
        p1 = 0x91
        p2 = 0x00
        data = "BF2800"
        lc = len(data) // 2
        return f"{cla:02X}{ins:02X}{p1:02X}{p2:02X}{lc:02X}{data}"
    
    @staticmethod
    def remove_notification(sequence: str, channel: int = 0) -> str:
        """RemoveNotification (BF30)

        删除指定序号的通知

        Args:
            sequence: 通知序号（十六进制字符串）
            channel: 逻辑通道号 (0-3)
        """
        # CLA = 0x80 + 通道号
        cla = 0x80 + (channel & 0x03)
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

    @staticmethod
    def _build_chained_apdu_list(cla: int, ins: int, p1: int, p2: int, data: str) -> list:
        """构造链式 APDU 列表（数据超过 255 字节时）
        
        返回所有分块的 APDU 列表
        
        根据 SGP.33 规范和参考日志，ES10 命令的链式分块格式：
        - 所有块：P1 = 0x11, P2 = 块号（递增）
        - 最后一块：P1 = 0x91, P2 = 块号
        
        注意：LoadBoundProfilePackage 可能需要按照 Profile 包的 ASN.1 结构
        来分块，而不是简单地按 255 字节切分。当前实现使用简单分块。
        
        Args:
            cla: CLA 字节
            ins: INS 字节
            p1: P1 参数（未使用，根据规范自动设置）
            p2: P2 参数（未使用，根据规范自动设置）
            data: 完整数据（已经是包含标签的连续数据）
            
        Returns:
            APDU 列表
        """
        apdus = []
        max_block_size = 255  # 每块最大 255 字节
        
        # 计算总块数
        total_blocks = (len(data) + max_block_size * 2 - 1) // (max_block_size * 2)
        
        for block_num, i in enumerate(range(0, len(data), max_block_size * 2)):
            block = data[i:i + max_block_size * 2]
            lc = len(block) // 2
            
            # 确定 P1 和 P2
            # 根据 SGP.33 规范：
            # - 非最后块: P1 = 0x11, P2 = 块号
            # - 最后块: P1 = 0x91, P2 = 块号
            if block_num == total_blocks - 1:
                # 最后一块：P1 = 0x91
                block_p1 = 0x91
            else:
                # 非最后块：P1 = 0x11
                block_p1 = 0x11
            
            block_p2 = block_num
            
            apdus.append(f"{cla:02X}{ins:02X}{block_p1:02X}{block_p2:02X}{lc:02X}{block}")
        
        return apdus


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
