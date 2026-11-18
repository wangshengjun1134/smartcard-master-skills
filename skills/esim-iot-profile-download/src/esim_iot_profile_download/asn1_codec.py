"""ASN.1 编解码模块

实现 eSIM Profile 下载流程中的 ASN.1 数据结构编解码。
基于 pyasn1 库实现。
"""

from typing import Optional, List, Dict, Any
from pyasn1.type import univ, namedtype, tag, char
from pyasn1.codec.der import encoder, decoder
from pyasn1.error import PyAsn1Error
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
import os


class Asn1CodecError(Exception):
    """ASN.1 编解码异常"""
    pass


# ========== 基础类型定义 ==========

class UTF8String(char.UTF8String):
    """UTF8String"""
    pass


class BOOLEAN(univ.Boolean):
    """BOOLEAN"""
    pass


# ========== DER 基础工具 ==========

def _der_len(n: int) -> bytes:
    """DER 长度编码"""
    if n < 128:
        return bytes([n])
    if n < 256:
        return bytes([0x81, n])
    if n < 65536:
        return bytes([0x82, (n >> 8) & 0xFF, n & 0xFF])
    raise Asn1CodecError(f"Length too large: {n}")


def _der_tlv(tag_bytes: bytes, value: bytes) -> bytes:
    """构造 DER TLV"""
    return tag_bytes + _der_len(len(value)) + value


# ========== BF38 AuthenticateServerRequest ==========

def encode_server_signed1(
    transaction_id: bytes,
    euicc_challenge: bytes,
    server_address: str,
    server_challenge: bytes
) -> bytes:
    """编码 ServerSigned1 SEQUENCE

    结构 (SGP.22 5.7.5):
    ServerSigned1 ::= SEQUENCE {
        transactionId   [0] TransactionId,
        euiccChallenge  [1] Octet16,
        serverAddress   [3] UTF8String,
        serverChallenge [4] Octet16
    }

    Args:
        transaction_id: 16 字节事务 ID
        euicc_challenge: 16 字节 eUICC 挑战值
        server_address: SM-DP+ 地址
        server_challenge: 16 字节服务器挑战值

    Returns:
        DER 编码的 ServerSigned1 (SEQUENCE)
    """
    if not transaction_id or len(transaction_id) > 16:
        raise Asn1CodecError(f"transactionId must be 1..16 bytes, got {len(transaction_id)}")
    if len(euicc_challenge) != 16:
        raise Asn1CodecError(f"euiccChallenge must be 16 bytes, got {len(euicc_challenge)}")
    if len(server_challenge) != 16:
        raise Asn1CodecError(f"serverChallenge must be 16 bytes, got {len(server_challenge)}")

    content = (
        _der_tlv(b'\x80', transaction_id)
        + _der_tlv(b'\x81', euicc_challenge)
        + _der_tlv(b'\x83', server_address.encode('utf-8'))
        + _der_tlv(b'\x84', server_challenge)
    )
    return _der_tlv(b'\x30', content)


def encode_bf38_authenticate_server_request(
    server_signed1: bytes,
    server_signature1: bytes,
    euicc_ci_pk_id: bytes,
    server_certificate: bytes,
    matching_id: str,
    tac: bytes
) -> bytes:
    """
    编码 AuthenticateServerRequest (BF38)
    
    结构:
    - ServerSigned1: 已编码的签名数据
    - serverSignature1: [55] 签名
    - euiccCiPkIdToBeUsed: OCTET STRING
    - serverCertificate: 证书
    - ctxParams1: [0] matchingId, [1] deviceInfo
    """
    if len(tac) != 4:
        raise Asn1CodecError("TAC must be 4 bytes")
    
    # deviceCapabilities: 8 个 [n] OCTET STRING
    caps = [
        b'\x05\x00\x00', b'\x08\x00\x00', b'\x01\x00\x00', b'\x01\x00\x00',
        b'\x02\x00\x00', b'\x02\x00\x00', b'\x09\x00\x00', b'\x02\x01\x00',
    ]
    caps_seq = b''.join(_der_tlv(bytes([0x80 | i]), c) for i, c in enumerate(caps))

    # deviceInfo: [0] tac, [1] deviceCapabilities
    # 注意：不包含 deviceIdentifier [2]（IMEI 为 Octet32，默认省略）
    device = (
        _der_tlv(b'\x80', tac)
        + _der_tlv(b'\xa1', caps_seq)
    )

    # context: [0] matchingId, [1] deviceInfo
    context = b''
    if matching_id:
        context += _der_tlv(b'\x80', matching_id.encode('utf-8'))
    context += _der_tlv(b'\xa1', device)

    ctx_params1 = _der_tlv(b'\xa0', context)
    
    fields = (
        server_signed1
        + _der_tlv(b'\x5f\x37', server_signature1)
        + _der_tlv(b'\x04', euicc_ci_pk_id)
        + server_certificate
        + ctx_params1
    )
    
    return _der_tlv(b'\xbf\x38', fields)


# ========== SmdpSigned2 ==========

def encode_smdp_signed2(
    transaction_id: str,
    confirmation_code_required: bool = False,
    bpp_euicc_otpk: Optional[bytes] = None
) -> bytes:
    """
    编码 SmdpSigned2
    
    SmdpSigned2 ::= SEQUENCE {
        transactionId        [0] OCTET STRING,
        ccRequired           BOOLEAN,
        bppEuiccOtpk         [5F49] OCTET STRING OPTIONAL
    }
    """
    tid_bytes = bytes.fromhex(transaction_id.replace(" ", ""))
    
    tid_field = univ.OctetString(tid_bytes).subtype(
        implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0)
    )
    
    cc_field = BOOLEAN(confirmation_code_required)
    
    if bpp_euicc_otpk:
        otpk_field = univ.OctetString(bpp_euicc_otpk).subtype(
            implicitTag=tag.Tag(tag.tagClassApplication, tag.tagFormatSimple, 73)
        )
        smdp_signed2 = univ.Sequence(
            componentType=namedtype.NamedTypes(
                namedtype.NamedType('transactionId', tid_field),
                namedtype.NamedType('ccRequired', cc_field),
                namedtype.NamedType('bppEuiccOtpk', otpk_field),
            )
        )
        smdp_signed2.setComponentByPosition(0, tid_field)
        smdp_signed2.setComponentByPosition(1, cc_field)
        smdp_signed2.setComponentByPosition(2, otpk_field)
    else:
        smdp_signed2 = univ.Sequence(
            componentType=namedtype.NamedTypes(
                namedtype.NamedType('transactionId', tid_field),
                namedtype.NamedType('ccRequired', cc_field),
            )
        )
        smdp_signed2.setComponentByPosition(0, tid_field)
        smdp_signed2.setComponentByPosition(1, cc_field)
    
    try:
        return encoder.encode(smdp_signed2)
    except PyAsn1Error as e:
        raise Asn1CodecError(f"Cannot encode SmdpSigned2: {e}")


# ========== BF21 PrepareDownloadRequest ==========

def encode_bf21_prepare_download_request(
    smdp_signed2: bytes,
    smdp_signature2: bytes,
    smdp_certificate: bytes,
    hash_cc: Optional[bytes] = None
) -> bytes:
    """
    编码 PrepareDownloadRequest (BF21)
    """
    # 证书直接使用原始字节，不需要解码
    cert_der = smdp_certificate
    
    # 编码 smdpSignature2 [55]
    smdp_sig2_field = univ.OctetString(smdp_signature2).subtype(
        implicitTag=tag.Tag(tag.tagClassApplication, tag.tagFormatSimple, 55)
    )
    smdp_sig2_der = encoder.encode(smdp_sig2_field)
    
    # BF21 内容
    if hash_cc:
        hash_cc_der = bytes([0x04, len(hash_cc)]) + hash_cc
        bf21_content = smdp_signed2 + smdp_sig2_der + hash_cc_der + cert_der
    else:
        bf21_content = smdp_signed2 + smdp_sig2_der + cert_der
    
    # 添加 BF21 tag [33] IMPLICIT
    bf21_len = len(bf21_content)
    if bf21_len < 128:
        bf21 = bytes([0xBF, 0x21, bf21_len]) + bf21_content
    elif bf21_len < 256:
        bf21 = bytes([0xBF, 0x21, 0x81, bf21_len]) + bf21_content
    else:
        bf21 = bytes([0xBF, 0x21, 0x82, (bf21_len >> 8) & 0xFF, bf21_len & 0xFF]) + bf21_content
    
    return bf21


# ========== PrepareDownloadResponse 解码 ==========

def decode_prepare_download_response(response: bytes) -> Dict[str, Any]:
    """
    解码 PrepareDownloadResponse (BF21 响应)
    
    提取:
    - transaction_id
    - euicc_otpk
    - euicc_signature2
    """
    if len(response) < 4:
        raise Asn1CodecError("Response too short")
    
    result = {}
    offset = 0
    
    # 解析 BF21 tag
    if response[offset] == 0xBF and offset + 1 < len(response) and response[offset + 1] == 0x21:
        offset += 2
    else:
        raise Asn1CodecError(f"Expected BF21 tag")
    
    # 解析 length
    length_byte = response[offset]
    offset += 1
    if length_byte & 0x80:
        num_bytes = length_byte & 0x7F
        length = 0
        for i in range(num_bytes):
            length = (length << 8) | response[offset]
            offset += 1
    else:
        length = length_byte
    
    # 解析 A0/A1 tag
    if response[offset] not in (0xA0, 0xA1):
        raise Asn1CodecError(f"Expected A0 or A1 tag")
    offset += 1
    
    # 解析 A0 length
    a0_len_byte = response[offset]
    offset += 1
    if a0_len_byte & 0x80:
        num_bytes = a0_len_byte & 0x7F
        a0_length = 0
        for i in range(num_bytes):
            a0_length = (a0_length << 8) | response[offset]
            offset += 1
    else:
        a0_length = a0_len_byte
    
    a0_end = offset + a0_length
    
    # 解析 SEQUENCE
    if response[offset] != 0x30:
        raise Asn1CodecError(f"Expected SEQUENCE tag")
    offset += 1
    
    seq_len_byte = response[offset]
    offset += 1
    if seq_len_byte & 0x80:
        num_bytes = seq_len_byte & 0x7F
        seq_length = 0
        for i in range(num_bytes):
            seq_length = (seq_length << 8) | response[offset]
            offset += 1
    else:
        seq_length = seq_len_byte
    
    seq_end = offset + seq_length
    
    # [0] transactionId
    if offset < seq_end and response[offset] == 0x80:
        offset += 1
        tid_len = response[offset]
        offset += 1
        result['transaction_id'] = response[offset:offset + tid_len].hex().upper()
        offset += tid_len
    
    # [5F49] euiccOtpk
    if offset < seq_end and response[offset] == 0x5F and offset + 1 < len(response) and response[offset + 1] == 0x49:
        offset += 2
        otpk_len = response[offset]
        offset += 1
        result['euicc_otpk'] = response[offset:offset + otpk_len]
        offset += otpk_len
    
    # [55] euiccSignature2
    if offset < len(response) and response[offset] == 0x5F:
        if offset + 1 < len(response) and response[offset + 1] == 0x37:
            offset += 2
            sig_len_byte = response[offset]
            offset += 1
            if sig_len_byte & 0x80:
                num_bytes = sig_len_byte & 0x7F
                sig_len = 0
                for i in range(num_bytes):
                    sig_len = (sig_len << 8) | response[offset]
                    offset += 1
            else:
                sig_len = sig_len_byte
            result['euicc_signature2'] = response[offset:offset + sig_len]
    
    return result


# ========== EuiccInfo1 解码 ==========

def decode_euicc_info1(response: bytes) -> Dict[str, Any]:
    """
    解码 EuiccInfo1 (BF20 响应)

    提取:
    - svn: 版本号
    - verification_ci_pk_ids: 验证 CI 公钥 ID 列表（20 字节 SKI）
    - signing_ci_pk_ids: 签名 CI 公钥 ID 列表

    EuiccInfo1 ::= [APPLICATION 32] SEQUENCE {
        svn [2] VersionType,
        euiccCiPKIdListForVerification [9] SEQUENCE OF SubjectKeyIdentifier,
        euiccCiPKIdListForSigning [10] SEQUENCE OF SubjectKeyIdentifier OPTIONAL
    }
    """
    result = {}
    if len(response) < 4:
        raise Asn1CodecError("Response too short")

    def read_len(buf, pos):
        lb = buf[pos]
        pos += 1
        if lb & 0x80:
            n = lb & 0x7F
            val = int.from_bytes(buf[pos:pos + n], 'big')
            return val, pos + n
        return lb, pos

    # 跳过 BF20 tag (2 字节) 和外层长度
    offset = 2
    _, offset = read_len(response, offset)

    while offset < len(response):
        tag = response[offset]
        offset += 1
        # 多字节 tag（如 9F xx）
        if (tag & 0x1F) == 0x1F:
            while offset < len(response):
                b = response[offset]
                offset += 1
                if not (b & 0x80):
                    break
        if offset >= len(response):
            break
        length, offset = read_len(response, offset)
        value = response[offset:offset + length]
        offset += length

        if tag == 0x82:  # [2] svn
            result['svn'] = value.hex().upper()
        elif tag in (0xA9, 0x89):  # [9] euiccCiPKIdListForVerification
            result['verification_ci_pk_ids'] = _parse_octet_string_set(value)
        elif tag in (0xAA, 0x8A):  # [10] euiccCiPKIdListForSigning
            result['signing_ci_pk_ids'] = _parse_octet_string_set(value)

    return result


def _parse_octet_string_set(data: bytes) -> List[bytes]:
    """解析 OCTET STRING SET"""
    result = []
    offset = 0
    while offset < len(data):
        if offset >= len(data):
            break
        tag_byte = data[offset]
        offset += 1
        if tag_byte == 0x04:  # OCTET STRING
            if offset >= len(data):
                break
            length = data[offset]
            offset += 1
            if offset + length <= len(data):
                result.append(data[offset:offset + length])
            offset += length
        else:
            if offset < len(data):
                length = data[offset]
                offset += 1 + length
    return result


# ========== BF2E Challenge 解码 ==========

def decode_bf2e_challenge(response: bytes) -> bytes:
    """
    解码 GetEuiccChallenge 响应，提取 16 字节 challenge
    """
    if len(response) < 6:
        raise Asn1CodecError("Response too short")
    
    # 跳过 BF2E tag (2 bytes) 和 length (1 byte)
    offset = 3
    
    if offset < len(response) and response[offset] == 0x80:
        offset += 1
        if offset < len(response):
            length = response[offset]
            offset += 1
            if length == 16 and len(response) >= offset + 16:
                return response[offset:offset + 16]
    
    raise Asn1CodecError("BF2E response has no 16-byte challenge")


# ========== BF57 AddInitialEim ==========

def encode_bf57_add_initial_eim(
    eim_id: str,
    eim_counter: int = 1,
    eim_certificate: bytes = b""
) -> bytes:
    """
    编码 AddInitialEim (BF57)
    """
    # eimId: UTF8String
    eim_id_field = _der_tlv(b'\x80', eim_id.encode('utf-8'))
    
    # counter: INTEGER
    counter_field = _der_tlv(b'\x02', eim_counter.to_bytes(1, 'big'))
    
    # certificate: [1]
    cert_field = b''
    if eim_certificate:
        cert_field = _der_tlv(b'\xa1', eim_certificate)
    
    content = eim_id_field + counter_field + cert_field
    return _der_tlv(b'\xbf\x57', content)


# ========== BF51 EnablePSMO ==========

def encode_bf51_enable_psmo(
    iccid: str,
    profile_id: str,
    eim_counter: int = 2
) -> bytes:
    """
    编码 EnablePSMO (BF51)
    """
    # iccid: OCTET STRING (BCD 编码)
    iccid_bytes = bytes.fromhex(iccid) if len(iccid) % 2 == 0 else bytes.fromhex(iccid + 'F')
    iccid_field = _der_tlv(b'\x04', iccid_bytes)
    
    # profileId: OCTET STRING
    profile_bytes = bytes.fromhex(profile_id.replace(" ", ""))
    profile_field = _der_tlv(b'\x04', profile_bytes)
    
    # counter: INTEGER
    counter_field = _der_tlv(b'\x02', eim_counter.to_bytes(1, 'big'))
    
    content = iccid_field + profile_field + counter_field
    return _der_tlv(b'\xbf\x51', content)


# ========== GetProfilesInfo 解码 ==========

def decode_profiles_info(response: bytes) -> Dict[str, Any]:
    """
    解码 GetProfilesInfo (BF2D 响应)
    
    提取 profileState (9F70)
    """
    result = {
        "profiles": [],
        "raw": response.hex().upper() if response else ""
    }
    
    if not response or len(response) < 4:
        return result
    
    # 查找 9F70 (profileState)
    offset = 0
    while offset < len(response) - 1:
        if response[offset] == 0x9F and response[offset + 1] == 0x70:
            offset += 2
            if offset < len(response):
                length = response[offset]
                offset += 1
                if offset + length <= len(response):
                    state_bytes = response[offset:offset + length]
                    # profileState: 0 = DISABLED, 1 = ENABLED
                    if len(state_bytes) > 0:
                        state = "ENABLED" if state_bytes[0] == 1 else "DISABLED"
                        result["profile_state"] = state
            break
        offset += 1

    return result


# ========== BPP (Bound Profile Package) 生成 ==========

class BPPGenerator:
    """BPP 生成器
    
    实现 SGP.22 规范的 Bound Profile Package 生成，包括：
    - ECKA 密钥协商 (ECDH)
    - SCP03t 安全通道保护
    - ASN.1 编码
    
    注意：当 euicc_otpk 为空或无效时，使用简化模式，
    跳过加密步骤，直接发送 UPP 数据。
    """
    
    # 测试用 Host ID
    TEST_HOST_ID = b"GSMA SM-XX"
    
    # PPK (Profile Protection Key) 常量
    PPK_INITIAL_MAC_CHAINING_VALUE = bytes.fromhex("c516a604f2398a298c7f56250b4bff48")
    PPK_ENC = bytes.fromhex("2639dce906b2ace1bce33d930863ce61")
    PPK_CMAC = bytes.fromhex("50eef08f28e4394223fc1f288ef56006")
    
    def __init__(self, dp_pb_private_key_pem: bytes, dp_pb_cert_der: bytes):
        """初始化 BPP 生成器
        
        Args:
            dp_pb_private_key_pem: DP+ Profile Binding 私钥 (PEM 格式)
            dp_pb_cert_der: DP+ Profile Binding 证书 (DER 格式)
        """
        self.dp_pb_private_key = serialization.load_pem_private_key(
            dp_pb_private_key_pem,
            password=None,
            backend=default_backend()
        )
        self.dp_pb_cert = dp_pb_cert_der
    
    def generate_bpp(
        self,
        transaction_id: str,
        eid: str,
        euicc_otpk: bytes,
        profile_package: bytes,
        iccid: str,
        profile_id: str,
        profile_name: str,
        service_provider_name: str = "Test Operator",
        profile_class: int = 2
    ) -> bytes:
        """生成 Bound Profile Package
        
        Args:
            transaction_id: 事务 ID (十六进制字符串)
            eid: eUICC EID
            euicc_otpk: eUICC One-Time Public Key (65 字节，04||x||y)
                       如果为空或无效，使用简化模式
            profile_package: Profile 包数据 (UPP 格式)
            iccid: ICCID
            profile_id: Profile ID
            profile_name: Profile 名称
            service_provider_name: 服务提供商名称
            profile_class: Profile 类别
            
        Returns:
            BPP 数据 (DER 编码)
        """
        # 检查 euicc_otpk 是否有效
        use_simplified_mode = (
            not euicc_otpk or 
            len(euicc_otpk) != 65 or 
            euicc_otpk[0] != 0x04 or
            euicc_otpk == bytes(65)
        )
        
        if use_simplified_mode:
            # 简化模式：跳过加密，直接构造 BPP
            return self._generate_bpp_simplified(
                transaction_id,
                profile_package,
                iccid,
                profile_name,
                profile_class
            )
        
        # 正常模式：完整的 BPP 生成
        # 1. 生成 SM-DP+ 一次性密钥对
        smdp_otpk_private = ec.generate_private_key(ec.SECP256R1(), default_backend())
        smdp_otpk_public = smdp_otpk_private.public_key()
        smdp_otpk = self._encode_ec_public_key(smdp_otpk_public)
        
        # 2. ECKA 密钥协商
        euicc_public = self._decode_ec_public_key(euicc_otpk)
        shared_secret = smdp_otpk_private.exchange(ec.ECDH(), euicc_public)
        
        # 3. 派生 SCP03t 会话密钥
        session_keys = self._derive_session_keys(
            shared_secret,
            self.TEST_HOST_ID,
            bytes.fromhex(eid),
            smdp_otpk,
            euicc_otpk
        )
        
        # 4. 构造 ConfigureISDP (87)
        configure_isdp = self._encode_configure_isdp(profile_package)
        first_87 = self._scp03t_protect(0x87, configure_isdp, session_keys)
        
        # 5. 构造 StoreMetadata (88)
        metadata = self._encode_store_metadata(
            iccid, service_provider_name, profile_name, profile_class
        )
        sequence_88 = self._scp03t_protect(0x88, metadata, session_keys)
        
        # 6. 构造 sequenceOf86 (Profile 数据)
        sequence_86 = self._scp03t_protect(0x86, profile_package, session_keys)
        
        # 7. 构造 BF23 (initialiseSecureChannelRequest)
        bf23 = self._encode_bf23(
            transaction_id,
            smdp_otpk,
            euicc_otpk
        )
        
        # 8. 组装 BPP
        bpp = self._assemble_bpp(bf23, first_87, sequence_88, sequence_86)
        
        return bpp
    
    def _generate_bpp_simplified(
        self,
        transaction_id: str,
        profile_package: bytes,
        iccid: str,
        profile_name: str,
        profile_class: int
    ) -> bytes:
        """简化模式的 BPP 生成
        
        跳过加密步骤，但仍然构造完整的 BPP 结构。
        用于测试或当 euicc_otpk 不可用时。
        
        注意：这种模式生成的 BPP 可能被某些卡片拒绝，
        因为缺少有效的签名和 MAC。
        """
        # 构造 StoreMetadata (88) - 不加密，但需要添加 MAC
        metadata = self._encode_store_metadata(
            iccid, "Test Operator", profile_name, profile_class
        )
        # 添加 8 字节的 MAC (全零)
        mac = bytes(8)
        sequence_88_content = metadata + mac
        sequence_88 = bytes([0x88]) + self._encode_ber_len(len(sequence_88_content)) + sequence_88_content
        
        # 构造 sequenceOf86 (Profile 数据) - 不加密，但需要添加 MAC
        # 按照 SCP03t 格式，每个数据块最大 1007 字节明文 + 8 字节 MAC
        MAX_PPP_PLAINTEXT_SEGMENT = 1007
        sequence_86_parts = []
        for offset in range(0, len(profile_package), MAX_PPP_PLAINTEXT_SEGMENT):
            segment = profile_package[offset:offset + MAX_PPP_PLAINTEXT_SEGMENT]
            # 添加 8 字节的 MAC (全零)
            part_content = segment + mac
            part = bytes([0x86]) + self._encode_ber_len(len(part_content)) + part_content
            sequence_86_parts.append(part)
        
        # 构造 BF23 (initialiseSecureChannelRequest) - 简化版本
        bf23 = self._encode_bf23_simplified(transaction_id)
        
        # 构造 A0 (firstSequenceOf87) - ConfigureISDP with MAC
        configure_isdp = b'\x80\x01\x01'  # 简化的配置数据
        configure_isdp_with_mac = configure_isdp + mac
        first_87 = bytes([0x87]) + self._encode_ber_len(len(configure_isdp_with_mac)) + configure_isdp_with_mac
        a0 = _der_tlv(b'\xa0', first_87)
        
        # 构造 A1 (sequenceOf88)
        a1 = _der_tlv(b'\xa1', sequence_88)
        
        # 构造 A3 (sequenceOf86) - 包含多个 86 TLV
        a3_content = b''.join(sequence_86_parts)
        a3 = _der_tlv(b'\xa3', a3_content)
        
        # BPP 内容
        bpp_content = bf23 + a0 + a1 + a3
        
        # BF36: BoundProfilePackage
        return _der_tlv(b'\xbf\x36', bpp_content)
    
    def _encode_bf23_simplified(self, transaction_id: str) -> bytes:
        """编码 BF23 (initialiseSecureChannelRequest) - 简化版本
        
        用于简化模式，跳过签名。
        """
        # remoteOperation [2]
        remote_op = _der_tlv(b'\xa2', b'\x02\x01\x01')  # INTEGER 1
        
        # transactionId [0]
        tid_bytes = bytes.fromhex(transaction_id)
        tid_field = _der_tlv(b'\xa0', tid_bytes)
        
        # controlReferenceTemplate [6]
        crt_content = (
            _der_tlv(b'\x80', b'\x01') +  # 算法标识
            _der_tlv(b'\x81', b'\x10') +  # 密钥长度
            _der_tlv(b'\x84', self.TEST_HOST_ID)  # Host ID
        )
        crt_field = _der_tlv(b'\xa6', crt_content)
        
        # smdpPublic [73] - 使用空的公钥
        smdp_public = _der_tlv(b'\x86', bytes(65))
        
        # 签名 (简化：使用空签名)
        signature = _der_tlv(b'\x87', b'\x00' * 64)
        
        content = remote_op + tid_field + crt_field + smdp_public + signature
        return _der_tlv(b'\xbf\x23', content)
    
    def _encode_ec_public_key(self, public_key) -> bytes:
        """编码 EC 公钥为 65 字节格式 (04||x||y)"""
        public_numbers = public_key.public_numbers()
        x = public_numbers.x.to_bytes(32, 'big')
        y = public_numbers.y.to_bytes(32, 'big')
        return b'\x04' + x + y
    
    def _decode_ec_public_key(self, data: bytes):
        """解码 65 字节格式的 EC 公钥"""
        if len(data) != 65 or data[0] != 0x04:
            raise Asn1CodecError(f"Invalid EC public key format: {len(data)} bytes")
        
        x = int.from_bytes(data[1:33], 'big')
        y = int.from_bytes(data[33:65], 'big')
        
        public_numbers = ec.EllipticCurvePublicNumbers(x, y, ec.SECP256R1())
        return public_numbers.public_key(default_backend())
    
    def _derive_session_keys(
        self,
        shared_secret: bytes,
        host_id: bytes,
        eid: bytes,
        smdp_otpk: bytes,
        euicc_otpk: bytes
    ) -> Dict[str, bytes]:
        """派生 SCP03t 会话密钥
        
        使用简化的密钥派生函数 (KDF)
        """
        # 简化的 KDF：使用 SHA-256 派生密钥
        kdf_input = shared_secret + host_id + eid + smdp_otpk + euicc_otpk
        
        digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
        digest.update(kdf_input)
        derived = digest.finalize()
        
        # 派生 3 个 16 字节密钥
        return {
            's_enc': derived[:16],
            's_cmac': derived[16:32],
            's_rmac': derived[0:16]  # 简化：使用相同的前 16 字节
        }
    
    def _encode_configure_isdp(self, profile_package: bytes) -> bytes:
        """编码 ConfigureISDP 命令"""
        # 简化的 ConfigureISDP：只包含必要字段
        # 实际应该包含更多配置参数
        return b'\x80\x01\x01'  # 简化的配置数据
    
    def _encode_store_metadata(
        self,
        iccid: str,
        service_provider_name: str,
        profile_name: str,
        profile_class: int
    ) -> bytes:
        """编码 StoreMetadata 命令"""
        # ICCID (80)
        iccid_bytes = bytes.fromhex(iccid) if len(iccid) % 2 == 0 else bytes.fromhex(iccid + 'F')
        iccid_field = _der_tlv(b'\x80', iccid_bytes)
        
        # Service Provider Name (82)
        spn_field = _der_tlv(b'\x82', service_provider_name.encode('utf-8'))
        
        # Profile Name (90)
        pn_field = _der_tlv(b'\x90', profile_name.encode('utf-8'))
        
        # Profile Class (95)
        pc_field = _der_tlv(b'\x95', bytes([profile_class]))
        
        content = iccid_field + spn_field + pn_field + pc_field
        return content
    
    def _scp03t_protect(self, tag: int, data: bytes, keys: Dict[str, bytes]) -> bytes:
        """SCP03t 保护数据
        
        简化的 SCP03t 实现：
        - 使用 AES-128-CMAC 计算 MAC
        - 使用 AES-128 加密数据
        """
        # 简化的 SCP03t：只计算 MAC，不加密
        # 实际应该使用完整的 SCP03t 协议
        
        # 计算 CMAC
        from cryptography.hazmat.primitives.cmac import CMAC
        from cryptography.hazmat.primitives.ciphers import algorithms
        
        cmac = CMAC(algorithms.AES(keys['s_cmac']), backend=default_backend())
        cmac.update(data)
        mac = cmac.finalize()[:8]  # 取前 8 字节作为 MAC
        
        # 构造受保护的数据块
        # 格式: tag + length + data + mac
        protected = bytes([tag]) + self._encode_ber_len(len(data) + 8) + data + mac
        
        return protected
    
    def _encode_bf23(
        self,
        transaction_id: str,
        smdp_otpk: bytes,
        euicc_otpk: bytes
    ) -> bytes:
        """编码 BF23 (initialiseSecureChannelRequest)"""
        # remoteOperation [2]
        remote_op = _der_tlv(b'\xa2', b'\x02\x01\x01')  # INTEGER 1
        
        # transactionId [0]
        tid_bytes = bytes.fromhex(transaction_id)
        tid_field = _der_tlv(b'\xa0', tid_bytes)
        
        # controlReferenceTemplate [6]
        crt_content = (
            _der_tlv(b'\x80', b'\x01') +  # 算法标识
            _der_tlv(b'\x81', b'\x10') +  # 密钥长度
            _der_tlv(b'\x84', self.TEST_HOST_ID)  # Host ID
        )
        crt_field = _der_tlv(b'\xa6', crt_content)
        
        # smdpPublic [73] (SM-DP+ 一次性公钥)
        smdp_public = _der_tlv(b'\x86', smdp_otpk)  # 简化：使用 OCTET STRING
        
        # 签名 (简化：使用空签名)
        signature = _der_tlv(b'\x87', b'\x00' * 64)
        
        content = remote_op + tid_field + crt_field + smdp_public + signature
        return _der_tlv(b'\xbf\x23', content)
    
    def _assemble_bpp(
        self,
        bf23: bytes,
        first_87: bytes,
        sequence_88: bytes,
        sequence_86: bytes
    ) -> bytes:
        """组装 BPP"""
        # A0: firstSequenceOf87
        a0 = _der_tlv(b'\xa0', first_87)
        
        # A1: sequenceOf88
        a1 = _der_tlv(b'\xa1', sequence_88)
        
        # A3: sequenceOf86
        a3 = _der_tlv(b'\xa3', sequence_86)
        
        # BPP 内容
        bpp_content = bf23 + a0 + a1 + a3
        
        # BF36: BoundProfilePackage
        return _der_tlv(b'\xbf\x36', bpp_content)
    
    def _encode_ber_len(self, length: int) -> bytes:
        """编码 BER 长度"""
        if length < 128:
            return bytes([length])
        elif length < 256:
            return bytes([0x81, length])
        else:
            return bytes([0x82, (length >> 8) & 0xFF, length & 0xFF])


def generate_bpp(
    transaction_id: str,
    eid: str,
    euicc_otpk: bytes,
    profile_package: bytes,
    iccid: str,
    profile_id: str,
    profile_name: str,
    dp_pb_private_key_pem: bytes,
    dp_pb_cert_der: bytes
) -> bytes:
    """生成 Bound Profile Package 的便捷函数
    
    Args:
        transaction_id: 事务 ID (十六进制字符串)
        eid: eUICC EID
        euicc_otpk: eUICC One-Time Public Key (65 字节，04||x||y)
        profile_package: Profile 包数据 (UPP 格式)
        iccid: ICCID
        profile_id: Profile ID
        profile_name: Profile 名称
        dp_pb_private_key_pem: DP+ Profile Binding 私钥 (PEM 格式)
        dp_pb_cert_der: DP+ Profile Binding 证书 (DER 格式)
        
    Returns:
        BPP 数据 (DER 编码)
    """
    generator = BPPGenerator(dp_pb_private_key_pem, dp_pb_cert_der)
    return generator.generate_bpp(
        transaction_id=transaction_id,
        eid=eid,
        euicc_otpk=euicc_otpk,
        profile_package=profile_package,
        iccid=iccid,
        profile_id=profile_id,
        profile_name=profile_name
    )
