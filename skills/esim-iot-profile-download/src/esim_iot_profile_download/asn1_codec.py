"""ASN.1 编解码模块

实现 eSIM Profile 下载流程中的 ASN.1 数据结构编解码。
基于 pyasn1 库实现。
"""

from typing import Optional, List, Dict, Any
from pyasn1.type import univ, namedtype, tag, char
from pyasn1.codec.der import encoder, decoder
from pyasn1.error import PyAsn1Error


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
    
    # deviceInfo: [0] tac, [1] deviceCapabilities, [2] deviceIdentifier
    device = (
        _der_tlv(b'\x80', tac)
        + _der_tlv(b'\xa1', caps_seq)
        + _der_tlv(b'\x82', bytes([0, 0, 0, 0, 0x11, 0x11, 0x11, 0x11]))
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
    - verification_ci_pk_ids: 验证 CI 公钥 ID 列表
    - signing_ci_pk_ids: 签名 CI 公钥 ID 列表
    """
    result = {}
    if len(response) < 4:
        raise Asn1CodecError("Response too short")
    
    # 跳过 BF20 tag 和 length
    offset = 2
    if offset >= len(response):
        return result
    
    data = response[offset:]
    
    # 解析 [2] version
    if len(data) > 1 and data[0] == 0x82:
        offset = 1
        ver_len = data[offset]
        offset += 1
        if offset + ver_len <= len(data):
            result['svn'] = data[offset:offset + ver_len].decode('utf-8', errors='ignore')
            offset += ver_len
    else:
        offset = 1
    
    # 解析 [9] verificationCiPkIds
    if offset < len(data) and data[offset] == 0x89:
        offset += 1
        if offset < len(data):
            ver_len = data[offset]
            offset += 1
            ver_data = data[offset:offset + ver_len]
            result['verification_ci_pk_ids'] = _parse_octet_string_set(ver_data)
            offset += ver_len
    
    # 解析 [10] signingCiPkIds
    if offset < len(data) and data[offset] == 0x8A:
        offset += 1
        if offset < len(data):
            sign_len = data[offset]
            offset += 1
            sign_data = data[offset:offset + sign_len]
            result['signing_ci_pk_ids'] = _parse_octet_string_set(sign_data)
    
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
