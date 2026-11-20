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


def _tlv_header(tag: int, length: int) -> bytes:
    """构造单字节 tag 的 BER-TLV 头部"""
    if length < 0x80:
        return bytes([tag, length])
    if length <= 0xFF:
        return bytes([tag, 0x81, length])
    return bytes([tag, 0x82, (length >> 8) & 0xFF, length & 0xFF])


def _iso7816_pad(data: bytes) -> bytes:
    """ISO/IEC 7816-4 填充：追加 0x80 后补 0x00 至 16 字节整数倍"""
    padding = 16 - (len(data) % 16)
    return data + b'\x80' + bytes(padding - 1)


def _aes_ecb_encrypt(key: bytes, data: bytes) -> bytes:
    """AES-128 ECB 加密（无填充）"""
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

    encryptor = Cipher(algorithms.AES(key), modes.ECB()).encryptor()
    return encryptor.update(data) + encryptor.finalize()


def _aes_cbc_encrypt(key: bytes, data: bytes, iv: bytes) -> bytes:
    """AES-128 CBC 加密（无填充）"""
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

    encryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
    return encryptor.update(data) + encryptor.finalize()


def _aes_cmac(key: bytes, data: bytes) -> bytes:
    """AES-128 CMAC（输出完整 16 字节）"""
    from cryptography.hazmat.primitives.cmac import CMAC
    from cryptography.hazmat.primitives.ciphers import algorithms

    cmac = CMAC(algorithms.AES(key), backend=default_backend())
    cmac.update(data)
    return cmac.finalize()


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
    tac: bytes,
    device_identifier: bytes = b'\x00\x00\x00\x00\x11\x11\x11\x11'
) -> bytes:
    """
    编码 AuthenticateServerRequest (BF38)

    结构:
    - ServerSigned1: 已编码的签名数据
    - serverSignature1: [55] 签名
    - euiccCiPkIdToBeUsed: OCTET STRING
    - serverCertificate: 证书
    - ctxParams1: [0] { [0] matchingId, [1] deviceInfo }
      deviceInfo = [0] tac, [1] deviceCapabilities, [2] deviceIdentifier
    """
    if len(tac) != 4:
        raise Asn1CodecError("TAC must be 4 bytes")

    # deviceCapabilities: 8 个 [n] OCTET STRING（固定向量，空 SEQUENCE 会被真卡拒绝）
    caps = [
        b'\x05\x00\x00', b'\x08\x00\x00', b'\x01\x00\x00', b'\x01\x00\x00',
        b'\x02\x00\x00', b'\x02\x00\x00', b'\x09\x00\x00', b'\x02\x01\x00',
    ]
    caps_seq = b''.join(_der_tlv(bytes([0x80 | i]), c) for i, c in enumerate(caps))

    # deviceInfo: [0] tac, [1] deviceCapabilities, [2] deviceIdentifier(IMEI)
    device = _der_tlv(b'\x80', tac) + _der_tlv(b'\xa1', caps_seq)
    if device_identifier:
        device += _der_tlv(b'\x82', device_identifier)

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


_AUTH_ERROR_NAMES = {
    1: "invalidCertificate",
    2: "invalidSignature",
    3: "unsupportedCurve",
    4: "noSessionContext",
    5: "invalidOid",
    6: "euiccChallengeMismatch",
    7: "ciPKUnknown",
    127: "undefinedError",
}


def check_authenticate_server_response(response: bytes) -> Dict[str, Any]:
    """检查 AuthenticateServer (BF38) 响应是成功还是错误

    结构：
    BF38 { A0 ... } = authenticateResponseOk
    BF38 { A1 [SEQUENCE { [0] transactionId, errorCode }] } = authenticateResponseError

    Returns:
        {"ok": bool, "error_code": int, "error_name": str, "transaction_id": str}
    """
    result = {"ok": False, "error_code": None, "error_name": "", "transaction_id": ""}
    if not response or len(response) < 4:
        result["error_name"] = "empty response"
        return result

    offset = 0
    if response[offset] == 0xBF and response[offset + 1] == 0x38:
        offset += 2
    else:
        result["error_name"] = "not BF38"
        return result

    # 跳过长度
    if offset >= len(response):
        return result
    lb = response[offset]
    offset += 1
    if lb & 0x80:
        offset += (lb & 0x7F)

    if offset >= len(response):
        return result

    branch = response[offset]
    if branch != 0xA1:
        # A0 或其他 = 成功分支
        result["ok"] = True
        return result

    # A1 错误容器
    offset += 1
    if offset >= len(response):
        result["error_name"] = "truncated error"
        return result
    lb = response[offset]
    offset += 1
    if lb & 0x80:
        offset += (lb & 0x7F)

    # 解析内部 [0] transactionId 和 INTEGER errorCode
    while offset < len(response):
        tag = response[offset]
        offset += 1
        if offset >= len(response):
            break
        lb = response[offset]
        offset += 1
        if lb & 0x80:
            n = lb & 0x7F
            length = int.from_bytes(response[offset:offset + n], 'big')
            offset += n
        else:
            length = lb
        value = response[offset:offset + length]
        offset += length

        if tag == 0x80:
            result["transaction_id"] = value.hex().upper()
        elif tag == 0x02 and value:
            code = int.from_bytes(value, 'big')
            result["error_code"] = code
            result["error_name"] = _AUTH_ERROR_NAMES.get(code, f"unknown({code})")

    return result


def _read_tlv(data: bytes, offset: int):
    """读取一个 BER TLV，返回 (tag, value, next_offset)"""
    if offset + 2 > len(data):
        return None, b"", len(data)

    first = data[offset]
    offset += 1
    if (first & 0x1F) == 0x1F:
        if offset >= len(data):
            return None, b"", len(data)
        tag = (first << 8) | data[offset]
        offset += 1
    else:
        tag = first

    if offset >= len(data):
        return None, b"", len(data)
    lb = data[offset]
    offset += 1
    if lb & 0x80:
        n = lb & 0x7F
        if n == 0 or offset + n > len(data):
            return None, b"", len(data)
        length = int.from_bytes(data[offset:offset + n], 'big')
        offset += n
    else:
        length = lb

    end = offset + length
    if end > len(data):
        end = len(data)
    return tag, data[offset:end], end


def decode_authenticate_server_ok(response: bytes) -> Dict[str, Any]:
    """解析 BF38 的成功分支 (authenticateResponseOk)，提取后续签名所需字段

    结构:
    BF38 { A0 { SEQUENCE { euiccSigned1, 5F37 euiccSignature1,
                          euiccCertificate, eumCertificate } } }

    Returns:
        {"ok", "transaction_id", "euicc_signed1", "euicc_signature1",
         "euicc_certificate", "eum_certificate"}
    """
    result = {
        "ok": False,
        "transaction_id": "",
        "euicc_signed1": b"",
        "euicc_signature1": b"",
        "euicc_certificate": b"",
        "eum_certificate": b"",
    }

    tag, body, _ = _read_tlv(response, 0)
    if tag != 0xBF38:
        return result

    tag, a0_body, _ = _read_tlv(body, 0)
    if tag != 0xA0:
        return result

    # A0 为 EXPLICIT 标记，内容通常是 euiccSigned1 的 SEQUENCE
    tag, inner, nxt = _read_tlv(a0_body, 0)
    if tag == 0x30:
        signed1 = a0_body[0:nxt]
        result["euicc_signed1"] = signed1
        for field_tag, value, _ in _iter_tlvs(inner):
            if field_tag == 0x80:
                result["transaction_id"] = value.hex().upper()
                break
        a0_body = a0_body[nxt:]

    for field_tag, value, raw in _iter_tlvs(a0_body):
        if field_tag == 0x5F37:
            result["euicc_signature1"] = value
        elif field_tag == 0x30 and not result["euicc_certificate"]:
            result["euicc_certificate"] = raw
        elif field_tag == 0x30 and not result["eum_certificate"]:
            result["eum_certificate"] = raw

    result["ok"] = bool(result["euicc_signature1"])
    return result


def _iter_tlvs(data: bytes):
    """顺序遍历 TLV，产出 (tag, value, raw_tlv)"""
    offset = 0
    while offset < len(data):
        tag, value, nxt = _read_tlv(data, offset)
        if tag is None or nxt <= offset:
            return
        yield tag, value, data[offset:nxt]
        offset = nxt


def encode_application_signature(signature: bytes) -> bytes:
    """编码 [APPLICATION 55] OCTET STRING (5F37)，即 euiccSignature1 的 ASN.1 形式"""
    return _der_tlv(b'\x5f\x37', signature)


_BPP_COMMAND_NAMES = {
    0: "initialiseSecureChannel",
    1: "configureISDP",
    2: "storeMetadata",
    3: "replaceSessionKeys",
    4: "loadProfileElements",
}

_PIR_ERROR_REASONS = {
    1: "incorrectInputValues",
    2: "invalidSignature",
    3: "invalidTransactionId",
    4: "unsupportedCrtValues",
    5: "unsupportedRemoteOperationType",
    6: "unsupportedProfileClass",
    7: "scp03tStructureError",
    8: "scp03tSecurityError",
    9: "installFailedDueToInsufficientMemory",
    10: "installFailedDueToInterruption",
    127: "undefinedError",
}


def decode_profile_installation_result(response: bytes) -> Dict[str, Any]:
    """解析 ProfileInstallationResult (BF37)

    BF37 { BF27 { [0] transactionId, BF2F notificationMetadata, OID,
                  [2] finalResult { [0] successResult | [1] errorResult } },
           5F37 euiccSignPIR }

    Returns:
        {"ok", "transaction_id", "bpp_command_id", "bpp_command",
         "error_reason", "error_name"}
    """
    result = {
        "ok": False,
        "transaction_id": "",
        "bpp_command_id": None,
        "bpp_command": "",
        "error_reason": None,
        "error_name": "",
    }

    tag, bf37_body, _ = _read_tlv(response, 0)
    if tag != 0xBF37:
        result["error_name"] = "not BF37"
        return result

    bf27_body = None
    for field_tag, value, _ in _iter_tlvs(bf37_body):
        if field_tag == 0xBF27:
            bf27_body = value
            break
    if bf27_body is None:
        result["error_name"] = "no BF27"
        return result

    final_result = None
    for field_tag, value, _ in _iter_tlvs(bf27_body):
        if field_tag == 0x80:
            result["transaction_id"] = value.hex().upper()
        elif field_tag == 0xA2:
            final_result = value

    if final_result is None:
        result["error_name"] = "no finalResult"
        return result

    choice_tag, choice_body, _ = _read_tlv(final_result, 0)
    if choice_tag == 0xA0:
        result["ok"] = True
        return result
    if choice_tag != 0xA1:
        result["error_name"] = f"unknown finalResult tag 0x{choice_tag:02X}"
        return result

    for field_tag, value, _ in _iter_tlvs(choice_body):
        if field_tag == 0x80 and value:
            code = int.from_bytes(value, 'big')
            result["bpp_command_id"] = code
            result["bpp_command"] = _BPP_COMMAND_NAMES.get(code, f"unknown({code})")
        elif field_tag == 0x81 and value:
            code = int.from_bytes(value, 'big')
            result["error_reason"] = code
            result["error_name"] = _PIR_ERROR_REASONS.get(code, f"unknown({code})")

    return result


def decode_notification_sequences(response: bytes) -> list:
    """解析 RetrieveNotificationsListResponse (BF2B)，提取所有通知的 seqNumber

    递归扫描 BF2F (notificationMetadata)，取其直接子字段 tag=0x80 且长度为 1/2 的值，
    保留卡返回的原始长度（部分卡用单字节 80 01 xx，部分用双字节 80 02 xx xx）。
    """
    sequences = []
    tag, body, _ = _read_tlv(response, 0)
    if tag != 0xBF2B:
        return sequences

    def scan(data: bytes):
        for field_tag, value, _ in _iter_tlvs(data):
            if field_tag == 0xBF2F:
                for meta_tag, meta_value, _ in _iter_tlvs(value):
                    if meta_tag == 0x80 and len(meta_value) in (1, 2):
                        sequences.append(meta_value.hex().upper())
            elif field_tag in (0xBF37, 0xBF27, 0xA0, 0x30, 0xBF2B):
                scan(value)
            elif field_tag in (0xE3, 0xE7):
                scan(value)

    scan(body)
    return sequences


def decode_remove_notification_result(response: bytes) -> int:
    """解析 RemoveNotificationResponse (BF30)，返回 removeResult（0 = ok）"""
    tag, body, _ = _read_tlv(response, 0)
    if tag != 0xBF30:
        return -1
    for field_tag, value, _ in _iter_tlvs(body):
        if field_tag == 0x80 and value:
            return int.from_bytes(value, 'big')
    return -1


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


# ========== BF57 AddInitialEim / BF51 EuiccPackage ==========

def _strip_outer_sequence(der: bytes) -> bytes:
    """去掉 DER SEQUENCE 的外层 tag+长度，返回内容"""
    if len(der) < 2 or der[0] != 0x30:
        return der
    pos = 1
    lb = der[pos]
    pos += 1
    if lb & 0x80:
        n = lb & 0x7F
        length = int.from_bytes(der[pos:pos + n], 'big')
        pos += n
    else:
        length = lb
    if pos + length != len(der):
        return der
    return der[pos:pos + length]


def extract_spki(cert_or_spki_der: bytes) -> bytes:
    """从 X.509 证书 DER 提取 SubjectPublicKeyInfo DER；传入已是 SPKI 时原样返回"""
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives import serialization

        cert = x509.load_der_x509_certificate(cert_or_spki_der, default_backend())
        return cert.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo
        )
    except Exception:
        return cert_or_spki_der


def encode_eim_configuration_data(
    eim_id: str,
    counter_value: int,
    eim_public_key_spki: bytes,
    eim_fqdn: str = "",
    eim_id_type: int = -1,
    euicc_ci_pk_id: bytes = b""
) -> bytes:
    """编码 EimConfigurationData

    EimConfigurationData ::= SEQUENCE {
        eimId            [0] UTF8String,
        eimFqdn          [1] UTF8String OPTIONAL,
        eimIdType        [2] INTEGER OPTIONAL,
        counterValue     [3] INTEGER,
        eimPublicKeyData [5] CHOICE { eimPublicKey [0] SubjectPublicKeyInfo },
        euiccCiPKId      [8] SubjectKeyIdentifier OPTIONAL
    }
    """
    content = _der_tlv(b'\x80', eim_id.encode('utf-8'))
    if eim_fqdn:
        content += _der_tlv(b'\x81', eim_fqdn.encode('utf-8'))
    if eim_id_type >= 0:
        content += _der_tlv(b'\x82', _der_int(eim_id_type))
    content += _der_tlv(b'\x83', _der_int(counter_value))
    if eim_public_key_spki:
        content += _der_tlv(b'\xa5', _der_tlv(b'\xa0', _strip_outer_sequence(eim_public_key_spki)))
    if euicc_ci_pk_id:
        content += _der_tlv(b'\x88', euicc_ci_pk_id)
    return _der_tlv(b'\x30', content)


def encode_bf57_add_initial_eim(
    eim_id: str,
    counter_value: int,
    eim_public_key_spki: bytes,
    eim_fqdn: str = "",
    eim_id_type: int = -1,
    euicc_ci_pk_id: bytes = b""
) -> bytes:
    """编码 AddInitialEimRequest (BF57)

    BF57 { [0] SEQUENCE OF EimConfigurationData }
    """
    ecd = encode_eim_configuration_data(
        eim_id, counter_value, eim_public_key_spki,
        eim_fqdn=eim_fqdn, eim_id_type=eim_id_type, euicc_ci_pk_id=euicc_ci_pk_id
    )
    return _der_tlv(b'\xbf\x57', _der_tlv(b'\xa0', ecd))


_ADD_INITIAL_EIM_ERROR_NAMES = {
    1: "insufficientMemory",
    2: "associatedEimAlreadyExists",
    3: "ciPKUnknown",
    5: "invalidAssociationToken",
    6: "counterValueOutOfRange",
    7: "commandError",
    127: "undefinedError",
}


def decode_add_initial_eim_response(response: bytes) -> Dict[str, Any]:
    """解析 AddInitialEimResponse (BF57)

    AddInitialEimResponse ::= [87] CHOICE {
        addInitialEimOk    [0] SEQUENCE OF ...   -- A0
        addInitialEimError [1] INTEGER           -- 81
    }

    Returns:
        {"ok", "error_code", "error_name", "association_token"}
    """
    result = {"ok": False, "error_code": None, "error_name": "", "association_token": None}
    tag, body, _ = _read_tlv(response, 0)
    if tag != 0xBF57:
        result["error_name"] = "not BF57"
        return result

    member_tag, member_body, _ = _read_tlv(body, 0)
    if member_tag == 0x81:
        code = int.from_bytes(member_body, 'big') if member_body else None
        result["error_code"] = code
        result["error_name"] = _ADD_INITIAL_EIM_ERROR_NAMES.get(code, f"unknown({code})")
        return result
    if member_tag != 0xA0:
        result["error_name"] = f"unknown member tag 0x{member_tag:02X}"
        return result

    result["ok"] = True
    for field_tag, value, _ in _iter_tlvs(member_body):
        if field_tag == 0x84 and value:
            result["association_token"] = int.from_bytes(value, 'big')
    return result


def decode_memory_reset_result(response: bytes):
    """解析 EuiccMemoryResetResponse (BF64)，返回 resetResult（0=ok, 1=nothingToDelete）"""
    tag, body, _ = _read_tlv(response, 0)
    if tag != 0xBF64:
        return None
    for field_tag, value, _ in _iter_tlvs(body):
        if field_tag == 0x80 and value:
            return int.from_bytes(value, 'big')
    return None


def encode_enable_profile(identifier: bytes, refresh_flag: bool = True, use_aid: bool = False) -> bytes:
    """编码 ES10c.EnableProfile (BF31)

    EnableProfileRequest ::= [49] SEQUENCE {
        profileIdentifier [0] CHOICE {         -- A0（CHOICE 需显式标记）
            isdpAid [15] OctetTo16,            -- 4F <16 字节 AID>
            iccid   [10] OctetTo16             -- 5A <10 字节 BCD ICCID>
        },
        refreshFlag       [1] BOOLEAN          -- 81 FF
    }

    Args:
        identifier: AID 字节或 BCD(半字节交换) ICCID 字节
        refresh_flag: 是否要求 REFRESH
        use_aid: True 用 isdpAid(4F)，False 用 iccid(5A)
    """
    inner = _der_tlv(b'\x4f' if use_aid else b'\x5a', identifier)
    identifier_field = _der_tlv(b'\xa0', inner)
    refresh = _der_tlv(b'\x81', b'\xff' if refresh_flag else b'\x00')
    return _der_tlv(b'\xbf\x31', identifier_field + refresh)


def encode_enable_psmo(iccid_bcd: bytes, rollback_flag: bool = False) -> bytes:
    """编码 enable PSMO: [3] SEQUENCE { 5A iccid, [0] rollbackFlag OPTIONAL }"""
    content = _der_tlv(b'\x5a', iccid_bcd)
    if rollback_flag:
        content += b'\x80\x00'
    return _der_tlv(b'\xa3', content)


def encode_psmo_list(*psmo: bytes) -> bytes:
    """编码 psmoList: [0] SEQUENCE OF Psmo"""
    return _der_tlv(b'\xa0', b''.join(psmo))


def encode_euicc_package_signed(
    eim_id: str,
    eid: bytes,
    counter_value: int,
    euicc_package: bytes
) -> bytes:
    """编码 EuiccPackageSigned

    SEQUENCE { 80 eimId, 5A eidValue, 81 counterValue, <euiccPackage> }
    """
    content = (
        _der_tlv(b'\x80', eim_id.encode('utf-8'))
        + _der_tlv(b'\x5a', eid)
        + _der_tlv(b'\x81', _der_int(counter_value))
        + euicc_package
    )
    return _der_tlv(b'\x30', content)


def encode_bf51_euicc_package_request(signed: bytes, eim_signature: bytes) -> bytes:
    """编码 EuiccPackageRequest (BF51): BF51 { euiccPackageSigned, 5F37 eimSignature }"""
    return _der_tlv(b'\xbf\x51', signed + _der_tlv(b'\x5f\x37', eim_signature))


def sign_euicc_package(signed: bytes, eim_private_key) -> bytes:
    """eIM 签名：对 euiccPackageSigned || 84 01 00 签名，返回裸 r||s"""
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec, utils

    to_sign = signed + b'\x84\x01\x00'
    der = eim_private_key.sign(to_sign, ec.ECDSA(hashes.SHA256()))
    r, s = utils.decode_dss_signature(der)
    return r.to_bytes(32, 'big') + s.to_bytes(32, 'big')


def decode_euicc_package_result(response: bytes) -> Dict[str, Any]:
    """解析 EuiccPackageResult (BF51 响应)

    成功: BF51 { A0 { 30 { 80 eimId, 81 counter, 83 eimTransactionId,
                           30 { 83 01 <enableResult> } } }, 5F37 }
    失败: BF51 { A1 { 30 { ... 02 <euiccPackageErrorCode> } , 5F37 } }

    Returns:
        {"ok", "eim_id", "enable_result", "error_code", "error_name"}
    """
    result = {"ok": False, "eim_id": "", "enable_result": None,
              "error_code": None, "error_name": ""}
    tag, body, _ = _read_tlv(response, 0)
    if tag != 0xBF51:
        return result

    member_tag, member_body, _ = _read_tlv(body, 0)
    if member_tag == 0xA1:
        # 错误分支：EuiccPackageErrorDataSigned 内含裸 INTEGER euiccPackageErrorCode
        code = None
        seq_tag, seq_body, _ = _read_tlv(member_body, 0)
        if seq_tag == 0x30:
            for field_tag, value, _ in _iter_tlvs(seq_body):
                if field_tag == 0x02 and value:
                    code = int.from_bytes(value, 'big')
        result["error_code"] = code
        result["error_name"] = _EUICC_PACKAGE_ERROR_NAMES.get(code, f"unknown({code})")
        return result

    if member_tag != 0xA0:
        result["error_name"] = f"unknown result tag 0x{member_tag:02X}"
        return result

    seq_tag, seq_body, _ = _read_tlv(member_body, 0)
    if seq_tag != 0x30:
        result["error_name"] = "no EuiccPackageResultData"
        return result

    for field_tag, value, _ in _iter_tlvs(seq_body):
        if field_tag == 0x80:
            try:
                result["eim_id"] = value.decode('utf-8')
            except Exception:
                result["eim_id"] = value.hex().upper()
        elif field_tag == 0x30:
            for inner_tag, inner_value, _ in _iter_tlvs(value):
                if inner_tag == 0x83 and inner_value:
                    result["enable_result"] = int.from_bytes(inner_value, 'big')

    result["ok"] = result["enable_result"] == 0
    if not result["ok"] and result["enable_result"] is not None:
        result["error_name"] = f"enableResult={result['enable_result']}"
    return result


_EUICC_PACKAGE_ERROR_NAMES = {
    3: "invalidEid",
    4: "replayError",
    6: "counterValueOutOfRange",
    15: "sizeOverflow",
    104: "ecallActive",
    127: "undefinedError",
}


def _der_int(value: int) -> bytes:
    """DER INTEGER 内容（最少字节，正数）"""
    if value == 0:
        return b'\x00'
    length = (value.bit_length() + 8) // 8
    return value.to_bytes(length, 'big')


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
        # SCP03t 是有状态的：87 → 88 → 86 共用同一个计数器/MCV 链
        self._scp03t_state = {'counter': 1, 'mcv': session_keys['mcv']}

        # 4. 构造 ConfigureISDP (87)
        configure_isdp = self._encode_configure_isdp(profile_package)
        first_87 = self._scp03t_protect(0x87, configure_isdp, session_keys)

        # 5. 构造 StoreMetadata (88)
        metadata = self._encode_store_metadata(
            iccid, service_provider_name, profile_name, profile_class
        )
        sequence_88 = self._scp03t_protect(0x88, metadata, session_keys)

        # 6. 构造 sequenceOf86（Profile 数据，每段最多 1007 字节明文）
        max_plaintext_segment = 1007
        sequence_86 = b""
        for offset in range(0, len(profile_package), max_plaintext_segment):
            segment = profile_package[offset:offset + max_plaintext_segment]
            sequence_86 += self._scp03t_protect(0x86, segment, session_keys)

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
        """派生 SCP03t 会话密钥 (SGP.22 Annex G / X9.63 KDF-SHA256)

        sharedInfo = keyType(0x88) || keyLength(0x10) || len(hostId) || hostId
                     || len(eid) || eid
        KDF 输出 48 字节: MCV(16) || S-ENC(16) || S-MAC(16)
        """
        key_type = 0x88
        key_length = 0x10
        shared_info = (
            bytes([key_type, key_length, len(host_id)]) + host_id
            + bytes([len(eid)]) + eid
        )

        kdf_output = b""
        counter = 1
        while len(kdf_output) < 48:
            digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
            digest.update(shared_secret)
            digest.update(counter.to_bytes(4, 'big'))
            digest.update(shared_info)
            kdf_output += digest.finalize()
            counter += 1

        return {
            'mcv': kdf_output[0:16],
            's_enc': kdf_output[16:32],
            's_mac': kdf_output[32:48],
        }

    def _encode_configure_isdp(self, profile_package: bytes) -> bytes:
        """编码 ConfigureISDPRequest (BF24)

        BF24 { B8 <dpProprietaryData> }，dpProprietaryData 取
        #SMDP_PROP_DATA 宏值 80 03 88 37 0A（与参考报告一致）。
        """
        dp_proprietary_data = bytes.fromhex("800388370A")
        body = _der_tlv(b'\xb8', dp_proprietary_data)
        return _der_tlv(b'\xbf\x24', body)

    def _encode_store_metadata(
        self,
        iccid: str,
        service_provider_name: str,
        profile_name: str,
        profile_class: int
    ) -> bytes:
        """编码 StoreMetadataRequest (BF25)

        BF25 { 5A iccid, 91 serviceProviderName, 92 profileName, 95 profileClass }
        ICCID 为 BCD（半字节交换）编码。
        """
        digits = iccid.replace(" ", "").upper().rstrip("F")
        if len(digits) % 2:
            digits += "F"
        iccid_bytes = bytearray()
        for i in range(0, len(digits), 2):
            low = int(digits[i], 16)
            high = int(digits[i + 1], 16)
            iccid_bytes.append((high << 4) | low)

        content = (
            _der_tlv(b'\x5a', bytes(iccid_bytes))
            + _der_tlv(b'\x91', service_provider_name.encode('utf-8'))
            + _der_tlv(b'\x92', profile_name.encode('utf-8'))
            + _der_tlv(b'\x95', bytes([profile_class]))
        )
        return _der_tlv(b'\xbf\x25', content)

    def _scp03t_protect(self, tag: int, data: bytes, keys: Dict[str, bytes]) -> bytes:
        """SCP03t 保护一个 BPP 数据块（86/87/88）

        - 计数器从 1 递增，ICV = AES-ECB(S-ENC, counter_block)
        - tag 0x88（元数据）不加密，其余用 AES-CBC + ISO7816 填充加密
        - C-MAC = CMAC(S-MAC, MCV || 头部 || 受保护数据)，MCV 用完整 16 字节 MAC 链式更新
        - 输出 = 头部 || 加密数据 || MAC 前 8 字节
        """
        state = self._scp03t_state
        counter = state['counter']
        state['counter'] = counter + 1

        counter_block = bytes(12) + counter.to_bytes(4, 'big')
        icv = _aes_ecb_encrypt(keys['s_enc'], counter_block)

        if tag == 0x88:
            protected_data = data
        else:
            protected_data = _aes_cbc_encrypt(keys['s_enc'], _iso7816_pad(data), icv)

        header = _tlv_header(tag, len(protected_data) + 8)
        mac_input = state['mcv'] + header + protected_data
        full_mac = _aes_cmac(keys['s_mac'], mac_input)
        state['mcv'] = full_mac

        return header + protected_data + full_mac[:8]
    
    def _encode_bf23(
        self,
        transaction_id: str,
        smdp_otpk: bytes,
        euicc_otpk: bytes
    ) -> bytes:
        """编码 BF23 (initialiseSecureChannelRequest)

        结构 (SGP.22 5.7.5):
        BF23 {
          [2] INTEGER 1                       remoteOpId = installBoundProfilePackage
          [0] OCTET STRING                    transactionId
          [6] SEQUENCE {                      controlInitializationData
                [0] keyType, [1] keyLength(0x10), [4] hostId }
          5F49 OCTET STRING                   smdpOtpk
          5F37 OCTET STRING                   smdpSignature
        }
        smdpSignature 覆盖 remoteOpId || transactionId || controlInitializationData
                               || 5F49(smdpOtpk) || 5F49(euiccOtpk)
        """
        remote_op = _der_tlv(b'\x82', b'\x01')
        tid_field = _der_tlv(b'\x80', bytes.fromhex(transaction_id))

        crt_content = (
            _der_tlv(b'\x80', b'\x88')   # keyType = AES-128
            + _der_tlv(b'\x81', b'\x10')  # keyLength = 128 bit
            + _der_tlv(b'\x84', self.TEST_HOST_ID)
        )
        crt_field = _der_tlv(b'\xa6', crt_content)

        smdp_public = _der_tlv(b'\x5f\x49', smdp_otpk)
        euicc_public = _der_tlv(b'\x5f\x49', euicc_otpk)

        signed_data = remote_op + tid_field + crt_field + smdp_public + euicc_public
        raw_signature = self._der_signature_to_raw(signed_data)
        signature = _der_tlv(b'\x5f\x37', raw_signature)

        content = remote_op + tid_field + crt_field + smdp_public + signature
        return _der_tlv(b'\xbf\x23', content)

    def _der_signature_to_raw(self, signed_data: bytes) -> bytes:
        """用 DP+ Profile Binding 私钥签名，返回 64 字节裸 r||s"""
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import ec, utils

        der = self.dp_pb_private_key.sign(signed_data, ec.ECDSA(hashes.SHA256()))
        r, s = utils.decode_dss_signature(der)
        return r.to_bytes(32, 'big') + s.to_bytes(32, 'big')
    
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
    dp_pb_cert_der: bytes,
    service_provider_name: str = "Test Operator",
    profile_class: int = 2
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
        service_provider_name: 服务提供商名称（写入 StoreMetadata）
        profile_class: Profile 类别（写入 StoreMetadata）

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
        profile_name=profile_name,
        service_provider_name=service_provider_name,
        profile_class=profile_class
    )
