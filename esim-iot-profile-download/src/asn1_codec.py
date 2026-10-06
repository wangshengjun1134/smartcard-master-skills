"""ASN.1 DER 编解码模块 - 基于 pyasn1"""

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
    if n < 128:
        return bytes([n])
    if n < 256:
        return bytes([0x81, n])
    if n < 65536:
        return bytes([0x82, (n >> 8) & 0xFF, n & 0xFF])
    raise Asn1CodecError(f"Length too large: {n}")


def _der_tlv(tag: bytes, value: bytes) -> bytes:
    return tag + _der_len(len(value)) + value


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

    严格对齐 Java Sgp22ProfileDownloadCodec.encodeAuthenticateServerRequest：
    - ServerSigned1 使用 IMPLICIT 上下文标签 [0][1][3][4]（由调用方生成）
    - serverSignature1 使用 APPLICATION 55 → 5F 37
    - euiccCiPkIdToBeUsed 使用 OCTET STRING → 04
    - serverCertificate 原样嵌入
    - ctxParams1 = A0 { [0] matchingId(UTF8String), A1 { [0] tac, A1 {caps}, [2] deviceIdentifier } }
    最终 BF38 = [56] IMPLICIT SEQUENCE → BF 38
    """
    if len(tac) != 4:
        raise Asn1CodecError("TAC must be 4 bytes")

    # deviceCapabilities: 8 个 [n] OCTET STRING（SGP.23 v1.16 固定向量）
    caps = [
        b'\x05\x00\x00', b'\x08\x00\x00', b'\x01\x00\x00', b'\x01\x00\x00',
        b'\x02\x00\x00', b'\x02\x00\x00', b'\x09\x00\x00', b'\x02\x01\x00',
    ]
    caps_seq = b''.join(_der_tlv(bytes([0x80 | i]), c) for i, c in enumerate(caps))

    # deviceInfo 内容: [0] tac, [1] deviceCapabilities, [2] deviceIdentifier
    device = (
        _der_tlv(b'\x80', tac)
        + _der_tlv(b'\xa1', caps_seq)
        + _der_tlv(b'\x82', bytes([0, 0, 0, 0, 0x11, 0x11, 0x11, 0x11]))
    )

    # context（ctxParams1 内容）: [0] matchingId, [1] deviceInfo
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
    # 严格按照 Java版本格式编码
    # Java: new DERTaggedObject(false, 0, new DEROctetString(tid_bytes))
    # transaction_id 是十六进制字符串，需要转换为字节数组
    tid_bytes = bytes.fromhex(transaction_id.replace(" ", ""))
    
    tid_field = univ.OctetString(tid_bytes).subtype(
        implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0)
    )

    # Java: confirmationCodeRequired ? ASN1Boolean.TRUE : ASN1Boolean.FALSE
    # 始终包含 ccRequired 字段（即使为 FALSE）
    cc_field = BOOLEAN(confirmation_code_required)

    if bpp_euicc_otpk:
        # 带 otpk
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

    严格按照 Java版本 Sgp22ProfileDownloadCodec.encodePrepareDownloadRequest 实现
    
    Java版本:
        ASN1EncodableVector fields = new ASN1EncodableVector();
        fields.add(readOne(smdpSigned2, "SmdpSigned2"));  // 直接添加 DER 字节
        fields.add(new DERApplicationSpecific(false, 55, new DEROctetString(smdpSignature2)));  // [55]
        if (hashCc != null && hashCc.length > 0) {
            fields.add(new DEROctetString(hashCc));  // OCTET STRING
        }
        fields.add(readOne(smdpCertificate, "smdpCertificate"));  // 直接添加 DER 字节
        return new DERTaggedObject(false, 33, new DERSequence(fields)).getEncoded("DER");
    """
    try:
        # 解析 smdp_certificate
        cert, _ = decoder.decode(smdp_certificate)
        cert_der = encoder.encode(cert)
    except PyAsn1Error as e:
        raise Asn1CodecError(f"Cannot decode smdpCertificate: {e}")

    # 编码 smdpSignature2 [55]
    # Java: new DERApplicationSpecific(false, 55, new DEROctetString(smdpSignature2))
    smdp_sig2_field = univ.OctetString(smdp_signature2).subtype(
        implicitTag=tag.Tag(tag.tagClassApplication, tag.tagFormatSimple, 55)
    )
    smdp_sig2_der = encoder.encode(smdp_sig2_field)

    # BF21 是 IMPLICIT 标签：[33] 已替换 SEQUENCE 标签 0x30，
    # 内容直接是各字段，不能再包一层 SEQUENCE（否则 eUICC 返回 0x7F "参数错误"）。
    # Java: new DERTaggedObject(false, 33, new DERSequence(fields))
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
    
    严格按照 Java版本 Sgp22ProfileDownloadCodec.decodePrepareDownloadResponse 实现
    
    格式:
        BF21 ::= [33] IMPLICIT SEQUENCE {
            euiccSigned2      SEQUENCE {
                transactionId  [0] OCTET STRING,
                euiccOtpk      [5F49] OCTET STRING
            },
            euiccSignature2   [55] OCTET STRING
        }
    """
    if len(response) < 4:
        raise Asn1CodecError("Response too short")
    
    result = {}
    offset = 0
    
    # 解析 BF21 tag
    if response[offset] == 0xBF and offset + 1 < len(response) and response[offset + 1] == 0x21:
        offset += 2
    elif response[offset] == 0xBF:
        offset += 1
    else:
        raise Asn1CodecError(f"Expected BF21 tag, got {response[:min(2, len(response))].hex().upper()}")
    
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
    
    # 解析 A0 tag (context-specific [0])
    # 某些卡实现使用 A1 而不是 A0
    if offset >= len(response):
        raise Asn1CodecError("Response too short for A0 tag")
    if response[offset] not in (0xA0, 0xA1):
        raise Asn1CodecError(f"Expected A0 or A1 tag, got {response[offset]:02X}")
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
    
    # 解析 A0 内部: SEQUENCE { euiccSigned2, euiccSignature2 }
    if offset >= len(response) or response[offset] != 0x30:
        raise Asn1CodecError(f"Expected SEQUENCE tag (0x30), got {response[offset]:02X}")
    offset += 1
    
    # 解析 SEQUENCE length
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
    
    # 解析 A0 内部: SEQUENCE { [0] transactionId, [5F49] euiccOtpk }
    # 注意：euiccSigned2 不是一个单独的 tag，而是 A0 内部的 SEQUENCE 直接包含 transactionId 和 euiccOtpk
    
    # [0] transactionId
    if offset < seq_end and response[offset] == 0x80:
        offset += 1
        tid_len = response[offset]
        offset += 1
        result['transaction_id'] = response[offset:offset + tid_len].hex().upper()
        offset += tid_len
    
    # [5F49] euiccOtpk (Application-Specific tag 73 = 0x5F49)
    if offset < seq_end and response[offset] == 0x5F and offset + 1 < len(response) and response[offset + 1] == 0x49:
        offset += 2
        otpk_len = response[offset]
        offset += 1
        result['euicc_otpk'] = response[offset:offset + otpk_len]
        offset += otpk_len
    
    # [55] euiccSignature2 (Application-Specific tag 55 = 0x5F37)
    # 注意：euiccSignature2 在 SEQUENCE 之外，所以在 seq_end 之后
    if offset < len(response) and response[offset] == 0x5F:
        if offset + 1 < len(response) and response[offset + 1] == 0x37:
            offset += 2
            # 解析 length
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


# ========== EuiccInfo1 编码/解码 ==========

def encode_euicc_info1(
    svn: str,
    verification_ci_pk_ids: List[bytes],
    signing_ci_pk_ids: List[bytes]
) -> bytes:
    """
    编码 EuiccInfo1 (BF20)
    """
    try:
        # version [2]
        version_field = univ.OctetString(svn.encode('utf-8')).subtype(
            implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 2)
        )
        
        # verificationCiPkIds [9]
        ver_ids = univ.SetOf(componentType=univ.OctetString()).subtype(
            implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 9)
        )
        for i, pk_id in enumerate(verification_ci_pk_ids):
            ver_ids.setComponentByPosition(i, univ.OctetString(pk_id))
        
        # signingCiPkIds [10]
        sign_ids = univ.SetOf(componentType=univ.OctetString()).subtype(
            implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 10)
        )
        for i, pk_id in enumerate(signing_ci_pk_ids):
            sign_ids.setComponentByPosition(i, univ.OctetString(pk_id))
        
        euicc_info1 = univ.Sequence(
            componentType=namedtype.NamedTypes(
                namedtype.NamedType('version', version_field),
                namedtype.NamedType('verificationCiPkIds', ver_ids),
                namedtype.NamedType('signingCiPkIds', sign_ids),
            )
        ).subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 32))
        
        euicc_info1.setComponentByPosition(0, version_field)
        euicc_info1.setComponentByPosition(1, ver_ids)
        euicc_info1.setComponentByPosition(2, sign_ids)
        
        return encoder.encode(euicc_info1)
    except PyAsn1Error as e:
        raise Asn1CodecError(f"Cannot encode EuiccInfo1: {e}")


def decode_euicc_info1(response: bytes) -> Dict[str, Any]:
    """
    解码 EuiccInfo1 (BF20 响应)
    格式: BF20 <len> [2] <ver> [9] <ver_ids> [10] <sign_ids>
    """
    result = {}
    if len(response) < 4:
        raise Asn1CodecError("Response too short")
    
    # 跳过 BF20 tag 和 length
    offset = 2
    data = response[offset:]
    
    # 解析 [2] version
    if data[0] == 0x82:
        offset = 1
        ver_len = data[offset]
        offset += 1
        result['svn'] = data[offset:offset + ver_len].decode('utf-8')
        offset += ver_len
    else:
        # 如果格式不对，尝试跳过
        offset = 1
        while offset < len(data) and data[offset] != 0x89 and data[offset] != 0x8A:
            offset += 1
    
    # 解析 [9] verificationCiPkIds
    if offset < len(data) and data[offset] == 0x89:
        offset += 1
        ver_len = data[offset]
        offset += 1
        ver_data = data[offset:offset + ver_len]
        result['verification_ci_pk_ids'] = _parse_octet_string_set(ver_data)
        offset += ver_len
    
    # 解析 [10] signingCiPkIds
    if offset < len(data) and data[offset] == 0x8A:
        offset += 1
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
        tag = data[offset]
        offset += 1
        if tag == 0x04:  # OCTET STRING
            length = data[offset]
            offset += 1
            result.append(data[offset:offset + length])
            offset += length
        else:
            # 跳过未知 tag
            if offset < len(data):
                length = data[offset]
                offset += 1 + length
    return result


# ========== BF2E Challenge 解码 ==========

def decode_bf2e_challenge(response: bytes) -> bytes:
    """
    解码 GetEuiccChallenge 响应，提取 16 字节 challenge
    格式: BF2E <len> <80 <16> <challenge>
    """
    if len(response) < 6:
        raise Asn1CodecError("Response too short")
    
    # 跳过 BF2E tag (2 bytes) 和 length (1 byte)
    offset = 3
    # response[offset] is the inner tag (0x80)
    if response[offset] == 0x80:
        offset += 1
        length = response[offset]
        offset += 1
        if length == 16 and len(response) >= offset + 16:
            return response[offset:offset + 16]
    
    raise Asn1CodecError("BF2E response has no 16-byte challenge")


# ========== BF37 ProfileInstallationResult 解码 ==========

