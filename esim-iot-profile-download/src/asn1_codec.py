"""ASN.1 DER 编解码模块 - 基于 pyasn1"""

from typing import Optional, List, Dict, Any, Tuple
from pyasn1.type import univ, namedtype, tag, constraint, char
from pyasn1.codec.der import encoder, decoder
from pyasn1.error import PyAsn1Error


class Asn1CodecError(Exception):
    """ASN.1 编解码异常"""
    pass


# ========== 基础类型定义 ==========

class OCTET_STRING(univ.OctetString):
    """扩展的 OCTET STRING"""
    pass


class UTF8String(char.UTF8String):
    """UTF8String"""
    pass


class BOOLEAN(univ.Boolean):
    """BOOLEAN"""
    pass


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
    """
    if len(tac) != 4:
        raise Asn1CodecError("TAC must be 4 bytes")
    
    # 解析 serverSigned1 和 serverCertificate
    try:
        ss1, _ = decoder.decode(server_signed1)
    except PyAsn1Error as e:
        raise Asn1CodecError(f"Cannot decode serverSigned1: {e}")
    
    try:
        cert, _ = decoder.decode(server_certificate)
    except PyAsn1Error as e:
        raise Asn1CodecError(f"Cannot decode serverCertificate: {e}")
    
    # DeviceCapabilities
    capabilities = univ.Sequence(
        componentType=namedtype.NamedTypes(
            namedtype.NamedType('cap1', univ.OctetString()),
            namedtype.NamedType('cap2', univ.OctetString()),
            namedtype.NamedType('cap3', univ.OctetString()),
            namedtype.NamedType('cap4', univ.OctetString()),
            namedtype.NamedType('cap5', univ.OctetString()),
            namedtype.NamedType('cap6', univ.OctetString()),
            namedtype.NamedType('cap7', univ.OctetString()),
            namedtype.NamedType('cap8', univ.OctetString()),
        )
    )
    capabilities.setComponentByPosition(0, univ.OctetString(hexValue='050000'))
    capabilities.setComponentByPosition(1, univ.OctetString(hexValue='080000'))
    capabilities.setComponentByPosition(2, univ.OctetString(hexValue='010000'))
    capabilities.setComponentByPosition(3, univ.OctetString(hexValue='010000'))
    capabilities.setComponentByPosition(4, univ.OctetString(hexValue='020000'))
    capabilities.setComponentByPosition(5, univ.OctetString(hexValue='020000'))
    capabilities.setComponentByPosition(6, univ.OctetString(hexValue='090000'))
    capabilities.setComponentByPosition(7, univ.OctetString(hexValue='020100'))
    
    # DeviceInfo
    device_info = univ.Sequence(
        componentType=namedtype.NamedTypes(
            namedtype.NamedType('tac', univ.OctetString()),
            namedtype.NamedType('capabilities', capabilities),
            namedtype.NamedType('deviceIdentifier', univ.OctetString()),
        )
    )
    device_info.setComponentByPosition(0, univ.OctetString(tac))
    device_info.setComponentByPosition(1, capabilities)
    device_info.setComponentByPosition(2, univ.OctetString(hexValue='000000000011111111'))
    
    # ContextParams [0]
    context_params = univ.Sequence(
        componentType=namedtype.NamedTypes(
            namedtype.OptionalNamedType('matchingId', UTF8String()),
            namedtype.NamedType('deviceInfo', device_info),
        )
    ).subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 0))
    
    if matching_id:
        context_params.setComponentByPosition(0, UTF8String(matching_id))
    context_params.setComponentByPosition(1, device_info)
    
    # BF38 主结构 [56]
    bf38 = univ.Sequence(
        componentType=namedtype.NamedTypes(
            namedtype.NamedType('serverSigned1', ss1),
            namedtype.NamedType('serverSignature1', univ.OctetString()),
            namedtype.NamedType('euiccCiPkIdToBeUsed', univ.OctetString()),
            namedtype.NamedType('serverCertificate', cert),
            namedtype.NamedType('contextParams', context_params),
        )
    ).subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 56))
    
    bf38.setComponentByPosition(0, ss1)
    bf38.setComponentByPosition(1, univ.OctetString(server_signature1))
    bf38.setComponentByPosition(2, univ.OctetString(euicc_ci_pk_id))
    bf38.setComponentByPosition(3, cert)
    bf38.setComponentByPosition(4, context_params)
    
    try:
        return encoder.encode(bf38)
    except PyAsn1Error as e:
        raise Asn1CodecError(f"Cannot encode BF38: {e}")


# ========== SmdpSigned2 ==========

def encode_smdp_signed2(
    transaction_id: str,
    confirmation_code_required: bool = False,
    bpp_euicc_otpk: Optional[bytes] = None
) -> bytes:
    """
    编码 SmdpSigned2
    
    SmdpSigned2 ::= SEQUENCE {
        transactionId        OCTET STRING,
        ccRequired           BOOLEAN DEFAULT FALSE,
        bppEuiccOtpk         [73] OCTET STRING OPTIONAL
    }
    """
    tid_bytes = bytes.fromhex(transaction_id.replace(" ", ""))
    
    if bpp_euicc_otpk:
        # 带 otpk
        otpk_field = univ.OctetString(bpp_euicc_otpk).subtype(
            implicitTag=tag.Tag(tag.tagClassApplication, tag.tagFormatSimple, 73)
        )
        smdp_signed2 = univ.Sequence(
            componentType=namedtype.NamedTypes(
                namedtype.NamedType('transactionId', univ.OctetString()),
                namedtype.DefaultedNamedType('ccRequired', BOOLEAN(False)),
                namedtype.OptionalNamedType('bppEuiccOtpk', otpk_field),
            )
        )
        smdp_signed2.setComponentByPosition(0, univ.OctetString(tid_bytes))
        smdp_signed2.setComponentByPosition(1, BOOLEAN(confirmation_code_required))
        smdp_signed2.setComponentByPosition(2, otpk_field)
    else:
        smdp_signed2 = univ.Sequence(
            componentType=namedtype.NamedTypes(
                namedtype.NamedType('transactionId', univ.OctetString()),
                namedtype.DefaultedNamedType('ccRequired', BOOLEAN(False)),
            )
        )
        smdp_signed2.setComponentByPosition(0, univ.OctetString(tid_bytes))
        smdp_signed2.setComponentByPosition(1, BOOLEAN(confirmation_code_required))
    
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
    try:
        ss2, _ = decoder.decode(smdp_signed2)
    except PyAsn1Error as e:
        raise Asn1CodecError(f"Cannot decode smdpSigned2: {e}")
    
    try:
        cert, _ = decoder.decode(smdp_certificate)
    except PyAsn1Error as e:
        raise Asn1CodecError(f"Cannot decode smdpCertificate: {e}")
    
    # 构建字段
    fields = [
        ('smdpSigned2', ss2),
        ('smdpSignature2', univ.OctetString(smdp_signature2).subtype(
            implicitTag=tag.Tag(tag.tagClassApplication, tag.tagFormatSimple, 55)
        )),
    ]
    
    if hash_cc:
        fields.append(('hashCc', univ.OctetString(hash_cc)))
    
    fields.append(('smdpCertificate', cert))
    
    bf21 = univ.Sequence(
        componentType=namedtype.NamedTypes(
            *(namedtype.NamedType(name, comp) for name, comp in fields)
        )
    ).subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 33))
    
    for i, (name, comp) in enumerate(fields):
        bf21.setComponentByPosition(i, comp)
    
    try:
        return encoder.encode(bf21)
    except PyAsn1Error as e:
        raise Asn1CodecError(f"Cannot encode BF21: {e}")


# ========== PrepareDownloadResponse 解码 ==========

def decode_prepare_download_response(response: bytes) -> Dict[str, Any]:
    """
    解码 PrepareDownloadResponse (BF21 响应)
    
    严格按照 Java版本 Sgp22ProfileDownloadCodec.decodePrepareDownloadResponse 实现
    
    格式:
        BF21 ::= [33] IMPLICIT SEQUENCE {
            euiccSigned2      SEQUENCE,
            euiccSignature2   [55] OCTET STRING
        }
    
    euiccSigned2 格式:
        SEQUENCE {
            transactionId  [0] OCTET STRING,
            euiccOtpk      [5F49] OCTET STRING (Application-Specific tag 73)
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
    
    # A0 包含: SEQUENCE { euiccSigned2 }, [5F37] euiccSignature2
    a0_end = offset + a0_length
    
    # 解析 euiccSigned2 (SEQUENCE)
    if offset >= len(response):
        raise Asn1CodecError("Response too short for euiccSigned2 SEQUENCE tag")
    if response[offset] != 0x30:
        raise Asn1CodecError(f"Expected euiccSigned2 SEQUENCE tag (0x30), got {response[offset]:02X}")
    offset += 1
    
    # 解析 euiccSigned2 length
    euicc_signed2_len_byte = response[offset]
    offset += 1
    if euicc_signed2_len_byte & 0x80:
        num_bytes = euicc_signed2_len_byte & 0x7F
        euicc_signed2_len = 0
        for i in range(num_bytes):
            euicc_signed2_len = (euicc_signed2_len << 8) | response[offset]
            offset += 1
    else:
        euicc_signed2_len = euicc_signed2_len_byte
    
    euicc_signed2_data = response[offset:offset + euicc_signed2_len]
    offset += euicc_signed2_len
    
    # 解析 euiccSigned2 内部结构
    seq_offset = 0
    if euicc_signed2_data[seq_offset] == 0x30:
        seq_offset += 1
        seq_len_byte = euicc_signed2_data[seq_offset]
        seq_offset += 1
        if seq_len_byte & 0x80:
            num_bytes = seq_len_byte & 0x7F
            for i in range(num_bytes):
                seq_offset += 1
    
    # [0] transactionId
    if euicc_signed2_data[seq_offset] == 0x80:
        seq_offset += 1
        tid_len = euicc_signed2_data[seq_offset]
        seq_offset += 1
        result['transaction_id'] = euicc_signed2_data[seq_offset:seq_offset + tid_len].hex().upper()
        seq_offset += tid_len
        
        # [5F49] euiccOtpk (Application-Specific tag 73 = 0x5F49)
        if seq_offset < len(euicc_signed2_data):
            if euicc_signed2_data[seq_offset] == 0x5F and seq_offset + 1 < len(euicc_signed2_data):
                if euicc_signed2_data[seq_offset + 1] == 0x49:
                    seq_offset += 2
                    otpk_len = euicc_signed2_data[seq_offset]
                    seq_offset += 1
                    result['euicc_otpk'] = euicc_signed2_data[seq_offset:seq_offset + otpk_len]
    
    # 解析 euiccSignature2 (tag 5F37 = Application-Specific [55])
    if offset < a0_end and response[offset] == 0x5F:
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

def decode_bf37_profile_installation_result(response: bytes) -> Optional[str]:
    """
    解码 ProfileInstallationResult (BF37)，提取 ISD-P AID
    """
    try:
        pdu, _ = decoder.decode(response)
    except PyAsn1Error:
        return None
    
    # 查找 profileIdentifier [2] A2
    try:
        for i in range(pdu.getSize()):
            component = pdu.getComponentByPosition(i)
            if component is None:
                continue
            
            # 检查是否是 A2 tag (profileIdentifier)
            tag_set = component.getTagSet()
            for t in tag_set:
                if t.getTagClass() == tag.tagClassContext and t.getTagNumber() == 2:
                    # 解析 AID (4F)
                    if hasattr(component, '__iter__'):
                        for field in component:
                            if hasattr(field, '__len__') and len(bytes(field)) == 16:
                                return bytes(field).hex().upper()
    except Exception:
        pass
    
    return None


# ========== StoreData 编码 ==========

def encode_store_data(block_number: int, is_last: bool, data: bytes) -> bytes:
    """
    编码 StoreData 命令数据
    """
    # StoreData 数据格式: [81] OCTET STRING (实际数据)
    try:
        data_field = univ.OctetString(data).subtype(
            implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 1)
        )
        return encoder.encode(data_field)
    except PyAsn1Error as e:
        raise Asn1CodecError(f"Cannot encode StoreData: {e}")
