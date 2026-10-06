"""SGP.32 eUICC 包 / eIM 包编解码（间接模式激活）

移植自 Java `com.iot.sgp.sgp32.Sgp32EuiccPackageCodec` 的必要子集：
  - AddInitialEimRequest (BF57) / EimConfigurationData
  - PsmoList / enable PSMO（configureImmediateEnable）
  - EuiccPackageRequest (BF51) + eimSignature(5F37)
  - AddInitialEimResponse / EuiccPackageResult(enableResult) 校验
"""

from typing import List, Optional

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePrivateKey

from .crypto_provider import sign_ecdsa_p256, verify_ecdsa_p256


class Sgp32CodecError(Exception):
    """SGP.32 eIM 包编解码异常"""
    pass


# ========== BER-TLV 基础 ==========

def _len(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    if n <= 0xFF:
        return bytes([0x81, n])
    return bytes([0x82, (n >> 8) & 0xFF, n & 0xFF])


def _tlv(tag: bytes, value: bytes) -> bytes:
    """tag 已按字节给出（如 b'\\x80'、b'\\xbf\\x57'、b'\\x5f\\x37'）。"""
    return tag + _len(len(value)) + value


def _seq(value: bytes) -> bytes:
    return _tlv(b'\x30', value)


def _int_content(value: int) -> bytes:
    """DER INTEGER 最小内容（对齐 Java longToBytes）。"""
    if value < 0:
        raise Sgp32CodecError("negative INTEGER not supported")
    if value < 0x80:
        return bytes([value])
    if value < 0x8000:
        return bytes([(value >> 8) & 0xFF, value & 0xFF])
    length = (value.bit_length() + 7) // 8
    return value.to_bytes(length, 'big')


def _read_tag(data: bytes, pos: int):
    if pos >= len(data):
        raise Sgp32CodecError("BER-TLV truncated (tag)")
    first = data[pos]
    pos += 1
    tag = first
    if (first & 0x1F) == 0x1F:
        if pos >= len(data):
            raise Sgp32CodecError("BER-TLV truncated (multi-byte tag)")
        tag = (tag << 8) | data[pos]
        pos += 1
    return tag, pos


def _read_length(data: bytes, pos: int):
    if pos >= len(data):
        raise Sgp32CodecError("BER-TLV truncated (length)")
    first = data[pos]
    pos += 1
    if (first & 0x80) == 0:
        return first, pos
    count = first & 0x7F
    if count == 0 or count > 2:
        raise Sgp32CodecError("unsupported BER-TLV length form")
    length = 0
    for _ in range(count):
        if pos >= len(data):
            raise Sgp32CodecError("BER-TLV truncated (long-form length)")
        length = (length << 8) | data[pos]
        pos += 1
    return length, pos


def _read_int(data: bytes, pos: int, length: int) -> int:
    if pos + length > len(data):
        raise Sgp32CodecError("BER-TLV truncated (INTEGER value)")
    value = 0
    for i in range(length):
        value = (value << 8) | data[pos + i]
    return value


def _strip_outer_sequence(der: bytes) -> bytes:
    """去掉 DER SEQUENCE 外层 tag+长度，返回内容。"""
    if not der or len(der) < 2 or der[0] != 0x30:
        return der
    pos = 1
    length = der[pos]
    pos += 1
    if length & 0x80:
        num = length & 0x7F
        length = 0
        for i in range(num):
            length = (length << 8) | der[pos]
            pos += 1
    if pos + length != len(der):
        return der
    return der[pos:pos + length]


def encode_eim_configuration_data(eim_id: str, counter_value: int, eim_cert_der: bytes) -> bytes:
    """EimConfigurationData（eimId + counterValue + eimPublicKeyData）

    AUTOMATIC TAGS：eimId → 80（IMPLICIT primitive），counterValue → 83，
    eimPublicKeyData [5] 包所选 CHOICE 分支（此处放完整证书 DER）→ A5。

    实测对齐 Java 参考脚本（IOT_PERF_TEST_Install_Enable_Profile）发出的 BF57 报文：
    A5 内直接是 CERT_EIM 的完整 X.509 DER，而不是 SPKI。
    """
    body = b''
    body += _tlv(b'\x80', eim_id.encode('utf-8'))
    body += _tlv(b'\x83', _int_content(counter_value))
    if eim_cert_der:
        body += _tlv(b'\xa5', eim_cert_der)
    return _seq(body)


def encode_add_initial_eim_request(*eim_configuration_data_list: bytes) -> bytes:
    """AddInitialEimRequest (BF57)：A0 { EimConfigurationData... }"""
    list_body = b''.join(ecd for ecd in eim_configuration_data_list if ecd)
    return _tlv(b'\xbf\x57', _tlv(b'\xa0', list_body))


def verify_add_initial_eim_ok(response: bytes, allow_already_exists: bool = True) -> bool:
    """校验 AddInitialEimResponse：addInitialEimOk(A0) 或（可选放行）alreadyExists(2)。

    :return True=本次配置成功；False=已存在且被放行
    """
    tag, pos = _read_tag(response, 0)
    if tag != 0xBF57:
        raise Sgp32CodecError("Not a BF57 AddInitialEimResponse")
    outer_len, pos = _read_length(response, pos)
    content_end = pos + outer_len
    member_tag, pos = _read_tag(response, pos)
    if member_tag == 0x81:
        err_len, pos = _read_length(response, pos)
        code = _read_int(response, pos, err_len)
        if allow_already_exists and code == 2:
            return False
        raise Sgp32CodecError(f"AddInitialEim failed, addInitialEimError={code}")
    if member_tag != 0xA0:
        raise Sgp32CodecError(f"Unexpected AddInitialEimResponse member tag 0x{member_tag:04X}")
    if pos > content_end:
        raise Sgp32CodecError("AddInitialEimResponse length overflow")
    return True


# ========== Psmo / LoadEuiccPackage (BF51) ==========

def encode_enable_psmo(iccid_bcd: bytes, rollback_flag: bool = False) -> bytes:
    """enable PSMO：A3 { 5A iccid [80 rollbackFlag] }"""
    body = _tlv(b'\x5a', iccid_bcd)
    if rollback_flag:
        body += _tlv(b'\x80', b'')
    return _tlv(b'\xa3', body)


def encode_psmo_list(*psmo_der: bytes) -> bytes:
    """psmoList：A0 { Psmo... }"""
    return _tlv(b'\xa0', b''.join(psmo_der))


def encode_euicc_package_signed(eim_id: str, eid_value: bytes, counter_value: int,
                                euicc_package_der: Optional[bytes] = None) -> bytes:
    """EuiccPackageSigned：SEQUENCE { 80 eimId, 5A eidValue, 81 counterValue, <psmoList> }"""
    body = b''
    body += _tlv(b'\x80', eim_id.encode('utf-8'))
    body += _tlv(b'\x5a', eid_value)
    body += _tlv(b'\x81', _int_content(counter_value))
    body += euicc_package_der if euicc_package_der else b'\xa0\x00'
    return _seq(body)


def sign_euicc_package(euicc_package_signed: bytes, eim_private_key: EllipticCurvePrivateKey) -> bytes:
    """eimSignature = ECDSA(euiccPackageSigned ‖ 84 01 00)"""
    return sign_ecdsa_p256(euicc_package_signed + b'\x84\x01\x00', eim_private_key)


def encode_euicc_package_request(euicc_package_signed: bytes, eim_signature: bytes) -> bytes:
    """EuiccPackageRequest (BF51)：{ euiccPackageSigned, 5F37 eimSignature }"""
    return _tlv(b'\xbf\x51', euicc_package_signed + _tlv(b'\x5f\x37', eim_signature))


def decode_euicc_package_request(request: bytes):
    """解析 BF51 → (euiccPackageSigned, eimSignature)"""
    if len(request) < 4 or request[0] != 0xBF or request[1] != 0x51:
        raise Sgp32CodecError("Not a BF51 EuiccPackageRequest")
    pos = 2
    _outer_len, pos = _read_length(request, pos)
    signed_start = pos
    signed_tag, pos = _read_tag(request, pos)
    if signed_tag != 0x30:
        raise Sgp32CodecError("BF51 has no euiccPackageSigned SEQUENCE")
    signed_len, pos = _read_length(request, pos)
    signed_end = pos + signed_len
    signed = request[signed_start:signed_end]
    sig_tag, sig_pos = _read_tag(request, signed_end)
    if sig_tag != 0x5F37:
        raise Sgp32CodecError("BF51 has no eimSignature(5F37)")
    sig_len, sig_pos = _read_length(request, sig_pos)
    signature = request[sig_pos:sig_pos + sig_len]
    return signed, signature


def verify_euicc_package(euicc_package_signed: bytes, eim_signature: bytes,
                         eim_certificate: x509.Certificate) -> bool:
    """用 CERT.EIM 校验 eIM 签名。"""
    return verify_ecdsa_p256(euicc_package_signed + b'\x84\x01\x00', eim_signature,
                             eim_certificate.public_key())


def verify_enable_result_ok(response: bytes) -> int:
    """校验 EuiccPackageResult(BF51) 内 enableResult [3] == ok(0)。

    返回 enableResult 值（0 表示 ok）；非 ok 或结构异常抛异常。
    """
    tag, pos = _read_tag(response, 0)
    if tag != 0xBF51:
        raise Sgp32CodecError("Not a BF51 EuiccPackageResult")
    outer_len, pos = _read_length(response, pos)
    member_tag, pos = _read_tag(response, pos)
    if member_tag == 0xA1:
        raise Sgp32CodecError("LoadEuiccPackage returned signed error result")
    if member_tag == 0xA2:
        raise Sgp32CodecError("LoadEuiccPackage returned unsigned error result")
    if member_tag != 0xA0:
        raise Sgp32CodecError(f"Unexpected EuiccPackageResult member tag 0x{member_tag:04X}")
    signed_len, pos = _read_length(response, pos)
    signed_end = pos + signed_len
    seq_tag, pos = _read_tag(response, pos)
    if seq_tag != 0x30:
        raise Sgp32CodecError("euiccPackageResultSigned has no data SEQUENCE")
    data_len, pos = _read_length(response, pos)
    data_end = pos + data_len

    # 扫描 dataSigned 内字段，最后一个 30 是 euiccResult
    result_start = -1
    cursor = pos
    while cursor < data_end:
        tag_i, cursor2 = _read_tag(response, cursor)
        len_i, cursor3 = _read_length(response, cursor2)
        field_end = cursor3 + len_i
        if tag_i == 0x30:
            result_start = cursor3
            result_end = field_end
        cursor = field_end
    if result_start < 0:
        raise Sgp32CodecError("No euiccResult SEQUENCE in result data")

    pos = result_start
    while pos < result_end:
        tag_i, pos = _read_tag(response, pos)
        len_i, pos = _read_length(response, pos)
        field_end = pos + len_i
        if tag_i in (0x83, 0xA3):  # enableResult [3] IMPLICIT INTEGER
            value = _read_int(response, pos, len_i)
            if value != 0:
                raise Sgp32CodecError(f"enableResult={value} (expected ok(0))")
            return value
        pos = field_end
    raise Sgp32CodecError("No enableResult in euiccResult")
