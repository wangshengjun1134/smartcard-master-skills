"""标准 BF36 BoundProfilePackage 编码器

移植自 Java：
  com.iot.sgp.asn1.Sgp22BoundProfilePackageCodec.encode(...)
仅实现 NIST/AES-128 (keyType 0x88) 路径，且不含 ReplaceSessionKeys 分支。

BF36 BoundProfilePackage ::= [54] SEQUENCE {
    initialiseSecureChannelRequest [35] (BF23),
    firstSequenceOf87              [0]  (A0),
    sequenceOf88                   [1]  (A1),
    sequenceOf86                   [3]  (A3)
}
"""

from typing import List

from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePrivateKey

from .asn1_codec import _der_tlv
from .crypto_provider import sign_ecdsa_p256
from .profile_package_store import ProfilePackageTemplate
from .scp03t import (
    AES_KEY_TYPE,
    AES_128_LENGTH,
    Scp03t,
    Scp03tProtectedBlock,
    decode_uncompressed,
    derive_session_keys,
    encode_uncompressed,
    generate_ephemeral_keypair,
)
from .utils import digits_to_bcd


class BppEncodeError(Exception):
    """BPP 编码异常"""
    pass


# SGP.23 测试套件固定 Host ID（TC 4.2.21.2.1-01）
TEST_HOST_ID = b"GSMA SM-XX"
MAX_PPP_PLAINTEXT_SEGMENT = 1007


def _integer_content(value: int) -> bytes:
    """DER INTEGER 的最小补码内容（不含 0x02 标签）。"""
    if value == 0:
        return b'\x00'
    length = (value.bit_length() + 8) // 8  # 预留符号位
    return value.to_bytes(length, 'big', signed=True)


def encode_configure_isdp(dp_proprietary_data: bytes = None) -> bytes:
    """ConfigureISDPRequest(BF24)：{ dpProprietaryData [24] (B8) OPTIONAL }"""
    body = b''
    if dp_proprietary_data:
        body = _der_tlv(b'\xb8', dp_proprietary_data)
    return _der_tlv(b'\xbf\x24', body)


def _iccid_to_bcd(digits: str) -> bytes:
    """ICCID → BCD（半字节交换：low=第 1 位数字，high=第 2 位数字）。

    对齐 Java Sgp22ProfileDownloadCodec.iccidToBcd（ICCID 为标准 BCD 低先行；
    注意与 EID 的非交换打包不同）。
    """
    value = digits
    if len(value) % 2 != 0:
        value += 'F'

    def nibble(ch: str) -> int:
        return int(ch, 16) if ch and ch.upper() in '0123456789ABCDEF' else 0x0F

    out = bytearray()
    for i in range(0, len(value), 2):
        low = nibble(value[i])
        high = nibble(value[i + 1]) if i + 1 < len(value) else 0x0F
        out.append((high << 4) | low)
    return bytes(out)


def encode_store_metadata_request(
    iccid: str,
    service_provider_name: str,
    profile_name: str,
    profile_class: int,
    icon: bytes = None,
    icon_type: int = -1,
) -> bytes:
    """StoreMetadataRequest(BF25)

    StoreMetadataRequest ::= [37] SEQUENCE {
        iccid                [APPLICATION 26] (5A) Iccid,
        serviceProviderName  [17] (91) UTF8String,
        profileName          [18] (92) UTF8String,
        iconType             [19] (93) INTEGER OPTIONAL,
        icon                 [20] (94) OCTET STRING OPTIONAL,
        profileClass         [21] (95) INTEGER
    }
    """
    fields = b''
    fields += _der_tlv(b'\x5a', _iccid_to_bcd(iccid))                       # iccid (APPLICATION 26)
    fields += _der_tlv(b'\x91', service_provider_name.encode('utf-8'))      # serviceProviderName
    fields += _der_tlv(b'\x92', profile_name.encode('utf-8'))               # profileName
    if icon_type >= 0:
        fields += _der_tlv(b'\x93', _integer_content(icon_type))            # iconType
    if icon:
        fields += _der_tlv(b'\x94', icon)                                   # icon
    fields += _der_tlv(b'\x95', _integer_content(profile_class))            # profileClass
    return _der_tlv(b'\xbf\x25', fields)


def _protected_sequence(tag_number: int, blocks: List[Scp03tProtectedBlock]) -> bytes:
    inner = b''
    for block in blocks:
        inner += _der_tlv(bytes([0x80 | (block.tag & 0x1F)]), block.encrypted_data + block.mac)
    return _der_tlv(bytes([0xA0 | tag_number]), inner)


def eid_to_octets(eid: str) -> bytes:
    """EID 的 32 位十进制数字按十六进制半字节打包为 16 字节（对齐 Java eidToOctets）。"""
    value = eid.replace(" ", "")
    if len(value) != 32 or not value.isdigit():
        raise BppEncodeError("EID must contain exactly 32 decimal digits")
    return digits_to_bcd(value)


def encode_standard_bpp(
    transaction_id: str,
    eid: str,
    euicc_otpk: bytes,
    template: ProfilePackageTemplate,
    dp_pb_private_key: EllipticCurvePrivateKey,
    host_id: bytes = TEST_HOST_ID,
) -> bytes:
    """生成标准 BF36 BoundProfilePackage（NIST/AES-128）。"""
    # 1. 临时密钥对 + ECKA 会话密钥
    smdp_keypair = generate_ephemeral_keypair()
    smdp_otpk = encode_uncompressed(smdp_keypair.public_key())
    euicc_public = decode_uncompressed(euicc_otpk)
    eid_octets = eid_to_octets(eid)
    keys = derive_session_keys(smdp_keypair, euicc_public, host_id, eid_octets, AES_KEY_TYPE)
    channel = Scp03t(keys)

    # 2. SCP03t 受保护块
    configure_isdp = encode_configure_isdp(template.dp_proprietary_data)
    metadata = encode_store_metadata_request(
        template.iccid, template.service_provider_name, template.profile_name,
        template.profile_class, template.icon, template.icon_type,
    )
    first87 = [channel.protect_command(0x87, configure_isdp)]
    sequence88 = [channel.protect_command(0x88, metadata)]
    sequence86: List[Scp03tProtectedBlock] = []
    payload = template.payload or b''
    for offset in range(0, len(payload), MAX_PPP_PLAINTEXT_SEGMENT):
        sequence86.append(
            channel.protect_command(0x86, payload[offset:offset + MAX_PPP_PLAINTEXT_SEGMENT])
        )

    # 3. initialiseSecureChannelRequest (BF23)
    remote_op = _der_tlv(b'\x82', _integer_content(1))                 # remoteOperationType [2] = 1
    transaction = _der_tlv(b'\x80', bytes.fromhex(transaction_id))     # transactionId [0]
    crt_fields = (
        _der_tlv(b'\x80', bytes([AES_KEY_TYPE]))    # keyType [0]
        + _der_tlv(b'\x81', bytes([AES_128_LENGTH]))  # keyLength [1]
        + _der_tlv(b'\x84', host_id)                 # hostId [4]
    )
    control_ref = _der_tlv(b'\xa6', crt_fields)                        # controlRef [6]
    smdp_public = _der_tlv(b'\x5f\x49', smdp_otpk)                     # smdpOtpk [73]
    euicc_public_obj = _der_tlv(b'\x5f\x49', euicc_otpk)               # euiccOtpk [73]
    signed_data = remote_op + transaction + control_ref + smdp_public + euicc_public_obj
    signature = _der_tlv(b'\x5f\x37', sign_ecdsa_p256(signed_data, dp_pb_private_key))
    initialise = _der_tlv(b'\xbf\x23', remote_op + transaction + control_ref + smdp_public + signature)

    # 4. 组装 BF36
    bpp = (
        initialise
        + _protected_sequence(0, first87)
        + _protected_sequence(1, sequence88)
        + _protected_sequence(3, sequence86)
    )
    return _der_tlv(b'\xbf\x36', bpp)


# ========== BPP StoreData 分段（对齐 Java ES10ApduChannel） ==========

def _read_tlv(data: bytes, offset: int):
    """读取一个 BER-TLV，返回 (tag_bytes, value_bytes, total_length)。"""
    pos = offset
    first = data[pos]
    pos += 1
    if (first & 0x1F) == 0x1F:  # 多字节 tag
        while data[pos] & 0x80:
            pos += 1
        pos += 1
    tag = data[offset:pos]
    length_byte = data[pos]
    pos += 1
    if length_byte & 0x80:
        num = length_byte & 0x7F
        length = int.from_bytes(data[pos:pos + num], 'big')
        pos += num
    else:
        length = length_byte
    value = data[pos:pos + length]
    pos += length
    return tag, value, pos - offset


def _split_tlvs(data: bytes):
    """把一段 TLV 流拆成 [(tag_bytes, value_bytes, raw_bytes), ...]。"""
    result = []
    off = 0
    while off < len(data):
        tag, value, total = _read_tlv(data, off)
        result.append((tag, value, data[off:off + total]))
        off += total
    return result


def encode_bpp_store_objects(bpp: bytes) -> List[bytes]:
    """按 SGP.22 2.5.5 把 BF36 拆成若干 StoreData 对象（对齐 Java encodeBoundProfilePackageCommands）。

    每个对象随后各自按 ≤255 字节切块，块号从 0 重启，末块 P1=0x91。
    """
    _tag, outer_value, outer_total = _read_tlv(bpp, 0)
    outer_header = bpp[:outer_total - len(outer_value)]
    fields = _split_tlvs(outer_value)
    if len(fields) < 4 or fields[0][0] != b'\xbf\x23':
        raise BppEncodeError("BF36 must begin with BF23 and contain protected sequences")

    objects: List[bytes] = [outer_header + fields[0][2]]

    for tag, value, raw in fields[1:]:
        children = _split_tlvs(value)
        seq_header = raw[:len(raw) - len(value)]
        if tag in (b'\xa0', b'\xa2'):
            # sequences of '87': header + first '87' TLV, 其余各自成对象
            if not children:
                objects.append(raw)
            else:
                objects.append(seq_header + children[0][2])
                for child in children[1:]:
                    objects.append(child[2])
        else:
            # A1(sequenceOf88)/A3(sequenceOf86)：头单独成对象，每个子 TLV 各自成对象
            objects.append(seq_header)
            for child in children:
                objects.append(child[2])
    return objects

