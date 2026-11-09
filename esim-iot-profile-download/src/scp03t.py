"""SCP03t / ECKA / X9.63 KDF

移植自 Java sgp-standard-core：
  com.iot.sgp.download.crypto.{EckaKeyAgreement, Sgp22KeyAgreement, X963Kdf,
                               Scp03t, Scp03tSessionKeys, Scp03tProtectedBlock}
仅实现 NIST/AES-128 (keyType 0x88) 路径。
"""

from dataclasses import dataclass

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import cmac as _cmac
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat


class Scp03tError(Exception):
    """SCP03t / ECKA 异常"""
    pass


BLOCK_SIZE = 16
MAC_LENGTH = 8
AES_KEY_TYPE = 0x88
SM2_KEY_TYPE = 0x89
AES_128_LENGTH = 0x10


# ========== AES 原语 ==========

def _aes_cbc(key: bytes, iv: bytes, data: bytes, encrypt: bool) -> bytes:
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    ctx = cipher.encryptor() if encrypt else cipher.decryptor()
    return ctx.update(data) + ctx.finalize()


def _aes_ecb_encrypt(key: bytes, data: bytes) -> bytes:
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
    ctx = cipher.encryptor()
    return ctx.update(data) + ctx.finalize()


def aes_cmac(key: bytes, data: bytes) -> bytes:
    c = _cmac.CMAC(algorithms.AES(key), backend=default_backend())
    c.update(data)
    return c.finalize()


# ========== ECKA 密钥协商 ==========

def generate_ephemeral_keypair() -> ec.EllipticCurvePrivateKey:
    return ec.generate_private_key(ec.SECP256R1(), default_backend())


def encode_uncompressed(pub: ec.EllipticCurvePublicKey) -> bytes:
    return pub.public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)


def decode_uncompressed(data: bytes) -> ec.EllipticCurvePublicKey:
    if not data or len(data) != 65 or data[0] != 0x04:
        raise Scp03tError("EC public key must use uncompressed point encoding (65 bytes, 0x04)")
    return ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), data)


def derive_shared_secret(priv: ec.EllipticCurvePrivateKey,
                         peer: ec.EllipticCurvePublicKey) -> bytes:
    return priv.exchange(ec.ECDH(), peer)


# ========== X9.63 KDF ==========

def x963_kdf_sha256(shared_secret: bytes, shared_info: bytes, output_length: int) -> bytes:
    if not shared_secret:
        raise Scp03tError("sharedSecret must not be empty")
    if output_length <= 0:
        raise Scp03tError("outputLength must be positive")
    info = shared_info or b''
    out = bytearray()
    counter = 1
    while len(out) < output_length:
        digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
        digest.update(shared_secret)
        digest.update(counter.to_bytes(4, 'big'))
        digest.update(info)
        out.extend(digest.finalize())
        counter += 1
    return bytes(out[:output_length])


def shared_info(key_type: int, key_length: int, host_id: bytes, eid_octets: bytes) -> bytes:
    if not host_id or len(host_id) > 16:
        raise Scp03tError("HostID must contain 1 to 16 bytes")
    if not eid_octets or len(eid_octets) > 255:
        raise Scp03tError("EID must contain 1 to 255 bytes")
    return (bytes([key_type, key_length, len(host_id)]) + host_id
            + bytes([len(eid_octets)]) + eid_octets)


# ========== 会话密钥 ==========

@dataclass
class Scp03tSessionKeys:
    initial_mac_chaining_value: bytes
    s_enc: bytes
    s_mac: bytes

    @classmethod
    def from_kdf_output(cls, key_data: bytes) -> "Scp03tSessionKeys":
        if not key_data or len(key_data) < 48:
            raise Scp03tError("SCP03t key data must contain at least 48 bytes")
        return cls(key_data[0:16], key_data[16:32], key_data[32:48])


def derive_session_keys(smdp_private: ec.EllipticCurvePrivateKey,
                        euicc_public: ec.EllipticCurvePublicKey,
                        host_id: bytes, eid_octets: bytes,
                        key_type: int = AES_KEY_TYPE) -> Scp03tSessionKeys:
    secret = derive_shared_secret(smdp_private, euicc_public)
    info = shared_info(key_type, AES_128_LENGTH, host_id, eid_octets)
    kdf_output = x963_kdf_sha256(secret, info, 48)
    return Scp03tSessionKeys.from_kdf_output(kdf_output)


# ========== SCP03t 受保护块 ==========

@dataclass
class Scp03tProtectedBlock:
    counter: int
    tag: int
    encrypted_data: bytes
    mac: bytes


class Scp03t:
    """有状态的 SCP03t 命令保护（BPP 标签 86/87/88）。"""

    def __init__(self, keys: Scp03tSessionKeys):
        if keys is None:
            raise Scp03tError("keys must not be null")
        self.keys = keys
        self.mac_chaining_value = keys.initial_mac_chaining_value
        self.encryption_counter = 1

    def protect_command(self, tag: int, plaintext: bytes) -> Scp03tProtectedBlock:
        if tag not in (0x86, 0x87, 0x88):
            raise Scp03tError("SCP03t tag must be 86, 87 or 88")
        if plaintext is None:
            raise Scp03tError("plaintext must not be null")
        counter = self.encryption_counter
        self.encryption_counter += 1
        icv = self._encryption_icv(counter)
        if tag == 0x88:
            protected_data = bytes(plaintext)
        else:
            protected_data = _aes_cbc(self.keys.s_enc, icv, iso7816_pad(plaintext), True)
        header = _tlv_header(tag, len(protected_data) + MAC_LENGTH)
        mac_input = self.mac_chaining_value + header + protected_data
        full_mac = aes_cmac(self.keys.s_mac, mac_input)
        self.mac_chaining_value = full_mac
        return Scp03tProtectedBlock(counter, tag, protected_data, full_mac[:MAC_LENGTH])

    def _encryption_icv(self, counter: int) -> bytes:
        counter_block = bytearray(BLOCK_SIZE)
        counter_block[12:16] = counter.to_bytes(4, 'big')
        return _aes_ecb_encrypt(self.keys.s_enc, bytes(counter_block))

def _tlv_header(tag: int, length: int) -> bytes:
    out = bytearray([tag])
    if length < 0x80:
        out.append(length)
    elif length <= 0xFF:
        out.extend([0x81, length])
    else:
        out.extend([0x82, (length >> 8) & 0xFF, length & 0xFF])
    return bytes(out)


def iso7816_pad(data: bytes) -> bytes:
    padding = BLOCK_SIZE - (len(data) % BLOCK_SIZE)
    return bytes(data) + b'\x80' + b'\x00' * (padding - 1)
