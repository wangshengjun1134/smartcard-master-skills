"""密码学操作模块"""

from typing import Optional
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ec import ECDSA, EllipticCurvePrivateKey, EllipticCurvePublicKey
from cryptography.hazmat.primitives.kdf.x963kdf import X963KDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.keywrap import UnwrapAes, WrapAes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature, decode_dss_signature
import os


class CryptoError(Exception):
    """密码学操作异常"""
    pass


def sign_ecdsa_p256(data: bytes, private_key: EllipticCurvePrivateKey) -> bytes:
    """
    ECDSA P-256 签名 (SHA256withECDSA)
    
    返回 R||S 格式的 64 字节签名
    """
    try:
        signature = private_key.sign(data, ECDSA(hashes.SHA256()))
        # DER 格式转 R||S 格式
        r, s = decode_dss_signature(signature)
        return r.to_bytes(32, 'big') + s.to_bytes(32, 'big')
    except Exception as e:
        raise CryptoError(f"ECDSA P-256 signing failed: {e}")


def verify_ecdsa_p256(data: bytes, signature: bytes, public_key: EllipticCurvePublicKey) -> bool:
    """
    验证 ECDSA P-256 签名
    
    签名格式: R||S (64 字节) 或 DER
    """
    try:
        if len(signature) == 64:
            # R||S 转 DER
            r = int.from_bytes(signature[:32], 'big')
            s = int.from_bytes(signature[32:], 'big')
            der_signature = encode_dss_signature(r, s)
        else:
            der_signature = signature
        
        public_key.verify(der_signature, data, ECDSA(hashes.SHA256()))
        return True
    except Exception as e:
        raise CryptoError(f"ECDSA P-256 verification failed: {e}")


def ecdh_key_agreement(
    private_key: EllipticCurvePrivateKey,
    public_key: EllipticCurvePublicKey
) -> bytes:
    """
    ECDH 密钥协商
    
    返回共享密钥
    """
    try:
        return private_key.exchange(ec.ECDH(), public_key)
    except Exception as e:
        raise CryptoError(f"ECDH key agreement failed: {e}")


def derive_keys_x963(
    shared_secret: bytes,
    shared_info: bytes,
    key_length: int = 32
) -> bytes:
    """
    X9.63 KDF 密钥派生
    """
    try:
        kdf = X963KDF(
            algorithm=hashes.SHA256(),
            length=key_length,
            sharedinfo=shared_info,
            backend=default_backend()
        )
        return kdf.derive(shared_secret)
    except Exception as e:
        raise CryptoError(f"X9.63 KDF derivation failed: {e}")


def aes_key_wrap(key: bytes, data: bytes) -> bytes:
    """AES 密钥包装 (RFC 3394)"""
    try:
        wrapper = WrapAes(key)
        return wrapper.wrap(data)
    except Exception as e:
        raise CryptoError(f"AES key wrap failed: {e}")


def aes_key_unwrap(key: bytes, wrapped_data: bytes) -> bytes:
    """AES 密钥解包装 (RFC 3394)"""
    try:
        unwrapper = UnwrapAes(key)
        return unwrapper.unwrap(wrapped_data)
    except Exception as e:
        raise CryptoError(f"AES key unwrap failed: {e}")


def aes_gcm_encrypt(
    key: bytes,
    plaintext: bytes,
    associated_data: Optional[bytes] = None
) -> bytes:
    """
    AES-GCM 加密
    
    返回: nonce (12 bytes) + ciphertext + tag (16 bytes)
    """
    try:
        nonce = os.urandom(12)
        cipher = Cipher(algorithms.AES(key), modes.GCM(nonce), backend=default_backend())
        encryptor = cipher.encryptor()
        
        if associated_data:
            encryptor.authenticate_additional_data(associated_data)
        
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()
        return nonce + ciphertext + encryptor.tag
    except Exception as e:
        raise CryptoError(f"AES-GCM encryption failed: {e}")


def aes_gcm_decrypt(
    key: bytes,
    encrypted_data: bytes,
    associated_data: Optional[bytes] = None
) -> bytes:
    """
    AES-GCM 解密
    
    输入: nonce (12 bytes) + ciphertext + tag (16 bytes)
    """
    try:
        nonce = encrypted_data[:12]
        ciphertext_and_tag = encrypted_data[12:]
        ciphertext = ciphertext_and_tag[:-16]
        tag = ciphertext_and_tag[-16:]
        
        cipher = Cipher(algorithms.AES(key), modes.GCM(nonce, tag), backend=default_backend())
        decryptor = cipher.decryptor()
        
        if associated_data:
            decryptor.authenticate_additional_data(associated_data)
        
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        return plaintext
    except Exception as e:
        raise CryptoError(f"AES-GCM decryption failed: {e}")


def aes_cbc_encrypt(key: bytes, plaintext: bytes, iv: bytes) -> bytes:
    """AES-CBC 加密（带 PKCS7 填充）"""
    try:
        # PKCS7 填充
        pad_len = 16 - (len(plaintext) % 16)
        padded = plaintext + bytes([pad_len] * pad_len)
        
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        return encryptor.update(padded) + encryptor.finalize()
    except Exception as e:
        raise CryptoError(f"AES-CBC encryption failed: {e}")


def aes_cbc_decrypt(key: bytes, ciphertext: bytes, iv: bytes) -> bytes:
    """AES-CBC 解密（移除 PKCS7 填充）"""
    try:
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        padded = decryptor.update(ciphertext) + decryptor.finalize()
        
        # 移除 PKCS7 填充
        pad_len = padded[-1]
        return padded[:-pad_len]
    except Exception as e:
        raise CryptoError(f"AES-CBC decryption failed: {e}")
