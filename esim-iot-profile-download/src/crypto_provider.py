"""密码学操作模块"""

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ec import ECDSA, EllipticCurvePrivateKey, EllipticCurvePublicKey
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature, decode_dss_signature


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

