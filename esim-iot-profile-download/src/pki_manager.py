"""PKI 证书和密钥管理模块"""

from typing import List, Optional, Tuple
from cryptography import x509
from cryptography.x509 import load_der_x509_certificate, load_pem_x509_certificate
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePrivateKey, EllipticCurvePublicKey
from cryptography.hazmat.backends import default_backend


class PkiError(Exception):
    """PKI 操作异常"""
    pass


class PkiIdentity:
    """PKI 身份（私钥 + 证书链）"""
    
    def __init__(self, private_key: EllipticCurvePrivateKey, certificates: List[x509.Certificate]):
        """
        初始化 PKI 身份
        
        Args:
            private_key: 私钥
            certificates: 证书链（第一个是实体证书，后续是中间证书）
        """
        self.private_key = private_key
        self.certificates = certificates
    
    @property
    def certificate(self) -> x509.Certificate:
        """获取实体证书"""
        return self.certificates[0] if self.certificates else None

def load_private_key_from_pem(pem_data: bytes, password: Optional[bytes] = None) -> EllipticCurvePrivateKey:
    """从 PEM 格式加载私钥"""
    try:
        return serialization.load_pem_private_key(pem_data, password=password, backend=default_backend())
    except Exception as e:
        raise PkiError(f"Cannot load private key from PEM: {e}")


def load_private_key_from_der(der_data: bytes) -> EllipticCurvePrivateKey:
    """从 DER 格式加载私钥"""
    try:
        return serialization.load_der_private_key(der_data, backend=default_backend())
    except Exception as e:
        raise PkiError(f"Cannot load private key from DER: {e}")


def load_certificate_from_der(der_data: bytes) -> x509.Certificate:
    """从 DER 格式加载证书"""
    try:
        return load_der_x509_certificate(der_data, default_backend())
    except Exception as e:
        raise PkiError(f"Cannot load certificate from DER: {e}")


def load_certificate_from_pem(pem_data: bytes) -> x509.Certificate:
    """从 PEM 格式加载证书"""
    try:
        return load_pem_x509_certificate(pem_data, default_backend())
    except Exception as e:
        raise PkiError(f"Cannot load certificate from PEM: {e}")


def get_subject_key_identifier(cert: x509.Certificate) -> bytes:
    """获取证书 Subject Key Identifier (SKI)"""
    try:
        ski_ext = cert.extensions.get_extension_for_class(x509.SubjectKeyIdentifier)
        return ski_ext.value.digest
    except Exception as e:
        raise PkiError(f"Cannot get SKI from certificate: {e}")

def generate_ecdsa_p256_keypair() -> Tuple[EllipticCurvePrivateKey, EllipticCurvePublicKey]:
    """生成 ECDSA P-256 密钥对"""
    private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    return private_key, private_key.public_key()

