"""PKI 证书和密钥管理模块"""

from typing import List, Optional, Tuple
from cryptography import x509
from cryptography.x509 import load_der_x509_certificate, load_pem_x509_certificate
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePrivateKey, EllipticCurvePublicKey
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature
import os


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
    
    def get_public_key(self) -> EllipticCurvePublicKey:
        """获取公钥"""
        return self.private_key.public_key()


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


def get_authority_key_identifier(cert: x509.Certificate) -> bytes:
    """获取证书 Authority Key Identifier (AKI)"""
    try:
        aki_ext = cert.extensions.get_extension_for_class(x509.AuthorityKeyIdentifier)
        return aki_ext.value.key_identifier
    except Exception as e:
        raise PkiError(f"Cannot get AKI from certificate: {e}")


def validate_certificate_chain(
    certificate: x509.Certificate,
    trusted_root: x509.Certificate,
    intermediate_certs: Optional[List[x509.Certificate]] = None
) -> bool:
    """
    验证证书链（简化版）
    
    验证证书由根证书或中间证书签名
    """
    try:
        # 尝试用根证书验证
        root_public_key = trusted_root.public_key()
        if isinstance(root_public_key, EllipticCurvePublicKey):
            root_public_key.verify(
                certificate.signature,
                certificate.tbs_certificate_bytes,
                ec.ECDSA(hashes.SHA256())
            )
            return True
        
        # 尝试用中间证书验证
        if intermediate_certs:
            for intermediate in intermediate_certs:
                inter_public_key = intermediate.public_key()
                if isinstance(inter_public_key, EllipticCurvePublicKey):
                    try:
                        inter_public_key.verify(
                            certificate.signature,
                            certificate.tbs_certificate_bytes,
                            ec.ECDSA(hashes.SHA256())
                        )
                        return True
                    except InvalidSignature:
                        continue
        
        return False
    except Exception as e:
        raise PkiError(f"Certificate chain validation failed: {e}")


def extract_eid_from_certificate(cert: x509.Certificate) -> Optional[str]:
    """从证书 subject 的 SERIALNUMBER 字段提取 EID"""
    try:
        for attr in cert.subject:
            if attr.oid == x509.oid.NameOID.SERIAL_NUMBER:
                return attr.value.strip()
    except Exception:
        pass
    return None


def generate_ecdsa_p256_keypair() -> Tuple[EllipticCurvePrivateKey, EllipticCurvePublicKey]:
    """生成 ECDSA P-256 密钥对"""
    private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    return private_key, private_key.public_key()


def create_self_signed_certificate(
    private_key: EllipticCurvePrivateKey,
    subject: x509.Name,
    validity_days: int = 365
) -> x509.Certificate:
    """创建自签名证书"""
    from cryptography.x509 import CertificateBuilder
    
    public_key = private_key.public_key()
    
    builder = CertificateBuilder()
    builder = builder.subject_name(subject)
    builder = builder.issuer_name(subject)
    builder = builder.public_key(public_key)
    builder = builder.serial_number(x509.random_serial_number())
    builder = builder.not_valid_before(os.urandom(8))  # 简化处理
    builder = builder.not_valid_after(os.urandom(8))   # 简化处理
    
    # 添加基本约束
    builder = builder.add_extension(
        x509.BasicConstraints(ca=False, path_length=None),
        critical=True
    )
    
    # 添加 SKI
    ski = x509.SubjectKeyIdentifier.from_public_key(public_key)
    builder = builder.add_extension(ski, critical=False)
    
    certificate = builder.sign(private_key, hashes.SHA256(), default_backend())
    return certificate
