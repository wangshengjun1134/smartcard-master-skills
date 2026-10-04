"""BPP (Bound Profile Package) 生成器模块"""

from typing import Optional, Tuple
from pyasn1.type import univ, namedtype, tag
from pyasn1.codec.der import encoder, decoder
from pyasn1.error import PyAsn1Error

from .crypto_provider import (
    ecdh_key_agreement,
    derive_keys_x963,
    aes_key_wrap,
    aes_gcm_encrypt,
    sign_ecdsa_p256,
)
from .pki_manager import PkiIdentity
from .profile_package_store import ProfilePackageTemplate
from .utils import bytes_to_hex, hex_to_bytes
import os


class BppGeneratorError(Exception):
    """BPP 生成异常"""
    pass


class BppGenerator:
    """Bound Profile Package 生成器"""
    
    def __init__(
        self,
        profile_binding_identity: PkiIdentity,
        trusted_root_certificate,
    ):
        """
        初始化 BPP 生成器
        
        Args:
            profile_binding_identity: DP Profile Binding 身份
            trusted_root_certificate: CI 根证书
        """
        self.profile_binding_identity = profile_binding_identity
        self.trusted_root = trusted_root_certificate
    
    def generate_bpp(
        self,
        transaction_id: str,
        eid: str,
        euicc_otpk_bytes: bytes,
        template: ProfilePackageTemplate,
    ) -> bytes:
        """
        生成 Bound Profile Package (BF36 格式)
        
        Args:
            transaction_id: 交易 ID
            eid: eUICC EID
            euicc_otpk_bytes: eUICC One-Time Public Key (65 bytes, 0x04||x||y)
            template: Profile Package 模板
        
        Returns:
            BF36 DER 编码
        """
        try:
            # 1. 解析 eUICC OTPK
            euicc_otpk = self._parse_euicc_otpk(euicc_otpk_bytes)
            
            # 2. ECKA 密钥协商
            shared_secret = ecdh_key_agreement(
                self.profile_binding_identity.private_key,
                euicc_otpk
            )
            
            # 3. 派生加密密钥
            # sharedInfo: transactionId || eid
            shared_info = hex_to_bytes(transaction_id) + hex_to_bytes(eid)
            enc_key = derive_keys_x963(shared_secret, shared_info, key_length=16)
            
            # 4. 加密 UPP Payload
            encrypted_payload = self._encrypt_payload(template.payload, enc_key)
            
            # 5. 编码 BoundProfilePackage
            bpp = self._encode_bpp(
                transaction_id=transaction_id,
                eid=eid,
                profile_id=template.profile_id,
                profile_name=template.profile_name,
                iccid=template.iccid,
                service_provider_name=template.service_provider_name,
                profile_class=template.profile_class,
                encrypted_payload=encrypted_payload,
            )
            
            # 6. 签名 BPP
            signed_bpp = self._sign_bpp(bpp)
            
            return signed_bpp
        
        except BppGeneratorError:
            raise
        except Exception as e:
            raise BppGeneratorError(f"Generate BPP failed: {e}")
    
    def _parse_euicc_otpk(self, otpk_bytes: bytes):
        """解析 eUICC One-Time Public Key (0x04||x||y)"""
        if len(otpk_bytes) != 65 or otpk_bytes[0] != 0x04:
            raise BppGeneratorError("Invalid eUICC OTPK format (expected 65 bytes starting with 0x04)")
        
        from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey
        from cryptography.hazmat.backends import default_backend
        
        # 0x04||x||y 转 uncompressed point
        return EllipticCurvePublicKey.from_encoded_point(
            ec.SECP256R1(),
            otpk_bytes
        )
    
    def _encrypt_payload(self, payload: bytes, enc_key: bytes) -> bytes:
        """加密 UPP Payload (AES-GCM)"""
        if not payload:
            return b''
        
        try:
            return aes_gcm_encrypt(enc_key, payload)
        except Exception as e:
            raise BppGeneratorError(f"Payload encryption failed: {e}")
    
    def _encode_bpp(
        self,
        transaction_id: str,
        eid: str,
        profile_id: str,
        profile_name: str,
        iccid: str,
        service_provider_name: str,
        profile_class: int,
        encrypted_payload: bytes,
    ) -> bytes:
        """编码 BoundProfilePackage 结构"""
        try:
            # BoundProfilePackage ::= SEQUENCE {
            #     profileId              OCTET STRING,
            #     profileName            UTF8String,
            #     iccid                  OCTET STRING,
            #     serviceProviderName    UTF8String OPTIONAL,
            #     profileClass           INTEGER DEFAULT 0,
            #     encryptedPayload       OCTET STRING
            # }
            
            bpp = univ.Sequence(
                componentType=namedtype.NamedTypes(
                    namedtype.NamedType('profileId', univ.OctetString()),
                    namedtype.NamedType('profileName', univ.UTF8String()),
                    namedtype.NamedType('iccid', univ.OctetString()),
                    namedtype.OptionalNamedType('serviceProviderName', univ.UTF8String()),
                    namedtype.DefaultedNamedType('profileClass', univ.Integer(0)),
                    namedtype.NamedType('encryptedPayload', univ.OctetString()),
                )
            )
            
            bpp.setComponentByPosition(0, univ.OctetString(hex_to_bytes(profile_id)))
            bpp.setComponentByPosition(1, univ.UTF8String(profile_name))
            bpp.setComponentByPosition(2, univ.OctetString(iccid.encode('utf-8')))
            if service_provider_name:
                bpp.setComponentByPosition(3, univ.UTF8String(service_provider_name))
            bpp.setComponentByPosition(4, univ.Integer(profile_class))
            bpp.setComponentByPosition(5, univ.OctetString(encrypted_payload))
            
            return encoder.encode(bpp)
        except PyAsn1Error as e:
            raise BppGeneratorError(f"Cannot encode BPP: {e}")
    
    def _sign_bpp(self, bpp_der: bytes) -> bytes:
        """签名 BPP 并编码为 BF36 格式"""
        try:
            # 签名 BPP
            signature = sign_ecdsa_p256(bpp_der, self.profile_binding_identity.private_key)
            
            # 获取证书
            cert_der = self.profile_binding_identity.certificate.public_bytes(
                __import__('cryptography.hazmat.primitives.serialization', fromlist=['Encoding']).Encoding.DER
            )
            
            # 编码为 SignedProfilePackage
            # SignedProfilePackage ::= SEQUENCE {
            #     profilePackage         OCTET STRING,
            #     dpProfileBindingSignature OCTET STRING,
            #     dpProfileBindingCertificate SEQUENCE
            # }
            signed_package = univ.Sequence(
                componentType=namedtype.NamedTypes(
                    namedtype.NamedType('profilePackage', univ.OctetString()),
                    namedtype.NamedType('dpProfileBindingSignature', univ.OctetString()),
                    namedtype.NamedType('dpProfileBindingCertificate', univ.Any()),
                )
            )
            
            # 解析证书
            cert, _ = decoder.decode(cert_der)
            
            signed_package.setComponentByPosition(0, univ.OctetString(bpp_der))
            signed_package.setComponentByPosition(1, univ.OctetString(signature))
            signed_package.setComponentByPosition(2, cert)
            
            signed_der = encoder.encode(signed_package)
            
            # 编码为 BF36 格式
            bf36 = univ.OctetString(signed_der).subtype(
                implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 54)
            )
            
            return encoder.encode(bf36)
        except PyAsn1Error as e:
            raise BppGeneratorError(f"Cannot sign BPP: {e}")
        except Exception as e:
            raise BppGeneratorError(f"BPP signing failed: {e}")
    
    def segment_bpp(self, bpp_der: bytes, max_segment_size: int = 255) -> list:
        """
        将 BPP 分块（用于 StoreData 分段传输）
        
        Args:
            bpp_der: BPP DER 编码
            max_segment_size: 最大分段大小（默认 255 字节）
        
        Returns:
            分段列表 [(is_last, data), ...]
        """
        segments = []
        offset = 0
        
        while offset < len(bpp_der):
            chunk = bpp_der[offset:offset + max_segment_size]
            is_last = (offset + max_segment_size >= len(bpp_der))
            segments.append((is_last, chunk))
            offset += max_segment_size
        
        return segments


# 导入 ec 模块
from cryptography.hazmat.primitives.asymmetric import ec
