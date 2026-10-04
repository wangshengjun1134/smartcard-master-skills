"""本地 SM-DP+ 实现模块"""

from typing import Optional, Dict, Any, List
import uuid
import os
import logging

from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey
from cryptography import x509

from .pki_manager import PkiIdentity, get_subject_key_identifier
from .asn1_codec import (
    encode_bf38_authenticate_server_request,
    encode_bf21_prepare_download_request,
    encode_smdp_signed2,
    encode_euicc_info1,
    decode_prepare_download_response,
    decode_euicc_info1,
    decode_bf2e_challenge,
)
from .crypto_provider import sign_ecdsa_p256, verify_ecdsa_p256
from .profile_package_store import ProfilePackageStore, ProfilePackageTemplate
from .bpp_generator import BppGenerator
from .state_machine import DownloadSession, DownloadSessionState
from .utils import bytes_to_hex, hex_to_bytes

logger = logging.getLogger(__name__)


class SmdpPlusError(Exception):
    """SM-DP+ 交互异常"""
    pass


class LocalSmdpPlus:
    """本地 SM-DP+ 服务器实现"""
    
    def __init__(
        self,
        packages: ProfilePackageStore,
        dp_auth_identity: PkiIdentity,
        dp_profile_binding_identity: PkiIdentity,
        trusted_root_certificate: x509.Certificate,
    ):
        """
        初始化本地 SM-DP+
        
        Args:
            packages: Profile Package 存储
            dp_auth_identity: DPauth 身份
            dp_profile_binding_identity: DP Profile Binding 身份
            trusted_root_certificate: CI 根证书
        """
        self.packages = packages
        self.dp_auth_identity = dp_auth_identity
        self.dp_profile_binding_identity = dp_profile_binding_identity
        self.trusted_root = trusted_root_certificate
        
        # BPP 生成器
        self.bpp_generator = BppGenerator(dp_profile_binding_identity, trusted_root_certificate)
        
        # 会话存储
        self._sessions: Dict[str, DownloadSession] = {}
    
    def initiate_authentication(
        self,
        matching_id: str,
        eid: str,
        euicc_challenge: bytes,
        euicc_info1: bytes,
        smdp_address: str
    ) -> Dict[str, Any]:
        """
        InitiateAuthentication - 初始化认证
        
        Args:
            matching_id: Matching ID
            eid: eUICC EID
            euicc_challenge: eUICC Challenge (16 bytes)
            euicc_info1: EuiccInfo1 DER 编码
            smdp_address: SM-DP+ 地址
        
        Returns:
            认证响应数据
        """
        logger.info(f"InitiateAuthentication: matching_id={matching_id}, eid={eid}")
        
        try:
            # 1. 验证 Profile Package 存在
            template = self.packages.require_by_matching_id(matching_id)
            
            # 2. 解析 EuiccInfo1
            euicc_info = decode_euicc_info1(euicc_info1)
            
            # 3. 验证 CI PK ID
            ci_pk_id = get_subject_key_identifier(self.trusted_root)
            supported = any(
                bytes(cid) == ci_pk_id
                for cid in euicc_info.get('verification_ci_pk_ids', [])
            )
            if not supported:
                raise SmdpPlusError("CI PK ID not supported by eUICC")
            
            # 4. 生成 transactionId
            transaction_id = uuid.uuid4().hex
            
            # 5. 生成 serverChallenge
            server_challenge = os.urandom(16)
            
            # 6. 编码 serverSigned1
            server_signed1_der = self._encode_server_signed1(
                transaction_id, euicc_challenge, smdp_address, server_challenge
            )
            
            # 7. 签名 serverSigned1
            server_signature1 = sign_ecdsa_p256(server_signed1_der, self.dp_auth_identity.private_key)
            
            # 8. 获取证书 DER
            cert_der = self.dp_auth_identity.certificate.public_bytes(
                __import__('cryptography.hazmat.primitives.serialization', fromlist=['Encoding']).Encoding.DER
            )
            
            # 9. 创建会话
            session = DownloadSession(transaction_id, matching_id, eid)
            session.server_challenge = server_challenge
            session.euicc_challenge = euicc_challenge
            session.profile_id = template.profile_id
            session.iccid = template.iccid
            self._sessions[transaction_id] = session
            
            logger.info(f"InitiateAuthentication success: transaction_id={transaction_id}")
            
            return {
                'transaction_id': transaction_id,
                'server_challenge': server_challenge,
                'server_signed1': server_signed1_der,
                'server_signature1': server_signature1,
                'euicc_ci_pk_id': ci_pk_id,
                'server_certificate': cert_der,
            }
        
        except SmdpPlusError:
            raise
        except Exception as e:
            logger.error(f"InitiateAuthentication failed: {e}", exc_info=True)
            raise SmdpPlusError(f"InitiateAuthentication failed: {e}")
    
    def authenticate_client(
        self,
        transaction_id: str,
        authenticate_server_response: bytes
    ) -> Dict[str, Any]:
        """
        AuthenticateClient - 客户端认证
        
        Args:
            transaction_id: 交易 ID
            authenticate_server_response: eUICC 的 AuthenticateServerResponse
        
        Returns:
            认证响应数据
        """
        logger.info(f"AuthenticateClient: transaction_id={transaction_id}")
        
        # 1. 查找会话
        session = self._require_session(transaction_id)
        if session.state != DownloadSessionState.INITIATED:
            raise SmdpPlusError(f"Invalid session state: {session.state.name}")
        
        try:
            # 2. 解析 AuthenticateServerResponse
            # 假设响应包含: euiccCertificate, eumCertificate, signedData, signature
            # 简化版：跳过详细解析，直接进行后续步骤
            
            # 3. 验证 transactionId/EID/challenge 匹配
            # 实际实现中需解析响应并验证
            
            # 4. 编码 smdpSigned2
            smdp_signed2 = encode_smdp_signed2(
                transaction_id=transaction_id,
                confirmation_code_required=False,
            )
            
            # 5. 签名 smdpSigned2
            smdp_signature2 = sign_ecdsa_p256(smdp_signed2, self.dp_profile_binding_identity.private_key)
            
            # 6. 获取证书 DER
            cert_der = self.dp_profile_binding_identity.certificate.public_bytes(
                __import__('cryptography.hazmat.primitives.serialization', fromlist=['Encoding']).Encoding.DER
            )
            
            # 7. 更新会话状态
            session.transition_to(DownloadSessionState.CLIENT_AUTHENTICATED)
            
            # 8. 编码 profileMetadata (StoreMetadataRequest)
            template = self.packages.require_by_matching_id(session.matching_id)
            profile_metadata = self._encode_store_metadata(template)
            
            logger.info(f"AuthenticateClient success")
            
            return {
                'transaction_id': transaction_id,
                'profile_id': template.profile_id,
                'iccid': template.iccid,
                'profile_metadata': profile_metadata,
                'smdp_signed2': smdp_signed2,
                'smdp_signature2': smdp_signature2,
                'smdp_certificate': cert_der,
            }
        
        except SmdpPlusError:
            raise
        except Exception as e:
            logger.error(f"AuthenticateClient failed: {e}", exc_info=True)
            session.mark_failed("AUTHENTICATE_CLIENT_ERROR", str(e))
            raise SmdpPlusError(f"AuthenticateClient failed: {e}")
    
    def get_bound_profile_package(
        self,
        transaction_id: str,
        prepare_download_response: bytes
    ) -> bytes:
        """
        GetBoundProfilePackage - 获取 Bound Profile Package
        
        Args:
            transaction_id: 交易 ID
            prepare_download_response: PrepareDownload 响应 (BF21 响应)
        
        Returns:
            BoundProfilePackage DER 编码 (BF36 格式)
        """
        logger.info(f"GetBoundProfilePackage: transaction_id={transaction_id}")
        
        # 1. 查找会话
        session = self._require_session(transaction_id)
        if session.state != DownloadSessionState.CLIENT_AUTHENTICATED:
            raise SmdpPlusError(f"Invalid session state: {session.state.name}")
        
        try:
            # 2. 解析 PrepareDownloadResponse
            parsed = decode_prepare_download_response(prepare_download_response)
            
            # 3. 获取 eUICC OTPK
            euicc_otpk = parsed.get('euicc_otpk')
            if not euicc_otpk:
                raise SmdpPlusError("eUICC OTPK not found in PrepareDownloadResponse")
            
            # 4. 获取 Profile Package 模板
            template = self.packages.require_by_matching_id(session.matching_id)
            
            # 5. 生成 BPP
            bpp_der = self.bpp_generator.generate_bpp(
                transaction_id=transaction_id,
                eid=session.eid,
                euicc_otpk_bytes=euicc_otpk,
                template=template,
            )
            
            # 6. 更新会话
            session.bpp_data = bpp_der
            session.transition_to(DownloadSessionState.PROFILE_DOWNLOADED)
            
            # 7. 分段
            segments = self.bpp_generator.segment_bpp(bpp_der)
            session.bpp_total_segments = len(segments)
            session.bpp_segments_sent = 0
            
            logger.info(f"GetBoundProfilePackage success: {len(bpp_der)} bytes, {len(segments)} segments")
            
            return bpp_der
        
        except SmdpPlusError:
            raise
        except Exception as e:
            logger.error(f"GetBoundProfilePackage failed: {e}", exc_info=True)
            session.mark_failed("GET_BPP_ERROR", str(e))
            raise SmdpPlusError(f"GetBoundProfilePackage failed: {e}")
    
    def get_bpp_segments(self, transaction_id: str) -> List[tuple]:
        """
        获取 BPP 分段列表
        
        Returns:
            [(is_last, data), ...]
        """
        session = self._require_session(transaction_id)
        if session.bpp_data is None:
            raise SmdpPlusError("BPP not generated yet")
        
        return self.bpp_generator.segment_bpp(session.bpp_data)
    
    def _encode_server_signed1(
        self,
        transaction_id: str,
        euicc_challenge: bytes,
        smdp_address: str,
        server_challenge: bytes
    ) -> bytes:
        """编码 ServerSigned1"""
        from pyasn1.type import univ, namedtype
        from pyasn1.codec.der import encoder
        
        server_signed1 = univ.Sequence(
            componentType=namedtype.NamedTypes(
                namedtype.NamedType('transactionId', univ.OctetString()),
                namedtype.NamedType('euiccChallenge', univ.OctetString()),
                namedtype.NamedType('smdpAddress', univ.UTF8String()),
                namedtype.NamedType('serverChallenge', univ.OctetString()),
            )
        )
        server_signed1.setComponentByPosition(0, univ.OctetString(bytes.fromhex(transaction_id)))
        server_signed1.setComponentByPosition(1, univ.OctetString(euicc_challenge))
        server_signed1.setComponentByPosition(2, univ.UTF8String(smdp_address))
        server_signed1.setComponentByPosition(3, univ.OctetString(server_challenge))
        
        return encoder.encode(server_signed1)
    
    def _encode_store_metadata(self, template: ProfilePackageTemplate) -> bytes:
        """编码 StoreMetadataRequest"""
        # 简化版：返回空元数据
        # 完整实现需编码 ICCID、SPN、ProfileName、ProfileClass、Icon 等
        return b''
    
    def _require_session(self, transaction_id: str) -> DownloadSession:
        """获取会话（不存在则抛出异常）"""
        session = self._sessions.get(transaction_id)
        if session is None:
            raise SmdpPlusError(f"Session not found: {transaction_id}")
        return session
    
    def get_session(self, transaction_id: str) -> Optional[DownloadSession]:
        """获取会话"""
        return self._sessions.get(transaction_id)
    
    def clear_session(self, transaction_id: str):
        """清除会话"""
        if transaction_id in self._sessions:
            del self._sessions[transaction_id]
    
    def clear_all_sessions(self):
        """清除所有会话"""
        self._sessions.clear()
