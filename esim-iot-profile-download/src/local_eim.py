"""本地 eIM 平台模拟（间接模式激活）

对应 Java `com.tfes.ctst.LocalEim`：扮演 eIM 角色，用 EIM 身份（SK_EIM + CERT_EIM）
打包 eUICC Package（EuiccPackageRequest BF51）并签名，供 eUICC 的 LoadEuiccPackage 执行。
"""

from cryptography.hazmat.primitives.serialization import Encoding

from . import sgp32_codec as codec
from .pki_manager import PkiIdentity


class LocalEim:
    """本地 eIM 平台模拟"""

    def __init__(self, eim_identity: PkiIdentity):
        self.eim_identity = eim_identity

    @property
    def certificate_der(self) -> bytes:
        return self.eim_identity.certificate.public_bytes(Encoding.DER)

    def build_add_initial_eim(self, eim_id: str, counter_value: int) -> bytes:
        """构造 AddInitialEimRequest (BF57)"""
        ecd = codec.encode_eim_configuration_data(eim_id, counter_value, self.certificate_der)
        return codec.encode_add_initial_eim_request(ecd)

    def transfer_eim_package(self, eim_id: str, eid_octets: bytes, counter_value: int,
                             euicc_package_der: bytes) -> bytes:
        """TransferEimPackage：打包 EuiccPackageRequest (BF51) + eimSignature"""
        signed = codec.encode_euicc_package_signed(eim_id, eid_octets, counter_value, euicc_package_der)
        signature = codec.sign_euicc_package(signed, self.eim_identity.private_key)
        return codec.encode_euicc_package_request(signed, signature)

    def build_enable_package(self, eim_id: str, eid_octets: bytes, counter_value: int,
                             iccid_bcd: bytes, rollback_flag: bool = False) -> bytes:
        """构造 enable PSMO 的 BF51（eIM enable，无 rollbackFlag）"""
        psmo = codec.encode_enable_psmo(iccid_bcd, rollback_flag)
        psmo_list = codec.encode_psmo_list(psmo)
        return self.transfer_eim_package(eim_id, eid_octets, counter_value, psmo_list)
