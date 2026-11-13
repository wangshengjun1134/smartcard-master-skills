"""资源加载模块

管理证书和 Profile 包的加载。
"""

import os
from typing import Optional, Dict, Any
from pathlib import Path


class ResourceLoadError(Exception):
    """资源加载异常"""
    pass


class ResourceManager:
    """资源管理器
    
    负责加载：
    - 证书文件（PEM/DER 格式）
    - Profile 包文件（HEX 格式）
    - 图标文件
    """
    
    def __init__(self, resources_dir: Optional[str] = None):
        """初始化资源管理器
        
        Args:
            resources_dir: 资源目录路径，默认为包内的 resources 目录
        """
        if resources_dir:
            self.resources_dir = Path(resources_dir)
        else:
            # 默认使用包内的 resources 目录
            self.resources_dir = Path(__file__).parent.parent.parent / "resources"
        
        self.certs_dir = self.resources_dir / "certs"
        self.profiles_dir = self.resources_dir / "profiles"
    
    def load_certificate(self, cert_name: str) -> bytes:
        """加载证书文件
        
        Args:
            cert_name: 证书文件名（如 "CERT_CI_ECDSA_NIST.pem"）
        
        Returns:
            证书内容（DER 格式字节）
        """
        cert_path = self.certs_dir / cert_name
        
        if not cert_path.exists():
            raise ResourceLoadError(f"证书文件不存在: {cert_path}")
        
        content = cert_path.read_bytes()
        
        # 如果是 PEM 格式，转换为 DER
        if cert_name.endswith(".pem"):
            content = self._pem_to_der(content)
        
        return content
    
    def load_profile_package(self, iccid: str) -> str:
        """加载 Profile 包
        
        Args:
            iccid: ICCID（用于查找对应的 Profile 文件）
        
        Returns:
            Profile 包的十六进制字符串
        """
        # 查找匹配的 Profile 文件
        # 文件名格式: PROFILE_OPERATIONAL1_<ICCID>.HEX
        profile_files = list(self.profiles_dir.glob(f"*{iccid}*.HEX"))
        
        if not profile_files:
            # 尝试不带 ICCID 的默认文件
            profile_files = list(self.profiles_dir.glob("PROFILE_*.HEX"))
        
        if not profile_files:
            raise ResourceLoadError(f"未找到 ICCID {iccid} 对应的 Profile 文件")
        
        profile_path = profile_files[0]
        content = profile_path.read_text(encoding="utf-8").strip()
        
        # 移除可能的空白字符和换行
        content = content.replace("\n", "").replace("\r", "").replace(" ", "")
        
        return content
    
    def load_icon(self, icon_name: str = "icon1.png") -> bytes:
        """加载图标文件
        
        Args:
            icon_name: 图标文件名
        
        Returns:
            图标内容
        """
        icon_path = self.profiles_dir / icon_name
        
        if not icon_path.exists():
            raise ResourceLoadError(f"图标文件不存在: {icon_path}")
        
        return icon_path.read_bytes()
    
    def _pem_to_der(self, pem_content: bytes) -> bytes:
        """将 PEM 格式转换为 DER 格式
        
        Args:
            pem_content: PEM 格式内容
        
        Returns:
            DER 格式字节
        """
        import base64
        
        # 移除 PEM 头部和尾部
        lines = pem_content.decode("utf-8").strip().split("\n")
        
        # 找到 BEGIN 和 END 之间的内容
        der_lines = []
        in_body = False
        for line in lines:
            if "BEGIN" in line:
                in_body = True
                continue
            if "END" in line:
                break
            if in_body:
                der_lines.append(line.strip())
        
        # Base64 解码
        der_base64 = "".join(der_lines)
        return base64.b64decode(der_base64)
    
    def get_all_certs_info(self) -> Dict[str, Any]:
        """获取所有证书信息
        
        Returns:
            证书信息字典
        """
        info = {
            "available_certs": [],
            "certs_dir": str(self.certs_dir),
        }
        
        if self.certs_dir.exists():
            for cert_file in self.certs_dir.iterdir():
                if cert_file.suffix in [".pem", ".der", ".crt"]:
                    info["available_certs"].append(cert_file.name)
        
        return info
    
    def get_all_profiles_info(self) -> Dict[str, Any]:
        """获取所有 Profile 信息
        
        Returns:
            Profile 信息字典
        """
        info = {
            "available_profiles": [],
            "profiles_dir": str(self.profiles_dir),
        }
        
        if self.profiles_dir.exists():
            for profile_file in self.profiles_dir.iterdir():
                if profile_file.suffix == ".HEX":
                    info["available_profiles"].append(profile_file.name)
        
        return info


class CertificateManager:
    """证书管理器
    
    管理 SM-DP+ 相关的证书和密钥。
    """
    
    def __init__(self, resource_manager: ResourceManager):
        self.resource_manager = resource_manager
        self._cache: Dict[str, bytes] = {}
    
    def get_dp_auth_cert(self) -> bytes:
        """获取 SM-DP+ 认证证书"""
        if "dp_auth_cert" not in self._cache:
            self._cache["dp_auth_cert"] = self.resource_manager.load_certificate(
                "CERT_S_SM_DPauth_ECDSA_NIST.der"
            )
        return self._cache["dp_auth_cert"]
    
    def get_dp_auth_key(self) -> bytes:
        """获取 SM-DP+ 认证私钥"""
        if "dp_auth_key" not in self._cache:
            self._cache["dp_auth_key"] = self.resource_manager.load_certificate(
                "SK_S_SM_DPauth_ECDSA_NIST.pem"
            )
        return self._cache["dp_auth_key"]
    
    def get_dp_pb_cert(self) -> bytes:
        """获取 SM-DP+ Profile Binding 证书"""
        if "dp_pb_cert" not in self._cache:
            self._cache["dp_pb_cert"] = self.resource_manager.load_certificate(
                "CERT_S_SM_DPpb_ECDSA_NIST.der"
            )
        return self._cache["dp_pb_cert"]
    
    def get_dp_pb_key(self) -> bytes:
        """获取 SM-DP+ Profile Binding 私钥"""
        if "dp_pb_key" not in self._cache:
            self._cache["dp_pb_key"] = self.resource_manager.load_certificate(
                "SK_S_SM_DPpb_ECDSA_NIST.pem"
            )
        return self._cache["dp_pb_key"]
    
    def get_ci_cert(self) -> bytes:
        """获取 CI 根证书"""
        if "ci_cert" not in self._cache:
            self._cache["ci_cert"] = self.resource_manager.load_certificate(
                "CERT_CI_ECDSA_NIST.pem"
            )
        return self._cache["ci_cert"]
    
    def get_eim_cert(self) -> bytes:
        """获取 eIM 证书"""
        if "eim_cert" not in self._cache:
            self._cache["eim_cert"] = self.resource_manager.load_certificate(
                "CERT_EIM_ECDSA_NIST.der"
            )
        return self._cache["eim_cert"]
    
    def get_eim_key(self) -> bytes:
        """获取 eIM 私钥"""
        if "eim_key" not in self._cache:
            self._cache["eim_key"] = self.resource_manager.load_certificate(
                "SK_EIM_ECDSA_NIST.pem"
            )
        return self._cache["eim_key"]


class ProfileManager:
    """Profile 管理器
    
    管理 Profile 包的加载和缓存。
    """
    
    def __init__(self, resource_manager: ResourceManager):
        self.resource_manager = resource_manager
        self._cache: Dict[str, str] = {}
    
    def get_profile_package(self, iccid: str) -> str:
        """获取 Profile 包
        
        Args:
            iccid: ICCID
        
        Returns:
            Profile 包（十六进制字符串）
        """
        if iccid not in self._cache:
            self._cache[iccid] = self.resource_manager.load_profile_package(iccid)
        return self._cache[iccid]
    
    def get_icon(self, icon_name: str = "icon1.png") -> bytes:
        """获取图标
        
        Args:
            icon_name: 图标文件名
        
        Returns:
            图标内容
        """
        cache_key = f"icon_{icon_name}"
        if cache_key not in self._cache:
            icon_data = self.resource_manager.load_icon(icon_name)
            self._cache[cache_key] = icon_data.hex().upper()
        return bytes.fromhex(self._cache[cache_key])
