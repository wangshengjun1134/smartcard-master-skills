"""资源加载测试"""

import pytest
import tempfile
from pathlib import Path
from esim_iot_profile_download.resources import (
    ResourceManager, CertificateManager, ProfileManager, ResourceLoadError
)


def test_resource_manager_init():
    """测试资源管理器初始化"""
    with tempfile.TemporaryDirectory() as tmpdir:
        # 创建测试目录结构
        certs_dir = Path(tmpdir) / "certs"
        profiles_dir = Path(tmpdir) / "profiles"
        certs_dir.mkdir()
        profiles_dir.mkdir()
        
        rm = ResourceManager(tmpdir)
        assert rm.resources_dir == Path(tmpdir)
        assert rm.certs_dir == certs_dir
        assert rm.profiles_dir == profiles_dir


def test_resource_manager_load_certificate():
    """测试加载证书"""
    with tempfile.TemporaryDirectory() as tmpdir:
        certs_dir = Path(tmpdir) / "certs"
        certs_dir.mkdir()
        
        # 创建测试证书文件（DER 格式）
        cert_content = b"\x30\x00"  # 空 SEQUENCE
        cert_file = certs_dir / "test_cert.der"
        cert_file.write_bytes(cert_content)
        
        rm = ResourceManager(tmpdir)
        loaded = rm.load_certificate("test_cert.der")
        
        assert loaded == cert_content


def test_resource_manager_load_certificate_pem():
    """测试加载 PEM 格式证书"""
    with tempfile.TemporaryDirectory() as tmpdir:
        certs_dir = Path(tmpdir) / "certs"
        certs_dir.mkdir()
        
        # 创建测试 PEM 文件
        pem_content = b"""-----BEGIN CERTIFICATE-----
MIIBkTCB+wIJAKHBfpQgcMFvMA0GCSqGSIb3DQEBCwUAMBExDzANBgNVBAMMBnRl
-----END CERTIFICATE-----"""
        cert_file = certs_dir / "test_cert.pem"
        cert_file.write_bytes(pem_content)
        
        rm = ResourceManager(tmpdir)
        loaded = rm.load_certificate("test_cert.pem")
        
        # 应该返回 DER 格式
        assert isinstance(loaded, bytes)
        assert len(loaded) > 0


def test_resource_manager_load_certificate_not_found():
    """测试加载不存在的证书"""
    with tempfile.TemporaryDirectory() as tmpdir:
        certs_dir = Path(tmpdir) / "certs"
        certs_dir.mkdir()
        
        rm = ResourceManager(tmpdir)
        
        with pytest.raises(ResourceLoadError):
            rm.load_certificate("nonexistent.der")


def test_resource_manager_load_profile_package():
    """测试加载 Profile 包"""
    with tempfile.TemporaryDirectory() as tmpdir:
        profiles_dir = Path(tmpdir) / "profiles"
        profiles_dir.mkdir()
        
        # 创建测试 Profile 文件
        profile_content = "3000AABBCCDD"
        profile_file = profiles_dir / "PROFILE_TEST_123456.HEX"
        profile_file.write_text(profile_content)
        
        rm = ResourceManager(tmpdir)
        loaded = rm.load_profile_package("123456")
        
        assert loaded == profile_content


def test_resource_manager_load_profile_package_not_found():
    """测试加载不存在的 Profile"""
    with tempfile.TemporaryDirectory() as tmpdir:
        profiles_dir = Path(tmpdir) / "profiles"
        profiles_dir.mkdir()
        
        rm = ResourceManager(tmpdir)
        
        with pytest.raises(ResourceLoadError):
            rm.load_profile_package("nonexistent_iccid")


def test_certificate_manager():
    """测试证书管理器"""
    with tempfile.TemporaryDirectory() as tmpdir:
        certs_dir = Path(tmpdir) / "certs"
        certs_dir.mkdir()
        
        # 创建测试证书文件
        (certs_dir / "CERT_S_SM_DPauth_ECDSA_NIST.der").write_bytes(b"\x30\x01\x01")
        (certs_dir / "SK_S_SM_DPauth_ECDSA_NIST.pem").write_bytes(b"-----BEGIN PRIVATE KEY-----\nMC4CAQEE\n-----END PRIVATE KEY-----")
        (certs_dir / "CERT_S_SM_DPpb_ECDSA_NIST.der").write_bytes(b"\x30\x01\x02")
        (certs_dir / "SK_S_SM_DPpb_ECDSA_NIST.pem").write_bytes(b"-----BEGIN PRIVATE KEY-----\nMC4CAQEE\n-----END PRIVATE KEY-----")
        (certs_dir / "CERT_CI_ECDSA_NIST.pem").write_bytes(b"-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----")
        (certs_dir / "CERT_EIM_ECDSA_NIST.der").write_bytes(b"\x30\x01\x03")
        (certs_dir / "SK_EIM_ECDSA_NIST.pem").write_bytes(b"-----BEGIN PRIVATE KEY-----\nMC4CAQEE\n-----END PRIVATE KEY-----")
        
        rm = ResourceManager(tmpdir)
        cm = CertificateManager(rm)
        
        # 测试加载各种证书
        dp_auth_cert = cm.get_dp_auth_cert()
        assert isinstance(dp_auth_cert, bytes)
        
        dp_auth_key = cm.get_dp_auth_key()
        assert isinstance(dp_auth_key, bytes)
        
        dp_pb_cert = cm.get_dp_pb_cert()
        assert isinstance(dp_pb_cert, bytes)
        
        ci_cert = cm.get_ci_cert()
        assert isinstance(ci_cert, bytes)
        
        eim_cert = cm.get_eim_cert()
        assert isinstance(eim_cert, bytes)
        
        eim_key = cm.get_eim_key()
        assert isinstance(eim_key, bytes)


def test_profile_manager():
    """测试 Profile 管理器"""
    with tempfile.TemporaryDirectory() as tmpdir:
        profiles_dir = Path(tmpdir) / "profiles"
        profiles_dir.mkdir()
        
        # 创建测试 Profile 文件
        (profiles_dir / "PROFILE_TEST_123456.HEX").write_text("3000AABB")
        
        rm = ResourceManager(tmpdir)
        pm = ProfileManager(rm)
        
        profile = pm.get_profile_package("123456")
        assert profile == "3000AABB"
        
        # 测试缓存
        profile2 = pm.get_profile_package("123456")
        assert profile2 == profile
